// Copyright 2026 Google LLC
//
// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::undocumented_unsafe_blocks,
    clippy::field_reassign_with_default
)]

use std::collections::{HashMap, VecDeque};
use std::mem::size_of;
use std::ops::{Deref, DerefMut};
use std::os::fd::FromRawFd;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::{fmt, io, ptr, result, slice};

use vm_memory::guest_memory;

static NEXT_HANDLE_ID: AtomicU64 = AtomicU64::new(0x8000_0000_8000_0000);

use anyhow::anyhow;
use epoll;
use event_monitor::event;
use hypervisor::kvm::kvm_ioctls;
use log::{debug, error, info, warn};
use pci::{PciBarConfiguration, PciBarPrefetchable, PciBarRegionType};
use seccompiler::SeccompAction;
use serde::{Deserialize, Serialize};
use tachyon::rpc::{Client, Message, RpcClient};
use tachyon::{INVALID_HANDLE, Operation as TachyonOp, kvm, vfio};
use thiserror::Error;
use virtio_queue::{Queue, QueueT};
use vm_device::UserspaceMapping;
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::{
    Address, ByteValued, Bytes, GuestAddress, GuestAddressSpace, GuestMemory, GuestMemoryAtomic,
    GuestMemoryRegion, MmapRegion,
};
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};
use vm_virtio::AccessPlatform;
use vmm_sys_util::errno::Error as ErrnoError;
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::ioctl;

use super::{
    ActivateError, ActivateResult, ActivationContext, EPOLL_HELPER_EVENT_LAST, EpollHelper,
    EpollHelperError, EpollHelperHandler, Error as DeviceError, VIRTIO_F_VERSION_1, VirtioCommon,
    VirtioDevice, VirtioDeviceType,
};
use crate::seccomp_filters::Thread;
use crate::{GuestMemoryMmap, QueueSync, VirtioInterrupt, VirtioInterruptType};

const QUEUE_SIZE: u16 = 256;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE];
const VIRTIO_KVM_BAR_INDEX: usize = 4;

// New descriptors are pending on the virtio queue.
const QUEUE_AVAIL_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;

#[derive(Debug)]
struct PollWorkReq {
    resp_addr: GuestAddress,
    head_index: u16,
}

#[derive(Debug)]
enum PollWork {
    Process(PollWorkReq),
    Stop,
}

#[allow(clippy::needless_pass_by_value)]
fn poll_worker_run(
    receiver: mpsc::Receiver<PollWork>,
    poll_fd: RawFd,
    poll_wakeup_fd: EventFd,
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
    mut queue: QueueSync,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
    fd_to_handle: Arc<Mutex<HashMap<RawFd, u64>>>,
) {
    let event = epoll::Event::new(epoll::Events::EPOLLIN, poll_wakeup_fd.as_raw_fd() as u64);
    epoll::ctl(
        poll_fd,
        epoll::ControlOptions::EPOLL_CTL_ADD,
        poll_wakeup_fd.as_raw_fd(),
        event,
    )
    .unwrap();

    while let Ok(work) = receiver.recv() {
        let req = match work {
            PollWork::Process(req) => req,
            PollWork::Stop => break,
        };

        const MAX_EVENTS: usize = VIRTIO_KVM_POLL_BATCH;
        let mut events = [epoll::Event::new(epoll::Events::empty(), 0); MAX_EVENTS];
        let timeout = -1; // Blocking wait

        match epoll::wait(poll_fd, timeout, &mut events) {
            Ok(nfds) => {
                let mut poll = VirtioKvmPoll::default();
                let mut count = 0;
                let mut stop_received = false;
                for event in events.iter().take(nfds) {
                    let fd = event.data as i32;
                    if fd == poll_wakeup_fd.as_raw_fd() {
                        poll_wakeup_fd.read().unwrap();
                        stop_received = true;
                        continue;
                    }
                    let mut val: u64 = 0;
                    match unsafe { libc::read(fd, &mut val as *mut u64 as *mut libc::c_void, 8) } {
                        8 if count < VIRTIO_KVM_POLL_BATCH => {
                            let local_handle = *fd_to_handle.lock().unwrap().get(&fd).unwrap_or(&0);
                            poll.handle[count] = local_handle;
                            poll.vals[count] = val;
                            count += 1;
                        }
                        _ => { /* ignore read errors? */ }
                    }
                }

                if stop_received {
                    let resp = VirtioKvmResp::from_errno(libc::EINTR);
                    mem.memory()
                        .write_obj(resp, req.resp_addr)
                        .expect("virtio-kvm: failed to complete poll request");

                    let mut q = queue.lock();
                    q.add_used(
                        &*mem.memory(),
                        req.head_index,
                        size_of::<VirtioKvmResp>() as u32,
                    )
                    .expect("virtio-kvm: failed to complete poll request");
                    if q.needs_notification(&*mem.memory())
                        .expect("virtio-kvm: failed to complete poll request")
                    {
                        interrupt_cb
                            .trigger(VirtioInterruptType::Queue(0))
                            .expect("virtio-kvm: failed to complete poll request");
                    }
                    continue;
                }

                poll.status = count as u64;
                let mut resp = VirtioKvmResp::success();
                unsafe {
                    *(&mut resp as *mut _ as *mut VirtioKvmPoll) = poll;
                }
                mem.memory()
                    .write_obj(resp, req.resp_addr)
                    .expect("virtio-kvm: failed to complete poll request");

                let mut q = queue.lock();
                q.add_used(
                    &*mem.memory(),
                    req.head_index,
                    size_of::<VirtioKvmResp>() as u32,
                )
                .expect("virtio-kvm: failed to complete poll request");
                if q.needs_notification(&*mem.memory())
                    .expect("virtio-kvm: failed to complete poll request")
                {
                    interrupt_cb
                        .trigger(VirtioInterruptType::Queue(0))
                        .expect("virtio-kvm: failed to complete poll request");
                }
            }
            Err(e) => {
                let resp = VirtioKvmResp::from_errno(e.raw_os_error().unwrap_or(libc::EIO));
                mem.memory()
                    .write_obj(resp, req.resp_addr)
                    .expect("virtio-kvm: failed to complete poll request");

                let mut q = queue.lock();
                q.add_used(
                    &*mem.memory(),
                    req.head_index,
                    size_of::<VirtioKvmResp>() as u32,
                )
                .expect("virtio-kvm: failed to complete poll request");
                if q.needs_notification(&*mem.memory())
                    .expect("virtio-kvm: failed to complete poll request")
                {
                    interrupt_cb
                        .trigger(VirtioInterruptType::Queue(0))
                        .expect("virtio-kvm: failed to complete poll request");
                }
            }
        }
    }
}

#[derive(Debug, Copy, Clone)]
enum Operation {
    Open,
    Close,
    Ioctl,
    Kill,
    DeviceMmap,
    DeviceMunmap,
    MemoryFileCreate,
    MemoryFileDelete,
    EventfdGet,
    EventfdPut,
    EventfdWrite,
    EventfdPoll,
    FileIO,
    Ready,
    SetRunNotify,
    SetL1Memslot,
    InvalidateL1Memslot,
    L1FaultPoll,
    L1FaultAck,
    OpenVfioContainer,
    OpenVfioGroup,
    VfioGetGroups,
}

impl TryFrom<u64> for Operation {
    type Error = ();

    fn try_from(v: u64) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(Operation::Open),
            1 => Ok(Operation::Close),
            2 => Ok(Operation::Ioctl),
            3 => Ok(Operation::Kill),
            4 => Ok(Operation::DeviceMmap),
            5 => Ok(Operation::DeviceMunmap),
            6 => Ok(Operation::MemoryFileCreate),
            7 => Ok(Operation::MemoryFileDelete),
            8 => Ok(Operation::EventfdGet),
            9 => Ok(Operation::EventfdPut),
            10 => Ok(Operation::EventfdWrite),
            11 => Ok(Operation::EventfdPoll),
            12 => Ok(Operation::FileIO),
            13 => Ok(Operation::Ready),
            14 => Ok(Operation::SetRunNotify),
            15 => Ok(Operation::SetL1Memslot),
            16 => Ok(Operation::InvalidateL1Memslot),
            17 => Ok(Operation::L1FaultPoll),
            18 => Ok(Operation::L1FaultAck),
            64 => Ok(Operation::OpenVfioContainer),
            65 => Ok(Operation::OpenVfioGroup),
            68 => Ok(Operation::VfioGetGroups),
            _ => Err(()),
        }
    }
}

enum FileIoDirection {
    Read,
    Write,
}

impl TryFrom<u64> for FileIoDirection {
    type Error = ();

    fn try_from(v: u64) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(FileIoDirection::Read),
            2 => Ok(FileIoDirection::Write),
            _ => Err(()),
        }
    }
}

#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, Hash, Default)]
struct Handle(u64);

impl fmt::Debug for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Handle(0x{:x})", self.0)
    }
}

impl fmt::LowerHex for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

// SAFETY: it only has data and has no implicit padding.
unsafe impl ByteValued for Handle {}

impl Handle {
    fn new() -> Self {
        Handle(NEXT_HANDLE_ID.fetch_add(1, Ordering::Relaxed))
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct VirtioKvmReq {
    handle: Handle,
    operation: u64,
    arg: u64,
    longarg: u64,
}

// SAFETY: it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioKvmReq {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct VirtioKvmResp {
    status: u64,
    data: u64,
    pad: u64,
}

impl VirtioKvmResp {
    pub fn success() -> VirtioKvmResp {
        VirtioKvmResp {
            status: 0,
            data: 0,
            pad: 0,
        }
    }
    pub fn from_errno(errno: i32) -> VirtioKvmResp {
        VirtioKvmResp {
            status: errno as u64,
            data: 0,
            pad: 0,
        }
    }
    pub fn from_last_errno() -> VirtioKvmResp {
        VirtioKvmResp {
            status: ErrnoError::last().errno() as u64,
            data: 0,
            pad: 0,
        }
    }
    pub fn from_data(data: u64) -> VirtioKvmResp {
        VirtioKvmResp {
            status: 0,
            data,
            pad: 0,
        }
    }
}

// SAFETY: it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioKvmResp {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct VirtioKvmDevMmap {
    size: u64,
    device_offset: u64,
    phys_offset: u64,
}

// SAFETY: it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioKvmDevMmap {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct VirtioKvmMunmapDev {
    size: u64,
    phys_offset: u64,
}

// SAFETY: it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioKvmMunmapDev {}

const VIRTIO_KVM_POLL_BATCH: usize = 1;
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct VirtioKvmPoll {
    status: u64,
    handle: [u64; VIRTIO_KVM_POLL_BATCH],
    vals: [u64; VIRTIO_KVM_POLL_BATCH],
}
unsafe impl ByteValued for VirtioKvmPoll {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct VirtioKvmFileIo {
    buffer: u64,
    size: i64,
    offset: i64,
}

// SAFETY: it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioKvmFileIo {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct VirtioKvmMemoryFileCreate {
    size: u64,
    phys_offset: u64,
    handle: u64,
}

// SAFETY: it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioKvmMemoryFileCreate {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct VirtioKvmIoeventfd {
    kvm: kvm::kvm_ioeventfd,
    fd_handle: u64,
}

// SAFETY: it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioKvmIoeventfd {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct VirtioKvmIrqfd {
    kvm: kvm::kvm_irqfd,
    fd_handle: u64,
    resamplefd_handle: u64,
}

// SAFETY: it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioKvmIrqfd {}

#[derive(Clone)]
pub struct TachyonPartition {
    pub partition_id: u64,
    pub client: Arc<RpcClient>,
}

impl fmt::Debug for TachyonPartition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TachyonPartition")
            .field("partition_id", &self.partition_id)
            .finish()
    }
}

impl TachyonPartition {
    pub fn new(partition_id: u64, client: Arc<RpcClient>) -> Self {
        TachyonPartition {
            partition_id,
            client,
        }
    }

    pub fn partition_id(&self) -> u64 {
        self.partition_id
    }

    pub fn client(&self) -> &Arc<RpcClient> {
        &self.client
    }

    pub fn call(&self, msg: Message) -> io::Result<Message> {
        self.client.call(msg)
    }

    pub fn asynchronous_call(&self, msg: Message) -> io::Result<()> {
        self.client.asynchronous_call(msg)
    }

    pub fn fail_pending_requests(&self) {
        self.client.fail_pending_requests();
    }
}

struct KvmMemoryFile {
    fd: RawFd,
    size: u64,
    phys_offset: u64,
    tachyon_handle: u64,
    partition: TachyonPartition,
}

impl Drop for KvmMemoryFile {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

#[derive(Error, Debug)]
enum Error {
    #[error("Guest gave us a write only descriptor that protocol says to read from")]
    UnexpectedWriteOnlyDescriptor,
    #[error("Descriptor chain too short")]
    DescriptorChainTooShort,
    #[error("Failed to access guest memory: {0}")]
    GuestMemory(guest_memory::Error),
    #[error("Failed adding used index: {0}")]
    QueueAddUsed(virtio_queue::Error),
    #[error("Guest sent us invalid request")]
    InvalidRequest,
}

type LockedResource = Arc<Mutex<VirtioKvmResource>>;

type VmResourceMap = Mutex<HashMap<Handle, LockedResource>>;

struct EventfdInfo {
    eventfd: EventFd,
    refs: u32,
    tachyon_handle: u64,
    partition: TachyonPartition,
}

impl AsRawFd for EventfdInfo {
    fn as_raw_fd(&self) -> RawFd {
        self.eventfd.as_raw_fd()
    }
}

#[derive(Clone)]
struct KvmBarMapping {
    phys_offset: u64,
    size: u64,
    device_offset: u64,
}

struct NoopVirtioInterrupt;

impl VirtioInterrupt for NoopVirtioInterrupt {
    fn trigger(&self, _int_type: VirtioInterruptType) -> result::Result<(), io::Error> {
        Ok(())
    }

    fn set_notifier(
        &self,
        _int_type: u32,
        _notifier: Option<EventFd>,
        _vm: &dyn hypervisor::Vm,
    ) -> result::Result<(), io::Error> {
        Ok(())
    }
}

type MemFiles = HashMap<u64, KvmMemoryFile>;

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct VirtioKvmL1Fault {
    vm_handle: u64,
    gpa: u64,
    seq: u64,
}

// SAFETY: `VirtioKvmL1Fault` is a plain `#[repr(C)]` struct of `u64` fields.
unsafe impl ByteValued for VirtioKvmL1Fault {}

#[derive(Copy, Clone)]
struct PendingL1Fault {
    vm_handle: u64,
    gpa: u64,
    seq: u64,
}

struct PendingL1FaultPoll {
    head_index: u16,
    resp_addr: GuestAddress,
    fault_addr: GuestAddress,
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
    queue: QueueSync,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
}

#[derive(Default)]
struct L1FaultState {
    pending_faults: VecDeque<PendingL1Fault>,
    pending_poll: Option<PendingL1FaultPoll>,
}

#[derive(Clone)]
struct TachyonConnection {
    socket_dir: PathBuf,
    partitions: Arc<Mutex<HashMap<u64, TachyonPartition>>>,
    l1_fault_state: Arc<Mutex<L1FaultState>>,
}

impl TachyonConnection {
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(socket_dir: PathBuf) -> TachyonConnection {
        TachyonConnection {
            socket_dir,
            partitions: Arc::new(Mutex::new(HashMap::new())),
            l1_fault_state: Arc::new(Mutex::new(L1FaultState::default())),
        }
    }

    fn socket_for_partition(&self, partition_id: u64) -> PathBuf {
        self.socket_dir.join(format!("{partition_id}.sock"))
    }

    /// Sends the L1 guest RAM backing fds and GPA ranges to Tachyon so that
    /// `/dev/tachyon-mem` can map L1-backed L2 memslots.
    fn send_l1_memory(conn: &Arc<RpcClient>, mem_atomic: &GuestMemoryAtomic<GuestMemoryMmap>) {
        #[repr(C)]
        struct RegionDescWire {
            l1_gpa: u64,
            size: u64,
            fd_offset: u64,
        }
        let mem = mem_atomic.memory();
        let mut body = Vec::new();
        let mut fds = Vec::new();
        for region in mem.iter() {
            let Some(fo) = region.file_offset() else {
                continue;
            };
            let desc = RegionDescWire {
                l1_gpa: region.start_addr().raw_value(),
                size: region.len(),
                fd_offset: fo.start(),
            };
            // SAFETY: `RegionDescWire` is `#[repr(C)]` plain data.
            let bytes = unsafe {
                slice::from_raw_parts(&desc as *const _ as *const u8, size_of::<RegionDescWire>())
            };
            body.extend_from_slice(bytes);
            fds.push(fo.file().as_raw_fd());
        }
        if fds.is_empty() {
            return;
        }
        let msg = Message::simple(TachyonOp::SetL1Memory as u32, 1)
            .with_body(body)
            .with_fds(fds);
        match conn.call(msg) {
            Ok(resp) if resp.status == 0 => {
                info!("virtio-kvm: registered L1 backing memory with Tachyon");
            }
            Ok(resp) => {
                warn!("virtio-kvm: SetL1Memory returned status {}", resp.status);
            }
            Err(e) => {
                warn!("virtio-kvm: SetL1Memory RPC failed: {e}");
            }
        }
    }

    fn connect(socket_path: &PathBuf) -> io::Result<RpcClient> {
        info!("Attempting to connect to Tachyon at {socket_path:?}");
        let tachyon_channel = Client::connect(socket_path).map_err(|e| {
            io::Error::other(format!(
                "Failed to connect to tachyon at {socket_path:?}: {e}",
            ))
        })?;
        info!("Connected to Tachyon at {socket_path:?}");
        Ok(RpcClient::new(tachyon_channel))
    }

    fn prepare_connection(conn: &Arc<RpcClient>, virtio_kvm: &VirtioKvmEpollHandler) {
        // Register notification handler for live-update
        let handler_resources = virtio_kvm.resources.clone();
        let handler_mappings = virtio_kvm.mappings.clone();
        let handler_tachyon = virtio_kvm.tachyon.clone();
        let handler_bar_mapping = virtio_kvm.bar_mapping.clone();

        conn.set_notification_handler(move |msg| {
            if msg.msg_type == TachyonOp::FaultL1Page as u32 && msg.body.len() >= 24 {
                let tachyon_vm_handle = u64::from_le_bytes(msg.body[0..8].try_into().unwrap());
                let gpa = u64::from_le_bytes(msg.body[8..16].try_into().unwrap());
                let seq = u64::from_le_bytes(msg.body[16..24].try_into().unwrap());

                let l1_vm_handle = {
                    let resources = handler_resources.lock().unwrap();
                    resources.iter().find_map(|(id, res)| {
                        let guard = res.lock().unwrap();
                        match &*guard {
                            VirtioKvmResource::Vm(vm)
                                if vm.tachyon_handle() == tachyon_vm_handle =>
                            {
                                Some(id.0)
                            }
                            _ => None,
                        }
                    })
                };

                match l1_vm_handle {
                    Some(vm_handle) => {
                        handler_tachyon.push_l1_fault(vm_handle, gpa, seq);
                    }
                    None => {
                        handler_tachyon.ack_l1_fault(seq);
                    }
                }
            } else if msg.msg_type == TachyonOp::NotifyLiveUpdate as u32 {
                // Abort all pending requests so they can be retried with new resources
                handler_tachyon.fail_pending_requests();

                // We need to call refresh_resources. Since we don't want to capture
                // the whole handler (which might be moved into a thread), we recreate
                // a minimal handler or just the logic.
                let temp_handler = VirtioKvmEpollHandler {
                    mem: GuestMemoryAtomic::new(GuestMemoryMmap::new()), // Dummy, not needed for refresh
                    queue: QueueSync::from(Queue::new(1024).unwrap()),   // Dummy
                    interrupt_cb: Arc::new(NoopVirtioInterrupt),         // Dummy
                    queue_evt: EventFd::new(0).unwrap(),                 // Dummy
                    kill_evt: EventFd::new(0).unwrap(),                  // Dummy
                    pause_evt: EventFd::new(0).unwrap(),                 // Dummy
                    access_platform: None,
                    resources: handler_resources.clone(),
                    eventfds: Arc::new(Mutex::new(HashMap::new())), // Dummy
                    fd_to_handle: Arc::new(Mutex::new(HashMap::new())), // Dummy
                    mem_files: Arc::new(Mutex::new(HashMap::new())), // Dummy
                    mappings: handler_mappings.clone(),
                    poll_fd: -1,
                    bar_mapping: handler_bar_mapping.clone(),
                    poll_work_sender: mpsc::channel().0, // Dummy
                    tachyon: handler_tachyon.clone(),
                };
                temp_handler.refresh_resources();
            }
        });
    }

    fn complete_l1_fault_poll(mut poll: PendingL1FaultPoll, fault: PendingL1Fault) {
        let wire = VirtioKvmL1Fault {
            vm_handle: fault.vm_handle,
            gpa: fault.gpa,
            seq: fault.seq,
        };
        let mem = poll.mem.memory();
        let resp = if mem.write_obj(wire, poll.fault_addr).is_ok() {
            VirtioKvmResp::success()
        } else {
            VirtioKvmResp::from_errno(libc::EFAULT)
        };
        if let Err(e) = mem.write_obj(resp, poll.resp_addr) {
            error!("virtio-kvm: failed to write L1FaultPoll resp: {e}");
            return;
        }
        let mut q = poll.queue.lock();
        if let Err(e) = q.add_used(&*mem, poll.head_index, size_of::<VirtioKvmResp>() as u32) {
            error!("virtio-kvm: failed to add_used L1FaultPoll: {e}");
            return;
        }
        if q.needs_notification(&*mem).unwrap_or(true)
            && let Err(e) = poll.interrupt_cb.trigger(VirtioInterruptType::Queue(0))
        {
            error!("virtio-kvm: failed to trigger L1FaultPoll interrupt: {e}");
        }
    }

    fn push_l1_fault(&self, vm_handle: u64, gpa: u64, seq: u64) {
        let fault = PendingL1Fault {
            vm_handle,
            gpa,
            seq,
        };
        let poll = {
            let mut state = self.l1_fault_state.lock().unwrap();
            if let Some(poll) = state.pending_poll.take() {
                Some(poll)
            } else {
                state.pending_faults.push_back(fault);
                None
            }
        };
        if let Some(poll) = poll {
            Self::complete_l1_fault_poll(poll, fault);
        }
    }

    fn ack_l1_fault(&self, seq: u64) {
        let partitions = self.partitions.lock().unwrap();
        for p in partitions.values() {
            let mut msg = Message::simple(TachyonOp::AckL1Fault as u32, 1);
            msg.arg = seq;
            if let Err(e) = p.client().call(msg) {
                warn!("virtio-kvm: AckL1Fault RPC failed for seq={seq}: {e}");
            }
        }
    }

    pub fn prepare_all_connections(&self, virtio_kvm: &VirtioKvmEpollHandler) {
        let partitions = self.partitions.lock().unwrap();
        for partition in partitions.values() {
            Self::prepare_connection(partition.client(), virtio_kvm);
        }
    }

    pub fn prepare_partition(
        &self,
        virtio_kvm: &VirtioKvmEpollHandler,
        partition_id: u64,
    ) -> io::Result<TachyonPartition> {
        let mut partitions = self.partitions.lock().unwrap();
        if let Some(partition) = partitions.get(&partition_id) {
            Self::prepare_connection(partition.client(), virtio_kvm);
            return Ok(partition.clone());
        }
        let sock_path = self.socket_for_partition(partition_id);
        let new_conn = Arc::new(Self::connect(&sock_path)?);
        Self::prepare_connection(&new_conn, virtio_kvm);
        Self::send_l1_memory(&new_conn, &virtio_kvm.mem);
        let partition = TachyonPartition::new(partition_id, new_conn);
        partitions.insert(partition_id, partition.clone());
        Ok(partition)
    }

    pub fn get_partition(&self, partition_id: u64) -> io::Result<TachyonPartition> {
        let mut partitions = self.partitions.lock().unwrap();
        if let Some(partition) = partitions.get(&partition_id) {
            return Ok(partition.clone());
        }
        let sock_path = self.socket_for_partition(partition_id);
        let client = Arc::new(Self::connect(&sock_path)?);
        let partition = TachyonPartition::new(partition_id, client);
        partitions.insert(partition_id, partition.clone());
        Ok(partition)
    }

    #[allow(dead_code)]
    pub fn call(&self, msg: Message) -> io::Result<Message> {
        self.call_partition(0, msg)
    }

    pub fn call_partition(&self, partition_id: u64, msg: Message) -> io::Result<Message> {
        let partition = self.get_partition(partition_id)?;
        partition.call(msg)
    }

    #[allow(dead_code)]
    pub fn asynchronous_call(&self, msg: Message) -> io::Result<()> {
        self.asynchronous_call_partition(0, msg)
    }

    pub fn asynchronous_call_partition(&self, partition_id: u64, msg: Message) -> io::Result<()> {
        let partition = self.get_partition(partition_id)?;
        partition.asynchronous_call(msg)
    }

    pub fn fail_pending_requests(&self) {
        let partitions = self.partitions.lock().unwrap();
        for partition in partitions.values() {
            partition.fail_pending_requests();
        }
    }

    pub fn pause_all(&self) {
        let partitions = self.partitions.lock().unwrap();
        for (partition_id, partition) in partitions.iter() {
            let msg = Message::simple(TachyonOp::Pause as u32, 1);
            if let Err(e) = partition.call(msg) {
                error!(
                    "virtio-kvm: Failed to send Pause RPC to Tachyon partition {partition_id}: {e}"
                );
            }
        }
    }

    pub fn unpause_all(&self) {
        let partitions = self.partitions.lock().unwrap();
        for (partition_id, partition) in partitions.iter() {
            let msg = Message::simple(TachyonOp::Unpause as u32, 1);
            if let Err(e) = partition.call(msg) {
                error!(
                    "virtio-kvm: Failed to send Unpause RPC to Tachyon partition {partition_id}: {e}"
                );
            }
        }
    }
}

pub struct VirtioKvm {
    common: VirtioCommon,
    id: String,
    seccomp_action: SeccompAction,
    exit_evt: EventFd,
    resources: Arc<VmResourceMap>,
    eventfds: Arc<Mutex<HashMap<u64, EventfdInfo>>>,
    fd_to_handle: Arc<Mutex<HashMap<RawFd, u64>>>,
    mem_files: Arc<Mutex<MemFiles>>,
    mappings: Arc<Mutex<HashMap<Handle, KvmBarMapping>>>,
    #[allow(dead_code)]
    _bar_region: Arc<MmapRegion<AtomicBitmap>>,
    bar_mapping: UserspaceMapping,
    poll_fd: Option<RawFd>,
    poll_thread: Option<JoinHandle<()>>,
    poll_work_sender: Option<mpsc::Sender<PollWork>>,
    poll_wakeup_fd: Option<EventFd>,
    tachyon: TachyonConnection,
}

struct VirtioKvmEpollHandler {
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
    queue: QueueSync,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
    queue_evt: EventFd,
    kill_evt: EventFd,
    pause_evt: EventFd,
    #[allow(dead_code)]
    access_platform: Option<Arc<dyn AccessPlatform>>,
    resources: Arc<VmResourceMap>,
    eventfds: Arc<Mutex<HashMap<u64, EventfdInfo>>>,
    fd_to_handle: Arc<Mutex<HashMap<RawFd, u64>>>,
    mem_files: Arc<Mutex<MemFiles>>,
    mappings: Arc<Mutex<HashMap<Handle, KvmBarMapping>>>,
    poll_fd: RawFd,
    bar_mapping: UserspaceMapping,
    poll_work_sender: mpsc::Sender<PollWork>,
    tachyon: TachyonConnection,
}

trait TachyonResource {
    fn tachyon_handle(&self) -> u64;
    fn partition(&self) -> &TachyonPartition;
    fn partition_id(&self) -> u64 {
        self.partition().partition_id()
    }
}

#[derive(Debug)]
struct VirtioKvmSystem {
    kvm: kvm_ioctls::Kvm,
    partition: TachyonPartition,
}

impl AsRawFd for VirtioKvmSystem {
    fn as_raw_fd(&self) -> RawFd {
        self.kvm.as_raw_fd()
    }
}

impl TachyonResource for VirtioKvmSystem {
    fn tachyon_handle(&self) -> u64 {
        1
    }

    fn partition(&self) -> &TachyonPartition {
        &self.partition
    }
}

struct VirtioKvmVm {
    fd: RawFd,
    shm_fd: RawFd,
    tachyon_handle: u64,
    shm_bar_offset: Arc<AtomicU64>,
    partition: TachyonPartition,
}

impl Drop for VirtioKvmVm {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
            libc::close(self.shm_fd);
        }
    }
}

impl AsRawFd for VirtioKvmVm {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl TachyonResource for VirtioKvmVm {
    fn tachyon_handle(&self) -> u64 {
        self.tachyon_handle
    }

    fn partition(&self) -> &TachyonPartition {
        &self.partition
    }
}

struct VirtioKvmVfioContainer {
    fd: RawFd,
    tachyon_handle: u64,
    partition: TachyonPartition,
}

impl Drop for VirtioKvmVfioContainer {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

impl AsRawFd for VirtioKvmVfioContainer {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl fmt::Debug for VirtioKvmVfioContainer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VirtioKvmVfioContainer")
            .field("fd", &self.fd)
            .field("tachyon_handle", &self.tachyon_handle)
            .field("partition_id", &self.partition.partition_id())
            .finish()
    }
}

impl TachyonResource for VirtioKvmVfioContainer {
    fn tachyon_handle(&self) -> u64 {
        self.tachyon_handle
    }

    fn partition(&self) -> &TachyonPartition {
        &self.partition
    }
}

struct VirtioKvmVfioGroup {
    fd: RawFd,
    tachyon_handle: u64,
    partition: TachyonPartition,
}

impl Drop for VirtioKvmVfioGroup {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

impl AsRawFd for VirtioKvmVfioGroup {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl fmt::Debug for VirtioKvmVfioGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VirtioKvmVfioGroup")
            .field("fd", &self.fd)
            .field("tachyon_handle", &self.tachyon_handle)
            .field("partition_id", &self.partition.partition_id())
            .finish()
    }
}

impl TachyonResource for VirtioKvmVfioGroup {
    fn tachyon_handle(&self) -> u64 {
        self.tachyon_handle
    }

    fn partition(&self) -> &TachyonPartition {
        &self.partition
    }
}

struct VirtioKvmVfioDevice {
    fd: RawFd,
    tachyon_handle: u64,
    partition: TachyonPartition,
}

impl Drop for VirtioKvmVfioDevice {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

impl AsRawFd for VirtioKvmVfioDevice {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl fmt::Debug for VirtioKvmVfioDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VirtioKvmVfioDevice")
            .field("fd", &self.fd)
            .field("tachyon_handle", &self.tachyon_handle)
            .field("partition_id", &self.partition.partition_id())
            .finish()
    }
}

impl TachyonResource for VirtioKvmVfioDevice {
    fn tachyon_handle(&self) -> u64 {
        self.tachyon_handle
    }

    fn partition(&self) -> &TachyonPartition {
        &self.partition
    }
}

struct VirtioKvmVcpu {
    fd: RawFd,
    vcpu_id: u32,
    vm_handle: Handle,
    tachyon_handle: u64,
    partition: TachyonPartition,
}

impl Drop for VirtioKvmVcpu {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

impl fmt::Debug for VirtioKvmVcpu {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VirtioKvmVcpu")
            .field("fd", &self.fd)
            .field(
                "tachyon_handle",
                &format_args!("0x{:x}", self.tachyon_handle),
            )
            .field("partition_id", &self.partition.partition_id())
            .finish()
    }
}

impl AsRawFd for VirtioKvmVcpu {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl TachyonResource for VirtioKvmVcpu {
    fn tachyon_handle(&self) -> u64 {
        self.tachyon_handle
    }

    fn partition(&self) -> &TachyonPartition {
        &self.partition
    }
}

impl fmt::Debug for VirtioKvmVm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VirtioKvmVm")
            .field("fd", &self.fd)
            .field("shm_fd", &self.shm_fd)
            .field(
                "tachyon_handle",
                &format_args!("0x{:x}", self.tachyon_handle),
            )
            .field("shm_bar_offset", &self.shm_bar_offset)
            .field("partition_id", &self.partition.partition_id())
            .finish()
    }
}

struct VirtioKvmStats {
    fd: RawFd,
    parent_handle: Handle,
    partition: TachyonPartition,
}

impl AsRawFd for VirtioKvmStats {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl fmt::Debug for VirtioKvmStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VirtioKvmStats")
            .field("fd", &self.fd)
            .field("partition_id", &self.partition.partition_id())
            .finish()
    }
}

impl Drop for VirtioKvmStats {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

impl TachyonResource for VirtioKvmStats {
    fn tachyon_handle(&self) -> u64 {
        0
    }

    fn partition(&self) -> &TachyonPartition {
        &self.partition
    }
}

#[derive(Debug)]
enum VirtioKvmResource {
    System(VirtioKvmSystem),
    Vm(VirtioKvmVm),
    Vcpu(VirtioKvmVcpu),
    Stats(VirtioKvmStats),
    VfioContainer(VirtioKvmVfioContainer),
    VfioGroup(VirtioKvmVfioGroup),
    VfioDevice(VirtioKvmVfioDevice),
}

impl AsRawFd for VirtioKvmResource {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            VirtioKvmResource::System(sys) => sys.as_raw_fd(),
            VirtioKvmResource::Vm(vm) => vm.as_raw_fd(),
            VirtioKvmResource::Vcpu(vcpu) => vcpu.as_raw_fd(),
            VirtioKvmResource::Stats(stats) => stats.as_raw_fd(),
            VirtioKvmResource::VfioContainer(container) => container.as_raw_fd(),
            VirtioKvmResource::VfioGroup(group) => group.as_raw_fd(),
            VirtioKvmResource::VfioDevice(device) => device.as_raw_fd(),
        }
    }
}

impl TachyonResource for VirtioKvmResource {
    fn tachyon_handle(&self) -> u64 {
        match self {
            VirtioKvmResource::System(sys) => sys.tachyon_handle(),
            VirtioKvmResource::Vm(vm) => vm.tachyon_handle(),
            VirtioKvmResource::Vcpu(vcpu) => vcpu.tachyon_handle(),
            VirtioKvmResource::Stats(stats) => stats.tachyon_handle(),
            VirtioKvmResource::VfioContainer(container) => container.tachyon_handle(),
            VirtioKvmResource::VfioGroup(group) => group.tachyon_handle(),
            VirtioKvmResource::VfioDevice(device) => device.tachyon_handle(),
        }
    }

    fn partition(&self) -> &TachyonPartition {
        match self {
            VirtioKvmResource::System(sys) => &sys.partition,
            VirtioKvmResource::Vm(vm) => &vm.partition,
            VirtioKvmResource::Vcpu(vcpu) => &vcpu.partition,
            VirtioKvmResource::Stats(stats) => &stats.partition,
            VirtioKvmResource::VfioContainer(container) => &container.partition,
            VirtioKvmResource::VfioGroup(group) => &group.partition,
            VirtioKvmResource::VfioDevice(device) => &device.partition,
        }
    }
}

impl VirtioKvmResource {
    fn new_system(partition: TachyonPartition) -> Result<Self, ErrnoError> {
        match kvm_ioctls::Kvm::new() {
            Ok(kvm) => Ok(VirtioKvmResource::System(VirtioKvmSystem {
                kvm,
                partition,
            })),
            Err(e) => Err(e),
        }
    }
}

fn virtio_kvm_ioctl_with_uaccess(
    fd: RawFd,
    req: &VirtioKvmReq,
    memory: &GuestMemoryAtomic<GuestMemoryMmap>,
) -> VirtioKvmResp {
    // req.longarg is the GPA for the arguments we are meant to pass to the ioctl.
    // Translate it to the corresponding host virtual address now.
    let mem = memory.memory();
    let hva = match mem.get_host_address(GuestAddress::new(req.longarg)) {
        Ok(hva) => hva,
        Err(_e) => {
            debug!(
                "!! virtio_kvm: uaccess: failed to get host address: {:#?}",
                req.longarg
            );
            return VirtioKvmResp::from_errno(libc::EFAULT);
        }
    };
    // SAFETY: This is not safe (yet!). Please bounds-check the pointer!
    let ret = unsafe { ioctl::ioctl_with_ptr(&fd, req.arg, hva) };
    if ret < 0 {
        VirtioKvmResp::from_last_errno()
    } else {
        VirtioKvmResp::from_data(ret as u64)
    }
}

impl VirtioKvmEpollHandler {
    fn resolve_eventfd(&self, local_handle: u64) -> Option<u64> {
        let eventfds = self.eventfds.lock().unwrap();
        eventfds.get(&local_handle).map(|info| info.tachyon_handle)
    }

    fn handle_set_msr_filter(
        &self,
        partition: &TachyonPartition,
        tachyon_handle: u64,
        req: &VirtioKvmReq,
        mem: &GuestMemoryMmap,
    ) -> VirtioKvmResp {
        let gpa = GuestAddress::new(req.longarg);
        let mut filter: kvm::kvm_msr_filter = match mem.read_obj(gpa) {
            Ok(filter) => filter,
            Err(_) => return VirtioKvmResp::from_errno(libc::EFAULT),
        };

        let mut body = vec![0u8; size_of::<kvm::kvm_msr_filter>()];
        // We will store the filter at the beginning of the body.
        // We'll update it later with offsets.

        for range in filter.ranges.iter_mut() {
            if range.nmsrs == 0 {
                range.bitmap = 0;
                continue;
            }

            if range.bitmap == 0 {
                return VirtioKvmResp::from_errno(libc::EINVAL);
            }

            let bitmap_size = range.nmsrs.div_ceil(8) as usize;
            let offset = body.len();
            let mut bitmap_buf = vec![0u8; bitmap_size];
            if mem
                .read_slice(&mut bitmap_buf, GuestAddress::new(range.bitmap))
                .is_err()
            {
                return VirtioKvmResp::from_errno(libc::EFAULT);
            }
            body.extend_from_slice(&bitmap_buf);
            range.bitmap = offset as u64;
        }

        // Update the filter at the beginning of the body with the offsets
        let filter_slice = unsafe {
            slice::from_raw_parts(
                &filter as *const kvm::kvm_msr_filter as *const u8,
                size_of::<kvm::kvm_msr_filter>(),
            )
        };
        body[0..size_of::<kvm::kvm_msr_filter>()].copy_from_slice(filter_slice);

        let msg = Message::ioctl(tachyon_handle, req.arg, 0).with_body(body);

        match partition.call(msg) {
            Ok(resp) => {
                if resp.status == 0 {
                    VirtioKvmResp::from_data(resp.arg)
                } else {
                    VirtioKvmResp::from_errno(resp.status as i32)
                }
            }
            Err(e) => {
                error!("virtio-kvm: KVM_X86_SET_MSR_FILTER RPC failed: {e}");
                VirtioKvmResp::from_errno(libc::EIO)
            }
        }
    }

    fn handle_open(&self, req: &VirtioKvmReq) -> VirtioKvmResp {
        let partition_id = req.arg;
        debug!("!! virtio_kvm: handle_open for partition {partition_id}");
        let partition = match self.tachyon.prepare_partition(self, partition_id) {
            Ok(p) => p,
            Err(e) => {
                debug!(
                    "!! virtio_kvm: failed to prepare tachyon for partition {partition_id}: {e}"
                );
                return VirtioKvmResp::from_errno(libc::EIO);
            }
        };
        let vm = match VirtioKvmResource::new_system(partition) {
            Ok(vm) => vm,
            Err(e) => {
                return VirtioKvmResp::from_errno(e.errno());
            }
        };
        let mut map = self.resources.lock().unwrap();

        debug!("!! virtio_kvm: handle_open: vm: {vm:#?}");
        let handle = Handle::new();

        if map.contains_key(&handle) {
            debug!("!! virtio_kvm: open(): duplicate handle: 0x{handle:x}");
            return VirtioKvmResp::from_errno(libc::EEXIST);
        }

        debug!("!! virtio_kvm: handle_open: inserting vm into map");
        map.insert(handle, Arc::new(Mutex::new(vm)));

        debug!("!! virtio_kvm: handle_open: returning response");
        VirtioKvmResp::from_data(handle.0)
    }

    fn handle_close(&self, req: &VirtioKvmReq) -> VirtioKvmResp {
        let mut map = self.resources.lock().unwrap();
        let handle = req.handle;
        let resource = match map.remove(&handle) {
            Some(r) => r,
            None => {
                debug!("!! virtio_kvm: close(): unknown handle: 0x{:x}", req.handle);
                return VirtioKvmResp::from_errno(libc::ENOENT);
            }
        };

        let (tachyon_handle, partition) = {
            let guard = resource.lock().unwrap();
            (guard.tachyon_handle(), guard.partition().clone())
        };

        let msg = Message::new(TachyonOp::Close as u32, tachyon_handle, 0, 0);
        if let Err(e) = partition.call(msg) {
            error!("virtio-kvm: close() RPC failed: {e}");
        }

        VirtioKvmResp::success()
    }

    fn handle_kill(&self, req: &VirtioKvmReq) -> Option<VirtioKvmResp> {
        let handle: Handle = req.handle;
        let resource = {
            let resource_map = self.resources.lock().unwrap();
            match resource_map.get(&handle) {
                Some(resource) => resource.clone(),
                None => return Some(VirtioKvmResp::from_errno(libc::ENOENT)),
            }
        };
        let mut guard = resource.lock().unwrap();
        match guard.deref_mut() {
            VirtioKvmResource::Vcpu(virtio_vcpu) => {
                debug!(
                    "!! virtio_kvm: handle_kill: sending Interrupt to tachyon handle 0x{:x}",
                    virtio_vcpu.tachyon_handle
                );
                let msg = Message {
                    msg_type: TachyonOp::Interrupt as u32,
                    request_id: 0,
                    handle: virtio_vcpu.tachyon_handle,
                    status: 0,
                    arg: 0,
                    cmd: 0,
                    resp_size: 0,
                    body: Vec::new(),
                    fds: None,
                };
                if let Err(e) = virtio_vcpu.partition.asynchronous_call(msg) {
                    error!("!! virtio_kvm: failed to send Interrupt RPC: {e}");
                }
                Some(VirtioKvmResp::success())
            }
            _ => Some(VirtioKvmResp::from_errno(libc::EINVAL)),
        }
    }

    fn handle_system_create_vm(&self, partition: &TachyonPartition) -> VirtioKvmResp {
        // 1. Request VM from Tachyon
        let handle: u64 = 1; // KVM Device handle in Tachyon is always 1
        let msg = Message::ioctl(handle, kvm::KVM_CREATE_VM, 0);

        let resp = match partition.call(msg) {
            Ok(r) => r,
            Err(e) => {
                error!("virtio-kvm: KVM_CREATE_VM RPC failed: {e}");
                return VirtioKvmResp::from_errno(libc::EIO);
            }
        };

        if resp.status != 0 {
            return VirtioKvmResp::from_errno(resp.status as i32);
        }

        let tachyon_vm_handle = resp.handle;
        let shm_fd = resp
            .fds
            .and_then(|mut fds| fds.pop())
            .ok_or(libc::EIO)
            .unwrap_or(-1);

        if shm_fd < 0 {
            error!("virtio-kvm: KVM_CREATE_VM RPC returned no SHM FD");
            return VirtioKvmResp::from_errno(libc::EIO);
        }

        // 2. Get VM FD from Tachyon
        let msg_fd = Message::get_file(tachyon_vm_handle);

        let resp_fd = match partition.call(msg_fd) {
            Ok(r) => r,
            Err(e) => {
                error!("virtio-kvm: GetFileDescriptor RPC failed: {e}");
                unsafe { libc::close(shm_fd) };
                return VirtioKvmResp::from_errno(libc::EIO);
            }
        };

        if resp_fd.status != 0 {
            unsafe { libc::close(shm_fd) };
            return VirtioKvmResp::from_errno(resp_fd.status as i32);
        }

        let vm_fd = resp_fd
            .fds
            .and_then(|mut fds| fds.pop())
            .ok_or(libc::EIO)
            .unwrap_or(-1);
        if vm_fd < 0 {
            unsafe { libc::close(shm_fd) };
            return VirtioKvmResp::from_errno(libc::EIO);
        }

        // 3. Initialize VirtioKvmVm
        let vm_handle = Handle::new();
        let vm = VirtioKvmVm {
            fd: vm_fd,
            shm_fd,
            tachyon_handle: tachyon_vm_handle,
            shm_bar_offset: Arc::new(AtomicU64::new(u64::MAX)),
            partition: partition.clone(),
        };
        self.resources
            .lock()
            .unwrap()
            .insert(vm_handle, Arc::new(Mutex::new(VirtioKvmResource::Vm(vm))));

        VirtioKvmResp::from_data(vm_handle.0)
    }

    fn handle_system_generic_ioctl(
        &self,
        partition: &TachyonPartition,
        req: &VirtioKvmReq,
    ) -> VirtioKvmResp {
        let ioctl_num = req.arg;
        let msg = Message::ioctl(1, ioctl_num, req.longarg);

        match partition.call(msg) {
            Ok(resp) => {
                if resp.status == 0 {
                    VirtioKvmResp::from_data(resp.arg)
                } else {
                    VirtioKvmResp::from_errno(resp.status as i32)
                }
            }
            Err(e) => {
                error!("virtio-kvm: system ioctl {ioctl_num} RPC failed: {e}");
                VirtioKvmResp::from_errno(libc::EIO)
            }
        }
    }

    fn handle_open_vfio_container(&self, req: &VirtioKvmReq) -> VirtioKvmResp {
        let partition_id = req.arg;
        let partition = match self.tachyon.prepare_partition(self, partition_id) {
            Ok(p) => p,
            Err(e) => {
                debug!(
                    "!! virtio_kvm: failed to prepare tachyon for partition {partition_id}: {e}"
                );
                return VirtioKvmResp::from_errno(libc::EIO);
            }
        };

        // Make the VFIO container in Tachyon
        let msg = Message::simple(TachyonOp::OpenVfioContainer as u32, 1);
        let resp = match partition.call(msg) {
            Ok(r) => r,
            Err(e) => {
                error!("virtio-kvm: OpenVfioContainer RPC failed: {e}");
                return VirtioKvmResp::from_errno(libc::EIO);
            }
        };

        if resp.status != 0 {
            return VirtioKvmResp::from_errno(resp.status as i32);
        }

        let tachyon_vfio_handle = resp.handle;

        // Get the open file.
        let msg_fd = Message::get_file(tachyon_vfio_handle);

        let resp_fd = match partition.call(msg_fd) {
            Ok(r) => r,
            Err(e) => {
                error!("virtio-kvm: GetFileDescriptor RPC failed: {e}");
                return VirtioKvmResp::from_errno(libc::EIO);
            }
        };

        if resp_fd.status != 0 {
            return VirtioKvmResp::from_errno(resp_fd.status as i32);
        }

        let vfio_fd = resp_fd
            .fds
            .and_then(|mut fds| fds.pop())
            .ok_or(libc::EIO)
            .unwrap_or(-1);
        if vfio_fd < 0 {
            return VirtioKvmResp::from_errno(libc::EIO);
        }

        let vfio_handle = Handle(vfio_fd as u64);
        let vfio = VirtioKvmVfioContainer {
            fd: vfio_fd,
            tachyon_handle: tachyon_vfio_handle,
            partition: partition.clone(),
        };
        self.resources.lock().unwrap().insert(
            vfio_handle,
            Arc::new(Mutex::new(VirtioKvmResource::VfioContainer(vfio))),
        );

        VirtioKvmResp::from_data(vfio_fd as u64)
    }

    fn handle_open_vfio_group(&self, req: &VirtioKvmReq) -> VirtioKvmResp {
        let partition_id = req.arg;
        let group_id = req.longarg;
        let partition = match self.tachyon.prepare_partition(self, partition_id) {
            Ok(p) => p,
            Err(e) => {
                debug!(
                    "!! virtio_kvm: failed to prepare tachyon for partition {partition_id}: {e}"
                );
                return VirtioKvmResp::from_errno(libc::EIO);
            }
        };

        let msg = Message::new(TachyonOp::OpenVfioGroup as u32, 1, 0, group_id);

        let resp = match partition.call(msg) {
            Ok(r) => r,
            Err(e) => {
                error!("virtio-kvm: OpenVfioGroup RPC failed: {e}");
                return VirtioKvmResp::from_errno(libc::EIO);
            }
        };

        if resp.status != 0 {
            return VirtioKvmResp::from_errno(resp.status as i32);
        }

        let tachyon_group_handle = resp.handle;

        // Get the open file.
        let msg_fd = Message::get_file(tachyon_group_handle);

        let resp_fd = match partition.call(msg_fd) {
            Ok(r) => r,
            Err(e) => {
                error!("virtio-kvm: GetFileDescriptor RPC failed: {e}");
                return VirtioKvmResp::from_errno(libc::EIO);
            }
        };

        if resp_fd.status != 0 {
            return VirtioKvmResp::from_errno(resp_fd.status as i32);
        }

        let group_fd = resp_fd
            .fds
            .and_then(|mut fds| fds.pop())
            .ok_or(libc::EIO)
            .unwrap_or(-1);
        if group_fd < 0 {
            return VirtioKvmResp::from_errno(libc::EIO);
        }

        let group_handle = Handle(group_fd as u64);
        let group = VirtioKvmVfioGroup {
            fd: group_fd,
            tachyon_handle: tachyon_group_handle,
            partition: partition.clone(),
        };
        self.resources.lock().unwrap().insert(
            group_handle,
            Arc::new(Mutex::new(VirtioKvmResource::VfioGroup(group))),
        );

        VirtioKvmResp::from_data(group_fd as u64)
    }

    fn handle_vfio_get_groups(&self, req: &VirtioKvmReq) -> VirtioKvmResp {
        let partition_id = req.arg;
        let buf_gpa = req.longarg;
        let partition = match self.tachyon.prepare_partition(self, partition_id) {
            Ok(p) => p,
            Err(e) => {
                debug!(
                    "!! virtio_kvm: failed to prepare tachyon for partition {partition_id}: {e}"
                );
                return VirtioKvmResp::from_errno(libc::EIO);
            }
        };

        let msg = Message::simple(TachyonOp::VfioGetGroups as u32, 1);
        let resp = match partition.call(msg) {
            Ok(r) => r,
            Err(e) => {
                error!("virtio-kvm: VfioGetGroups RPC failed: {e}");
                return VirtioKvmResp::from_errno(libc::EIO);
            }
        };

        if resp.status != 0 {
            return VirtioKvmResp::from_errno(resp.status as i32);
        }

        if buf_gpa != 0 && !resp.body.is_empty() {
            let mem = self.mem.memory();
            if let Err(e) = mem.write_slice(&resp.body, GuestAddress(buf_gpa)) {
                error!("virtio-kvm: failed to write VFIO groups to guest GPA: {e}");
                return VirtioKvmResp::from_errno(libc::EFAULT);
            }
        }

        VirtioKvmResp::from_data(resp.arg)
    }

    fn handle_msrs_ioctl(
        &self,
        partition: &TachyonPartition,
        handle: u64,
        req: &VirtioKvmReq,
        write_back: bool,
    ) -> VirtioKvmResp {
        let mem = self.mem.memory();
        let gpa = GuestAddress::new(req.longarg);
        let msrs: kvm::kvm_msrs = match mem.read_obj(gpa) {
            Ok(m) => m,
            Err(_) => return VirtioKvmResp::from_errno(libc::EFAULT),
        };

        let nmsrs = msrs.nmsrs;
        let full_size =
            size_of::<kvm::kvm_msrs>() + nmsrs as usize * size_of::<kvm::kvm_msr_entry>();
        let mut body = vec![0u8; full_size];
        if mem.read_slice(&mut body, gpa).is_err() {
            return VirtioKvmResp::from_errno(libc::EFAULT);
        }

        let mut msg = Message::ioctl(handle, req.arg, 0);
        msg.resp_size = if write_back { full_size as u32 } else { 0 };
        msg.body = body;

        match partition.call(msg) {
            Ok(resp) => {
                if write_back && !resp.body.is_empty() {
                    let _ = mem.write_slice(&resp.body, gpa);
                }
                if resp.status == 0 {
                    VirtioKvmResp::from_data(resp.arg)
                } else {
                    VirtioKvmResp::from_errno(resp.status as i32)
                }
            }
            Err(e) => {
                error!("virtio-kvm: MSRS ioctl RPC failed: {e}");
                VirtioKvmResp::from_errno(libc::EIO)
            }
        }
    }

    fn handle_enable_cap_ioctl(
        &self,
        partition: &TachyonPartition,
        handle: u64,
        req: &VirtioKvmReq,
    ) -> VirtioKvmResp {
        let mem = self.mem.memory();
        let gpa = GuestAddress::new(req.longarg);
        let mut body = vec![0u8; size_of::<kvm::kvm_enable_cap>()];
        if mem.read_slice(&mut body, gpa).is_err() {
            return VirtioKvmResp::from_errno(libc::EFAULT);
        }

        let msg = Message::ioctl(handle, req.arg, 0).with_body(body);

        match partition.call(msg) {
            Ok(resp) => {
                if resp.status == 0 {
                    VirtioKvmResp::from_data(resp.arg)
                } else {
                    VirtioKvmResp::from_errno(resp.status as i32)
                }
            }
            Err(e) => {
                error!("virtio-kvm: KVM_ENABLE_CAP RPC failed: {e}");
                VirtioKvmResp::from_errno(libc::EIO)
            }
        }
    }

    fn handle_msr_list_ioctl(
        &self,
        partition: &TachyonPartition,
        req: &VirtioKvmReq,
    ) -> VirtioKvmResp {
        let mem = self.mem.memory();
        let gpa = GuestAddress::new(req.longarg);
        let list: kvm::kvm_msr_list = match mem.read_obj(gpa) {
            Ok(l) => l,
            Err(_) => return VirtioKvmResp::from_errno(libc::EFAULT),
        };

        let nmsrs = list.nmsrs;
        let full_size = size_of::<kvm::kvm_msr_list>() + nmsrs as usize * 4;
        let mut body = vec![0u8; full_size];
        if mem.read_slice(&mut body, gpa).is_err() {
            return VirtioKvmResp::from_errno(libc::EFAULT);
        }

        let msg = Message::ioctl(1, req.arg, 0)
            .with_body(body)
            .with_resp(full_size as u32);

        match partition.call(msg) {
            Ok(resp) => {
                if !resp.body.is_empty() {
                    let _ = mem.write_slice(&resp.body, gpa);
                }
                if resp.status == 0 {
                    VirtioKvmResp::from_data(resp.arg)
                } else {
                    VirtioKvmResp::from_errno(resp.status as i32)
                }
            }
            Err(e) => {
                error!("virtio-kvm: MSR list ioctl RPC failed: {e}");
                VirtioKvmResp::from_errno(libc::EIO)
            }
        }
    }

    fn handle_system_ioctl(
        &self,
        _resource: &LockedResource,
        system: &VirtioKvmSystem,
        req: &VirtioKvmReq,
    ) -> VirtioKvmResp {
        debug!("!! virtio_kvm: handle_system_ioctl: req: {req:#?}");
        let ioctl_num = req.arg;
        match ioctl_num {
            kvm::KVM_GET_API_VERSION | kvm::KVM_GET_VCPU_MMAP_SIZE | kvm::KVM_CHECK_EXTENSION => {
                self.handle_system_generic_ioctl(&system.partition, req)
            }
            kvm::KVM_CREATE_VM => self.handle_system_create_vm(&system.partition),
            kvm::KVM_GET_SUPPORTED_CPUID | kvm::KVM_X86_GET_MCE_CAP_SUPPORTED => {
                virtio_kvm_ioctl_with_uaccess(system.as_raw_fd(), req, &self.mem)
            }
            kvm::KVM_GET_MSRS => self.handle_msrs_ioctl(&system.partition, 1, req, true),
            kvm::KVM_GET_MSR_INDEX_LIST | kvm::KVM_GET_MSR_FEATURE_INDEX_LIST => {
                self.handle_msr_list_ioctl(&system.partition, req)
            }
            _ => {
                debug!("!! virtio_kvm: handle_system_ioctl: unknown ioctl: {ioctl_num:#x}");
                VirtioKvmResp::from_errno(libc::EINVAL)
            }
        }
    }

    fn handle_vfio_container_ioctl(
        &self,
        _resource: &LockedResource,
        container: &VirtioKvmVfioContainer,
        req: &VirtioKvmReq,
    ) -> VirtioKvmResp {
        debug!("!! virtio_kvm: handle_vfio_container_ioctl: req: {req:#?}");
        let ioctl_num = req.arg;
        match ioctl_num {
            vfio::VFIO_GET_API_VERSION | vfio::VFIO_CHECK_EXTENSION | vfio::VFIO_SET_IOMMU => {
                self.handle_generic_ioctl(container, req)
            }
            vfio::VFIO_IOMMU_MAP_DMA => self.handle_iommu_map_dma(container, req),
            vfio::VFIO_IOMMU_UNMAP_DMA => self.handle_iommu_unmap_dma(container, req),
            vfio::VFIO_IOMMU_GET_INFO => {
                self.handle_vfio_argsz_ioctl(container, req, "VFIO_IOMMU_GET_INFO", 16)
            }
            _ => {
                debug!("!! virtio_kvm: handle_vfio_container_ioctl: unknown ioctl: {ioctl_num:#x}");
                VirtioKvmResp::from_errno(libc::EINVAL)
            }
        }
    }

    fn handle_iommu_map_dma(
        &self,
        container: &VirtioKvmVfioContainer,
        req: &VirtioKvmReq,
    ) -> VirtioKvmResp {
        let mem = self.mem.memory();
        let gpa = GuestAddress::new(req.longarg);
        let umap: vfio::vfio_iommu_type1_dma_map = match mem.read_obj(gpa) {
            Ok(map) => map,
            Err(_) => return VirtioKvmResp::from_errno(libc::EFAULT),
        };
        debug!("requested guest region: {umap:#x?}");

        if umap.size == 0 {
            return VirtioKvmResp::from_errno(libc::EINVAL);
        }

        let mut dma_map = vfio::vfio_iommu_type1_dma_map::default();
        dma_map.argsz = umap.argsz;
        dma_map.flags = umap.flags;
        dma_map.iova = umap.iova;
        dma_map.size = umap.size;

        let file_gpa = GuestAddress::new(umap.vaddr);
        let (_, _, offset_in_bar) = match self.resolve_bar_resource(file_gpa, umap.size) {
            Ok(res) => res,
            Err(e) => return e,
        };
        dma_map.vaddr = self
            .bar_mapping
            .mapping
            .as_ptr()
            .wrapping_add(offset_in_bar as usize) as u64;

        debug!("translated guest dma_map: {dma_map:#x?}");

        let ret = unsafe { libc::ioctl(container.fd, vfio::VFIO_IOMMU_MAP_DMA as _, &dma_map) };
        if ret < 0 {
            return VirtioKvmResp::from_last_errno();
        }

        VirtioKvmResp::success()
    }

    fn handle_iommu_unmap_dma(
        &self,
        container: &VirtioKvmVfioContainer,
        req: &VirtioKvmReq,
    ) -> VirtioKvmResp {
        let mem = self.mem.memory();
        let gpa = GuestAddress::new(req.longarg);
        let umap: vfio::vfio_iommu_type1_dma_unmap = match mem.read_obj(gpa) {
            Ok(map) => map,
            Err(_) => return VirtioKvmResp::from_errno(libc::EFAULT),
        };
        debug!("requested guest region: {umap:#x?}");

        if umap.size == 0 {
            return VirtioKvmResp::from_errno(libc::EINVAL);
        }

        let mut dma_map = vfio::vfio_iommu_type1_dma_unmap::default();
        dma_map.argsz = umap.argsz;
        dma_map.flags = umap.flags;
        dma_map.iova = umap.iova;
        dma_map.size = umap.size;

        debug!("translated guest dma_map: {dma_map:#x?}");

        let ret = unsafe { libc::ioctl(container.fd, vfio::VFIO_IOMMU_UNMAP_DMA as _, &dma_map) };
        if ret < 0 {
            return VirtioKvmResp::from_last_errno();
        }

        VirtioKvmResp::success()
    }

    fn handle_vfio_group_set_container(
        &self,
        group: &VirtioKvmVfioGroup,
        req: &VirtioKvmReq,
    ) -> VirtioKvmResp {
        let resource = {
            // Note, the driver diverged from the standard way of proxying this
            // ioctl. The VFIO UAPI requires the *pointer* of the fd to
            // passed, but in this case, the Tachyon driver simplified this to
            // simply pass the value. Grab the value now.
            let handle = Handle(req.longarg);
            let resource_map = self.resources.lock().unwrap();
            match resource_map.get(&handle) {
                Some(resource) => resource.clone(),
                None => {
                    error!(
                        "virtio-kvm: driver bug? attempted VFIO_GROUP_SET_CONTAINER with a non-existent container/handle {}",
                        req.longarg
                    );
                    return VirtioKvmResp::from_errno(libc::ENOENT);
                }
            }
        };
        let mut guard = resource.lock().unwrap();
        let container = &{
            match guard.deref_mut() {
                VirtioKvmResource::VfioContainer(container) => container,
                _ => {
                    error!(
                        "virtio-kvm: driver bug? attempted VFIO_GROUP_SET_CONTAINER on handle that is not a container {}",
                        req.longarg
                    );
                    return VirtioKvmResp::from_errno(libc::ENOENT);
                }
            }
        };
        let ioctl_num = req.arg;
        let msg = Message::ioctl(
            group.tachyon_handle,
            vfio::VFIO_GROUP_SET_CONTAINER,
            container.tachyon_handle,
        );
        match group.partition.call(msg) {
            Ok(resp) => {
                if resp.status == 0 {
                    VirtioKvmResp::from_data(resp.arg)
                } else {
                    VirtioKvmResp::from_errno(resp.status as i32)
                }
            }
            Err(e) => {
                error!("virtio-kvm: vcpu ioctl {ioctl_num} RPC failed: {e}");
                VirtioKvmResp::from_errno(libc::EIO)
            }
        }
    }

    fn handle_vfio_group_get_device_fd(
        &self,
        group: &VirtioKvmVfioGroup,
        req: &VirtioKvmReq,
    ) -> VirtioKvmResp {
        let mem = self.mem.memory();
        let gpa = GuestAddress::new(req.longarg);
        let mut body = vec![0u8; 16usize];
        if mem.read_slice(&mut body, gpa).is_err() {
            return VirtioKvmResp::from_errno(libc::EFAULT);
        }

        let msg = Message::ioctl(group.tachyon_handle(), req.arg, 0).with_body(body);
        let resp = match group.partition.call(msg) {
            Ok(r) => r,
            Err(e) => {
                error!("virtio-kvm: VFIO_GROUP_GET_DEVICE_FD RPC failed: {e}");
                return VirtioKvmResp::from_errno(libc::EIO);
            }
        };

        let tachyon_device_handle = resp.handle;

        let msg_fd = Message::get_file(tachyon_device_handle);
        let resp_fd = match group.partition.call(msg_fd) {
            Ok(r) => r,
            Err(e) => {
                error!("virtio-kvm: GetFileDescriptor RPC failed: {e}");
                return VirtioKvmResp::from_errno(libc::EIO);
            }
        };

        if resp_fd.status != 0 {
            return VirtioKvmResp::from_errno(resp_fd.status as i32);
        }

        let device_fd = resp_fd
            .fds
            .and_then(|mut fds| fds.pop())
            .ok_or(libc::EIO)
            .unwrap_or(-1);
        if device_fd < 0 {
            return VirtioKvmResp::from_errno(libc::EIO);
        }

        let device_handle = Handle(device_fd as u64);
        let device = VirtioKvmVfioDevice {
            fd: device_fd,
            tachyon_handle: tachyon_device_handle,
            partition: group.partition.clone(),
        };
        self.resources.lock().unwrap().insert(
            device_handle,
            Arc::new(Mutex::new(VirtioKvmResource::VfioDevice(device))),
        );

        VirtioKvmResp::from_data(device_fd as u64)
    }

    fn handle_vfio_group_ioctl(
        &self,
        _resource: &LockedResource,
        group: &VirtioKvmVfioGroup,
        req: &VirtioKvmReq,
    ) -> VirtioKvmResp {
        debug!("!! virtio_kvm: handle_vfio_group_ioctl: req: {req:#?}");
        let ioctl_num = req.arg;
        match ioctl_num {
            vfio::VFIO_GROUP_UNSET_CONTAINER => self.handle_generic_ioctl(group, req),
            vfio::VFIO_GROUP_GET_STATUS => {
                self.handle_vfio_argsz_ioctl(group, req, "VFIO_GROUP_GET_STATUS", 8)
            }
            vfio::VFIO_GROUP_SET_CONTAINER => self.handle_vfio_group_set_container(group, req),
            vfio::VFIO_GROUP_GET_DEVICE_FD => self.handle_vfio_group_get_device_fd(group, req),
            _ => {
                debug!("!! virtio_kvm: handle_vfio_group_ioctl: unknown ioctl: {ioctl_num:#x}");
                VirtioKvmResp::from_errno(libc::EINVAL)
            }
        }
    }

    fn vfio_set_irqs_resolve_eventfds(
        &self,
        set: *mut vfio::vfio_irq_set,
    ) -> Result<(), io::Error> {
        unsafe {
            let hdr = set.read_unaligned();
            if (hdr.flags & vfio::VFIO_IRQ_SET_DATA_EVENTFD) == 0 {
                return Ok(());
            }

            let hdr_sz = size_of::<vfio::vfio_irq_set>();

            let handles = (set as *mut u8).add(hdr_sz) as *mut u64;
            for i in 0usize..hdr.count as usize {
                let handle = handles.add(i).read_unaligned();
                if handle == INVALID_HANDLE {
                    continue;
                }
                match self.resolve_eventfd(handle) {
                    Some(tachyon_handle) => handles.add(i).write_unaligned(tachyon_handle),
                    None => {
                        return Err(io::Error::other(format!(
                            "Couldn't resolve tachyon handle {handle}"
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    fn handle_device_set_irqs(
        &self,
        device: &VirtioKvmVfioDevice,
        req: &VirtioKvmReq,
    ) -> VirtioKvmResp {
        let gpa = GuestAddress::new(req.longarg);
        let mem = self.mem.memory();
        let irqs_hdr: vfio::vfio_irq_set = match mem.read_obj(gpa) {
            Ok(irqs) => irqs,
            Err(_) => return VirtioKvmResp::from_errno(libc::EFAULT),
        };

        let hdr_size = size_of::<vfio::vfio_irq_set>();

        let mut sz = irqs_hdr.argsz as usize;
        if sz == 0 {
            sz = hdr_size;
        }

        let mut args = vec![0u8; sz];
        if mem.read_slice(&mut args, gpa).is_err() {
            return VirtioKvmResp::from_errno(libc::EFAULT);
        }

        if let Err(e) =
            self.vfio_set_irqs_resolve_eventfds(args.as_ptr() as *mut vfio::vfio_irq_set)
        {
            error!("Failed to resolve eventfds: {e}");
            return VirtioKvmResp::from_errno(libc::EINVAL);
        }

        let msg = Message::ioctl(device.tachyon_handle(), req.arg, 0)
            .with_body(args)
            .with_resp(sz as u32);
        match device.partition.call(msg) {
            Ok(resp) => {
                if !resp.body.is_empty() {
                    let _ = mem.write_slice(&resp.body, gpa);
                }
                if resp.status == 0 {
                    VirtioKvmResp::success()
                } else {
                    VirtioKvmResp::from_errno(resp.status as i32)
                }
            }
            Err(e) => {
                error!("virtio-kvm: VFIO_DEVICE_SET_IRQS RPC failed: {e}");
                VirtioKvmResp::from_errno(libc::EIO)
            }
        }
    }

    fn handle_vfio_device_ioctl(
        &self,
        _resource: &LockedResource,
        device: &VirtioKvmVfioDevice,
        req: &VirtioKvmReq,
    ) -> VirtioKvmResp {
        debug!("!! virtio_kvm: handle_vfio_device_ioctl: req: {req:#?}");
        let ioctl_num = req.arg;
        match ioctl_num {
            vfio::VFIO_DEVICE_GET_INFO => {
                self.handle_vfio_argsz_ioctl(device, req, "VFIO_DEVICE_GET_INFO", 16)
            }
            vfio::VFIO_DEVICE_GET_REGION_INFO => {
                self.handle_vfio_argsz_ioctl(device, req, "VFIO_DEVICE_GET_REGION_INFO", 32)
            }
            vfio::VFIO_DEVICE_RESET => self.handle_generic_ioctl(device, req),
            vfio::VFIO_DEVICE_GET_IRQ_INFO => {
                self.handle_vfio_argsz_ioctl(device, req, "VFIO_DEVICE_GET_IRQ_INFO", 16)
            }
            vfio::VFIO_DEVICE_SET_IRQS => self.handle_device_set_irqs(device, req),
            _ => {
                debug!("!! virtio_kvm: handle_vfio_device_ioctl: unknown ioctl: {ioctl_num:#x}");
                VirtioKvmResp::from_errno(libc::EINVAL)
            }
        }
    }

    fn resolve_bar_resource(
        &self,
        gpa: GuestAddress,
        len: u64,
    ) -> Result<(u64, u64, u64), VirtioKvmResp> {
        if gpa < self.bar_mapping.addr
            || gpa.raw_value() + len
                > self.bar_mapping.addr.raw_value() + self.bar_mapping.mapping.size() as u64
        {
            return Err(VirtioKvmResp::from_errno(libc::EFAULT));
        }

        let userspace_offset_in_bar = gpa.raw_value() - self.bar_mapping.addr.raw_value();

        {
            let mem_files = self.mem_files.lock().unwrap();
            for file in mem_files.values() {
                if userspace_offset_in_bar >= file.phys_offset
                    && userspace_offset_in_bar + len <= file.phys_offset + file.size
                {
                    let offset_in_file = userspace_offset_in_bar - file.phys_offset;
                    return Ok((file.tachyon_handle, offset_in_file, userspace_offset_in_bar));
                }
            }
        }

        {
            let mappings = self.mappings.lock().unwrap();
            let resources = self.resources.lock().unwrap();
            for (handle, mapping) in mappings.iter() {
                if userspace_offset_in_bar >= mapping.phys_offset
                    && userspace_offset_in_bar + len <= mapping.phys_offset + mapping.size
                    && let Some(resource) = resources.get(handle)
                {
                    let tachyon_handle = resource.lock().unwrap().tachyon_handle();
                    let offset_in_resource =
                        mapping.device_offset + (userspace_offset_in_bar - mapping.phys_offset);
                    return Ok((tachyon_handle, offset_in_resource, userspace_offset_in_bar));
                }
            }
        }

        debug!(
            "!! virtio_kvm: no memory file or BAR mapping found for offset {userspace_offset_in_bar:#x}"
        );
        Err(VirtioKvmResp::from_errno(libc::ENOENT))
    }

    fn handle_set_user_memory_region(&self, vm: &VirtioKvmVm, req: &VirtioKvmReq) -> VirtioKvmResp {
        let mem = self.mem.memory();
        let gpa = GuestAddress::new(req.longarg);
        let region: kvm::kvm_userspace_memory_region = match mem.read_obj(gpa) {
            Ok(region) => region,
            Err(_) => return VirtioKvmResp::from_errno(libc::EFAULT),
        };
        debug!("requested guest region: {region:#x?}");

        let mut region2 = kvm::kvm_userspace_memory_region2::default();
        region2.slot = region.slot;
        region2.guest_phys_addr = region.guest_phys_addr;

        let mut guest_memfd_handle = 0;
        if region.memory_size > 0 {
            region2.flags = region.flags;
            region2.memory_size = region.memory_size;

            let file_gpa = GuestAddress::new(region.userspace_addr);
            let (tachyon_handle, offset_in_resource, _) =
                match self.resolve_bar_resource(file_gpa, region.memory_size) {
                    Ok(res) => res,
                    Err(e) => return e,
                };

            guest_memfd_handle = tachyon_handle;
            region2.guest_memfd = tachyon_handle as u32;
            region2.guest_memfd_offset = offset_in_resource;
        }

        debug!("translated guest region2: {region2:#x?}, handle: 0x{guest_memfd_handle:x}");

        let wrapper = kvm::kvm_userspace_memory_region2_wrapper {
            region2,
            guest_memfd_handle,
        };

        let mut body = vec![0u8; size_of::<kvm::kvm_userspace_memory_region2_wrapper>()];
        unsafe {
            ptr::copy_nonoverlapping(
                &wrapper as *const _ as *const u8,
                body.as_mut_ptr(),
                body.len(),
            );
        }

        let msg =
            Message::ioctl(vm.tachyon_handle, kvm::KVM_SET_USER_MEMORY_REGION2, 0).with_body(body);

        match vm.partition.call(msg) {
            Ok(resp) => {
                if resp.status == 0 {
                    VirtioKvmResp::success()
                } else {
                    VirtioKvmResp::from_errno(resp.status as i32)
                }
            }
            Err(e) => {
                error!("virtio-kvm: KVM_SET_USER_MEMORY_REGION2 RPC failed: {e}");
                VirtioKvmResp::from_errno(libc::EIO)
            }
        }
    }

    fn handle_generic_ioctl<T: TachyonResource>(&self, t: &T, req: &VirtioKvmReq) -> VirtioKvmResp {
        let ioctl_num = req.arg;
        let msg = Message::ioctl(t.tachyon_handle(), ioctl_num, req.longarg);
        match t.partition().call(msg) {
            Ok(resp) => {
                if resp.status == 0 {
                    VirtioKvmResp::from_data(resp.arg)
                } else {
                    VirtioKvmResp::from_errno(resp.status as i32)
                }
            }
            Err(e) => {
                error!("virtio-kvm: ioctl {ioctl_num} RPC failed: {e}");
                VirtioKvmResp::from_errno(libc::EIO)
            }
        }
    }

    fn handle_vm_create_vcpu(
        &self,
        _resource: &LockedResource,
        vm: &VirtioKvmVm,
        req: &VirtioKvmReq,
    ) -> VirtioKvmResp {
        debug!("!! virtio_kvm: handle_vm_ioctl: KVM_CREATE_VCPU");

        // 1. Request VCPU from Tachyon
        let msg = Message::ioctl(vm.tachyon_handle, kvm::KVM_CREATE_VCPU, req.longarg);
        let resp = match vm.partition.call(msg) {
            Ok(r) => r,
            Err(e) => {
                error!("virtio-kvm: KVM_CREATE_VCPU RPC failed: {e}");
                return VirtioKvmResp::from_errno(libc::EIO);
            }
        };

        if resp.status != 0 {
            return VirtioKvmResp::from_errno(resp.status as i32);
        }

        let tachyon_vcpu_handle = resp.handle;

        // 2. Get VCPU FD from Tachyon
        let msg_fd = Message::get_file(tachyon_vcpu_handle);
        let resp_fd = match vm.partition.call(msg_fd) {
            Ok(r) => r,
            Err(e) => {
                error!("virtio-kvm: GetFileDescriptor RPC failed: {e}");
                return VirtioKvmResp::from_errno(libc::EIO);
            }
        };

        if resp_fd.status != 0 {
            return VirtioKvmResp::from_errno(resp_fd.status as i32);
        }

        let vcpu_fd = resp_fd
            .fds
            .and_then(|mut fds| fds.pop())
            .ok_or(libc::EIO)
            .unwrap_or(-1);
        if vcpu_fd < 0 {
            return VirtioKvmResp::from_errno(libc::EIO);
        }

        // 3. Initialize VirtioKvmVcpu
        let vcpu_handle = Handle::new();

        debug!("!! virtio_kvm: handle_vm_ioctl: KVM_CREATE_VCPU: created vcpu_fd: {vcpu_fd}");

        let vcpu = VirtioKvmVcpu {
            fd: vcpu_fd,
            vcpu_id: req.longarg as u32,
            vm_handle: req.handle,
            tachyon_handle: tachyon_vcpu_handle,
            partition: vm.partition.clone(),
        };
        self.resources.lock().unwrap().insert(
            vcpu_handle,
            Arc::new(Mutex::new(VirtioKvmResource::Vcpu(vcpu))),
        );

        VirtioKvmResp::from_data(vcpu_handle.0)
    }

    fn handle_vm_ioeventfd(&self, vm: &VirtioKvmVm, req: &VirtioKvmReq) -> VirtioKvmResp {
        let mem = self.mem.memory();
        let wrapper: VirtioKvmIoeventfd = match mem.read_obj(GuestAddress::new(req.longarg)) {
            Ok(ioeventfd) => ioeventfd,
            Err(_) => return VirtioKvmResp::from_errno(libc::EFAULT),
        };
        let ioeventfd = wrapper.kvm;
        let tachyon_fd_handle = match self.resolve_eventfd(wrapper.fd_handle) {
            Some(handle) => handle,
            None => return VirtioKvmResp::from_errno(libc::EINVAL),
        };

        let wrapped = kvm::kvm_ioeventfd_wrapped {
            kvm: ioeventfd,
            fd_handle: tachyon_fd_handle,
        };

        let mut body = vec![0u8; size_of::<kvm::kvm_ioeventfd_wrapped>()];
        unsafe {
            ptr::copy_nonoverlapping(
                &wrapped as *const _ as *const u8,
                body.as_mut_ptr(),
                body.len(),
            );
        }

        let msg = Message::ioctl(vm.tachyon_handle, kvm::KVM_IOEVENTFD, 0).with_body(body);
        match vm.partition.call(msg) {
            Ok(resp) => {
                if resp.status == 0 {
                    VirtioKvmResp::success()
                } else {
                    VirtioKvmResp::from_errno(resp.status as i32)
                }
            }
            Err(e) => {
                error!("virtio-kvm: KVM_IOEVENTFD RPC failed: {e}");
                VirtioKvmResp::from_errno(libc::EIO)
            }
        }
    }

    fn handle_vm_get_ioctl<T: ByteValued>(
        &self,
        vm: &VirtioKvmVm,
        req: &VirtioKvmReq,
        name: &str,
    ) -> VirtioKvmResp {
        debug!("!! virtio_kvm: handle_vm_ioctl: {name}");
        let mem = self.mem.memory();
        let gpa = GuestAddress::new(req.longarg);
        let msg = Message::ioctl(vm.tachyon_handle, req.arg, 0).with_resp(size_of::<T>() as u32);
        match vm.partition.call(msg) {
            Ok(resp) => {
                if !resp.body.is_empty() {
                    let _ = mem.write_slice(&resp.body, gpa);
                }
                if resp.status == 0 {
                    VirtioKvmResp::success()
                } else {
                    VirtioKvmResp::from_errno(resp.status as i32)
                }
            }
            Err(e) => {
                error!("virtio-kvm: {name} RPC failed: {e}");
                VirtioKvmResp::from_errno(libc::EIO)
            }
        }
    }

    fn handle_set_ioctl<T: ByteValued, R: TachyonResource>(
        &self,
        resource: &R,
        req: &VirtioKvmReq,
        name: &str,
    ) -> VirtioKvmResp {
        debug!("!! virtio_kvm: handle_set_ioctl: {name}");
        let mem = self.mem.memory();
        let gpa = GuestAddress::new(req.longarg);
        let mut body = vec![0u8; size_of::<T>()];
        if mem.read_slice(&mut body, gpa).is_err() {
            return VirtioKvmResp::from_errno(libc::EFAULT);
        }

        let msg = Message::ioctl(resource.tachyon_handle(), req.arg, 0).with_body(body);
        match resource.partition().call(msg) {
            Ok(resp) => {
                if resp.status == 0 {
                    VirtioKvmResp::success()
                } else {
                    VirtioKvmResp::from_errno(resp.status as i32)
                }
            }
            Err(e) => {
                error!("virtio-kvm: {name} RPC failed: {e}");
                VirtioKvmResp::from_errno(libc::EIO)
            }
        }
    }

    fn handle_vm_set_ioctl<T: ByteValued>(
        &self,
        vm: &VirtioKvmVm,
        req: &VirtioKvmReq,
        name: &str,
    ) -> VirtioKvmResp {
        self.handle_set_ioctl::<T, _>(vm, req, name)
    }

    fn handle_inout_ioctl<T: ByteValued, R: TachyonResource>(
        &self,
        resource: &R,
        req: &VirtioKvmReq,
        name: &str,
    ) -> VirtioKvmResp {
        debug!("!! virtio_kvm: handle_inout_ioctl: {name}");
        let mem = self.mem.memory();
        let gpa = GuestAddress::new(req.longarg);
        let mut body = vec![0u8; size_of::<T>()];
        if mem.read_slice(&mut body, gpa).is_err() {
            return VirtioKvmResp::from_errno(libc::EFAULT);
        }

        let msg = Message::ioctl(resource.tachyon_handle(), req.arg, 0)
            .with_body(body)
            .with_resp(size_of::<T>() as u32);
        match resource.partition().call(msg) {
            Ok(resp) => {
                if !resp.body.is_empty() {
                    let _ = mem.write_slice(&resp.body, gpa);
                }
                if resp.status == 0 {
                    VirtioKvmResp::success()
                } else {
                    VirtioKvmResp::from_errno(resp.status as i32)
                }
            }
            Err(e) => {
                error!("virtio-kvm: {name} RPC failed: {e}");
                VirtioKvmResp::from_errno(libc::EIO)
            }
        }
    }

    /// Dispatches a VFIO ioctl that uses an extensible structure starting with `argsz`.
    /// Dynamically determines the buffer size from guest memory, honoring historical UAPI minimum sizes.
    fn handle_vfio_argsz_ioctl<R: TachyonResource>(
        &self,
        resource: &R,
        req: &VirtioKvmReq,
        name: &str,
        min_size: usize,
    ) -> VirtioKvmResp {
        debug!("!! virtio_kvm: handle_vfio_argsz_ioctl: {name}");
        let mem = self.mem.memory();
        let gpa = GuestAddress::new(req.longarg);
        let mut hdr = [0u8; 4];
        if mem.read_slice(&mut hdr, gpa).is_err() {
            return VirtioKvmResp::from_errno(libc::EFAULT);
        }
        let argsz = u32::from_ne_bytes(hdr) as usize;
        let len = argsz.max(min_size);
        if len > 1024 * 1024 {
            return VirtioKvmResp::from_errno(libc::EINVAL);
        }
        let mut body = vec![0u8; len];
        if mem.read_slice(&mut body, gpa).is_err() {
            return VirtioKvmResp::from_errno(libc::EFAULT);
        }

        let msg = Message::ioctl(resource.tachyon_handle(), req.arg, 0)
            .with_body(body)
            .with_resp(len as u32);
        match resource.partition().call(msg) {
            Ok(resp) => {
                if !resp.body.is_empty() {
                    let write_len = resp.body.len().min(len);
                    let _ = mem.write_slice(&resp.body[..write_len], gpa);
                }
                if resp.status == 0 {
                    VirtioKvmResp::success()
                } else {
                    VirtioKvmResp::from_errno(resp.status as i32)
                }
            }
            Err(e) => {
                error!("virtio-kvm: {name} RPC failed: {e}");
                VirtioKvmResp::from_errno(libc::EIO)
            }
        }
    }

    fn handle_vm_irqfd(&self, vm: &VirtioKvmVm, req: &VirtioKvmReq) -> VirtioKvmResp {
        let mem = self.mem.memory();
        let wrapper: VirtioKvmIrqfd = match mem.read_obj(GuestAddress::new(req.longarg)) {
            Ok(irqfd) => irqfd,
            Err(_) => return VirtioKvmResp::from_errno(libc::EFAULT),
        };
        let irqfd = wrapper.kvm;

        let tachyon_fd_handle;
        let mut tachyon_resamplefd_handle = 0;

        if let Some(tachyon_handle) = self.resolve_eventfd(wrapper.fd_handle) {
            tachyon_fd_handle = tachyon_handle;
        } else {
            return VirtioKvmResp::from_errno(libc::EINVAL);
        }

        if (irqfd.flags & kvm::KVM_IRQFD_FLAG_RESAMPLE) != 0 {
            if let Some(tachyon_handle) = self.resolve_eventfd(wrapper.resamplefd_handle) {
                tachyon_resamplefd_handle = tachyon_handle;
            } else {
                return VirtioKvmResp::from_errno(libc::EINVAL);
            }
        }

        let wrapped = kvm::kvm_irqfd_wrapped {
            kvm: irqfd,
            fd_handle: tachyon_fd_handle,
            resamplefd_handle: tachyon_resamplefd_handle,
        };

        let mut body = vec![0u8; size_of::<kvm::kvm_irqfd_wrapped>()];
        unsafe {
            ptr::copy_nonoverlapping(
                &wrapped as *const _ as *const u8,
                body.as_mut_ptr(),
                body.len(),
            );
        }

        let msg = Message::ioctl(vm.tachyon_handle, kvm::KVM_IRQFD, 0).with_body(body);

        match vm.partition.call(msg) {
            Ok(resp) => {
                if resp.status == 0 {
                    VirtioKvmResp::success()
                } else {
                    VirtioKvmResp::from_errno(resp.status as i32)
                }
            }
            Err(e) => {
                error!("virtio-kvm: KVM_IRQFD RPC failed: {e}");
                VirtioKvmResp::from_errno(libc::EIO)
            }
        }
    }

    fn handle_vm_set_gsi_routing(&self, vm: &VirtioKvmVm, req: &VirtioKvmReq) -> VirtioKvmResp {
        let mem = self.mem.memory();
        let gpa = GuestAddress::new(req.longarg);
        let routing: kvm::kvm_irq_routing = match mem.read_obj(gpa) {
            Ok(r) => r,
            Err(_) => return VirtioKvmResp::from_errno(libc::EFAULT),
        };

        let full_size = size_of::<kvm::kvm_irq_routing>()
            + routing.nr as usize * size_of::<kvm::kvm_irq_routing_entry>();
        let mut body = vec![0u8; full_size];
        if mem.read_slice(&mut body, gpa).is_err() {
            return VirtioKvmResp::from_errno(libc::EFAULT);
        }

        let msg = Message::ioctl(vm.tachyon_handle, kvm::KVM_SET_GSI_ROUTING, 0).with_body(body);

        match vm.partition.call(msg) {
            Ok(resp) => {
                if resp.status == 0 {
                    VirtioKvmResp::success()
                } else {
                    VirtioKvmResp::from_errno(resp.status as i32)
                }
            }
            Err(e) => {
                error!("virtio-kvm: KVM_SET_GSI_ROUTING RPC failed: {e}");
                VirtioKvmResp::from_errno(libc::EIO)
            }
        }
    }

    fn handle_vm_ioctl(
        &self,
        _resource: &LockedResource,
        vm: &VirtioKvmVm,
        req: &VirtioKvmReq,
    ) -> VirtioKvmResp {
        let ioctl_num = req.arg;
        debug!("!! virtio_kvm: handle_vm_ioctl: ioctl_num: {ioctl_num:#x}");
        match ioctl_num {
            kvm::KVM_SET_USER_MEMORY_REGION | kvm::KVM_SET_USER_MEMORY_REGION2 => {
                self.handle_set_user_memory_region(vm, req)
            }
            kvm::KVM_ENABLE_CAP => {
                self.handle_enable_cap_ioctl(&vm.partition, vm.tachyon_handle, req)
            }
            kvm::KVM_X86_SET_MSR_FILTER => self.handle_set_msr_filter(
                &vm.partition,
                vm.tachyon_handle,
                req,
                &self.mem.memory(),
            ),
            kvm::KVM_CREATE_VCPU => self.handle_vm_create_vcpu(_resource, vm, req),
            kvm::KVM_IOEVENTFD => self.handle_vm_ioeventfd(vm, req),

            kvm::KVM_GET_STATS_FD => {
                self.handle_get_stats_fd(req.handle, vm.tachyon_handle, &vm.partition)
            }

            kvm::KVM_IRQFD => self.handle_vm_irqfd(vm, req),
            kvm::KVM_SET_GSI_ROUTING => self.handle_vm_set_gsi_routing(vm, req),

            kvm::KVM_GET_CLOCK => {
                self.handle_vm_get_ioctl::<kvm::kvm_clock_data>(vm, req, "KVM_GET_CLOCK")
            }
            kvm::KVM_SET_CLOCK => {
                self.handle_vm_set_ioctl::<kvm::kvm_clock_data>(vm, req, "KVM_SET_CLOCK")
            }

            kvm::KVM_GET_IRQCHIP => {
                self.handle_inout_ioctl::<kvm::kvm_irqchip, _>(vm, req, "KVM_GET_IRQCHIP")
            }
            kvm::KVM_SET_IRQCHIP => {
                self.handle_vm_set_ioctl::<kvm::kvm_irqchip>(vm, req, "KVM_SET_IRQCHIP")
            }

            kvm::KVM_SIGNAL_MSI => {
                self.handle_vm_set_ioctl::<kvm::kvm_msi>(vm, req, "KVM_SIGNAL_MSI")
            }

            kvm::KVM_GET_PIT => {
                self.handle_vm_get_ioctl::<kvm::kvm_pit_state>(vm, req, "KVM_GET_PIT")
            }
            kvm::KVM_SET_PIT => {
                self.handle_vm_set_ioctl::<kvm::kvm_pit_state>(vm, req, "KVM_SET_PIT")
            }

            kvm::KVM_GET_PIT2 => {
                self.handle_vm_get_ioctl::<kvm::kvm_pit_state2>(vm, req, "KVM_GET_PIT2")
            }
            kvm::KVM_SET_PIT2 => {
                self.handle_vm_set_ioctl::<kvm::kvm_pit_state2>(vm, req, "KVM_SET_PIT2")
            }

            kvm::KVM_REGISTER_COALESCED_MMIO | kvm::KVM_UNREGISTER_COALESCED_MMIO => {
                self.handle_vm_set_ioctl::<kvm::kvm_coalesced_mmio_zone>(
                    vm,
                    req,
                    "KVM_COALESCED_MMIO",
                )
            }

            kvm::KVM_SET_IDENTITY_MAP_ADDR => {
                self.handle_vm_set_ioctl::<u64>(vm, req, "KVM_SET_IDENTITY_MAP_ADDR")
            }
            kvm::KVM_SET_PMU_EVENT_FILTER => self.handle_vm_set_ioctl::<kvm::kvm_pmu_event_filter>(
                vm,
                req,
                "KVM_SET_PMU_EVENT_FILTER",
            ),
            kvm::KVM_CREATE_PIT2 => {
                self.handle_vm_set_ioctl::<kvm::kvm_pit_config>(vm, req, "KVM_CREATE_PIT2")
            }
            kvm::KVM_IRQ_LINE_STATUS => {
                self.handle_inout_ioctl::<kvm::kvm_irq_level, _>(vm, req, "KVM_IRQ_LINE_STATUS")
            }
            kvm::KVM_IRQ_LINE => {
                self.handle_vm_set_ioctl::<kvm::kvm_irq_level>(vm, req, "KVM_IRQ_LINE")
            }

            kvm::KVM_GET_LAPIC => {
                self.handle_vm_get_ioctl::<kvm::kvm_lapic_state>(vm, req, "KVM_GET_LAPIC")
            }
            kvm::KVM_GET_REGS => self.handle_vm_get_ioctl::<kvm::kvm_regs>(vm, req, "KVM_GET_REGS"),
            kvm::KVM_SET_FPU => self.handle_vm_set_ioctl::<kvm::kvm_fpu>(vm, req, "KVM_SET_FPU"),

            kvm::KVM_SET_BOOT_CPU_ID
            | kvm::KVM_CHECK_EXTENSION
            | kvm::KVM_CREATE_IRQCHIP
            | kvm::KVM_GET_TSC_KHZ
            | kvm::KVM_SET_TSC_KHZ
            | kvm::KVM_CREATE_PIT
            | kvm::KVM_SET_TSS_ADDR
            | kvm::KVM_SET_NR_MMU_PAGES => self.handle_generic_ioctl(vm, req),

            kvm::KVM_CREATE_DEVICE => {
                warn!("!! virtio_kvm: KVM_CREATE_DEVICE is not supported");
                VirtioKvmResp::from_errno(libc::ENOSYS)
            }

            _ => {
                debug!("!! virtio_kvm: handle_vm_ioctl: unknown ioctl: {ioctl_num:#x}");
                VirtioKvmResp::from_errno(libc::EINVAL)
            }
        }
    }

    fn handle_vcpu_get_ioctl<T: ByteValued>(
        &self,
        vcpu: &VirtioKvmVcpu,
        req: &VirtioKvmReq,
        name: &str,
    ) -> VirtioKvmResp {
        debug!("!! virtio_kvm: handle_vcpu_ioctl: {name}");
        let mem = self.mem.memory();
        let gpa = GuestAddress::new(req.longarg);
        let msg = Message::ioctl(vcpu.tachyon_handle, req.arg, 0).with_resp(size_of::<T>() as u32);

        match vcpu.partition.call(msg) {
            Ok(resp) => {
                if !resp.body.is_empty() {
                    let _ = mem.write_slice(&resp.body, gpa);
                }
                if resp.status == 0 {
                    VirtioKvmResp::success()
                } else {
                    VirtioKvmResp::from_errno(resp.status as i32)
                }
            }
            Err(e) => {
                error!("virtio-kvm: {name} RPC failed: {e}");
                VirtioKvmResp::from_errno(libc::EIO)
            }
        }
    }

    fn handle_vcpu_set_ioctl<T: ByteValued>(
        &self,
        vcpu: &VirtioKvmVcpu,
        req: &VirtioKvmReq,
        name: &str,
    ) -> VirtioKvmResp {
        debug!("!! virtio_kvm: handle_vcpu_ioctl: {name}");
        let mem = self.mem.memory();
        let gpa = GuestAddress::new(req.longarg);
        let mut body = vec![0u8; size_of::<T>()];
        if mem.read_slice(&mut body, gpa).is_err() {
            return VirtioKvmResp::from_errno(libc::EFAULT);
        }

        let msg = Message::ioctl(vcpu.tachyon_handle, req.arg, 0).with_body(body);

        match vcpu.partition.call(msg) {
            Ok(resp) => {
                if resp.status == 0 {
                    VirtioKvmResp::success()
                } else {
                    VirtioKvmResp::from_errno(resp.status as i32)
                }
            }
            Err(e) => {
                error!("virtio-kvm: {name} RPC failed: {e}");
                VirtioKvmResp::from_errno(libc::EIO)
            }
        }
    }

    fn handle_vcpu_inout_ioctl<T: ByteValued>(
        &self,
        vcpu: &VirtioKvmVcpu,
        req: &VirtioKvmReq,
        name: &str,
    ) -> VirtioKvmResp {
        debug!("!! virtio_kvm: handle_vcpu_ioctl: {name}");
        let mem = self.mem.memory();
        let gpa = GuestAddress::new(req.longarg);
        let mut body = vec![0u8; size_of::<T>()];
        if mem.read_slice(&mut body, gpa).is_err() {
            return VirtioKvmResp::from_errno(libc::EFAULT);
        }

        let msg = Message::ioctl(vcpu.tachyon_handle, req.arg, 0)
            .with_body(body)
            .with_resp(size_of::<T>() as u32);

        match vcpu.partition.call(msg) {
            Ok(resp) => {
                if !resp.body.is_empty() {
                    let _ = mem.write_slice(&resp.body, gpa);
                }
                if resp.status == 0 {
                    VirtioKvmResp::success()
                } else {
                    VirtioKvmResp::from_errno(resp.status as i32)
                }
            }
            Err(e) => {
                error!("virtio-kvm: {name} RPC failed: {e}");
                VirtioKvmResp::from_errno(libc::EIO)
            }
        }
    }

    fn handle_vcpu_generic_ioctl(&self, vcpu: &VirtioKvmVcpu, req: &VirtioKvmReq) -> VirtioKvmResp {
        let ioctl_num = req.arg;
        let msg = Message::ioctl(vcpu.tachyon_handle, ioctl_num, req.longarg);
        match vcpu.partition.call(msg) {
            Ok(resp) => {
                if resp.status == 0 {
                    VirtioKvmResp::from_data(resp.arg)
                } else {
                    VirtioKvmResp::from_errno(resp.status as i32)
                }
            }
            Err(e) => {
                error!("virtio-kvm: vcpu ioctl {ioctl_num} RPC failed: {e}");
                VirtioKvmResp::from_errno(libc::EIO)
            }
        }
    }

    fn handle_vcpu_set_cpuid2(&self, vcpu: &VirtioKvmVcpu, req: &VirtioKvmReq) -> VirtioKvmResp {
        debug!("!! virtio_kvm: handle_vcpu_ioctl: KVM_SET_CPUID2");
        let mem = self.mem.memory();
        let gpa = GuestAddress::new(req.longarg);
        let cpuid: kvm::kvm_cpuid2 = match mem.read_obj(gpa) {
            Ok(c) => c,
            Err(_) => return VirtioKvmResp::from_errno(libc::EFAULT),
        };

        let mut body = vec![
            0u8;
            size_of::<kvm::kvm_cpuid2>()
                + cpuid.nent as usize * size_of::<kvm::kvm_cpuid_entry2>()
        ];
        if mem.read_slice(&mut body, gpa).is_err() {
            return VirtioKvmResp::from_errno(libc::EFAULT);
        }

        let msg = Message::ioctl(vcpu.tachyon_handle, kvm::KVM_SET_CPUID2, 0).with_body(body);

        match vcpu.partition.call(msg) {
            Ok(resp) => {
                if resp.status == 0 {
                    VirtioKvmResp::success()
                } else {
                    VirtioKvmResp::from_errno(resp.status as i32)
                }
            }
            Err(e) => {
                error!("virtio-kvm: KVM_SET_CPUID2 RPC failed: {e}");
                VirtioKvmResp::from_errno(libc::EIO)
            }
        }
    }

    fn handle_vcpu_get_cpuid2(&self, vcpu: &VirtioKvmVcpu, req: &VirtioKvmReq) -> VirtioKvmResp {
        debug!("!! virtio_kvm: handle_vcpu_ioctl: KVM_GET_CPUID2");
        let mem = self.mem.memory();
        let gpa = GuestAddress::new(req.longarg);
        let cpuid: kvm::kvm_cpuid2 = match mem.read_obj(gpa) {
            Ok(c) => c,
            Err(_) => return VirtioKvmResp::from_errno(libc::EFAULT),
        };

        let resp_size =
            size_of::<kvm::kvm_cpuid2>() + cpuid.nent as usize * size_of::<kvm::kvm_cpuid_entry2>();
        let mut body = vec![0u8; size_of::<kvm::kvm_cpuid2>()];
        unsafe {
            ptr::copy_nonoverlapping(
                &cpuid as *const _ as *const u8,
                body.as_mut_ptr(),
                body.len(),
            );
        }

        let msg = Message::ioctl(vcpu.tachyon_handle, kvm::KVM_GET_CPUID2, 0)
            .with_body(body)
            .with_resp(resp_size as u32);

        match vcpu.partition.call(msg) {
            Ok(resp) => {
                if !resp.body.is_empty() {
                    let _ = mem.write_slice(&resp.body, gpa);
                }
                if resp.status == 0 {
                    VirtioKvmResp::success()
                } else {
                    VirtioKvmResp::from_errno(resp.status as i32)
                }
            }
            Err(e) => {
                error!("virtio-kvm: KVM_GET_CPUID2 RPC failed: {e}");
                VirtioKvmResp::from_errno(libc::EIO)
            }
        }
    }

    fn handle_vcpu_get_xsave2(&self, vcpu: &VirtioKvmVcpu, req: &VirtioKvmReq) -> VirtioKvmResp {
        debug!("!! virtio_kvm: handle_vcpu_ioctl: KVM_GET_XSAVE2");
        let mem = self.mem.memory();
        let gpa = GuestAddress::new(req.longarg);

        // 1. Get the size for XSAVE area from Tachyon
        let msg_size = Message::ioctl(1, kvm::KVM_CHECK_EXTENSION, kvm::KVM_CAP_XSAVE2 as u64);
        let xsave_size = match vcpu.partition.call(msg_size) {
            Ok(resp) => {
                if resp.status == 0 && resp.arg > 0 {
                    resp.arg as u32
                } else {
                    4096 // Fallback to basic size
                }
            }
            Err(_) => 4096,
        };

        // 2. Request XSAVE data
        let msg = Message::ioctl(vcpu.tachyon_handle, kvm::KVM_GET_XSAVE2, 0).with_resp(xsave_size);

        match vcpu.partition.call(msg) {
            Ok(resp) => {
                if !resp.body.is_empty() {
                    let _ = mem.write_slice(&resp.body, gpa);
                }
                if resp.status == 0 {
                    VirtioKvmResp::success()
                } else {
                    VirtioKvmResp::from_errno(resp.status as i32)
                }
            }
            Err(e) => {
                error!("virtio-kvm: KVM_GET_XSAVE2 RPC failed: {e}");
                VirtioKvmResp::from_errno(libc::EIO)
            }
        }
    }

    fn handle_vcpu_get_nested_state(
        &self,
        vcpu: &VirtioKvmVcpu,
        req: &VirtioKvmReq,
    ) -> VirtioKvmResp {
        debug!("!! virtio_kvm: handle_vcpu_ioctl: KVM_GET_NESTED_STATE");
        let mem = self.mem.memory();
        let gpa = GuestAddress::new(req.longarg);
        let nested: kvm::kvm_nested_state = match mem.read_obj(gpa) {
            Ok(n) => n,
            Err(_) => return VirtioKvmResp::from_errno(libc::EFAULT),
        };

        let full_size = nested.size as usize;
        let mut body = vec![0u8; size_of::<kvm::kvm_nested_state>()];
        if mem.read_slice(&mut body, gpa).is_err() {
            return VirtioKvmResp::from_errno(libc::EFAULT);
        }

        let msg = Message::ioctl(vcpu.tachyon_handle, kvm::KVM_GET_NESTED_STATE, 0)
            .with_body(body)
            .with_resp(full_size as u32);

        match vcpu.partition.call(msg) {
            Ok(resp) => {
                if !resp.body.is_empty() {
                    let _ = mem.write_slice(&resp.body, gpa);
                }
                if resp.status == 0 {
                    VirtioKvmResp::success()
                } else {
                    VirtioKvmResp::from_errno(resp.status as i32)
                }
            }
            Err(e) => {
                error!("virtio-kvm: KVM_GET_NESTED_STATE RPC failed: {e}");
                VirtioKvmResp::from_errno(libc::EIO)
            }
        }
    }

    fn handle_vcpu_set_nested_state(
        &self,
        vcpu: &VirtioKvmVcpu,
        req: &VirtioKvmReq,
    ) -> VirtioKvmResp {
        debug!("!! virtio_kvm: handle_vcpu_ioctl: KVM_SET_NESTED_STATE");
        let mem = self.mem.memory();
        let gpa = GuestAddress::new(req.longarg);
        let nested: kvm::kvm_nested_state = match mem.read_obj(gpa) {
            Ok(n) => n,
            Err(_) => return VirtioKvmResp::from_errno(libc::EFAULT),
        };

        let full_size = nested.size as usize;
        let mut body = vec![0u8; full_size];
        if mem.read_slice(&mut body, gpa).is_err() {
            return VirtioKvmResp::from_errno(libc::EFAULT);
        }

        let msg = Message::ioctl(vcpu.tachyon_handle, kvm::KVM_SET_NESTED_STATE, 0).with_body(body);

        match vcpu.partition.call(msg) {
            Ok(resp) => {
                if resp.status == 0 {
                    VirtioKvmResp::success()
                } else {
                    VirtioKvmResp::from_errno(resp.status as i32)
                }
            }
            Err(e) => {
                error!("virtio-kvm: KVM_SET_NESTED_STATE RPC failed: {e}");
                VirtioKvmResp::from_errno(libc::EIO)
            }
        }
    }

    fn handle_vcpu_get_xsave(&self, vcpu: &VirtioKvmVcpu, req: &VirtioKvmReq) -> VirtioKvmResp {
        debug!("!! virtio_kvm: handle_vcpu_ioctl: KVM_GET_XSAVE");
        let mem = self.mem.memory();
        let gpa = GuestAddress::new(req.longarg);
        let msg = Message::ioctl(vcpu.tachyon_handle, kvm::KVM_GET_XSAVE, 0).with_resp(4096);

        match vcpu.partition.call(msg) {
            Ok(resp) => {
                if !resp.body.is_empty() {
                    let _ = mem.write_slice(&resp.body, gpa);
                }
                if resp.status == 0 {
                    VirtioKvmResp::success()
                } else {
                    VirtioKvmResp::from_errno(resp.status as i32)
                }
            }
            Err(e) => {
                error!("virtio-kvm: KVM_GET_XSAVE RPC failed: {e}");
                VirtioKvmResp::from_errno(libc::EIO)
            }
        }
    }

    fn handle_vcpu_set_xsave(&self, vcpu: &VirtioKvmVcpu, req: &VirtioKvmReq) -> VirtioKvmResp {
        debug!("!! virtio_kvm: handle_vcpu_ioctl: KVM_SET_XSAVE");
        let mem = self.mem.memory();
        let gpa = GuestAddress::new(req.longarg);
        let mut body = vec![0u8; 4096];
        if mem.read_slice(&mut body, gpa).is_err() {
            return VirtioKvmResp::from_errno(libc::EFAULT);
        }

        let msg = Message::ioctl(vcpu.tachyon_handle, kvm::KVM_SET_XSAVE, 0).with_body(body);

        match vcpu.partition.call(msg) {
            Ok(resp) => {
                if resp.status == 0 {
                    VirtioKvmResp::success()
                } else {
                    VirtioKvmResp::from_errno(resp.status as i32)
                }
            }
            Err(e) => {
                error!("virtio-kvm: KVM_SET_XSAVE RPC failed: {e}");
                VirtioKvmResp::from_errno(libc::EIO)
            }
        }
    }

    fn handle_vcpu_ioctl(
        &self,
        _resource: &LockedResource,
        vcpu: &VirtioKvmVcpu,
        req: &VirtioKvmReq,
        _head_index: u16,
        _resp_addr: GuestAddress,
    ) -> Option<VirtioKvmResp> {
        let ioctl_num = req.arg;
        match ioctl_num {
            kvm::KVM_SET_CPUID2 => Some(self.handle_vcpu_set_cpuid2(vcpu, req)),
            kvm::KVM_GET_CPUID2 => Some(self.handle_vcpu_get_cpuid2(vcpu, req)),
            kvm::KVM_SET_SREGS => {
                Some(self.handle_vcpu_set_ioctl::<kvm::kvm_sregs>(vcpu, req, "KVM_SET_SREGS"))
            }
            kvm::KVM_GET_SREGS => {
                Some(self.handle_vcpu_get_ioctl::<kvm::kvm_sregs>(vcpu, req, "KVM_GET_SREGS"))
            }
            kvm::KVM_GET_REGS => {
                Some(self.handle_vcpu_get_ioctl::<kvm::kvm_regs>(vcpu, req, "KVM_GET_REGS"))
            }
            kvm::KVM_SET_REGS => {
                Some(self.handle_vcpu_set_ioctl::<kvm::kvm_regs>(vcpu, req, "KVM_SET_REGS"))
            }
            kvm::KVM_GET_FPU => {
                Some(self.handle_vcpu_get_ioctl::<kvm::kvm_fpu>(vcpu, req, "KVM_GET_FPU"))
            }
            kvm::KVM_SET_FPU => {
                Some(self.handle_vcpu_set_ioctl::<kvm::kvm_fpu>(vcpu, req, "KVM_SET_FPU"))
            }
            kvm::KVM_SET_XCRS => {
                Some(self.handle_vcpu_set_ioctl::<kvm::kvm_xcrs>(vcpu, req, "KVM_SET_XCRS"))
            }
            kvm::KVM_GET_XCRS => {
                Some(self.handle_vcpu_get_ioctl::<kvm::kvm_xcrs>(vcpu, req, "KVM_GET_XCRS"))
            }
            kvm::KVM_SET_MP_STATE => {
                Some(self.handle_vcpu_set_ioctl::<kvm::kvm_mp_state>(vcpu, req, "KVM_SET_MP_STATE"))
            }
            kvm::KVM_GET_MP_STATE => {
                Some(self.handle_vcpu_get_ioctl::<kvm::kvm_mp_state>(vcpu, req, "KVM_GET_MP_STATE"))
            }
            kvm::KVM_GET_MSRS => {
                Some(self.handle_msrs_ioctl(&vcpu.partition, vcpu.tachyon_handle, req, true))
            }
            kvm::KVM_SET_MSRS => {
                Some(self.handle_msrs_ioctl(&vcpu.partition, vcpu.tachyon_handle, req, false))
            }
            kvm::KVM_ENABLE_CAP => {
                Some(self.handle_enable_cap_ioctl(&vcpu.partition, vcpu.tachyon_handle, req))
            }
            kvm::KVM_SMI => Some(self.handle_vcpu_generic_ioctl(vcpu, req)),

            kvm::KVM_GET_STATS_FD => {
                Some(self.handle_get_stats_fd(req.handle, vcpu.tachyon_handle, &vcpu.partition))
            }

            kvm::KVM_GET_VCPU_EVENTS => Some(self.handle_vcpu_get_ioctl::<kvm::kvm_vcpu_events>(
                vcpu,
                req,
                "KVM_GET_VCPU_EVENTS",
            )),
            kvm::KVM_SET_VCPU_EVENTS => Some(self.handle_vcpu_set_ioctl::<kvm::kvm_vcpu_events>(
                vcpu,
                req,
                "KVM_SET_VCPU_EVENTS",
            )),
            kvm::KVM_GET_XSAVE => Some(self.handle_vcpu_get_xsave(vcpu, req)),
            kvm::KVM_SET_XSAVE => Some(self.handle_vcpu_set_xsave(vcpu, req)),
            kvm::KVM_GET_XSAVE2 => Some(self.handle_vcpu_get_xsave2(vcpu, req)),
            kvm::KVM_GET_NESTED_STATE => Some(self.handle_vcpu_get_nested_state(vcpu, req)),
            kvm::KVM_SET_NESTED_STATE => Some(self.handle_vcpu_set_nested_state(vcpu, req)),
            kvm::KVM_GET_DEBUGREGS => Some(self.handle_vcpu_get_ioctl::<kvm::kvm_debugregs>(
                vcpu,
                req,
                "KVM_GET_DEBUGREGS",
            )),
            kvm::KVM_SET_DEBUGREGS => Some(self.handle_vcpu_set_ioctl::<kvm::kvm_debugregs>(
                vcpu,
                req,
                "KVM_SET_DEBUGREGS",
            )),
            kvm::KVM_SET_SIGNAL_MASK => {
                warn!("!! virtio_kvm: KVM_SET_SIGNAL_MASK is not supported");
                Some(VirtioKvmResp::from_errno(libc::ENOSYS))
            }
            kvm::KVM_GET_TSC_KHZ | kvm::KVM_SET_TSC_KHZ => {
                Some(self.handle_vcpu_generic_ioctl(vcpu, req))
            }
            kvm::KVM_TRANSLATE => Some(self.handle_vcpu_inout_ioctl::<kvm::kvm_translation>(
                vcpu,
                req,
                "KVM_TRANSLATE",
            )),
            kvm::KVM_GET_LAPIC => {
                Some(self.handle_vcpu_get_ioctl::<kvm::kvm_lapic_state>(vcpu, req, "KVM_GET_LAPIC"))
            }
            kvm::KVM_SET_LAPIC => {
                Some(self.handle_vcpu_set_ioctl::<kvm::kvm_lapic_state>(vcpu, req, "KVM_SET_LAPIC"))
            }
            kvm::KVM_SET_GUEST_DEBUG => Some(self.handle_vcpu_set_ioctl::<kvm::kvm_guest_debug>(
                vcpu,
                req,
                "KVM_SET_GUEST_DEBUG",
            )),
            kvm::KVM_SET_SREGS2 => {
                Some(self.handle_vcpu_set_ioctl::<kvm::kvm_sregs2>(vcpu, req, "KVM_SET_SREGS2"))
            }
            kvm::KVM_GET_SREGS2 => {
                Some(self.handle_vcpu_get_ioctl::<kvm::kvm_sregs2>(vcpu, req, "KVM_GET_SREGS2"))
            }
            kvm::KVM_INTERRUPT => {
                Some(self.handle_vcpu_set_ioctl::<kvm::kvm_interrupt>(vcpu, req, "KVM_INTERRUPT"))
            }
            kvm::KVM_X86_SETUP_MCE => {
                Some(self.handle_vcpu_set_ioctl::<u64>(vcpu, req, "KVM_X86_SETUP_MCE"))
            }
            kvm::KVM_X86_SET_MCE => {
                Some(self.handle_vcpu_set_ioctl::<kvm::kvm_x86_mce>(vcpu, req, "KVM_X86_SET_MCE"))
            }
            kvm::KVM_KVMCLOCK_CTRL => Some(self.handle_vcpu_generic_ioctl(vcpu, req)),
            kvm::KVM_TPR_ACCESS_REPORTING => {
                Some(self.handle_vcpu_inout_ioctl::<kvm::kvm_tpr_access_ctl>(
                    vcpu,
                    req,
                    "KVM_TPR_ACCESS_REPORTING",
                ))
            }
            kvm::KVM_SET_VAPIC_ADDR => Some(self.handle_vcpu_set_ioctl::<kvm::kvm_vapic_addr>(
                vcpu,
                req,
                "KVM_SET_VAPIC_ADDR",
            )),
            _ => {
                debug!("!! virtio_kvm: handle_vcpu_ioctl: unknown ioctl: {ioctl_num:#x}");
                Some(VirtioKvmResp::from_errno(libc::EINVAL))
            }
        }
    }

    fn handle_ioctl(
        &self,
        req: &VirtioKvmReq,
        head_index: u16,
        resp_addr: GuestAddress,
    ) -> Option<VirtioKvmResp> {
        debug!("!! virtio_kvm: handle_ioctl: req: {req:#x?}");
        let handle: Handle = req.handle;
        let resource = {
            let resource_map = self.resources.lock().unwrap();
            match resource_map.get(&handle) {
                Some(resource) => resource.clone(),
                None => return Some(VirtioKvmResp::from_errno(libc::ENOENT)),
            }
        };
        let mut guard = resource.lock().unwrap();
        match guard.deref_mut() {
            VirtioKvmResource::System(kvm) => Some(self.handle_system_ioctl(&resource, kvm, req)),
            VirtioKvmResource::Vm(vm) => Some(self.handle_vm_ioctl(&resource, vm, req)),
            VirtioKvmResource::Vcpu(vcpu) => {
                self.handle_vcpu_ioctl(&resource, vcpu, req, head_index, resp_addr)
            }
            VirtioKvmResource::Stats(_) => Some(VirtioKvmResp::from_errno(libc::ENOTTY)),
            VirtioKvmResource::VfioContainer(container) => {
                Some(self.handle_vfio_container_ioctl(&resource, container, req))
            }
            VirtioKvmResource::VfioGroup(group) => {
                Some(self.handle_vfio_group_ioctl(&resource, group, req))
            }
            VirtioKvmResource::VfioDevice(device) => {
                Some(self.handle_vfio_device_ioctl(&resource, device, req))
            }
        }
    }

    fn handle_device_mmap(&self, req: &VirtioKvmReq) -> VirtioKvmResp {
        let handle: Handle = req.handle;
        let (fd, shm_bar_offset) = {
            let resource_map = self.resources.lock().unwrap();
            match resource_map.get(&handle) {
                Some(resource) => {
                    let guard = resource.lock().unwrap();
                    match guard.deref() {
                        VirtioKvmResource::Vm(vm) => (vm.shm_fd, Some(vm.shm_bar_offset.clone())),
                        _ => (guard.as_raw_fd(), None),
                    }
                }
                None => return VirtioKvmResp::from_errno(libc::ENOENT),
            }
        };

        let mem = self.mem.memory();
        let mmap_req: VirtioKvmDevMmap = match mem.read_obj(GuestAddress::new(req.longarg)) {
            Ok(mmap_req) => mmap_req,
            Err(_e) => {
                debug!(
                    "!! virtio_kvm: mmap: failed to read mmap_req: {:#x}",
                    req.longarg
                );
                return VirtioKvmResp::from_errno(libc::EFAULT);
            }
        };

        if mmap_req.phys_offset + mmap_req.size > self.bar_mapping.mapping.size() as u64 {
            return VirtioKvmResp::from_errno(libc::EINVAL);
        }

        let addr = unsafe {
            libc::mmap(
                (self
                    .bar_mapping
                    .mapping
                    .as_ptr()
                    .wrapping_add(mmap_req.phys_offset as usize))
                    as *mut libc::c_void,
                mmap_req.size as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_FIXED,
                fd,
                mmap_req.device_offset as libc::off_t,
            )
        };

        if addr == libc::MAP_FAILED {
            return VirtioKvmResp::from_last_errno();
        }

        if let Some(shm_bar_offset) = shm_bar_offset {
            shm_bar_offset.store(mmap_req.phys_offset, Ordering::Release);
        }

        self.mappings.lock().unwrap().insert(
            handle,
            KvmBarMapping {
                phys_offset: mmap_req.phys_offset,
                size: mmap_req.size,
                device_offset: mmap_req.device_offset,
            },
        );

        VirtioKvmResp::success()
    }

    fn handle_device_munmap(&self, req: &VirtioKvmReq) -> VirtioKvmResp {
        let mem = self.mem.memory();
        let munmap_req: VirtioKvmMunmapDev = match mem.read_obj(GuestAddress::new(req.longarg)) {
            Ok(munmap_req) => munmap_req,
            Err(_e) => {
                debug!(
                    "!! virtio_kvm: munmap: failed to read munmap_req: {:#x}",
                    req.longarg
                );
                return VirtioKvmResp::from_errno(libc::EFAULT);
            }
        };

        if munmap_req.phys_offset + munmap_req.size > self.bar_mapping.mapping.size() as u64 {
            return VirtioKvmResp::from_errno(libc::EINVAL);
        }

        let addr = unsafe {
            libc::mmap(
                (self
                    .bar_mapping
                    .mapping
                    .as_ptr()
                    .wrapping_add(munmap_req.phys_offset as usize))
                    as *mut libc::c_void,
                munmap_req.size as usize,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                -1,
                0,
            )
        };

        if addr == libc::MAP_FAILED {
            return VirtioKvmResp::from_last_errno();
        }

        self.mappings.lock().unwrap().remove(&req.handle);

        VirtioKvmResp::success()
    }

    fn handle_eventfd_get(&self, req: &VirtioKvmReq) -> VirtioKvmResp {
        let partition_id = req.arg;
        let ctx = req.longarg;
        let mut eventfds = self.eventfds.lock().unwrap();
        let mut fd_to_handle = self.fd_to_handle.lock().unwrap();

        if let Some(info) = eventfds.get_mut(&ctx) {
            info.refs += 1;
            debug!(
                "virtio-kvm: handle_eventfd_get: existing ctx={ctx}, refs={}, tachyon_handle={}",
                info.refs, info.tachyon_handle
            );
            return VirtioKvmResp::from_data(ctx);
        }

        let partition = match self.tachyon.prepare_partition(self, partition_id) {
            Ok(p) => p,
            Err(e) => {
                debug!(
                    "!! virtio_kvm: failed to prepare tachyon for partition {partition_id}: {e}"
                );
                return VirtioKvmResp::from_errno(libc::EIO);
            }
        };

        let msg = Message::simple(TachyonOp::EventfdGet as u32, 1);

        match partition.call(msg) {
            Ok(resp) => {
                if resp.status == 0 {
                    let tachyon_handle = resp.handle;
                    let fd = resp.fds.and_then(|mut fds| fds.pop()).unwrap_or(-1);
                    if fd < 0 {
                        return VirtioKvmResp::from_errno(libc::EIO);
                    }
                    // SAFETY: We own this fd because it was passed to us via SCM_RIGHTS.
                    let eventfd = unsafe { EventFd::from_raw_fd(fd) };

                    let event = epoll::Event::new(epoll::Events::EPOLLIN, fd as u64);
                    if let Err(e) = epoll::ctl(
                        self.poll_fd,
                        epoll::ControlOptions::EPOLL_CTL_ADD,
                        fd,
                        event,
                    ) {
                        return VirtioKvmResp::from_errno(e.raw_os_error().unwrap_or(libc::EIO));
                    }

                    fd_to_handle.insert(fd, ctx);
                    let info = EventfdInfo {
                        eventfd,
                        refs: 1,
                        tachyon_handle,
                        partition: partition.clone(),
                    };
                    eventfds.insert(ctx, info);
                    debug!(
                        "virtio-kvm: handle_eventfd_get: created ctx={ctx}, tachyon_handle={tachyon_handle}, fd={fd}, total_eventfds={}",
                        eventfds.len()
                    );
                    VirtioKvmResp::from_data(ctx)
                } else {
                    VirtioKvmResp::from_errno(resp.status as i32)
                }
            }
            Err(_e) => VirtioKvmResp::from_errno(libc::EIO),
        }
    }

    fn handle_eventfd_put(&self, req: &VirtioKvmReq) -> VirtioKvmResp {
        let handle = req.longarg; // Guest sends handle (which is ctx now)
        let mut eventfds = self.eventfds.lock().unwrap();
        let mut fd_to_handle = self.fd_to_handle.lock().unwrap();

        use std::collections::hash_map::Entry;
        match eventfds.entry(handle) {
            Entry::Occupied(mut entry) => {
                entry.get_mut().refs -= 1;
                let refs = entry.get().refs;
                debug!("virtio-kvm: handle_eventfd_put: handle={handle}, remaining_refs={refs}");
                if refs == 0 {
                    let info = entry.remove();
                    let fd = info.eventfd.as_raw_fd();
                    fd_to_handle.remove(&fd);

                    let event = epoll::Event::new(epoll::Events::EPOLLIN, fd as u64);
                    let _ = epoll::ctl(
                        self.poll_fd,
                        epoll::ControlOptions::EPOLL_CTL_DEL,
                        fd,
                        event,
                    );

                    let msg = Message::simple(TachyonOp::Close as u32, info.tachyon_handle);
                    let _ = info.partition.call(msg);
                }
                VirtioKvmResp::success()
            }
            Entry::Vacant(_) => {
                debug!("virtio-kvm: handle_eventfd_put: handle={handle} not found in eventfds");
                VirtioKvmResp::from_errno(libc::ENOENT)
            }
        }
    }

    fn handle_eventfd_write(&self, req: &VirtioKvmReq) -> VirtioKvmResp {
        let local_handle = req.handle.0;
        let eventfds = self.eventfds.lock().unwrap();
        if let Some(info) = eventfds.get(&local_handle) {
            return match info.eventfd.write(1) {
                Ok(_) => VirtioKvmResp::success(),
                Err(e) => VirtioKvmResp::from_errno(e.raw_os_error().unwrap_or(libc::EIO)),
            };
        }
        VirtioKvmResp::from_errno(libc::ENOENT)
    }

    fn handle_eventfd_poll(
        &self,
        head_index: u16,
        resp_addr: GuestAddress,
    ) -> Option<VirtioKvmResp> {
        self.poll_work_sender
            .send(PollWork::Process(PollWorkReq {
                resp_addr,
                head_index,
            }))
            .unwrap();
        None
    }

    fn handle_l1_fault_poll(
        &self,
        req: &VirtioKvmReq,
        head_index: u16,
        resp_addr: GuestAddress,
    ) -> Option<VirtioKvmResp> {
        let fault_addr = GuestAddress::new(req.longarg);
        let mut state = self.tachyon.l1_fault_state.lock().unwrap();
        if let Some(fault) = state.pending_faults.pop_front() {
            let wire = VirtioKvmL1Fault {
                vm_handle: fault.vm_handle,
                gpa: fault.gpa,
                seq: fault.seq,
            };
            let mem = self.mem.memory();
            if mem.write_obj(wire, fault_addr).is_err() {
                return Some(VirtioKvmResp::from_errno(libc::EFAULT));
            }
            return Some(VirtioKvmResp::success());
        }
        state.pending_poll = Some(PendingL1FaultPoll {
            head_index,
            resp_addr,
            fault_addr,
            mem: self.mem.clone(),
            queue: self.queue.clone(),
            interrupt_cb: self.interrupt_cb.clone(),
        });
        None
    }

    fn handle_l1_fault_ack(&self, req: &VirtioKvmReq) -> VirtioKvmResp {
        self.tachyon.ack_l1_fault(req.arg);
        VirtioKvmResp::success()
    }

    fn handle_memory_file_create(&self, req: &VirtioKvmReq) -> VirtioKvmResp {
        let partition_id = req.arg;
        let partition = match self.tachyon.prepare_partition(self, partition_id) {
            Ok(p) => p,
            Err(e) => {
                debug!(
                    "!! virtio_kvm: failed to prepare tachyon for partition {partition_id}: {e}"
                );
                return VirtioKvmResp::from_errno(libc::EIO);
            }
        };

        let mem = self.mem.memory();
        let mut create_req: VirtioKvmMemoryFileCreate =
            match mem.read_obj(GuestAddress::new(req.longarg)) {
                Ok(create_req) => create_req,
                Err(_e) => {
                    debug!(
                        "!! virtio_kvm: memory_file_create: failed to read create_req: {:#x}",
                        req.longarg
                    );
                    return VirtioKvmResp::from_errno(libc::EFAULT);
                }
            };

        if create_req.phys_offset + create_req.size > self.bar_mapping.mapping.size() as u64 {
            return VirtioKvmResp::from_errno(libc::EINVAL);
        }

        // 1. Request Memory File from Tachyon
        let msg = Message::new(TachyonOp::MemoryFileCreate as u32, 1, 0, create_req.size);

        let resp = match partition.call(msg) {
            Ok(r) => r,
            Err(e) => {
                error!("virtio-kvm: MemoryFileCreate RPC failed: {e}");
                return VirtioKvmResp::from_errno(libc::EIO);
            }
        };

        if resp.status != 0 {
            return VirtioKvmResp::from_errno(resp.status as i32);
        }

        let tachyon_mem_handle = resp.handle;
        let fd = resp
            .fds
            .and_then(|mut fds| fds.pop())
            .ok_or(libc::EIO)
            .unwrap_or(-1);

        if fd < 0 {
            error!("virtio-kvm: MemoryFileCreate RPC returned no FD");
            return VirtioKvmResp::from_errno(libc::EIO);
        }

        if create_req.size > 0 {
            let addr = unsafe {
                libc::mmap(
                    (self
                        .bar_mapping
                        .mapping
                        .as_ptr()
                        .wrapping_add(create_req.phys_offset as usize))
                        as *mut libc::c_void,
                    create_req.size as usize,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED | libc::MAP_FIXED,
                    fd,
                    0,
                )
            };

            if addr == libc::MAP_FAILED {
                let errno = VirtioKvmResp::from_last_errno();
                unsafe { libc::close(fd) };

                let msg = Message::simple(TachyonOp::Close as u32, tachyon_mem_handle);
                if let Err(e) = partition.call(msg) {
                    error!("virtio-kvm: MemoryFileCreate cleanup RPC failed: {e}");
                }

                return errno;
            }
            debug!(
                "memory file mapped: start={:#x}, end={:#x}",
                addr as u64,
                addr as u64 + create_req.size
            );
        }

        let file = KvmMemoryFile {
            fd,
            size: create_req.size,
            phys_offset: create_req.phys_offset,
            tachyon_handle: tachyon_mem_handle,
            partition: partition.clone(),
        };
        let handle = Handle::new().0;
        self.mem_files.lock().unwrap().insert(handle, file);
        debug!(
            "!! virtio_kvm: handle_memory_file_create: handle=0x{:x}, size={}, offset={:#x}, tachyon_handle=0x{:x}",
            handle, create_req.size, create_req.phys_offset, tachyon_mem_handle
        );

        create_req.handle = handle;
        match mem.write_obj(create_req, GuestAddress::new(req.longarg)) {
            Ok(_) => VirtioKvmResp::success(),
            Err(_e) => {
                debug!(
                    "!! virtio_kvm: memory_file_create: failed to write handle: {:#x}",
                    req.longarg
                );
                self.mem_files.lock().unwrap().remove(&handle);
                if create_req.size > 0 {
                    unsafe {
                        libc::mmap(
                            (self
                                .bar_mapping
                                .mapping
                                .as_ptr()
                                .wrapping_add(create_req.phys_offset as usize))
                                as *mut libc::c_void,
                            create_req.size as usize,
                            libc::PROT_NONE,
                            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                            -1,
                            0,
                        );
                    }
                }
                VirtioKvmResp::from_errno(libc::EFAULT)
            }
        }
    }

    fn handle_memory_file_delete(&self, req: &VirtioKvmReq) -> VirtioKvmResp {
        let handle = req.handle.0;
        if let Some(file) = self.mem_files.lock().unwrap().remove(&handle) {
            debug!(
                "!! virtio_kvm: handle_memory_file_delete: handle=0x{:x}, size={}, offset={:#x}, tachyon_handle=0x{:x}",
                handle, file.size, file.phys_offset, file.tachyon_handle
            );
            if file.size > 0 {
                let addr = unsafe {
                    libc::mmap(
                        (self
                            .bar_mapping
                            .mapping
                            .as_ptr()
                            .wrapping_add(file.phys_offset as usize))
                            as *mut libc::c_void,
                        file.size as usize,
                        libc::PROT_NONE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                        -1,
                        0,
                    )
                };
                if addr == libc::MAP_FAILED {
                    return VirtioKvmResp::from_last_errno();
                }
            }

            let msg = Message::simple(TachyonOp::Close as u32, file.tachyon_handle);

            match file.partition.call(msg) {
                Ok(resp) => {
                    if resp.status == 0 {
                        VirtioKvmResp::success()
                    } else {
                        VirtioKvmResp::from_errno(resp.status as i32)
                    }
                }
                Err(e) => {
                    error!("virtio-kvm: MemoryFileDelete (Close) RPC failed: {e}");
                    VirtioKvmResp::from_errno(libc::EIO)
                }
            }
        } else {
            VirtioKvmResp::from_errno(libc::ENOENT)
        }
    }

    fn handle_get_stats_fd(
        &self,
        parent_handle: Handle,
        parent_tachyon_handle: u64,
        partition: &TachyonPartition,
    ) -> VirtioKvmResp {
        let msg = Message::ioctl(parent_tachyon_handle, kvm::KVM_GET_STATS_FD, 0);

        match partition.call(msg) {
            Ok(resp) => {
                if resp.status == 0 {
                    let fd = resp.fds.and_then(|mut fds| fds.pop()).unwrap_or(-1);
                    if fd < 0 {
                        error!("virtio-kvm: KVM_GET_STATS_FD RPC returned no FD");
                        return VirtioKvmResp::from_errno(libc::EIO);
                    }
                    let stats = VirtioKvmStats {
                        fd,
                        parent_handle,
                        partition: partition.clone(),
                    };
                    let handle = Handle::new();
                    self.resources.lock().unwrap().insert(
                        handle,
                        Arc::new(Mutex::new(VirtioKvmResource::Stats(stats))),
                    );
                    VirtioKvmResp::from_data(handle.0)
                } else {
                    VirtioKvmResp::from_errno(resp.status as i32)
                }
            }
            Err(e) => {
                error!("virtio-kvm: KVM_GET_STATS_FD RPC failed: {e}");
                VirtioKvmResp::from_errno(libc::EIO)
            }
        }
    }

    fn handle_file_write(&self, req: &VirtioKvmReq, fd: RawFd) -> VirtioKvmResp {
        let mem = self.mem.memory();
        let file_io_gpa = GuestAddress::new(req.longarg);
        let mut file_io: VirtioKvmFileIo = match mem.read_obj(file_io_gpa) {
            Ok(io) => io,
            Err(_) => return VirtioKvmResp::from_errno(libc::EFAULT),
        };

        let size = file_io.size as usize;
        let buffer_gpa = GuestAddress::new(file_io.buffer);
        let offset = file_io.offset;

        let mut buf = vec![0u8; size];

        if let Err(e) = mem.read_slice(&mut buf, buffer_gpa) {
            debug!("virtio-kvm: handle_file_write: failed to read from guest memory: {e}");
            return VirtioKvmResp::from_errno(libc::EFAULT);
        }

        let ret = unsafe { libc::pwrite(fd, buf.as_ptr() as *const libc::c_void, size, offset) };

        if ret < 0 {
            debug!(
                "virtio-kvm: handle_file_write: write failed: {}",
                io::Error::last_os_error()
            );
            return VirtioKvmResp::from_last_errno();
        }

        file_io.size = ret as i64;
        if mem.write_obj(file_io, file_io_gpa).is_err() {
            return VirtioKvmResp::from_errno(libc::EFAULT);
        }

        debug!("virtio-kvm: handle_file_write: wrote {ret} bytes at offset {offset}");
        VirtioKvmResp::from_data(ret as u64)
    }

    fn handle_file_read(&self, req: &VirtioKvmReq, fd: RawFd) -> VirtioKvmResp {
        let mem = self.mem.memory();
        let file_io_gpa = GuestAddress::new(req.longarg);
        let mut file_io: VirtioKvmFileIo = match mem.read_obj(file_io_gpa) {
            Ok(io) => io,
            Err(_) => return VirtioKvmResp::from_errno(libc::EFAULT),
        };

        let size = file_io.size as usize;
        let buffer_gpa = GuestAddress::new(file_io.buffer);
        let offset = file_io.offset;

        let mut buf = vec![0u8; size];
        let ret = unsafe { libc::pread(fd, buf.as_mut_ptr() as *mut libc::c_void, size, offset) };
        if ret < 0 {
            debug!(
                "virtio-kvm: handle_file_read: read failed: {}",
                io::Error::last_os_error()
            );
            return VirtioKvmResp::from_last_errno();
        }

        if let Err(e) = mem.write_slice(&buf[..ret as usize], buffer_gpa) {
            debug!("virtio-kvm: handle_file_read: failed to write to guest memory: {e}");
            return VirtioKvmResp::from_errno(libc::EFAULT);
        }

        file_io.size = ret as i64;
        if mem.write_obj(file_io, file_io_gpa).is_err() {
            return VirtioKvmResp::from_errno(libc::EFAULT);
        }

        debug!("virtio-kvm: handle_file_read: read {ret} bytes at offset {offset}");
        VirtioKvmResp::from_data(ret as u64)
    }

    fn handle_file_io(&self, req: &VirtioKvmReq) -> VirtioKvmResp {
        let handle = req.handle;
        let resource = {
            let resources = self.resources.lock().unwrap();
            resources.get(&handle).cloned()
        };

        let direction = match FileIoDirection::try_from(req.arg) {
            Ok(d) => d,
            _ => {
                error!("virtio-kvm: Invalid IO direction for FILE_IO: {}", req.arg);
                return VirtioKvmResp::from_errno(libc::EINVAL);
            }
        };

        if let Some(res) = resource {
            let guard = res.lock().unwrap();
            return match *guard {
                VirtioKvmResource::Stats(ref stats) => match direction {
                    FileIoDirection::Read => self.handle_file_read(req, stats.fd),
                    _ => {
                        error!("virtio-kvm: Stats only supports read!");
                        VirtioKvmResp::from_errno(libc::EINVAL)
                    }
                },
                VirtioKvmResource::VfioDevice(ref device) => match direction {
                    FileIoDirection::Read => self.handle_file_read(req, device.fd),
                    FileIoDirection::Write => self.handle_file_write(req, device.fd),
                },
                ref other => {
                    error!("virtio-kvm: Attempted file IO on invalid file: {handle:?}=>{other:?}");
                    VirtioKvmResp::from_errno(libc::EINVAL)
                }
            };
        }
        VirtioKvmResp::from_errno(libc::ENOENT)
    }

    fn handle_ready(&self, req: &VirtioKvmReq) -> VirtioKvmResp {
        let handle: Handle = req.handle;
        let (tachyon_handle, partition) = {
            let resource_map = self.resources.lock().unwrap();
            match resource_map.get(&handle) {
                Some(resource) => {
                    let guard = resource.lock().unwrap();
                    match guard.deref() {
                        VirtioKvmResource::Vcpu(vcpu) => {
                            (vcpu.tachyon_handle, vcpu.partition.clone())
                        }
                        _ => return VirtioKvmResp::from_errno(libc::EINVAL),
                    }
                }
                None => return VirtioKvmResp::from_errno(libc::ENOENT),
            }
        };

        let msg = Message {
            msg_type: TachyonOp::Ready as u32,
            request_id: 0,
            handle: tachyon_handle,
            status: 0,
            arg: 0,
            cmd: 0,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };

        if let Err(e) = partition.asynchronous_call(msg) {
            error!("!! virtio_kvm: Ready RPC failed: {e}");
            return VirtioKvmResp::from_errno(libc::EIO);
        }

        VirtioKvmResp::success()
    }

    /// Binds the guest eventfd `req.arg` (as registered with EventfdGet) as
    /// the run-completion notifier of the VM `req.handle` in Tachyon.
    fn handle_set_run_notify(&self, req: &VirtioKvmReq) -> VirtioKvmResp {
        let handle: Handle = req.handle;
        let (tachyon_handle, partition) = {
            let resource_map = self.resources.lock().unwrap();
            match resource_map.get(&handle) {
                Some(resource) => {
                    let guard = resource.lock().unwrap();
                    match guard.deref() {
                        VirtioKvmResource::Vm(vm) => (vm.tachyon_handle(), vm.partition.clone()),
                        _ => return VirtioKvmResp::from_errno(libc::EINVAL),
                    }
                }
                None => return VirtioKvmResp::from_errno(libc::ENOENT),
            }
        };
        let Some(eventfd_handle) = self.resolve_eventfd(req.arg) else {
            return VirtioKvmResp::from_errno(libc::EBADF);
        };
        let mut msg = Message::simple(TachyonOp::SetRunNotify as u32, tachyon_handle);
        msg.arg = eventfd_handle;
        match partition.call(msg) {
            Ok(resp) if resp.status == 0 => VirtioKvmResp::success(),
            Ok(resp) => VirtioKvmResp::from_errno(resp.status as i32),
            Err(e) => {
                error!("virtio-kvm: SetRunNotify RPC failed: {e}");
                VirtioKvmResp::from_errno(libc::EIO)
            }
        }
    }

    fn handle_set_l1_memslot(&self, req: &VirtioKvmReq) -> VirtioKvmResp {
        #[repr(C, packed)]
        #[derive(Copy, Clone)]
        struct GuestL1MemslotReq {
            slot: u32,
            flags: u32,
            guest_phys_addr: u64,
            memory_size: u64,
            table_bar_gpa: u64,
            table_size: u64,
        }
        // SAFETY: Plain packed C struct with no invalid bit patterns.
        unsafe impl vm_memory::ByteValued for GuestL1MemslotReq {}

        #[repr(C)]
        struct WireReq {
            slot: u32,
            flags: u32,
            guest_phys_addr: u64,
            memory_size: u64,
            table_handle: u64,
            table_size: u64,
        }

        let handle: Handle = req.handle;
        let (tachyon_handle, partition) = {
            let resource_map = self.resources.lock().unwrap();
            match resource_map.get(&handle) {
                Some(resource) => {
                    let guard = resource.lock().unwrap();
                    match guard.deref() {
                        VirtioKvmResource::Vm(vm) => (vm.tachyon_handle(), vm.partition.clone()),
                        _ => return VirtioKvmResp::from_errno(libc::EINVAL),
                    }
                }
                None => return VirtioKvmResp::from_errno(libc::ENOENT),
            }
        };

        let mem = self.mem.memory();
        let greq: GuestL1MemslotReq = match mem.read_obj(GuestAddress::new(req.longarg)) {
            Ok(r) => r,
            Err(_) => return VirtioKvmResp::from_errno(libc::EFAULT),
        };

        let table_handle = if greq.memory_size > 0 {
            match self.resolve_bar_resource(GuestAddress::new(greq.table_bar_gpa), greq.table_size)
            {
                Ok((h, _, _)) => h,
                Err(e) => return e,
            }
        } else {
            0
        };

        let wire = WireReq {
            slot: greq.slot,
            flags: greq.flags,
            guest_phys_addr: greq.guest_phys_addr,
            memory_size: greq.memory_size,
            table_handle,
            table_size: greq.table_size,
        };
        let mut body = vec![0u8; size_of::<WireReq>()];
        // SAFETY: `WireReq` is `#[repr(C)]` plain data.
        unsafe {
            ptr::copy_nonoverlapping(
                &wire as *const _ as *const u8,
                body.as_mut_ptr(),
                body.len(),
            );
        }
        let msg = Message::simple(TachyonOp::SetL1Memslot as u32, tachyon_handle).with_body(body);
        match partition.call(msg) {
            Ok(resp) if resp.status == 0 => VirtioKvmResp::success(),
            Ok(resp) => VirtioKvmResp::from_errno(resp.status as i32),
            Err(e) => {
                error!("virtio-kvm: SetL1Memslot RPC failed: {e}");
                VirtioKvmResp::from_errno(libc::EIO)
            }
        }
    }

    fn handle_invalidate_l1_memslot(&self, req: &VirtioKvmReq) -> VirtioKvmResp {
        #[repr(C, packed)]
        #[derive(Copy, Clone)]
        struct GuestInvalidateReq {
            slot: u32,
            pad: u32,
            offset: u64,
            size: u64,
        }
        // SAFETY: Plain packed C struct with no invalid bit patterns.
        unsafe impl vm_memory::ByteValued for GuestInvalidateReq {}

        let handle: Handle = req.handle;
        let (tachyon_handle, partition) = {
            let resource_map = self.resources.lock().unwrap();
            match resource_map.get(&handle) {
                Some(resource) => {
                    let guard = resource.lock().unwrap();
                    match guard.deref() {
                        VirtioKvmResource::Vm(vm) => (vm.tachyon_handle(), vm.partition.clone()),
                        _ => return VirtioKvmResp::from_errno(libc::EINVAL),
                    }
                }
                None => return VirtioKvmResp::from_errno(libc::ENOENT),
            }
        };

        let mem = self.mem.memory();
        let greq: GuestInvalidateReq = match mem.read_obj(GuestAddress::new(req.longarg)) {
            Ok(r) => r,
            Err(_) => return VirtioKvmResp::from_errno(libc::EFAULT),
        };

        let mut body = vec![0u8; size_of::<GuestInvalidateReq>()];
        // SAFETY: `GuestInvalidateReq` is `#[repr(C, packed)]` plain data.
        unsafe {
            ptr::copy_nonoverlapping(
                &greq as *const _ as *const u8,
                body.as_mut_ptr(),
                body.len(),
            );
        }
        let msg =
            Message::simple(TachyonOp::InvalidateL1Memslot as u32, tachyon_handle).with_body(body);
        match partition.call(msg) {
            Ok(resp) if resp.status == 0 => VirtioKvmResp::success(),
            Ok(resp) => VirtioKvmResp::from_errno(resp.status as i32),
            Err(e) => {
                error!("virtio-kvm: InvalidateL1Memslot RPC failed: {e}");
                VirtioKvmResp::from_errno(libc::EIO)
            }
        }
    }

    fn refresh_resources(&self) {
        info!("virtio-kvm: Refreshing resources after live-update");
        // 1. Refresh VM and VCPU FDs
        let resources_clone = {
            let resources = self.resources.lock().unwrap();
            resources.values().cloned().collect::<Vec<_>>()
        };

        for resource in resources_clone {
            let (tachyon_handle, partition, old_fd) = {
                let mut guard = resource.lock().unwrap();
                match guard.deref_mut() {
                    VirtioKvmResource::Vm(vm) => (
                        vm.tachyon_handle,
                        vm.partition.clone(),
                        &mut vm.fd as *mut RawFd,
                    ),
                    VirtioKvmResource::Vcpu(vcpu) => (
                        vcpu.tachyon_handle,
                        vcpu.partition.clone(),
                        &mut vcpu.fd as *mut RawFd,
                    ),
                    _ => continue,
                }
            };

            let msg = Message {
                msg_type: TachyonOp::GetFileDescriptor as u32,
                request_id: 0,
                handle: tachyon_handle,
                status: 0,
                arg: 0,
                cmd: 0,
                resp_size: 0,
                body: Vec::new(),
                fds: None,
            };

            match partition.call(msg) {
                Ok(resp) => {
                    if let Some(mut fds) = resp.fds
                        && let Some(new_fd) = fds.pop()
                    {
                        debug!(
                            "virtio-kvm: Refreshed FD for handle 0x{:x}: {} -> {}",
                            tachyon_handle,
                            unsafe { *old_fd },
                            new_fd
                        );
                        unsafe {
                            libc::close(*old_fd);
                            *old_fd = new_fd;
                        }
                    }
                }
                Err(e) => {
                    error!("virtio-kvm: Failed to refresh FD for handle 0x{tachyon_handle:x}: {e}");
                }
            }
        }

        // 2. Refresh BAR Mappings
        let mappings_clone = {
            let mappings = self.mappings.lock().unwrap();
            mappings.clone()
        };

        let resources = self.resources.lock().unwrap();

        for (handle, mapping) in mappings_clone {
            let Some(resource) = resources.get(&handle) else {
                continue;
            };

            let (tachyon_handle, partition) = {
                let guard = resource.lock().unwrap();
                (guard.tachyon_handle(), guard.partition().clone())
            };

            let msg = Message {
                msg_type: TachyonOp::GetFileDescriptor as u32,
                request_id: 0,
                handle: tachyon_handle,
                status: 0,
                arg: 0,
                cmd: 0,
                resp_size: 0,
                body: Vec::new(),
                fds: None,
            };

            let resp = match partition.call(msg) {
                Ok(r) => r,
                Err(e) => {
                    error!(
                        "virtio-kvm: Failed to get new FD for BAR mapping at offset {:#x}: {e}",
                        mapping.phys_offset
                    );
                    continue;
                }
            };

            let fd = match resp.fds.and_then(|mut fds| fds.pop()) {
                Some(fd) => fd,
                None => {
                    error!(
                        "virtio-kvm: No FD returned for BAR mapping at offset {:#x}",
                        mapping.phys_offset
                    );
                    continue;
                }
            };

            let addr = unsafe {
                libc::mmap(
                    (self
                        .bar_mapping
                        .mapping
                        .as_ptr()
                        .wrapping_add(mapping.phys_offset as usize))
                        as *mut libc::c_void,
                    mapping.size as usize,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED | libc::MAP_FIXED,
                    fd,
                    0,
                )
            };

            if addr == libc::MAP_FAILED {
                error!(
                    "virtio-kvm: Failed to re-map BAR at offset {:#x} using new FD {}: {}",
                    mapping.phys_offset,
                    fd,
                    io::Error::last_os_error()
                );
            } else {
                debug!(
                    "virtio-kvm: Re-mapped BAR at offset {:#x} using new FD {}",
                    mapping.phys_offset, fd
                );
            }
        }
    }

    fn handle_request(
        &self,
        req: &VirtioKvmReq,
        head_index: u16,
        resp_addr: GuestAddress,
    ) -> Option<VirtioKvmResp> {
        let op = match Operation::try_from(req.operation) {
            Ok(op) => {
                debug!("!! virtio_kvm: handle_request: {op:#?}");
                op
            }
            _ => {
                debug!("!! virtio_kvm: unknown operation: {}", req.operation);
                return Some(VirtioKvmResp::from_errno(libc::EINVAL));
            }
        };

        match op {
            Operation::Open => Some(self.handle_open(req)),
            Operation::Close => Some(self.handle_close(req)),
            Operation::Ioctl => self.handle_ioctl(req, head_index, resp_addr),
            Operation::Kill => self.handle_kill(req),
            Operation::DeviceMmap => Some(self.handle_device_mmap(req)),
            Operation::DeviceMunmap => Some(self.handle_device_munmap(req)),
            Operation::MemoryFileCreate => Some(self.handle_memory_file_create(req)),
            Operation::MemoryFileDelete => Some(self.handle_memory_file_delete(req)),
            Operation::EventfdGet => Some(self.handle_eventfd_get(req)),
            Operation::EventfdPut => Some(self.handle_eventfd_put(req)),
            Operation::EventfdWrite => Some(self.handle_eventfd_write(req)),
            Operation::EventfdPoll => self.handle_eventfd_poll(head_index, resp_addr),
            Operation::FileIO => Some(self.handle_file_io(req)),
            Operation::Ready => Some(self.handle_ready(req)),
            Operation::SetRunNotify => Some(self.handle_set_run_notify(req)),
            Operation::SetL1Memslot => Some(self.handle_set_l1_memslot(req)),
            Operation::InvalidateL1Memslot => Some(self.handle_invalidate_l1_memslot(req)),
            Operation::L1FaultPoll => self.handle_l1_fault_poll(req, head_index, resp_addr),
            Operation::L1FaultAck => Some(self.handle_l1_fault_ack(req)),
            Operation::OpenVfioContainer => Some(self.handle_open_vfio_container(req)),
            Operation::OpenVfioGroup => Some(self.handle_open_vfio_group(req)),
            Operation::VfioGetGroups => Some(self.handle_vfio_get_groups(req)),
        }
    }

    fn process_queue(&mut self) -> result::Result<bool, Error> {
        let mut used_descs = false;
        let mem = self.mem.memory();
        loop {
            self.queue
                .disable_notification(&*mem)
                .map_err(Error::QueueAddUsed)?;

            while let Some(mut desc_chain) = self.queue.pop_descriptor_chain(&*mem) {
                let desc = desc_chain.next().ok_or(Error::DescriptorChainTooShort)?;

                if desc.is_write_only() {
                    return Err(Error::UnexpectedWriteOnlyDescriptor);
                }
                if desc.len() as usize != size_of::<VirtioKvmReq>() {
                    return Err(Error::InvalidRequest);
                }
                let req: VirtioKvmReq = mem.read_obj(desc.addr()).map_err(Error::GuestMemory)?;

                let head_index = desc_chain.head_index();
                let resp_addr = desc.addr().checked_add(desc.len().into()).unwrap();

                if let Some(resp) = self.handle_request(&req, head_index, resp_addr) {
                    debug!("!! virtio_kvm: resp: {resp:#?}");
                    // The response always follows the request in memory.
                    mem.write_obj(resp, resp_addr).map_err(Error::GuestMemory)?;

                    self.queue
                        .add_used(&*mem, head_index, size_of::<VirtioKvmResp>() as u32)
                        .map_err(Error::QueueAddUsed)?;
                    used_descs = true;
                }
            }

            if !self
                .queue
                .enable_notification(&*mem)
                .map_err(Error::QueueAddUsed)?
            {
                break;
            }
        }

        Ok(used_descs)
    }

    fn signal_used_queue(&mut self) -> result::Result<(), DeviceError> {
        if self
            .queue
            .needs_notification(&*self.mem.memory())
            .map_err(|e| DeviceError::FailedSignalingUsedQueue(io::Error::other(e)))?
        {
            self.interrupt_cb
                .trigger(VirtioInterruptType::Queue(0))
                .map_err(|e| {
                    error!("Failed to signal used queue: {e:?}");
                    DeviceError::FailedSignalingUsedQueue(e)
                })?;
        }
        Ok(())
    }

    fn run(
        &mut self,
        paused: &AtomicBool,
        paused_sync: &Barrier,
    ) -> result::Result<(), EpollHelperError> {
        let mut helper = EpollHelper::new(&self.kill_evt, &self.pause_evt)?;
        helper.add_event(self.queue_evt.as_raw_fd(), QUEUE_AVAIL_EVENT)?;
        helper.run(paused, paused_sync, self)?;

        Ok(())
    }
}

impl EpollHelperHandler for VirtioKvmEpollHandler {
    fn handle_event(
        &mut self,
        _helper: &mut EpollHelper,
        event: &epoll::Event,
    ) -> result::Result<(), EpollHelperError> {
        let ev_type = event.data as u16;
        match ev_type {
            QUEUE_AVAIL_EVENT => {
                self.queue_evt.read().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!("Failed to get queue event: {e:?}"))
                })?;
                let used_descs = self.process_queue().map_err(|e| {
                    debug!("!! virtio_kvm: process_queue failed: {e:?}");
                    EpollHelperError::HandleEvent(anyhow!("Failed to process queue : {e:?}"))
                })?;
                if used_descs {
                    debug!("!! virtio_kvm: needs_notification");
                    self.signal_used_queue().map_err(|e| {
                        EpollHelperError::HandleEvent(anyhow!("Failed to signal used queue: {e:?}"))
                    })?;
                }
            }
            _ => {
                return Err(EpollHelperError::HandleEvent(anyhow!(
                    "Unexpected event: {ev_type}"
                )));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub enum VirtioKvmResourceTypeState {
    System {
        #[serde(default)]
        partition_id: u64,
    },
    Vm {
        tachyon_handle: u64,
        shm_bar_offset: u64,
        #[serde(default)]
        partition_id: u64,
    },
    Vcpu {
        vcpu_id: u32,
        vm_handle: u64,
        tachyon_handle: u64,
        #[serde(default)]
        partition_id: u64,
    },
    Stats {
        parent_handle: u64,
        #[serde(default)]
        partition_id: u64,
    },
}

#[derive(Clone, Serialize, Deserialize)]
pub struct VirtioKvmResourceState {
    pub handle: u64,
    pub resource_type: VirtioKvmResourceTypeState,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EventfdState {
    pub ctx: u64,
    pub refs: u32,
    pub tachyon_handle: u64,
    #[serde(default)]
    pub partition_id: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KvmMemoryFileState {
    pub handle: u64,
    pub size: u64,
    pub phys_offset: u64,
    pub tachyon_handle: u64,
    #[serde(default)]
    pub partition_id: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KvmBarMappingState {
    pub handle: u64,
    pub phys_offset: u64,
    pub size: u64,
    pub device_offset: u64,
}

#[derive(Serialize, Deserialize)]
pub struct VirtioKvmState {
    pub avail_features: u64,
    pub acked_features: u64,
    pub next_handle_id: u64,
    pub resources: Vec<VirtioKvmResourceState>,
    pub eventfds: Vec<EventfdState>,
    pub mem_files: Vec<KvmMemoryFileState>,
    pub mappings: Vec<KvmBarMappingState>,
}

impl VirtioKvm {
    #[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
    pub fn new(
        socket_path: PathBuf,
        id: String,
        iommu: bool,
        seccomp_action: SeccompAction,
        exit_evt: EventFd,
        state: Option<VirtioKvmState>,
        _bar_region: Arc<MmapRegion<AtomicBitmap>>,
        bar_mapping: UserspaceMapping,
    ) -> io::Result<VirtioKvm> {
        let (avail_features, acked_features, paused) = if let Some(ref state) = state {
            info!("Restoring virtio-kvm {id}");
            (state.avail_features, state.acked_features, true)
        } else {
            if iommu {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "virtio-kvm device does not support IOMMU",
                ));
            }

            (1u64 << VIRTIO_F_VERSION_1, 0, false)
        };

        let resources = Arc::new(Mutex::new(HashMap::new()));
        let eventfds = Arc::new(Mutex::new(HashMap::new()));
        let fd_to_handle = Arc::new(Mutex::new(HashMap::new()));
        let mem_files = Arc::new(Mutex::new(HashMap::new()));
        let mappings = Arc::new(Mutex::new(HashMap::new()));

        let tachyon = TachyonConnection::new(socket_path);

        if let Some(ref state) = state {
            NEXT_HANDLE_ID.store(state.next_handle_id, Ordering::Relaxed);

            // 1. Reconstruct Memory Files
            for file_state in &state.mem_files {
                let partition = tachyon.get_partition(file_state.partition_id)?;
                let msg = Message {
                    msg_type: TachyonOp::GetFileDescriptor as u32,
                    request_id: 0,
                    handle: file_state.tachyon_handle,
                    status: 0,
                    arg: 0,
                    cmd: 0,
                    resp_size: 0,
                    body: Vec::new(),
                    fds: None,
                };
                let resp = partition.call(msg).map_err(|e| {
                    io::Error::other(format!("Failed to get FD for memory file: {e}"))
                })?;
                if resp.status != 0 {
                    return Err(io::Error::other(format!(
                        "Failed to get FD for memory file status={}",
                        resp.status
                    )));
                }
                let fd = resp
                    .fds
                    .and_then(|mut fds| fds.pop())
                    .ok_or_else(|| io::Error::other("No FD returned for memory file"))?;

                if file_state.size > 0 {
                    let addr = unsafe {
                        libc::mmap(
                            (bar_mapping
                                .mapping
                                .as_ptr()
                                .wrapping_add(file_state.phys_offset as usize))
                                as *mut libc::c_void,
                            file_state.size as usize,
                            libc::PROT_READ | libc::PROT_WRITE,
                            libc::MAP_SHARED | libc::MAP_FIXED,
                            fd,
                            0,
                        )
                    };
                    if addr == libc::MAP_FAILED {
                        unsafe { libc::close(fd) };
                        return Err(io::Error::last_os_error());
                    }
                }

                let file = KvmMemoryFile {
                    fd,
                    size: file_state.size,
                    phys_offset: file_state.phys_offset,
                    tachyon_handle: file_state.tachyon_handle,
                    partition,
                };
                mem_files.lock().unwrap().insert(file_state.handle, file);
            }

            // 2. Reconstruct Resources
            let mut vm_states = Vec::new();
            let mut vcpu_states = Vec::new();
            let mut stats_states = Vec::new();
            let mut system_states = Vec::new();

            for res_state in &state.resources {
                match &res_state.resource_type {
                    VirtioKvmResourceTypeState::System { .. } => system_states.push(res_state),
                    VirtioKvmResourceTypeState::Vm { .. } => vm_states.push(res_state),
                    VirtioKvmResourceTypeState::Vcpu { .. } => vcpu_states.push(res_state),
                    VirtioKvmResourceTypeState::Stats { .. } => stats_states.push(res_state),
                }
            }

            // Restore System
            for res_state in system_states {
                let partition_id = match &res_state.resource_type {
                    VirtioKvmResourceTypeState::System { partition_id } => *partition_id,
                    _ => 0,
                };
                let partition = tachyon.get_partition(partition_id)?;
                let system_res = VirtioKvmResource::new_system(partition).map_err(|e| {
                    io::Error::other(format!("Failed to create KVM system resource: {e}"))
                })?;
                resources
                    .lock()
                    .unwrap()
                    .insert(Handle(res_state.handle), Arc::new(Mutex::new(system_res)));
            }

            // Restore VMs
            for res_state in vm_states {
                if let VirtioKvmResourceTypeState::Vm {
                    tachyon_handle,
                    shm_bar_offset,
                    partition_id,
                } = &res_state.resource_type
                {
                    let partition = tachyon.get_partition(*partition_id)?;
                    let msg = Message {
                        msg_type: TachyonOp::GetFileDescriptor as u32,
                        request_id: 0,
                        handle: *tachyon_handle,
                        status: 0,
                        arg: 0,
                        cmd: 0,
                        resp_size: 0,
                        body: Vec::new(),
                        fds: None,
                    };
                    let resp = partition
                        .call(msg)
                        .map_err(|e| io::Error::other(format!("Failed to get FDs for VM: {e}")))?;
                    if resp.status != 0 {
                        return Err(io::Error::other(format!(
                            "Failed to get FDs for VM status={}",
                            resp.status
                        )));
                    }
                    let mut fds = resp
                        .fds
                        .ok_or_else(|| io::Error::other("No FDs returned for VM"))?;
                    if fds.len() < 2 {
                        for fd in fds {
                            unsafe { libc::close(fd) };
                        }
                        return Err(io::Error::other("Expected 2 FDs for VM (VM FD and SHM FD)"));
                    }
                    let vm_fd = fds.pop().unwrap();
                    let shm_fd = fds.pop().unwrap();

                    let vm = VirtioKvmVm {
                        fd: vm_fd,
                        shm_fd,
                        tachyon_handle: *tachyon_handle,
                        shm_bar_offset: Arc::new(AtomicU64::new(*shm_bar_offset)),
                        partition,
                    };
                    resources.lock().unwrap().insert(
                        Handle(res_state.handle),
                        Arc::new(Mutex::new(VirtioKvmResource::Vm(vm))),
                    );
                }
            }

            // Restore VCPUs
            for res_state in vcpu_states {
                if let VirtioKvmResourceTypeState::Vcpu {
                    vcpu_id,
                    vm_handle,
                    tachyon_handle,
                    partition_id,
                } = &res_state.resource_type
                {
                    let partition = tachyon.get_partition(*partition_id)?;
                    let msg = Message {
                        msg_type: TachyonOp::GetFileDescriptor as u32,
                        request_id: 0,
                        handle: *tachyon_handle,
                        status: 0,
                        arg: 0,
                        cmd: 0,
                        resp_size: 0,
                        body: Vec::new(),
                        fds: None,
                    };
                    let resp = partition
                        .call(msg)
                        .map_err(|e| io::Error::other(format!("Failed to get FD for VCPU: {e}")))?;
                    if resp.status != 0 {
                        return Err(io::Error::other(format!(
                            "Failed to get FD for VCPU status={}",
                            resp.status
                        )));
                    }
                    let vcpu_fd = resp
                        .fds
                        .and_then(|mut fds| fds.pop())
                        .ok_or_else(|| io::Error::other("No FD returned for VCPU"))?;

                    let vcpu = VirtioKvmVcpu {
                        fd: vcpu_fd,
                        vcpu_id: *vcpu_id,
                        vm_handle: Handle(*vm_handle),
                        tachyon_handle: *tachyon_handle,
                        partition,
                    };
                    resources.lock().unwrap().insert(
                        Handle(res_state.handle),
                        Arc::new(Mutex::new(VirtioKvmResource::Vcpu(vcpu))),
                    );
                }
            }

            // Restore Stats
            for res_state in stats_states {
                if let VirtioKvmResourceTypeState::Stats {
                    parent_handle,
                    partition_id,
                } = &res_state.resource_type
                {
                    let parent_tachyon_handle = {
                        let resources_guard = resources.lock().unwrap();
                        let parent_res =
                            resources_guard
                                .get(&Handle(*parent_handle))
                                .ok_or_else(|| {
                                    io::Error::other(format!(
                                        "Parent resource 0x{parent_handle:x} for Stats not found"
                                    ))
                                })?;
                        let guard = parent_res.lock().unwrap();
                        match guard.deref() {
                            VirtioKvmResource::Vm(vm) => vm.tachyon_handle,
                            VirtioKvmResource::Vcpu(vcpu) => vcpu.tachyon_handle,
                            _ => {
                                return Err(io::Error::other(
                                    "Invalid parent resource type for Stats",
                                ));
                            }
                        }
                    };

                    let partition = tachyon.get_partition(*partition_id)?;
                    let msg = Message {
                        msg_type: TachyonOp::Ioctl as u32,
                        request_id: 0,
                        handle: parent_tachyon_handle,
                        status: 0,
                        arg: 0,
                        cmd: kvm::KVM_GET_STATS_FD,
                        resp_size: 0,
                        body: Vec::new(),
                        fds: None,
                    };
                    let resp = partition.call(msg).map_err(|e| {
                        io::Error::other(format!("Failed to get stats FD from Tachyon: {e}"))
                    })?;
                    if resp.status != 0 {
                        return Err(io::Error::other(format!(
                            "Failed to get stats FD status={}",
                            resp.status
                        )));
                    }
                    let stats_fd = resp
                        .fds
                        .and_then(|mut fds| fds.pop())
                        .ok_or_else(|| io::Error::other("No FD returned for Stats"))?;

                    let stats = VirtioKvmStats {
                        fd: stats_fd,
                        parent_handle: Handle(*parent_handle),
                        partition,
                    };
                    resources.lock().unwrap().insert(
                        Handle(res_state.handle),
                        Arc::new(Mutex::new(VirtioKvmResource::Stats(stats))),
                    );
                }
            }

            // 3. Reconstruct Eventfds
            for ev_state in &state.eventfds {
                let partition = tachyon.get_partition(ev_state.partition_id)?;
                let msg = Message::get_file(ev_state.tachyon_handle);
                let resp = partition
                    .call(msg)
                    .map_err(|e| io::Error::other(format!("Failed to get FD for eventfd: {e}")))?;
                if resp.status != 0 {
                    return Err(io::Error::other(format!(
                        "Failed to get FD for eventfd status={}",
                        resp.status
                    )));
                }
                let fd = resp
                    .fds
                    .and_then(|mut fds| fds.pop())
                    .ok_or_else(|| io::Error::other("No FD returned for eventfd"))?;

                let eventfd = unsafe { EventFd::from_raw_fd(fd) };
                let info = EventfdInfo {
                    eventfd,
                    refs: ev_state.refs,
                    tachyon_handle: ev_state.tachyon_handle,
                    partition,
                };
                eventfds.lock().unwrap().insert(ev_state.ctx, info);
            }

            // 4. Reconstruct Mappings
            for map_state in &state.mappings {
                let fd = {
                    let resources_guard = resources.lock().unwrap();
                    let resource =
                        resources_guard
                            .get(&Handle(map_state.handle))
                            .ok_or_else(|| {
                                io::Error::other(format!(
                                    "Resource 0x{:x} for mapping not found",
                                    map_state.handle
                                ))
                            })?;
                    let guard = resource.lock().unwrap();
                    match guard.deref() {
                        VirtioKvmResource::Vm(vm) => vm.shm_fd,
                        _ => guard.as_raw_fd(),
                    }
                };

                let addr = unsafe {
                    libc::mmap(
                        (bar_mapping
                            .mapping
                            .as_ptr()
                            .wrapping_add(map_state.phys_offset as usize))
                            as *mut libc::c_void,
                        map_state.size as usize,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_SHARED | libc::MAP_FIXED,
                        fd,
                        map_state.device_offset as libc::off_t,
                    )
                };
                if addr == libc::MAP_FAILED {
                    return Err(io::Error::last_os_error());
                }

                let mapping = KvmBarMapping {
                    phys_offset: map_state.phys_offset,
                    size: map_state.size,
                    device_offset: map_state.device_offset,
                };
                mappings
                    .lock()
                    .unwrap()
                    .insert(Handle(map_state.handle), mapping);
            }
        }

        Ok(VirtioKvm {
            common: VirtioCommon {
                device_type: VirtioDeviceType::Kvm as u32,
                queue_sizes: QUEUE_SIZES.to_vec(),
                paused_sync: Some(Arc::new(Barrier::new(2))),
                avail_features,
                acked_features,
                min_queues: 1,
                paused: Arc::new(AtomicBool::new(paused)),
                ..Default::default()
            },
            id,
            seccomp_action,
            exit_evt,
            resources,
            eventfds,
            fd_to_handle,
            mem_files,
            mappings,
            _bar_region,
            bar_mapping,
            poll_fd: None,
            poll_thread: None,
            poll_work_sender: None,
            poll_wakeup_fd: None,
            tachyon,
        })
    }

    fn state(&self) -> VirtioKvmState {
        let resources_guard = self.resources.lock().unwrap();
        let mut resources = Vec::new();
        for (handle, resource_lock) in resources_guard.iter() {
            let resource_guard = resource_lock.lock().unwrap();
            let resource_type = match resource_guard.deref() {
                VirtioKvmResource::System(sys) => VirtioKvmResourceTypeState::System {
                    partition_id: sys.partition_id(),
                },
                VirtioKvmResource::Vm(vm) => VirtioKvmResourceTypeState::Vm {
                    tachyon_handle: vm.tachyon_handle,
                    shm_bar_offset: vm.shm_bar_offset.load(Ordering::Acquire),
                    partition_id: vm.partition_id(),
                },
                VirtioKvmResource::Vcpu(vcpu) => VirtioKvmResourceTypeState::Vcpu {
                    vcpu_id: vcpu.vcpu_id,
                    vm_handle: vcpu.vm_handle.0,
                    tachyon_handle: vcpu.tachyon_handle,
                    partition_id: vcpu.partition_id(),
                },
                VirtioKvmResource::Stats(stats) => VirtioKvmResourceTypeState::Stats {
                    parent_handle: stats.parent_handle.0,
                    partition_id: stats.partition_id(),
                },
                VirtioKvmResource::VfioContainer(_)
                | VirtioKvmResource::VfioGroup(_)
                | VirtioKvmResource::VfioDevice(_) => todo!("Implement save/restore for VFIO."),
            };
            resources.push(VirtioKvmResourceState {
                handle: handle.0,
                resource_type,
            });
        }

        let eventfds_guard = self.eventfds.lock().unwrap();
        let mut eventfds = Vec::new();
        for (ctx, info) in eventfds_guard.iter() {
            eventfds.push(EventfdState {
                ctx: *ctx,
                refs: info.refs,
                tachyon_handle: info.tachyon_handle,
                partition_id: info.partition.partition_id(),
            });
        }

        let mem_files_guard = self.mem_files.lock().unwrap();
        let mut mem_files = Vec::new();
        for (handle, file) in mem_files_guard.iter() {
            mem_files.push(KvmMemoryFileState {
                handle: *handle,
                size: file.size,
                phys_offset: file.phys_offset,
                tachyon_handle: file.tachyon_handle,
                partition_id: file.partition.partition_id(),
            });
        }

        let mappings_guard = self.mappings.lock().unwrap();
        let mut mappings = Vec::new();
        for (handle, mapping) in mappings_guard.iter() {
            mappings.push(KvmBarMappingState {
                handle: handle.0,
                phys_offset: mapping.phys_offset,
                size: mapping.size,
                device_offset: mapping.device_offset,
            });
        }

        VirtioKvmState {
            avail_features: self.common.avail_features,
            acked_features: self.common.acked_features,
            next_handle_id: NEXT_HANDLE_ID.load(Ordering::Relaxed),
            resources,
            eventfds,
            mem_files,
            mappings,
        }
    }

    #[cfg(fuzzing)]
    pub fn wait_for_epoll_threads(&mut self) {
        self.common.wait_for_epoll_threads();
    }
}

impl Drop for VirtioKvm {
    fn drop(&mut self) {
        // Ignore the result because there is nothing we can do about it.
        let _ = self.exit_evt.write(1);

        self.common.wait_for_epoll_threads();

        if let Some(sender) = self.poll_work_sender.take() {
            let _ = sender.send(PollWork::Stop);
        }
        if let Some(poll_wakeup_fd) = self.poll_wakeup_fd.take() {
            poll_wakeup_fd.write(1).unwrap();
        }
        if let Some(poll_thread) = self.poll_thread.take() {
            poll_thread.join().unwrap();
        }

        if let Some(poll_fd) = self.poll_fd.take() {
            unsafe { libc::close(poll_fd) };
        }
    }
}

impl VirtioDevice for VirtioKvm {
    fn device_type(&self) -> u32 {
        self.common.device_type
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.common.queue_sizes
    }

    fn features(&self) -> u64 {
        self.common.avail_features
    }

    fn ack_features(&mut self, value: u64) {
        self.common.ack_features(value);
    }

    fn get_bars(&self) -> Vec<PciBarConfiguration> {
        vec![
            PciBarConfiguration::new(
                VIRTIO_KVM_BAR_INDEX,
                self.bar_mapping.mapping.size() as u64,
                PciBarRegionType::Memory64BitRegion,
                PciBarPrefetchable::Prefetchable,
            )
            .set_address(self.bar_mapping.addr.raw_value()),
        ]
    }

    fn activate(&mut self, context: ActivationContext) -> ActivateResult {
        debug!("!! virtio_kvm: activate");
        let ActivationContext {
            mem,
            interrupt_cb,
            mut queues,
            device_status,
            ..
        } = context;
        self.common.activate(&queues, interrupt_cb.clone())?;
        let (kill_evt, pause_evt) = self.common.dup_eventfds()?;

        let (_, queue, queue_evt) = queues.remove(0);
        let queue = QueueSync::from(queue);

        let poll_fd = epoll::create(true).unwrap();
        let poll_wakeup_fd = EventFd::new(libc::EFD_CLOEXEC).unwrap();
        self.poll_fd = Some(poll_fd);

        // Register restored eventfds to the new poll_fd and populate fd_to_handle
        {
            let eventfds = self.eventfds.lock().unwrap();
            let mut fd_to_handle = self.fd_to_handle.lock().unwrap();
            for (ctx, info) in eventfds.iter() {
                let fd = info.eventfd.as_raw_fd();
                let event = epoll::Event::new(epoll::Events::EPOLLIN, fd as u64);
                if let Err(e) = epoll::ctl(poll_fd, epoll::ControlOptions::EPOLL_CTL_ADD, fd, event)
                {
                    error!("Failed to add restored eventfd to epoll: {e}");
                    return Err(ActivateError::BadActivate);
                }
                fd_to_handle.insert(fd, *ctx);
            }
        }

        let (sender, poll_work_receiver) = mpsc::channel();
        self.poll_work_sender = Some(sender.clone());

        let poll_worker_interrupt_cb = interrupt_cb.clone();
        let poll_worker_mem = mem.clone();
        let poll_worker_queue = queue.clone();
        let poll_worker_wakeup_fd = poll_wakeup_fd.try_clone().unwrap();
        let poll_worker_fd_to_handle = self.fd_to_handle.clone();
        self.poll_wakeup_fd = Some(poll_wakeup_fd.try_clone().unwrap());
        self.poll_thread = Some(
            thread::Builder::new()
                .name("virtio-kvm-poll".to_string())
                .spawn(move || {
                    poll_worker_run(
                        poll_work_receiver,
                        poll_fd,
                        poll_worker_wakeup_fd,
                        poll_worker_mem,
                        poll_worker_queue,
                        poll_worker_interrupt_cb,
                        poll_worker_fd_to_handle,
                    );
                })
                .map_err(ActivateError::ThreadSpawn)?,
        );

        let mut handler = VirtioKvmEpollHandler {
            mem,
            queue,
            interrupt_cb: interrupt_cb.clone(),
            queue_evt,
            kill_evt,
            pause_evt,
            access_platform: self.common.access_platform.clone(),
            resources: self.resources.clone(),
            eventfds: self.eventfds.clone(),
            fd_to_handle: self.fd_to_handle.clone(),
            mem_files: self.mem_files.clone(),
            mappings: self.mappings.clone(),
            poll_fd,
            bar_mapping: self.bar_mapping.clone(),
            poll_work_sender: sender,
            tachyon: self.tachyon.clone(),
        };

        // Attach live-update notification handlers to all existing partition connections (e.g. after restore)
        self.tachyon.prepare_all_connections(&handler);

        let paused = self.common.paused.clone();
        let paused_sync = self.common.paused_sync.clone();

        self.common.spawn_worker(
            &self.id,
            &self.seccomp_action,
            Thread::VirtioKvm,
            &self.exit_evt,
            device_status.clone(),
            interrupt_cb,
            move || handler.run(&paused, paused_sync.as_ref().unwrap()),
        )?;

        event!("virtio-device", "activated", "id", &self.id);

        Ok(())
    }

    fn reset(&mut self) {
        self.common.reset();
        event!("virtio-device", "reset", "id", &self.id);
    }

    fn set_access_platform(&mut self, access_platform: Arc<dyn AccessPlatform>) {
        self.common.set_access_platform(access_platform);
    }
}

impl Pausable for VirtioKvm {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        // Send Pause RPC to all active Tachyon partitions to stop VCPU worker threads from running KVM_RUN
        self.tachyon.pause_all();

        // Wake up the poll worker thread so that any active EventfdPoll request
        // is cleanly completed before we take a snapshot.
        if let Some(poll_wakeup_fd) = &self.poll_wakeup_fd {
            let _ = poll_wakeup_fd.write(1);
        }

        self.common.pause()
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        self.common.resume()?;

        // Send Unpause RPC to all active Tachyon partitions to resume VCPU worker threads
        self.tachyon.unpause_all();

        Ok(())
    }
}

impl Snapshottable for VirtioKvm {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> result::Result<Snapshot, MigratableError> {
        Snapshot::new_from_state(&self.state())
    }
}

impl Transportable for VirtioKvm {}
impl Migratable for VirtioKvm {}
