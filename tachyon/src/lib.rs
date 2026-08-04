// Copyright 2026 Google LLC
//
// SPDX-License-Identifier: Apache-2.0

pub mod kvm;
pub mod rpc;
pub mod state;
pub mod vfio;

use std::collections::HashMap;
use std::io::Write;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use log::{debug, error, trace, warn};
use rpc::Message;
use vmm_sys_util::ioctl;

use crate::kvm::*;

#[macro_export]
macro_rules! debug_panic_or_error {
    ($($arg:tt)+) => {
        if cfg!(debug_assertions) {
            panic!($($arg)+);
        } else {
            ::log::error!($($arg)+);
        }
    };
}

/// Manages the preservation and retrieval of file descriptors across
/// process updates or host reboots (kexec). The registry ensures that
/// resources like memfds, eventfds, and sockets can be re-attached
/// to their corresponding handles after restoration.
struct LuoRegistry {
    id_to_fd: HashMap<String, RawFd>,
    preserved_fds: Vec<RawFd>,
}

impl LuoRegistry {
    fn new() -> Self {
        LuoRegistry {
            id_to_fd: HashMap::new(),
            preserved_fds: Vec::new(),
        }
    }

    fn preserve(&mut self, fd: RawFd) -> String {
        let index = self.preserved_fds.len();
        self.preserved_fds.push(fd);
        index.to_string()
    }

    fn retrieve(&self, id: &str) -> Option<RawFd> {
        if let Ok(index) = id.parse::<usize>() {
            return self.preserved_fds.get(index).copied();
        }
        self.id_to_fd.get(id).copied()
    }

    fn set_fds(&mut self, fds: Vec<RawFd>) {
        self.preserved_fds = fds;
    }

    fn get_fds(&self) -> Vec<RawFd> {
        self.preserved_fds.clone()
    }
}

static LUO: Mutex<Option<LuoRegistry>> = Mutex::new(None);

fn with_luo<F, R>(f: F) -> R
where
    F: FnOnce(&mut LuoRegistry) -> R,
{
    let mut lock = LUO.lock().unwrap();
    if lock.is_none() {
        *lock = Some(LuoRegistry::new());
    }
    f(lock.as_mut().unwrap())
}

pub fn luo_preserve(fd: RawFd) -> String {
    with_luo(|luo| luo.preserve(fd))
}

pub fn luo_retrieve(id: &str) -> Option<RawFd> {
    with_luo(|luo| {
        luo.retrieve(id).map(|fd| {
            // Duplicate the FD so the caller can safely take ownership and close it on Drop.
            let new_fd = unsafe { libc::dup(fd) };
            if new_fd < 0 {
                panic!("Failed to dup FD in luo_retrieve");
            }
            warn!(
                "luo_retrieve: id={}, original_fd={}, new_fd={}",
                id, fd, new_fd
            );
            new_fd
        })
    })
}

pub fn luo_set_fds(fds: Vec<RawFd>) {
    with_luo(|luo| luo.set_fds(fds));
}

pub fn luo_get_fds() -> Vec<RawFd> {
    with_luo(|luo| luo.get_fds())
}

pub fn luo_preserve_with_id(id: &str, fd: RawFd) {
    with_luo(|luo| {
        luo.id_to_fd.insert(id.to_string(), fd);
    });
}

static NEXT_HANDLE_ID: AtomicU64 = AtomicU64::new(0xa000_0000_a000_0000);

pub const MAX_VCPUS: usize = 1024;
pub const DEFAULT_RPC_THREADS: usize = 4;

pub const STATE_IDLE: u32 = 0x0;
pub const STATE_RUN_REQUESTED: u32 = 0x1;
pub const STATE_COMPLETED: u32 = 0x2;
pub const STATE_MASK: u32 = 0xf;

pub const FLAG_HOST_POLLING: u32 = 0x10;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
pub enum Operation {
    Open = 0,
    Close = 1,
    Ioctl = 2,
    MemoryFileCreate = 3,
    GetFileDescriptor = 4,
    Interrupt = 5,
    Save = 6,
    EventfdGet = 7,
    EventfdWrite = 8,
    Ready = 9,
    Pause = 10,
    Unpause = 11,
    LiveUpdateSave = 12,
    LiveUpdateRestore = 13,
    NotifyLiveUpdate = 14,
    OpenVfioContainer = 15,
    OpenVfioGroup = 16,
    Unknown = u32::MAX,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum HandleType {
    KvmDevice = 1,
    MemoryFile = 2,
    Vm = 3,
    Vcpu = 4,
    Eventfd = 5,
    RpcServer = 6,
    RpcChannel = 7,
    VfioContainer = 8,
    VfioGroup = 9,
    VfioDevice = 10,
}

#[repr(C)]
struct MsgHeader {
    msg_type: u32,
    size: u32,
}

impl From<u32> for Operation {
    fn from(v: u32) -> Self {
        match v {
            0 => Operation::Open,
            1 => Operation::Close,
            2 => Operation::Ioctl,
            3 => Operation::MemoryFileCreate,
            4 => Operation::GetFileDescriptor,
            5 => Operation::Interrupt,
            6 => Operation::Save,
            7 => Operation::EventfdGet,
            8 => Operation::EventfdWrite,
            9 => Operation::Ready,
            10 => Operation::Pause,
            11 => Operation::Unpause,
            12 => Operation::LiveUpdateSave,
            13 => Operation::LiveUpdateRestore,
            14 => Operation::NotifyLiveUpdate,
            15 => Operation::OpenVfioContainer,
            16 => Operation::OpenVfioGroup,
            _ => Operation::Unknown,
        }
    }
}

pub trait HandleOps: Send + Sync {
    fn as_any(&self) -> &dyn std::any::Any;

    fn handle_request(
        &self,
        handle: &Handle,
        system: &Arc<System>,
        msg: &Message,
        channel: &Arc<rpc::Channel>,
    ) -> Option<Message>;

    fn cleanup(&self, _handle: &Handle, _system: &Arc<System>) {}

    fn save_state(
        &self,
        _handle: &Handle,
        _system: &Arc<System>,
        _writer: &mut dyn Write,
    ) -> Result<(), std::io::Error> {
        Ok(())
    }

    fn load_state(
        _system: &Arc<System>,
        _state: &[u8],
        _channel: &Arc<rpc::Channel>,
    ) -> Result<Arc<Handle>, std::io::Error>
    where
        Self: Sized,
    {
        unimplemented!()
    }

    fn get_type(&self) -> HandleType;
}

pub struct Handle {
    id: u64,
    fd: Option<OwnedFd>,
    ops: Arc<dyn HandleOps>,
}

#[derive(Debug)]
enum VcpuWork {
    Run(Message),
    Pause,
    Resume,
    Stop,
}

struct ShmEntryPtr(*mut PerVcpuState);
unsafe impl Send for ShmEntryPtr {}
unsafe impl Sync for ShmEntryPtr {}

struct VcpuWorker {
    sender: std::sync::mpsc::Sender<VcpuWork>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl VcpuWorker {
    /// The main execution loop for a Virtual CPU.
    ///
    /// This worker manages the lifecycle of a vCPU, alternating between
    /// busy-polling shared memory for run requests and blocking in the kernel
    /// via KVM_RUN. It also handles asynchronous commands like pausing and
    /// RPC-based execution.
    fn run(
        work_receiver: std::sync::mpsc::Receiver<VcpuWork>,
        channel: Arc<rpc::Channel>,
        vcpu_fd: RawFd,
        shm_entry_ptr: ShmEntryPtr,
    ) {
        let shm_entry: &mut PerVcpuState = unsafe { &mut *shm_entry_ptr.0 };
        debug!("VcpuWorker thread starting for fd={}", vcpu_fd);

        let sigset = Self::setup_signal_mask(vcpu_fd);

        let mut paused = false;
        loop {
            if paused {
                match work_receiver.recv() {
                    Ok(VcpuWork::Resume) => {
                        debug!("VcpuWorker: Resuming fd={}", vcpu_fd);
                        paused = false;
                    }
                    Ok(VcpuWork::Stop) => return,
                    _ => continue,
                }
            }

            if let Some(work) = Self::poll_for_work(&work_receiver) {
                match work {
                    VcpuWork::Run(req) => {
                        Self::do_run(&vcpu_fd, &channel, &sigset, &req);
                    }
                    VcpuWork::Pause => {
                        debug!("VcpuWorker: Paused during polling fd={}", vcpu_fd);
                        paused = true;
                        continue;
                    }
                    VcpuWork::Resume => (),
                    VcpuWork::Stop => return,
                }
            }

            if paused {
                continue;
            }

            match Self::wait_for_run_request(
                shm_entry,
                &work_receiver,
                &vcpu_fd,
                &channel,
                &sigset,
                &mut paused,
            ) {
                Ok(true) => {
                    Self::execute_kvm_run(vcpu_fd, shm_entry, &sigset);
                    continue;
                }
                Ok(false) => (),
                Err(()) => return,
            }

            if paused {
                continue;
            }

            // Sleep until Ready or RPC work
            std::thread::park();

            // Check if we were unparked for RPC work
            while let Ok(work) = work_receiver.try_recv() {
                match work {
                    VcpuWork::Run(req) => {
                        Self::do_run(&vcpu_fd, &channel, &sigset, &req);
                    }
                    VcpuWork::Pause => {
                        debug!("VcpuWorker: Paused during sleep fd={}", vcpu_fd);
                        paused = true;
                    }
                    VcpuWork::Resume => {
                        paused = false;
                    }
                    VcpuWork::Stop => return,
                }
            }
        }
    }

    /// Configures the signal mask to block SIGUSR2 normally but allow it
    /// to be delivered during KVM_RUN for interrupts.
    fn setup_signal_mask(vcpu_fd: RawFd) -> libc::sigset_t {
        let mut sigset: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut sigset);
            libc::sigaddset(&mut sigset, libc::SIGUSR2);
            libc::pthread_sigmask(libc::SIG_BLOCK, &sigset, std::ptr::null_mut());
        }

        let kvm_sigmask = kvm::kvm_signal_mask {
            len: 8,
            sigset: (!((1u64) << (libc::SIGUSR2 - 1))).to_le_bytes(),
        };

        unsafe {
            let _ = ioctl::ioctl_with_ptr(&vcpu_fd, kvm::KVM_SET_SIGNAL_MASK, &kvm_sigmask);
        }
        sigset
    }

    /// Busy-polls the shared memory state for a configured duration.
    /// Returns Ok(true) if a RUN request was observed, Ok(false) if it should sleep,
    /// and Err(()) if the worker should stop.
    fn wait_for_run_request(
        shm_entry: &PerVcpuState,
        work_receiver: &std::sync::mpsc::Receiver<VcpuWork>,
        vcpu_fd: &RawFd,
        channel: &Arc<rpc::Channel>,
        sigset: &libc::sigset_t,
        paused: &mut bool,
    ) -> Result<bool, ()> {
        shm_entry
            .state
            .fetch_or(FLAG_HOST_POLLING, Ordering::Release);

        let mut start = std::time::Instant::now();
        while start.elapsed() < std::time::Duration::from_millis(10) {
            let current_state = shm_entry.state.load(Ordering::Acquire);
            if (current_state & STATE_MASK) == STATE_RUN_REQUESTED {
                return Ok(true);
            }
            // Ensure FLAG_HOST_POLLING is set if the guest cleared it (e.g. after a prior run)
            if (current_state & STATE_MASK) == STATE_IDLE
                && (current_state & FLAG_HOST_POLLING) == 0
            {
                shm_entry
                    .state
                    .fetch_or(FLAG_HOST_POLLING, Ordering::Release);
            }
            if let Ok(work) = work_receiver.try_recv() {
                match work {
                    VcpuWork::Run(req) => {
                        Self::do_run(vcpu_fd, channel, sigset, &req);
                    }
                    VcpuWork::Pause => {
                        *paused = true;
                        return Ok(false);
                    }
                    VcpuWork::Resume => (),
                    VcpuWork::Stop => return Err(()),
                }
                start = std::time::Instant::now();
                shm_entry
                    .state
                    .fetch_or(FLAG_HOST_POLLING, Ordering::Release);
            }
            std::hint::spin_loop();
        }

        // Prepare to Sleep
        shm_entry
            .state
            .fetch_and(!FLAG_HOST_POLLING, Ordering::Release);

        // Critical Race Check: one last look before confirming we'll sleep
        let final_check = shm_entry.state.load(Ordering::Acquire);
        Ok((final_check & STATE_MASK) == STATE_RUN_REQUESTED)
    }

    /// Checks for RPC work without blocking.
    fn poll_for_work(work_receiver: &std::sync::mpsc::Receiver<VcpuWork>) -> Option<VcpuWork> {
        work_receiver.try_recv().ok()
    }

    /// Executes the KVM_RUN ioctl and updates the shared memory state
    /// with the result.
    fn execute_kvm_run(vcpu_fd: RawFd, shm_entry: &mut PerVcpuState, sigset: &libc::sigset_t) {
        trace!("VcpuWorker: KVM_RUN (polling) on fd={}", vcpu_fd);
        let ret = unsafe { libc::ioctl(vcpu_fd, kvm::KVM_RUN as _, 0) };
        let status = if ret < 0 {
            -std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            ret
        };
        shm_entry.status = status;

        // Consume any pending SIGUSR2 used to kick the vCPU
        let timeout = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        unsafe {
            if libc::sigtimedwait(sigset, std::ptr::null_mut(), &timeout) > 0 {
                trace!("VcpuWorker: Consumed pending SIGUSR2 on fd={}", vcpu_fd);
            }
        }

        trace!("VcpuWorker: status fd={} status={}", vcpu_fd, status);
        let mut current = shm_entry.state.load(Ordering::Acquire);
        loop {
            let next = (current & !STATE_MASK) | STATE_COMPLETED;
            match shm_entry.state.compare_exchange_weak(
                current,
                next,
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
    }

    fn do_run(
        vcpu_fd: &RawFd,
        channel: &Arc<rpc::Channel>,
        sigset: &libc::sigset_t,
        req: &Message,
    ) {
        trace!("VcpuWorker: KVM_RUN (RPC) on fd={}", vcpu_fd);
        // SAFETY: KVM_RUN ioctl
        let ret = unsafe { libc::ioctl(*vcpu_fd, kvm::KVM_RUN as _, 0) };

        let mut resp = Message {
            msg_type: req.msg_type,
            request_id: req.request_id,
            handle: req.handle,
            status: 0,
            arg: 0,
            cmd: req.cmd,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };

        if ret < 0 {
            let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            trace!(
                "VcpuWorker: KVM_RUN failed on fd={}: errno={}",
                vcpu_fd, err
            );
            resp.status = err as u64;
        } else {
            trace!("VcpuWorker: KVM_RUN success on fd={}", vcpu_fd);
            resp.arg = ret as u64;
        }

        // Consume any pending SIGUSR2
        let timeout = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        unsafe {
            if libc::sigtimedwait(sigset, std::ptr::null_mut(), &timeout) > 0 {
                trace!("VcpuWorker: Consumed pending SIGUSR2 on fd={}", vcpu_fd);
            }
        }

        if let Err(e) = channel.send(&resp) {
            error!("VcpuWorker failed to send response: {:?}", e);
        }
    }

    fn new(vcpu_fd: RawFd, channel: Arc<rpc::Channel>, shm_entry: *mut PerVcpuState) -> Self {
        let (work_sender, work_receiver) = std::sync::mpsc::channel();
        let shm_entry_ptr = ShmEntryPtr(shm_entry);

        // Block SIGUSR2 in the parent thread so the child thread inherits the mask.
        let mut sigset: libc::sigset_t = unsafe { std::mem::zeroed() };
        let mut oldset: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut sigset);
            libc::sigaddset(&mut sigset, libc::SIGUSR2);
            libc::pthread_sigmask(libc::SIG_BLOCK, &sigset, &mut oldset);
        }

        let thread_name = format!("vcpu-{}", vcpu_fd);
        let thread = std::thread::Builder::new()
            .name(thread_name)
            .spawn(move || {
                Self::run(work_receiver, channel, vcpu_fd, shm_entry_ptr);
            })
            .expect("Failed to spawn VcpuWorker thread");

        unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &oldset, std::ptr::null_mut());
        }

        VcpuWorker {
            sender: work_sender,
            thread: Some(thread),
        }
    }

    fn kick(&self) {
        if let Some(thread) = self.thread.as_ref() {
            debug!("VcpuWorker: Kicking thread {:?}", thread.thread().id());
            use std::os::unix::thread::JoinHandleExt;
            unsafe {
                libc::pthread_kill(thread.as_pthread_t() as _, libc::SIGUSR2);
            }
        }
    }

    fn unpark(&self) {
        if let Some(thread) = self.thread.as_ref() {
            thread.thread().unpark();
        }
    }

    fn pause(&self) {
        let _ = self.sender.send(VcpuWork::Pause);
        self.kick();
        self.unpark();
    }

    fn resume(&self) {
        let _ = self.sender.send(VcpuWork::Resume);
        self.unpark();
    }

    fn stop(&mut self) {
        let _ = self.sender.send(VcpuWork::Stop);
        self.kick();
        self.unpark();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for VcpuWorker {
    fn drop(&mut self) {
        self.stop();
    }
}

impl Handle {
    /// Creates a new resource handle.
    ///
    /// If an `id` is provided (e.g., during state restoration), the global
    /// ID counter is updated to ensure uniqueness for subsequent allocations.
    /// Otherwise, a new unique ID is automatically assigned.
    pub fn new(id: Option<u64>, fd: Option<RawFd>, ops: Arc<dyn HandleOps>) -> Arc<Self> {
        let final_id = match id {
            Some(id) => {
                let mut next = NEXT_HANDLE_ID.load(Ordering::SeqCst);
                while id >= next {
                    match NEXT_HANDLE_ID.compare_exchange(
                        next,
                        id + 1,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    ) {
                        Ok(_) => break,
                        Err(actual) => next = actual,
                    }
                }
                id
            }
            None => NEXT_HANDLE_ID.fetch_add(1, Ordering::SeqCst),
        };
        trace!("Creating Handle id=0x{:x}, fd={:?}", final_id, fd);
        Arc::new(Handle {
            id: final_id,
            fd: fd.map(|f| unsafe { OwnedFd::from_raw_fd(f) }),
            ops,
        })
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn fd(&self) -> Option<RawFd> {
        self.fd.as_ref().map(OwnedFd::as_raw_fd)
    }

    pub fn get_fd_message(&self, msg: &Message) -> Message {
        debug!(
            "Handle::get_fd_message: id=0x{:x}, fd={:?}",
            self.id, self.fd
        );
        Message {
            msg_type: msg.msg_type,
            request_id: msg.request_id,
            handle: msg.handle,
            status: 0,
            arg: 0,
            cmd: msg.cmd,
            resp_size: 0,
            body: Vec::new(),
            fds: self.fd.as_ref().map(|fd| vec![fd.as_raw_fd()]),
        }
    }

    /// Proxies an ioctl request to the underlying file descriptor.
    ///
    /// This method abstracts over the complexity of passing either simple
    /// numeric arguments or pointers to complex data structures (bodies)
    /// to the kernel. It ensures that response data is correctly captured
    /// from the kernel and returned in the response message.
    pub fn ioctl(&self, req: &Message, longarg: bool) -> Message {
        let fd = self.fd.as_ref().expect("Handle missing FD");
        let request = req.cmd;

        trace!(
            "Handle::ioctl: id=0x{:x}, fd={:?}, req=0x{:x}, arg=0x{:x}, body_len={}, resp_size={}",
            self.id,
            fd.as_raw_fd(),
            request,
            req.arg,
            req.body.len(),
            req.resp_size
        );

        let mut resp = Message::reply(req);
        let ret = if !longarg {
            // SAFETY: calling ioctl with a simple u64 argument.
            unsafe { ioctl::ioctl_with_val(&fd.as_raw_fd(), request as _, req.arg as _) }
        } else {
            let buffer_size = std::cmp::max(req.body.len(), req.resp_size as usize);
            let mut buffer = vec![0u8; buffer_size];
            buffer[0..req.body.len()].copy_from_slice(&req.body);

            // SAFETY: calling ioctl with a pointer to a buffer.
            let ret = unsafe {
                ioctl::ioctl_with_ptr(&fd.as_raw_fd(), request as _, buffer.as_mut_ptr())
            };

            if req.resp_size > 0 {
                resp.body = buffer[0..req.resp_size as usize].to_vec();
            }
            ret
        };

        if ret < 0 {
            let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            trace!("Handle::ioctl failed: id=0x{:x}, errno={}", self.id, err);
            resp.status = err as u64;
        } else {
            trace!("Handle::ioctl success: id=0x{:x}, ret={}", self.id, ret);
            resp.arg = ret as u64;
        }

        resp
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        debug!("Dropping Handle id=0x{:x}", self.id);
    }
}

pub struct EventfdOps;

impl HandleOps for EventfdOps {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn handle_request(
        &self,
        handle: &Handle,
        _system: &Arc<System>,
        msg: &Message,
        _channel: &Arc<rpc::Channel>,
    ) -> Option<Message> {
        let op = Operation::from(msg.msg_type);
        match op {
            Operation::EventfdWrite => {
                let fd = handle.fd().unwrap();
                let val: u64 = 1;
                let ret = unsafe { libc::write(fd, &val as *const u64 as *const libc::c_void, 8) };

                let mut resp = Message {
                    msg_type: msg.msg_type,
                    request_id: msg.request_id,
                    handle: msg.handle,
                    status: 0,
                    arg: 0,
                    cmd: msg.cmd,
                    resp_size: 0,
                    body: Vec::new(),
                    fds: None,
                };

                if ret != 8 {
                    resp.status =
                        std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u64;
                }

                Some(resp)
            }
            Operation::GetFileDescriptor => Some(handle.get_fd_message(msg)),
            _ => Some(Message {
                msg_type: msg.msg_type,
                request_id: msg.request_id,
                handle: msg.handle,
                status: libc::ENOSYS as u64,
                arg: msg.arg,
                cmd: msg.cmd,
                resp_size: 0,
                body: Vec::new(),
                fds: None,
            }),
        }
    }

    fn save_state(
        &self,
        handle: &Handle,
        _system: &Arc<System>,
        writer: &mut dyn Write,
    ) -> Result<(), std::io::Error> {
        use prost::Message;
        let luo_id = luo_preserve(handle.fd().unwrap());
        let state = state::tachyon_state::EventfdState {
            id: handle.id,
            luo_id,
        };
        let mut buf = Vec::new();
        state.encode(&mut buf).unwrap();

        let header = MsgHeader {
            msg_type: HandleType::Eventfd as u32,
            size: buf.len() as u32,
        };

        // SAFETY: MsgHeader is POD
        let header_slice = unsafe {
            std::slice::from_raw_parts(
                &header as *const MsgHeader as *const u8,
                std::mem::size_of::<MsgHeader>(),
            )
        };
        writer.write_all(header_slice)?;
        writer.write_all(&buf)?;
        Ok(())
    }

    fn load_state(
        _system: &Arc<System>,
        state: &[u8],
        _channel: &Arc<rpc::Channel>,
    ) -> Result<Arc<Handle>, std::io::Error> {
        use prost::Message;
        let state = state::tachyon_state::EventfdState::decode(state).unwrap();

        let fd = if !state.luo_id.is_empty() {
            let fd = luo_retrieve(&state.luo_id).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("LUO ID {} not found", state.luo_id),
                )
            })?;
            warn!(
                "EventfdOps: load_state: Restored eventfd id=0x{:x} from LUO ID {}, fd={}",
                state.id, state.luo_id, fd
            );
            fd
        } else {
            let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            warn!(
                "EventfdOps: load_state: Created new eventfd id=0x{:x}, fd={}",
                state.id, fd
            );
            fd
        };

        Ok(Handle::new(Some(state.id), Some(fd), Arc::new(EventfdOps)))
    }

    fn get_type(&self) -> HandleType {
        HandleType::Eventfd
    }
}

pub struct RpcServerOps {
    pub socket_path: String,
    pub luo_id: String,
}

impl HandleOps for RpcServerOps {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn handle_request(
        &self,
        handle: &Handle,
        _system: &Arc<System>,
        msg: &Message,
        _channel: &Arc<rpc::Channel>,
    ) -> Option<Message> {
        let op = Operation::from(msg.msg_type);
        match op {
            Operation::GetFileDescriptor => Some(handle.get_fd_message(msg)),
            _ => Some(Message {
                msg_type: msg.msg_type,
                request_id: msg.request_id,
                handle: msg.handle,
                status: libc::ENOSYS as u64,
                arg: msg.arg,
                cmd: msg.cmd,
                resp_size: 0,
                body: Vec::new(),
                fds: None,
            }),
        }
    }

    fn save_state(
        &self,
        handle: &Handle,
        _system: &Arc<System>,
        writer: &mut dyn Write,
    ) -> Result<(), std::io::Error> {
        use prost::Message;
        let luo_id = self.luo_id.clone();
        let state = state::tachyon_state::RpcServerState {
            id: handle.id,
            luo_id,
            socket_path: self.socket_path.clone(),
        };
        let mut buf = Vec::new();
        state.encode(&mut buf).unwrap();

        let header = MsgHeader {
            msg_type: HandleType::RpcServer as u32,
            size: buf.len() as u32,
        };

        // SAFETY: MsgHeader is POD
        let header_slice = unsafe {
            std::slice::from_raw_parts(
                &header as *const MsgHeader as *const u8,
                std::mem::size_of::<MsgHeader>(),
            )
        };
        writer.write_all(header_slice)?;
        writer.write_all(&buf)?;
        Ok(())
    }

    fn get_type(&self) -> HandleType {
        HandleType::RpcServer
    }

    fn load_state(
        system: &Arc<System>,
        state: &[u8],
        _channel: &Arc<rpc::Channel>,
    ) -> Result<Arc<Handle>, std::io::Error> {
        use prost::Message;
        let state = state::tachyon_state::RpcServerState::decode(state).unwrap();
        let fd = luo_retrieve(&state.luo_id).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("LUO ID {} not found for RpcServer", state.luo_id),
            )
        })?;

        let server = Arc::new(rpc::Server::from_fd(fd));
        let system_clone = system.clone();

        std::thread::Builder::new()
            .name("rpc-server-restored".to_string())
            .spawn(move || {
                warn!("Restored RPC server starting to accept connections");
                loop {
                    match server.accept() {
                        Ok(channel) => {
                            let channel_fd = channel.as_raw_fd();
                            let channel_luo_id = luo_preserve(channel_fd);
                            let channel_handle = Handle::new(
                                None,
                                None,
                                std::sync::Arc::new(RpcChannelOps {
                                    luo_id: channel_luo_id,
                                    channel: Mutex::new(None),
                                }),
                            );
                            let handle_id = channel_handle.id();
                            system_clone.add_handle(channel_handle);

                            let channel = std::sync::Arc::new(channel);
                            system_clone.handle_channel(channel, Some(handle_id));
                        }
                        Err(e) => {
                            error!("Restored RPC server failed to accept: {:?}", e);
                            break;
                        }
                    }
                }
            })
            .expect("Failed to spawn restored rpc server thread");

        Ok(Handle::new(
            Some(state.id),
            None,
            Arc::new(RpcServerOps {
                socket_path: state.socket_path,
                luo_id: state.luo_id,
            }),
        ))
    }
}

pub struct RpcChannelOps {
    pub luo_id: String,
    pub channel: Mutex<Option<Arc<rpc::Channel>>>,
}

impl HandleOps for RpcChannelOps {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn handle_request(
        &self,
        handle: &Handle,
        _system: &Arc<System>,
        msg: &Message,
        _channel: &Arc<rpc::Channel>,
    ) -> Option<Message> {
        let op = Operation::from(msg.msg_type);
        match op {
            Operation::GetFileDescriptor => Some(handle.get_fd_message(msg)),
            _ => Some(Message {
                msg_type: msg.msg_type,
                request_id: msg.request_id,
                handle: msg.handle,
                status: libc::ENOSYS as u64,
                arg: msg.arg,
                cmd: msg.cmd,
                resp_size: 0,
                body: Vec::new(),
                fds: None,
            }),
        }
    }

    fn save_state(
        &self,
        handle: &Handle,
        _system: &Arc<System>,
        writer: &mut dyn Write,
    ) -> Result<(), std::io::Error> {
        use prost::Message;
        let luo_id = self.luo_id.clone();
        let state = state::tachyon_state::RpcChannelState {
            id: handle.id,
            luo_id,
        };
        let mut buf = Vec::new();
        state.encode(&mut buf).unwrap();

        let header = MsgHeader {
            msg_type: HandleType::RpcChannel as u32,
            size: buf.len() as u32,
        };

        // SAFETY: MsgHeader is POD
        let header_slice = unsafe {
            std::slice::from_raw_parts(
                &header as *const MsgHeader as *const u8,
                std::mem::size_of::<MsgHeader>(),
            )
        };
        writer.write_all(header_slice)?;
        writer.write_all(&buf)?;
        Ok(())
    }

    fn get_type(&self) -> HandleType {
        HandleType::RpcChannel
    }

    fn load_state(
        system: &Arc<System>,
        state: &[u8],
        _channel: &Arc<rpc::Channel>,
    ) -> Result<Arc<Handle>, std::io::Error> {
        use prost::Message;
        let state = state::tachyon_state::RpcChannelState::decode(state).unwrap();
        let fd = {
            let fd = luo_retrieve(&state.luo_id).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("LUO ID {} not found for RpcChannel", state.luo_id),
                )
            })?;
            unsafe { OwnedFd::from_raw_fd(fd) }
        };
        let rpc_channel = Arc::new(rpc::Channel::new(fd));
        system.handle_channel(rpc_channel.clone(), Some(state.id));
        Ok(Handle::new(
            Some(state.id),
            None,
            Arc::new(RpcChannelOps {
                luo_id: state.luo_id,
                channel: Mutex::new(Some(rpc_channel)),
            }),
        ))
    }
}

pub struct KvmDeviceOps {
    eventfds: Mutex<Vec<u64>>,
}

#[repr(C, align(64))]
pub struct PerVcpuState {
    pub state: std::sync::atomic::AtomicU32,
    pub status: i32,
    pub _padding: [u8; 56],
}

#[repr(C)]
pub struct VcpuSharedMemory {
    pub vcpus: [PerVcpuState; MAX_VCPUS],
}

pub struct VcpuSharedMemoryMapping {
    fd: RawFd,
    addr: *mut VcpuSharedMemory,
    size: usize,
}

unsafe impl Send for VcpuSharedMemoryMapping {}
unsafe impl Sync for VcpuSharedMemoryMapping {}

impl VcpuSharedMemoryMapping {
    fn new() -> Self {
        let name = std::ffi::CString::new("tachyon-vcpu-shm").unwrap();
        let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
        if fd < 0 {
            panic!(
                "failed to create memfd: {}",
                std::io::Error::last_os_error()
            );
        }
        let size = std::mem::size_of::<VcpuSharedMemory>();
        if unsafe { libc::ftruncate(fd, size as libc::off_t) } < 0 {
            panic!(
                "failed to truncate memfd: {}",
                std::io::Error::last_os_error()
            );
        }
        Self::from_fd(fd)
    }

    fn from_fd(fd: RawFd) -> Self {
        let size = std::mem::size_of::<VcpuSharedMemory>();
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if addr == libc::MAP_FAILED {
            panic!("failed to mmap memfd: {}", std::io::Error::last_os_error());
        }
        VcpuSharedMemoryMapping {
            fd,
            addr: addr as *mut VcpuSharedMemory,
            size,
        }
    }

    fn fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for VcpuSharedMemoryMapping {
    fn drop(&mut self) {
        debug!("Dropping VcpuSharedMemoryMapping, closing fd={}", self.fd);
        unsafe {
            libc::munmap(self.addr as *mut libc::c_void, self.size);
        }
        let ret = unsafe { libc::close(self.fd) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EBADF) {
                debug_panic_or_error!(
                    "Double close detected on fd={} in VcpuSharedMemoryMapping::drop",
                    self.fd
                );
            }
        }
    }
}

struct MemoryMapping {
    addr: u64,
    size: usize,
    region: kvm::kvm_userspace_memory_region2,
    guest_memfd_handle: u64,
}

pub struct VmOps {
    regions: Mutex<HashMap<u64, MemoryMapping>>,
    vcpus: Mutex<Vec<u64>>,
    shared_memory: Arc<VcpuSharedMemoryMapping>,
    has_irqchip: std::sync::atomic::AtomicBool,
    has_pit: std::sync::atomic::AtomicBool,
    pit_config: Mutex<Option<Vec<u8>>>,
    enabled_caps: Mutex<Vec<Vec<u8>>>,
    gsi_routing: Mutex<Option<Vec<u8>>>,
    msr_filter: Mutex<Option<Vec<u8>>>,
    ioeventfds_configs: Mutex<Vec<(kvm::kvm_ioeventfd, u64)>>,
    irqfds_configs: Mutex<Vec<(kvm::kvm_irqfd, u64, u64)>>,
    tss_addr: AtomicU64,
    identity_map_addr: AtomicU64,
    pmu_event_filter: Mutex<Option<Vec<u8>>>,
}

impl Default for VmOps {
    fn default() -> Self {
        Self::new()
    }
}

impl VmOps {
    pub fn new() -> Self {
        VmOps {
            regions: Mutex::new(HashMap::new()),
            vcpus: Mutex::new(Vec::new()),
            shared_memory: Arc::new(VcpuSharedMemoryMapping::new()),
            has_irqchip: std::sync::atomic::AtomicBool::new(false),
            has_pit: std::sync::atomic::AtomicBool::new(false),
            pit_config: Mutex::new(None),
            enabled_caps: Mutex::new(Vec::new()),
            gsi_routing: Mutex::new(None),
            msr_filter: Mutex::new(None),
            ioeventfds_configs: Mutex::new(Vec::new()),
            irqfds_configs: Mutex::new(Vec::new()),
            tss_addr: AtomicU64::new(0),
            identity_map_addr: AtomicU64::new(0),
            pmu_event_filter: Mutex::new(None),
        }
    }

    pub fn get_shm_fd(&self) -> RawFd {
        self.shared_memory.fd()
    }

    fn handle_create_vcpu(
        &self,
        handle: &Handle,
        system: &Arc<System>,
        msg: &Message,
        channel: &Arc<rpc::Channel>,
    ) -> Message {
        let vcpu_id = msg.arg as u32;
        if vcpu_id >= MAX_VCPUS as u32 {
            return Message {
                msg_type: msg.msg_type,
                request_id: msg.request_id,
                handle: msg.handle,
                status: libc::EINVAL as u64,
                arg: msg.arg,
                cmd: msg.cmd,
                resp_size: 0,
                body: Vec::new(),
                fds: None,
            };
        }
        let mut resp = handle.ioctl(msg, false);
        if resp.status == 0 {
            let vcpu_fd = resp.arg as RawFd;
            debug!(
                "VmOps: KVM_CREATE_VCPU on id={}, vcpu_id={}, new fd={}",
                handle.id, vcpu_id, vcpu_fd
            );
            let shm_entry = unsafe {
                &mut (*self.shared_memory.addr).vcpus[vcpu_id as usize] as *mut PerVcpuState
            };
            let vcpu_handle = Handle::new(
                None,
                Some(vcpu_fd),
                Arc::new(VcpuOps::new(
                    handle.id,
                    vcpu_id,
                    vcpu_fd,
                    channel.clone(),
                    self.shared_memory.clone(),
                    shm_entry,
                )),
            );
            let vcpu_handle_id = vcpu_handle.id();
            system.add_handle(vcpu_handle);
            self.vcpus.lock().unwrap().push(vcpu_handle_id);
            resp.handle = vcpu_handle_id;
        }
        resp
    }

    /// Handles KVM_SET_USER_MEMORY_REGION and its variants.
    ///
    /// This function abstracts over multiple versions of the memory region
    /// structure and manages the mapping of guest memory files (memfds)
    /// into the VMM's address space. It ensures that the kernel receives
    /// a valid host virtual address for each memory slot, even when the
    /// client provides handle-based references.
    fn handle_set_user_memory_region2(
        &self,
        handle: &Handle,
        system: &Arc<System>,
        msg: &Message,
    ) -> Message {
        debug!("VmOps: KVM_SET_USER_MEMORY_REGION/2 on id={}", handle.id);

        let (region2, guest_memfd_handle) =
            if msg.body.len() == std::mem::size_of::<kvm::kvm_userspace_memory_region2_wrapper>() {
                let wrapper = unsafe {
                    &*(msg.body.as_ptr() as *const kvm::kvm_userspace_memory_region2_wrapper)
                };
                (wrapper.region2, wrapper.guest_memfd_handle)
            } else if msg.body.len() == std::mem::size_of::<kvm::kvm_userspace_memory_region2>() {
                let region2 = unsafe {
                    std::ptr::read(msg.body.as_ptr() as *const kvm::kvm_userspace_memory_region2)
                };
                (region2, 0)
            } else if msg.body.len() == std::mem::size_of::<kvm::kvm_userspace_memory_region>() {
                let region = unsafe {
                    std::ptr::read(msg.body.as_ptr() as *const kvm::kvm_userspace_memory_region)
                };
                let region2 = kvm::kvm_userspace_memory_region2 {
                    slot: region.slot,
                    flags: region.flags,
                    guest_phys_addr: region.guest_phys_addr,
                    memory_size: region.memory_size,
                    userspace_addr: region.userspace_addr,
                    ..Default::default()
                };
                (region2, 0)
            } else {
                debug!(
                    "VmOps: KVM_SET_USER_MEMORY_REGION/2 failed: invalid body size {}",
                    msg.body.len()
                );
                return Message::reply(msg).with_error(libc::EINVAL as u64);
            };

        let vm_fd = handle.fd().unwrap();
        if region2.memory_size == 0 {
            // Deleting the slot.
            let region = kvm::kvm_userspace_memory_region {
                slot: region2.slot,
                flags: region2.flags,
                guest_phys_addr: region2.guest_phys_addr,
                memory_size: 0,
                userspace_addr: 0,
            };

            let ret = unsafe { libc::ioctl(vm_fd, kvm::KVM_SET_USER_MEMORY_REGION as _, &region) };
            if ret < 0 {
                let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u64;
                debug!(
                    "VmOps: KVM_SET_USER_MEMORY_REGION delete failed: errno={}",
                    err
                );
                return Message::reply(msg).with_error(err);
            }

            let mut regions = self.regions.lock().unwrap();
            if let Some(mapping) = regions.remove(&(region2.slot as u64)) {
                unsafe {
                    libc::munmap(mapping.addr as *mut libc::c_void, mapping.size);
                }
            }

            return Message::reply(msg);
        }

        let (mem_fd, mmap_addr) = if guest_memfd_handle != 0 {
            let mem_handle = {
                let handles = system.handles.lock().unwrap();
                handles.get(&guest_memfd_handle).cloned()
            };

            let mem_fd = match mem_handle {
                Some(h) => h.fd().unwrap(),
                None => {
                    debug!("VmOps: memfd handle 0x{:x} not found", guest_memfd_handle);
                    return Message::reply(msg).with_error(libc::ENOENT as u64);
                }
            };

            let mmap_addr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    region2.memory_size as usize,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED | libc::MAP_FILE,
                    mem_fd,
                    region2.guest_memfd_offset as libc::off_t,
                )
            };

            if mmap_addr == libc::MAP_FAILED {
                let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                debug!("VmOps: mmap failed: errno={}", err);
                return Message::reply(msg).with_error(err as u64);
            }
            (mem_fd, mmap_addr)
        } else {
            (-1, region2.userspace_addr as *mut libc::c_void)
        };

        let mut final_region2 = region2;
        final_region2.userspace_addr = mmap_addr as u64;

        let ret = if guest_memfd_handle != 0 {
            let ret = unsafe {
                libc::ioctl(vm_fd, kvm::KVM_SET_USER_MEMORY_REGION2 as _, &final_region2)
            };
            if ret < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOTTY) {
                // Fallback to KVM_SET_USER_MEMORY_REGION even if we have a memfd handle.
                // Note: Standard KVM_SET_USER_MEMORY_REGION doesn't support guest_memfd,
                // so this might fail later, but it's better to try.
                let kvm_region = kvm::kvm_userspace_memory_region {
                    slot: region2.slot,
                    flags: region2.flags,
                    guest_phys_addr: region2.guest_phys_addr,
                    memory_size: region2.memory_size,
                    userspace_addr: mmap_addr as u64,
                };
                unsafe { libc::ioctl(vm_fd, kvm::KVM_SET_USER_MEMORY_REGION as _, &kvm_region) }
            } else {
                ret
            }
        } else {
            let kvm_region = kvm::kvm_userspace_memory_region {
                slot: region2.slot,
                flags: region2.flags,
                guest_phys_addr: region2.guest_phys_addr,
                memory_size: region2.memory_size,
                userspace_addr: mmap_addr as u64,
            };
            unsafe { libc::ioctl(vm_fd, kvm::KVM_SET_USER_MEMORY_REGION as _, &kvm_region) }
        };

        if ret < 0 {
            let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u64;
            debug!("VmOps: KVM_SET_USER_MEMORY_REGION failed: errno={}", err);
            if guest_memfd_handle != 0 {
                unsafe {
                    libc::munmap(mmap_addr, region2.memory_size as usize);
                }
            }
            return Message::reply(msg).with_error(err);
        }

        let mut regions = self.regions.lock().unwrap();
        if let Some(old_mapping) = regions.insert(
            region2.slot as u64,
            MemoryMapping {
                addr: mmap_addr as u64,
                size: region2.memory_size as usize,
                region: final_region2,
                guest_memfd_handle,
            },
        ) && guest_memfd_handle != 0
        {
            unsafe {
                libc::munmap(old_mapping.addr as *mut libc::c_void, old_mapping.size);
            }
        }

        // Suppress unused warning
        let _ = mem_fd;

        Message::reply(msg)
    }

    /// Registers a doorbell (ioeventfd) with the VM.
    ///
    /// Tachyon uses handle IDs for registration to ensure that doorbells
    /// can be consistently re-established across process updates. This
    /// function handles both standard KVM structures and Tachyon-wrapped
    /// persistent structures.
    fn handle_ioeventfd(&self, handle: &Handle, system: &Arc<System>, msg: &Message) -> Message {
        debug!(
            "VmOps: KVM_IOEVENTFD on id={}, body_len={}",
            handle.id,
            msg.body.len()
        );

        if msg.body.len() != std::mem::size_of::<kvm_ioeventfd_wrapped>() {
            warn!(
                "VmOps: KVM_IOEVENTFD failed: invalid body size {}, expected wrapped struct size",
                msg.body.len()
            );
            return Message::reply(msg).with_error(libc::EINVAL as u64);
        }

        let wrapped = unsafe { std::ptr::read(msg.body.as_ptr() as *const kvm_ioeventfd_wrapped) };
        let mut ioeventfd = wrapped.kvm;
        let handle_id = wrapped.fd_handle;

        if let Some(fds) = &msg.fds {
            for &fd in fds {
                unsafe { libc::close(fd) };
            }
        }

        if handle_id == 0 {
            warn!("VmOps: handle_ioeventfd: No handle ID provided");
            return Message::reply(msg).with_error(libc::EINVAL as u64);
        }

        let eventfd_handle = system.get_handle(handle_id);
        if eventfd_handle.is_none() {
            warn!(
                "VmOps: handle_ioeventfd: Handle 0x{:x} not found",
                handle_id
            );
            return Message::reply(msg).with_error(libc::ENOENT as u64);
        }
        let eventfd_handle = eventfd_handle.unwrap();

        ioeventfd.fd = eventfd_handle.fd().unwrap();

        let vm_fd = handle.fd().unwrap();
        let ret = unsafe { libc::ioctl(vm_fd, kvm::KVM_IOEVENTFD as _, &ioeventfd) };

        if ret == 0 {
            let mut configs = self.ioeventfds_configs.lock().unwrap();
            if (ioeventfd.flags & kvm::KVM_IOEVENTFD_FLAG_DEASSIGN) != 0 {
                configs.retain(|(c, _)| {
                    c.addr != ioeventfd.addr
                        || c.len != ioeventfd.len
                        || c.datamatch != ioeventfd.datamatch
                        || (c.flags & !kvm::KVM_IOEVENTFD_FLAG_DEASSIGN)
                            != (ioeventfd.flags & !kvm::KVM_IOEVENTFD_FLAG_DEASSIGN)
                });
            } else {
                configs.push((ioeventfd, handle_id));
                trace!(
                    "VmOps: handle_ioeventfd: Registered config for addr=0x{:x}, handle_id=0x{:x}",
                    ioeventfd.addr, handle_id
                );
            }
        } else {
            let err = std::io::Error::last_os_error();
            warn!(
                "VmOps: handle_ioeventfd failed: {} (addr=0x{:x}, fd={}, flags=0x{:x})",
                err, ioeventfd.addr, ioeventfd.fd, ioeventfd.flags
            );
        }

        let mut resp = Message::reply(msg);
        if ret < 0 {
            resp.status = std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u64;
        } else {
            resp.arg = ret as u64;
        }
        resp
    }

    /// Registers an interrupt (irqfd) with the VM.
    ///
    /// Like ioeventfds, irqfds are registered using Tachyon handle IDs.
    /// This ensures that the GSI routing remains valid across binary
    /// updates and that the proxy client does not need to re-register
    /// IRQs after a live update.
    fn handle_irqfd(&self, handle: &Handle, system: &Arc<System>, msg: &Message) -> Message {
        debug!(
            "VmOps: KVM_IRQFD on id={}, body_len={}",
            handle.id,
            msg.body.len()
        );

        if msg.body.len() != std::mem::size_of::<kvm_irqfd_wrapped>() {
            warn!(
                "VmOps: KVM_IRQFD failed: invalid body size {}, expected wrapped struct size",
                msg.body.len()
            );
            return Message::reply(msg).with_error(libc::EINVAL as u64);
        }

        let wrapped = unsafe { std::ptr::read(msg.body.as_ptr() as *const kvm_irqfd_wrapped) };
        let mut irqfd = wrapped.kvm;
        let fd_handle_id = wrapped.fd_handle;
        let resamplefd_handle_id = wrapped.resamplefd_handle;

        if let Some(fds) = &msg.fds {
            for &fd in fds {
                unsafe { libc::close(fd) };
            }
        }

        if fd_handle_id != 0 {
            let h = system.get_handle(fd_handle_id);
            if let Some(h) = h {
                irqfd.fd = h.fd().unwrap() as u32;
            } else {
                warn!(
                    "VmOps: handle_irqfd: FD handle 0x{:x} not found",
                    fd_handle_id
                );
                return Message::reply(msg).with_error(libc::ENOENT as u64);
            }
        } else if (irqfd.flags & kvm::KVM_IRQFD_FLAG_DEASSIGN) == 0 {
            warn!("VmOps: handle_irqfd: No FD handle ID provided for assignment");
            return Message::reply(msg).with_error(libc::EINVAL as u64);
        }

        if resamplefd_handle_id != 0 {
            let h = system.get_handle(resamplefd_handle_id);
            if let Some(h) = h {
                irqfd.resamplefd = h.fd().unwrap() as u32;
            } else {
                warn!(
                    "VmOps: handle_irqfd: Resample handle 0x{:x} not found",
                    resamplefd_handle_id
                );
                return Message::reply(msg).with_error(libc::ENOENT as u64);
            }
        } else if (irqfd.flags & kvm::KVM_IRQFD_FLAG_RESAMPLE) != 0 {
            warn!("VmOps: handle_irqfd: No resample handle ID provided for resample irqfd");
            return Message::reply(msg).with_error(libc::EINVAL as u64);
        }

        let vm_fd = handle.fd().unwrap();
        let ret = unsafe { libc::ioctl(vm_fd, kvm::KVM_IRQFD as _, &irqfd) };

        if ret == 0 {
            let mut configs = self.irqfds_configs.lock().unwrap();
            if (irqfd.flags & kvm::KVM_IRQFD_FLAG_DEASSIGN) != 0 {
                configs.retain(|(c, _, _)| {
                    c.gsi != irqfd.gsi
                        || (c.flags & !kvm::KVM_IRQFD_FLAG_DEASSIGN)
                            != (irqfd.flags & !kvm::KVM_IRQFD_FLAG_DEASSIGN)
                });
            } else {
                configs.push((irqfd, fd_handle_id, resamplefd_handle_id));
                trace!(
                    "VmOps: handle_irqfd: Registered config for gsi={}, fd_handle_id=0x{:x}",
                    irqfd.gsi, fd_handle_id
                );
            }
        } else {
            let err = std::io::Error::last_os_error();
            warn!(
                "VmOps: handle_irqfd failed: {} (gsi={}, fd={}, flags=0x{:x})",
                err, irqfd.gsi, irqfd.fd, irqfd.flags
            );
        }

        let mut resp = Message::reply(msg);
        if ret < 0 {
            resp.status = std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u64;
        } else {
            resp.arg = ret as u64;
        }
        resp
    }

    fn handle_set_msr_filter(&self, handle: &Handle, msg: &Message) -> Message {
        debug!("VmOps: KVM_X86_SET_MSR_FILTER on id={}", handle.id);
        if msg.body.len() < std::mem::size_of::<kvm::kvm_msr_filter>() {
            debug!("VmOps: KVM_X86_SET_MSR_FILTER failed: body too small");
            return Message::reply(msg).with_error(libc::EINVAL as u64);
        }

        let mut filter = unsafe { std::ptr::read(msg.body.as_ptr() as *const kvm::kvm_msr_filter) };
        let mut bitmaps = Vec::new();

        for range in filter.ranges.iter_mut() {
            if range.nmsrs == 0 {
                continue;
            }

            let offset = range.bitmap as usize;
            let bitmap_size = range.nmsrs.div_ceil(8) as usize;

            if offset == 0 || offset + bitmap_size > msg.body.len() {
                debug!("VmOps: KVM_X86_SET_MSR_FILTER failed: invalid bitmap offset/size");
                return Message::reply(msg).with_error(libc::EINVAL as u64);
            }

            let mut bitmap_buf = vec![0u8; bitmap_size];
            bitmap_buf.copy_from_slice(&msg.body[offset..offset + bitmap_size]);
            bitmaps.push(bitmap_buf);
            range.bitmap = bitmaps.last().unwrap().as_ptr() as u64;
        }

        let vm_fd = handle.fd().unwrap();
        let ret = unsafe { libc::ioctl(vm_fd, kvm::KVM_X86_SET_MSR_FILTER as _, &filter) };

        let mut resp = Message::reply(msg);
        if ret < 0 {
            resp.status = std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u64;
        } else {
            resp.arg = ret as u64;
            *self.msr_filter.lock().unwrap() = Some(msg.body.clone());
        }
        resp
    }

    fn handle_ioctl(
        &self,
        handle: &Handle,
        system: &Arc<System>,
        msg: &Message,
        channel: &Arc<rpc::Channel>,
    ) -> Option<Message> {
        match msg.cmd {
            kvm::KVM_CREATE_VCPU => Some(self.handle_create_vcpu(handle, system, msg, channel)),

            kvm::KVM_SET_USER_MEMORY_REGION | kvm::KVM_SET_USER_MEMORY_REGION2 => {
                Some(self.handle_set_user_memory_region2(handle, system, msg))
            }
            kvm::KVM_X86_SET_MSR_FILTER => Some(self.handle_set_msr_filter(handle, msg)),
            kvm::KVM_CREATE_IRQCHIP => {
                let resp = handle.ioctl(msg, false);
                if resp.status == 0 {
                    self.has_irqchip.store(true, Ordering::SeqCst);
                }
                Some(resp)
            }
            kvm::KVM_CREATE_PIT => {
                let resp = handle.ioctl(msg, false);
                if resp.status == 0 {
                    self.has_pit.store(true, Ordering::SeqCst);
                }
                Some(resp)
            }
            kvm::KVM_CREATE_PIT2 => {
                let resp = handle.ioctl(msg, true);
                if resp.status == 0 {
                    self.has_pit.store(true, Ordering::SeqCst);
                    *self.pit_config.lock().unwrap() = Some(msg.body.clone());
                }
                Some(resp)
            }
            kvm::KVM_ENABLE_CAP => {
                let resp = handle.ioctl(msg, true);
                if resp.status == 0 {
                    self.enabled_caps.lock().unwrap().push(msg.body.clone());
                }
                Some(resp)
            }
            kvm::KVM_SET_GSI_ROUTING => {
                let resp = handle.ioctl(msg, true);
                if resp.status == 0 {
                    *self.gsi_routing.lock().unwrap() = Some(msg.body.clone());
                }
                Some(resp)
            }
            kvm::KVM_SET_TSS_ADDR => {
                let resp = handle.ioctl(msg, false);
                if resp.status == 0 {
                    self.tss_addr.store(msg.arg, Ordering::Release);
                }
                Some(resp)
            }
            kvm::KVM_SET_IDENTITY_MAP_ADDR => {
                let resp = handle.ioctl(msg, true);
                if resp.status == 0 && msg.body.len() >= 8 {
                    let addr = u64::from_le_bytes(msg.body[0..8].try_into().unwrap());
                    self.identity_map_addr.store(addr, Ordering::Release);
                }
                Some(resp)
            }
            kvm::KVM_SET_PMU_EVENT_FILTER => {
                let resp = handle.ioctl(msg, true);
                if resp.status == 0 {
                    *self.pmu_event_filter.lock().unwrap() = Some(msg.body.clone());
                }
                Some(resp)
            }
            kvm::KVM_CHECK_EXTENSION
            | kvm::KVM_GET_TSC_KHZ
            | kvm::KVM_SET_BOOT_CPU_ID
            | kvm::KVM_SET_NR_MMU_PAGES => Some(handle.ioctl(msg, false)),
            kvm::KVM_GET_CLOCK
            | kvm::KVM_SET_CLOCK
            | kvm::KVM_GET_IRQCHIP
            | kvm::KVM_SET_IRQCHIP
            | kvm::KVM_SIGNAL_MSI
            | kvm::KVM_GET_PIT
            | kvm::KVM_SET_PIT
            | kvm::KVM_GET_PIT2
            | kvm::KVM_SET_PIT2
            | kvm::KVM_REGISTER_COALESCED_MMIO
            | kvm::KVM_UNREGISTER_COALESCED_MMIO
            | kvm::KVM_IRQ_LINE_STATUS
            | kvm::KVM_IRQ_LINE
            | kvm::KVM_GET_LAPIC
            | kvm::KVM_GET_REGS
            | kvm::KVM_SET_FPU => {
                let longarg = !msg.body.is_empty() || msg.resp_size > 0;
                Some(handle.ioctl(msg, longarg))
            }
            kvm::KVM_IOEVENTFD /* KVM_IOEVENTFD */ => Some(self.handle_ioeventfd(handle, system, msg)),
            kvm::KVM_IRQFD /* KVM_IRQFD */ => Some(self.handle_irqfd(handle, system, msg)),
            kvm::KVM_GET_STATS_FD => {
                let mut resp = handle.ioctl(msg, false);
                if resp.status == 0 {
                    let stats_fd = resp.arg as RawFd;
                    debug!(
                        "VmOps: KVM_GET_STATS_FD on id={}, new fd={}",
                        handle.id, stats_fd
                    );
                    resp.fds = Some(vec![stats_fd]);
                    let _ = channel.send(&resp);
                    unsafe { libc::close(stats_fd) };
                } else {
                    let _ = channel.send(&resp);
                }
                None
            }
            _ => Some(Message::reply(msg).with_error(libc::ENOSYS as u64)),
        }
    }
}

impl Drop for VmOps {
    fn drop(&mut self) {
        let mut regions = match self.regions.lock() {
            Ok(regions) => regions,
            Err(err) => {
                error!("Couldn't take regions lock: {err}, not unmapping.");
                return;
            }
        };
        debug!("Dropping VmOps, unmapping {} regions", regions.len());
        for (slot, mapping) in regions.drain() {
            debug!(
                "Unmapping region for slot {}, addr 0x{:x}, size={}",
                slot, mapping.addr, mapping.size
            );
            unsafe {
                libc::munmap(mapping.addr as *mut libc::c_void, mapping.size);
            }
        }
    }
}

/// Validates that an incoming VFIO ioctl message meets the minimum buffer requirements
/// and that any requested `argsz` does not exceed the provided message buffer size.
/// This prevents kernel out-of-bounds writes into user space during pointer ioctl execution.
fn validate_vfio_argsz(msg: &Message, min_size: usize) -> Result<(), u64> {
    if msg.body.len() < min_size || (msg.resp_size > 0 && (msg.resp_size as usize) < min_size) {
        return Err(libc::EINVAL as u64);
    }
    if msg.body.len() >= 4 {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&msg.body[0..4]);
        let argsz = u32::from_ne_bytes(bytes) as usize;
        let buffer_size = std::cmp::max(msg.body.len(), msg.resp_size as usize);
        if argsz > buffer_size {
            return Err(libc::EINVAL as u64);
        }
    }
    Ok(())
}

pub struct VfioContainerOps {}

impl Default for VfioContainerOps {
    fn default() -> Self {
        Self::new()
    }
}

impl VfioContainerOps {
    pub fn new() -> Self {
        VfioContainerOps {}
    }

    fn handle_ioctl(
        &self,
        handle: &Handle,
        _system: &Arc<System>,
        msg: &Message,
        _channel: &Arc<rpc::Channel>,
    ) -> Option<Message> {
        match msg.cmd {
            vfio::VFIO_IOMMU_GET_INFO => {
                if let Err(err) = validate_vfio_argsz(msg, 16) {
                    return Some(Message::reply(msg).with_error(err));
                }
                let longarg = !msg.body.is_empty() || msg.resp_size > 0;
                Some(handle.ioctl(msg, longarg))
            }
            vfio::VFIO_GET_API_VERSION | vfio::VFIO_SET_IOMMU | vfio::VFIO_CHECK_EXTENSION => {
                let longarg = !msg.body.is_empty() || msg.resp_size > 0;
                Some(handle.ioctl(msg, longarg))
            }
            _ => Some(Message::reply(msg).with_error(libc::ENOSYS as u64)),
        }
    }
}

impl HandleOps for VfioContainerOps {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn get_type(&self) -> HandleType {
        HandleType::VfioContainer
    }

    fn handle_request(
        &self,
        handle: &Handle,
        system: &Arc<System>,
        msg: &Message,
        channel: &Arc<rpc::Channel>,
    ) -> Option<Message> {
        let op = Operation::from(msg.msg_type);
        debug!(
            "VfioContainerOps::handle_request: id={}, op={:?}, cmd=0x{:x}",
            handle.id, op, msg.cmd
        );
        match op {
            Operation::Ioctl => self.handle_ioctl(handle, system, msg, channel),
            Operation::GetFileDescriptor => Some(handle.get_fd_message(msg)),
            _ => Some(Message::reply(msg).with_error(libc::ENOSYS as u64)),
        }
    }
}

pub struct VfioGroupOps {}

impl Default for VfioGroupOps {
    fn default() -> Self {
        Self::new()
    }
}

impl VfioGroupOps {
    pub fn new() -> Self {
        VfioGroupOps {}
    }

    fn handle_vfio_group_get_device_fd(
        &self,
        handle: &Handle,
        system: &Arc<System>,
        msg: &Message,
    ) -> Option<Message> {
        let mut resp = handle.ioctl(msg, true);
        if resp.status == 0 {
            let device_fd = resp.arg as RawFd;
            debug!(
                "VfioGroupOps: VFIO_GROUP_GET_DEVICE_FD on id={}, new fd={}",
                handle.id, device_fd
            );
            let device_handle = Handle::new(None, Some(device_fd), Arc::new(VfioDeviceOps::new()));
            let device_handle_id = device_handle.id();
            system.add_handle(device_handle);
            resp.handle = device_handle_id;
        }
        Some(resp)
    }

    fn handle_vfio_group_set_container(
        &self,
        handle: &Handle,
        system: &Arc<System>,
        msg: &Message,
    ) -> Option<Message> {
        let container_handle = {
            let handles = system.handles.lock().unwrap();
            handles.get(&{ msg.arg }).cloned().unwrap()
        };
        let fd = if let Some(fd) = container_handle.fd.as_ref() {
            fd.as_raw_fd() as u64
        } else {
            debug!(
                "VfioGroupOps: VFIO_GROUP_SET_CONTAINER found an invalid container for handle {}",
                msg.arg
            );
            return Some(Message::reply(msg).with_error(libc::EINVAL as u64));
        };
        // VFIO requires a pointer to the fd to passed.
        let container_fd_ptr = &fd as *const u64;
        let ret = unsafe {
            libc::ioctl(
                handle.fd.as_ref().unwrap().as_raw_fd(),
                vfio::VFIO_GROUP_SET_CONTAINER as _,
                container_fd_ptr,
            )
        };

        if ret < 0 {
            let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u64;
            debug!(
                "VfioGroupOps: VFIO_GROUP_SET_CONTAINER failed: errno={}",
                err
            );
            return Some(Message::reply(msg).with_error(err));
        }

        Some(Message::reply(msg))
    }

    fn handle_ioctl(
        &self,
        handle: &Handle,
        system: &Arc<System>,
        msg: &Message,
        _channel: &Arc<rpc::Channel>,
    ) -> Option<Message> {
        match msg.cmd {
            vfio::VFIO_GROUP_GET_STATUS => {
                if let Err(err) = validate_vfio_argsz(msg, 8) {
                    return Some(Message::reply(msg).with_error(err));
                }
                let longarg = !msg.body.is_empty() || msg.resp_size > 0;
                Some(handle.ioctl(msg, longarg))
            }
            vfio::VFIO_GROUP_UNSET_CONTAINER => {
                let longarg = !msg.body.is_empty() || msg.resp_size > 0;
                Some(handle.ioctl(msg, longarg))
            }
            vfio::VFIO_GROUP_GET_DEVICE_FD => {
                self.handle_vfio_group_get_device_fd(handle, system, msg)
            }
            vfio::VFIO_GROUP_SET_CONTAINER => {
                self.handle_vfio_group_set_container(handle, system, msg)
            }
            _ => Some(Message::reply(msg).with_error(libc::ENOSYS as u64)),
        }
    }
}

impl HandleOps for VfioGroupOps {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn get_type(&self) -> HandleType {
        HandleType::VfioGroup
    }

    fn handle_request(
        &self,
        handle: &Handle,
        system: &Arc<System>,
        msg: &Message,
        channel: &Arc<rpc::Channel>,
    ) -> Option<Message> {
        let op = Operation::from(msg.msg_type);
        debug!(
            "VfioGroupOps::handle_request: id={}, op={:?}, cmd=0x{:x}",
            handle.id, op, msg.cmd
        );
        match op {
            Operation::GetFileDescriptor => Some(handle.get_fd_message(msg)),
            Operation::Ioctl => self.handle_ioctl(handle, system, msg, channel),
            _ => Some(Message {
                msg_type: msg.msg_type,
                request_id: msg.request_id,
                handle: msg.handle,
                status: libc::ENOSYS as u64,
                arg: msg.arg,
                cmd: msg.cmd,
                resp_size: 0,
                body: Vec::new(),
                fds: None,
            }),
        }
    }
}

pub struct VfioDeviceOps {}

impl Default for VfioDeviceOps {
    fn default() -> Self {
        Self::new()
    }
}

impl VfioDeviceOps {
    pub fn new() -> Self {
        VfioDeviceOps {}
    }

    fn vfio_set_irqs_translate(
        msg: &Message,
        system: &Arc<System>,
    ) -> Result<Message, std::io::Error> {
        let body = &msg.body;
        unsafe {
            let meta = (body.as_ptr() as *const vfio::vfio_irq_set).read_unaligned();

            let mut new_msg = msg.clone();

            if (meta.flags & vfio::VFIO_IRQ_SET_DATA_EVENTFD) == 0 {
                return Ok(new_msg);
            }

            let hdr_sz = size_of::<vfio::vfio_irq_set>();

            let body_fds = body.clone();
            let handles = body.as_ptr().add(hdr_sz) as *const u64;
            let fds = body_fds.as_ptr().add(hdr_sz) as *mut i32;
            for i in 0usize..meta.count as usize {
                let handle = handles.add(i).read_unaligned();
                if handle == 0 {
                    continue;
                }
                let evfd = match system.get_handle(handle) {
                    Some(evfd) => evfd,
                    None => {
                        return Err(std::io::Error::other(format!(
                            "Unknown handle {:x}",
                            handle
                        )));
                    }
                };
                let fd = match evfd.fd() {
                    Some(fd) => fd,
                    None => {
                        return Err(std::io::Error::other(format!(
                            "No fd for handle {:x}",
                            handle
                        )));
                    }
                };
                fds.add(i).write_unaligned(fd);
            }
            new_msg.body = body_fds;
            Ok(new_msg)
        }
    }

    fn handle_vfio_device_set_irqs(
        &self,
        handle: &Handle,
        system: &Arc<System>,
        msg: &Message,
    ) -> Option<Message> {
        if let Err(err) = validate_vfio_argsz(msg, std::mem::size_of::<vfio::vfio_irq_set>()) {
            return Some(Message::reply(msg).with_error(err));
        }
        trace!("VFIO_DEVICE_SET_IRQS: {:?}", msg.body);
        let translated_msg = match Self::vfio_set_irqs_translate(msg, system) {
            Ok(msg) => msg,
            Err(e) => {
                error!("Couldn't translate vfio_set_irqs_translate {}", e);
                return Some(Message::reply(msg).with_error(libc::EIO as u64));
            }
        };
        Some(handle.ioctl(&translated_msg, true))
    }

    fn handle_ioctl(
        &self,
        handle: &Handle,
        system: &Arc<System>,
        msg: &Message,
        _channel: &Arc<rpc::Channel>,
    ) -> Option<Message> {
        match msg.cmd {
            vfio::VFIO_DEVICE_SET_IRQS => self.handle_vfio_device_set_irqs(handle, system, msg),
            vfio::VFIO_DEVICE_GET_INFO => {
                if let Err(err) = validate_vfio_argsz(msg, 16) {
                    return Some(Message::reply(msg).with_error(err));
                }
                let longarg = !msg.body.is_empty() || msg.resp_size > 0;
                Some(handle.ioctl(msg, longarg))
            }
            vfio::VFIO_DEVICE_GET_REGION_INFO => {
                if let Err(err) = validate_vfio_argsz(msg, 32) {
                    return Some(Message::reply(msg).with_error(err));
                }
                let longarg = !msg.body.is_empty() || msg.resp_size > 0;
                Some(handle.ioctl(msg, longarg))
            }
            vfio::VFIO_DEVICE_GET_IRQ_INFO => {
                if let Err(err) = validate_vfio_argsz(msg, 16) {
                    return Some(Message::reply(msg).with_error(err));
                }
                let longarg = !msg.body.is_empty() || msg.resp_size > 0;
                Some(handle.ioctl(msg, longarg))
            }
            vfio::VFIO_DEVICE_RESET => {
                let longarg = !msg.body.is_empty() || msg.resp_size > 0;
                Some(handle.ioctl(msg, longarg))
            }
            _ => Some(Message::reply(msg).with_error(libc::ENOSYS as u64)),
        }
    }
}

impl HandleOps for VfioDeviceOps {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn get_type(&self) -> HandleType {
        HandleType::VfioDevice
    }

    fn handle_request(
        &self,
        handle: &Handle,
        system: &Arc<System>,
        msg: &Message,
        channel: &Arc<rpc::Channel>,
    ) -> Option<Message> {
        let op = Operation::from(msg.msg_type);
        debug!(
            "VfioDeviceOps::handle_request: id={}, op={:?}, cmd=0x{:x}",
            handle.id, op, msg.cmd
        );
        match op {
            Operation::GetFileDescriptor => Some(handle.get_fd_message(msg)),
            Operation::Ioctl => self.handle_ioctl(handle, system, msg, channel),
            _ => Some(Message {
                msg_type: msg.msg_type,
                request_id: msg.request_id,
                handle: msg.handle,
                status: libc::ENOSYS as u64,
                arg: msg.arg,
                cmd: msg.cmd,
                resp_size: 0,
                body: Vec::new(),
                fds: None,
            }),
        }
    }
}

pub struct VcpuOps {
    vm_id: u64,
    vcpu_id: u32,
    worker: Mutex<VcpuWorker>,
    _shm: Arc<VcpuSharedMemoryMapping>,
}

impl VcpuOps {
    pub fn new(
        vm_id: u64,
        vcpu_id: u32,
        vcpu_fd: RawFd,
        channel: Arc<rpc::Channel>,
        shm: Arc<VcpuSharedMemoryMapping>,
        shm_entry: *mut PerVcpuState,
    ) -> Self {
        VcpuOps {
            vm_id,
            vcpu_id,
            worker: Mutex::new(VcpuWorker::new(vcpu_fd, channel, shm_entry)),
            _shm: shm,
        }
    }

    fn handle_run(&self, handle: &Handle, msg: &Message) -> Option<Message> {
        trace!("VcpuOps: KVM_RUN on id={}", handle.id);
        let worker = self.worker.lock().unwrap();
        let _ = worker.sender.send(VcpuWork::Run(msg.clone()));
        worker.unpark();
        None
    }

    pub fn pause(&self) {
        self.worker.lock().unwrap().pause();
    }

    pub fn resume(&self) {
        self.worker.lock().unwrap().resume();
    }

    fn handle_ready(&self, handle: &Handle) -> Option<Message> {
        trace!("VcpuOps: Ready on id={}", handle.id);
        let worker = self.worker.lock().unwrap();
        worker.unpark();
        None
    }

    fn handle_get_stats_fd(
        &self,
        handle: &Handle,
        msg: &Message,
        channel: &Arc<rpc::Channel>,
    ) -> Option<Message> {
        let mut resp = handle.ioctl(msg, false);
        if resp.status == 0 {
            let stats_fd = resp.arg as RawFd;
            debug!(
                "VcpuOps: KVM_GET_STATS_FD on id={}, new fd={}",
                handle.id, stats_fd
            );
            resp.fds = Some(vec![stats_fd]);
            let _ = channel.send(&resp);
            unsafe { libc::close(stats_fd) };
        } else {
            let _ = channel.send(&resp);
        }
        None
    }

    fn handle_ioctl(
        &self,
        handle: &Handle,
        _system: &Arc<System>,
        msg: &Message,
        channel: &Arc<rpc::Channel>,
    ) -> Option<Message> {
        match msg.cmd {
            kvm::KVM_RUN => self.handle_run(handle, msg),
            kvm::KVM_GET_REGS
            | kvm::KVM_SET_REGS
            | kvm::KVM_GET_SREGS
            | kvm::KVM_SET_SREGS
            | kvm::KVM_GET_FPU
            | kvm::KVM_SET_FPU
            | kvm::KVM_GET_MP_STATE
            | kvm::KVM_SET_MP_STATE
            | kvm::KVM_GET_DEBUGREGS
            | kvm::KVM_SET_DEBUGREGS
            | kvm::KVM_GET_XCRS
            | kvm::KVM_SET_XCRS
            | kvm::KVM_SET_CPUID2
            | kvm::KVM_GET_CPUID2
            | kvm::KVM_GET_MSRS
            | kvm::KVM_SET_MSRS
            | kvm::KVM_GET_VCPU_EVENTS
            | kvm::KVM_SET_VCPU_EVENTS
            | kvm::KVM_GET_XSAVE
            | kvm::KVM_SET_XSAVE
            | kvm::KVM_GET_XSAVE2
            | kvm::KVM_GET_NESTED_STATE
            | kvm::KVM_SET_NESTED_STATE
            | kvm::KVM_ENABLE_CAP
            | kvm::KVM_TRANSLATE
            | kvm::KVM_INTERRUPT
            | kvm::KVM_GET_LAPIC
            | kvm::KVM_SET_LAPIC
            | kvm::KVM_SET_GUEST_DEBUG
            | kvm::KVM_X86_SETUP_MCE
            | kvm::KVM_X86_SET_MCE
            | kvm::KVM_TPR_ACCESS_REPORTING
            | kvm::KVM_SET_VAPIC_ADDR
            | kvm::KVM_SMI
            | kvm::KVM_GET_TSC_KHZ
            | kvm::KVM_SET_TSC_KHZ
            | kvm::KVM_KVMCLOCK_CTRL
            | kvm::KVM_GET_SREGS2
            | kvm::KVM_SET_SREGS2 => {
                let longarg = !msg.body.is_empty() || msg.resp_size > 0;
                Some(handle.ioctl(msg, longarg))
            }
            kvm::KVM_GET_STATS_FD => self.handle_get_stats_fd(handle, msg, channel),

            _ => Some(Message::reply(msg).with_error(libc::ENOSYS as u64)),
        }
    }
}

pub struct MemoryFileOps {
    size: u64,
    luo_id: String,
}

impl MemoryFileOps {
    pub fn new(size: u64, luo_id: String) -> Self {
        MemoryFileOps { size, luo_id }
    }
}

impl HandleOps for MemoryFileOps {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn handle_request(
        &self,
        handle: &Handle,
        _system: &Arc<System>,
        msg: &Message,
        _channel: &Arc<rpc::Channel>,
    ) -> Option<Message> {
        let op = Operation::from(msg.msg_type);
        debug!(
            "MemoryFileOps::handle_request: id=0x{:x}, op={:?}",
            handle.id, op
        );
        match op {
            Operation::GetFileDescriptor => Some(handle.get_fd_message(msg)),
            _ => Some(Message::reply(msg).with_error(libc::ENOSYS as u64)),
        }
    }

    fn save_state(
        &self,
        handle: &Handle,
        _system: &Arc<System>,
        writer: &mut dyn Write,
    ) -> Result<(), std::io::Error> {
        use prost::Message;
        let state = state::tachyon_state::MemoryFileState {
            id: handle.id,
            luo_id: self.luo_id.clone(),
            size: self.size,
        };
        let mut buf = Vec::new();
        state.encode(&mut buf).unwrap();

        let header = MsgHeader {
            msg_type: HandleType::MemoryFile as u32,
            size: buf.len() as u32,
        };

        // SAFETY: MsgHeader is POD
        let header_slice = unsafe {
            std::slice::from_raw_parts(
                &header as *const MsgHeader as *const u8,
                std::mem::size_of::<MsgHeader>(),
            )
        };
        writer.write_all(header_slice)?;
        writer.write_all(&buf)?;
        Ok(())
    }

    fn get_type(&self) -> HandleType {
        HandleType::MemoryFile
    }

    fn load_state(
        _system: &Arc<System>,
        state: &[u8],
        _channel: &Arc<rpc::Channel>,
    ) -> Result<Arc<Handle>, std::io::Error> {
        use prost::Message;
        let state = state::tachyon_state::MemoryFileState::decode(state).unwrap();
        let fd = luo_retrieve(&state.luo_id).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("LUO ID {} not found", state.luo_id),
            )
        })?;

        Ok(Handle::new(
            Some(state.id),
            Some(fd),
            Arc::new(MemoryFileOps::new(state.size, state.luo_id)),
        ))
    }
}

impl HandleOps for VcpuOps {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn handle_request(
        &self,
        handle: &Handle,
        system: &Arc<System>,
        msg: &Message,
        channel: &Arc<rpc::Channel>,
    ) -> Option<Message> {
        let op = Operation::from(msg.msg_type);
        trace!(
            "VcpuOps::handle_request: id=0x{:x}, op={:?}, cmd=0x{:x}",
            handle.id, op, msg.cmd
        );
        match op {
            Operation::Ioctl => self.handle_ioctl(handle, system, msg, channel),
            Operation::GetFileDescriptor => Some(handle.get_fd_message(msg)),
            Operation::Interrupt => {
                debug!("VcpuOps: Interrupt (kick) on id={}", handle.id);
                let worker = self.worker.lock().unwrap();
                worker.kick();
                None
            }
            Operation::Ready => self.handle_ready(handle),
            _ => Some(Message::reply(msg).with_error(libc::ENOSYS as u64)),
        }
    }

    fn save_state(
        &self,
        handle: &Handle,
        system: &Arc<System>,
        writer: &mut dyn Write,
    ) -> Result<(), std::io::Error> {
        use prost::Message;

        let get_state = |cmd: u64, size: usize| -> Vec<u8> {
            let mut buf = vec![0u8; size];
            let fd = handle.fd().unwrap();
            let ret = unsafe { libc::ioctl(fd, cmd as _, buf.as_mut_ptr()) };
            if ret < 0 {
                debug!("VcpuOps: save_state: ioctl 0x{:x} failed", cmd);
                Vec::new()
            } else {
                buf
            }
        };

        let regs = get_state(kvm::KVM_GET_REGS, std::mem::size_of::<kvm::kvm_regs>());
        let sregs = get_state(kvm::KVM_GET_SREGS, std::mem::size_of::<kvm::kvm_sregs>());
        let sregs2 = get_state(kvm::KVM_GET_SREGS2, std::mem::size_of::<kvm::kvm_sregs2>());
        let fpu = get_state(kvm::KVM_GET_FPU, std::mem::size_of::<kvm::kvm_fpu>());
        let lapic = get_state(
            kvm::KVM_GET_LAPIC,
            std::mem::size_of::<kvm::kvm_lapic_state>(),
        );
        let mp_state = get_state(
            kvm::KVM_GET_MP_STATE,
            std::mem::size_of::<kvm::kvm_mp_state>(),
        );
        let debugregs = get_state(
            kvm::KVM_GET_DEBUGREGS,
            std::mem::size_of::<kvm::kvm_debugregs>(),
        );
        let events = get_state(
            kvm::KVM_GET_VCPU_EVENTS,
            std::mem::size_of::<kvm::kvm_vcpu_events>(),
        );
        let xcrs = get_state(kvm::KVM_GET_XCRS, std::mem::size_of::<kvm::kvm_xcrs>());

        // CPUID
        let mut cpuid = vec![
            0u8;
            std::mem::size_of::<kvm::kvm_cpuid2>()
                + 100 * std::mem::size_of::<kvm::kvm_cpuid_entry2>()
        ];
        let cpuid_ptr = cpuid.as_mut_ptr() as *mut kvm::kvm_cpuid2;
        unsafe { (*cpuid_ptr).nent = 100 };
        let fd = handle.fd().unwrap();
        let ret = unsafe { libc::ioctl(fd, kvm::KVM_GET_CPUID2 as _, cpuid_ptr) };
        if ret < 0 {
            debug!("VcpuOps: save_state: KVM_GET_CPUID2 failed");
            cpuid = Vec::new();
        } else {
            let nent = unsafe { (*cpuid_ptr).nent };
            cpuid.truncate(
                std::mem::size_of::<kvm::kvm_cpuid2>()
                    + nent as usize * std::mem::size_of::<kvm::kvm_cpuid_entry2>(),
            );
        }

        // XSAVE
        let kvm_fd = {
            let kvm_handle = system.get_handle(1).unwrap();
            kvm_handle.fd().unwrap()
        };
        let xsave_size = unsafe {
            libc::ioctl(
                kvm_fd,
                kvm::KVM_CHECK_EXTENSION as _,
                kvm::KVM_CAP_XSAVE2 as libc::c_int,
            )
        };
        if xsave_size < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let xsave_size = xsave_size as usize;

        let mut xsave = vec![0u8; xsave_size];
        let mut ret = unsafe { libc::ioctl(fd, kvm::KVM_GET_XSAVE2 as _, xsave.as_mut_ptr()) };
        if ret < 0 {
            ret = unsafe { libc::ioctl(fd, kvm::KVM_GET_XSAVE as _, xsave.as_mut_ptr()) };
        }
        if ret < 0 {
            debug!("VcpuOps: save_state: KVM_GET_XSAVE/2 failed");
            xsave = Vec::new();
        }

        // MSRs
        let mut msr_list_header = vec![0u8; std::mem::size_of::<kvm::kvm_msr_list>()];
        let msr_list_header_ptr = msr_list_header.as_mut_ptr() as *mut kvm::kvm_msr_list;
        unsafe { (*msr_list_header_ptr).nmsrs = 0 };
        let _ = unsafe {
            libc::ioctl(
                kvm_fd,
                kvm::KVM_GET_MSR_INDEX_LIST as _,
                msr_list_header_ptr,
            )
        };
        let nmsrs = unsafe { (*msr_list_header_ptr).nmsrs };
        let mut msr_list =
            vec![0u8; std::mem::size_of::<kvm::kvm_msr_list>() + nmsrs as usize * 4 + 64];
        let msr_list_ptr = msr_list.as_mut_ptr() as *mut kvm::kvm_msr_list;
        unsafe { (*msr_list_ptr).nmsrs = nmsrs };
        let ret = unsafe { libc::ioctl(kvm_fd, kvm::KVM_GET_MSR_INDEX_LIST as _, msr_list_ptr) };
        let msrs = if ret < 0 {
            debug!("VcpuOps: save_state: KVM_GET_MSR_INDEX_LIST failed");
            Vec::new()
        } else {
            let nmsrs = unsafe { (*msr_list_ptr).nmsrs };
            let mut msrs_query = vec![
                0u8;
                std::mem::size_of::<kvm::kvm_msrs>()
                    + nmsrs as usize
                        * std::mem::size_of::<kvm::kvm_msr_entry>()
                    + 64
            ];
            let msrs_query_ptr = msrs_query.as_mut_ptr() as *mut kvm::kvm_msrs;
            unsafe { (*msrs_query_ptr).nmsrs = nmsrs };

            let entries_ptr = unsafe {
                msrs_query
                    .as_mut_ptr()
                    .add(std::mem::size_of::<kvm::kvm_msrs>())
                    as *mut kvm::kvm_msr_entry
            };
            let indices_ptr = unsafe {
                msr_list
                    .as_ptr()
                    .add(std::mem::size_of::<kvm::kvm_msr_list>()) as *const u32
            };
            for i in 0..nmsrs {
                unsafe {
                    (*entries_ptr.add(i as usize)).index = *indices_ptr.add(i as usize);
                }
            }

            let ret = unsafe { libc::ioctl(fd, kvm::KVM_GET_MSRS as _, msrs_query_ptr) };
            if ret < 0 {
                debug!("VcpuOps: save_state: KVM_GET_MSRS failed");
                Vec::new()
            } else {
                let actual_nmsrs = ret as u32;
                unsafe { (*msrs_query_ptr).nmsrs = actual_nmsrs };
                debug!(
                    "VcpuOps: save_state: KVM_GET_MSRS returned {}/{} MSRs",
                    actual_nmsrs, nmsrs
                );
                msrs_query.truncate(
                    std::mem::size_of::<kvm::kvm_msrs>()
                        + actual_nmsrs as usize * std::mem::size_of::<kvm::kvm_msr_entry>(),
                );
                msrs_query
            }
        };

        // Nested State
        let nested_size = unsafe {
            libc::ioctl(
                kvm_fd,
                kvm::KVM_CHECK_EXTENSION as _,
                kvm::KVM_CAP_NESTED_STATE as libc::c_int,
            )
        };
        let nested_state = if nested_size > 0 {
            let mut buf = vec![0u8; nested_size as usize + 64];
            let ns_ptr = buf.as_mut_ptr() as *mut kvm::kvm_nested_state;
            unsafe { (*ns_ptr).size = nested_size as u32 };
            let ret = unsafe { libc::ioctl(fd, kvm::KVM_GET_NESTED_STATE as _, buf.as_mut_ptr()) };
            if ret < 0 {
                debug!("VcpuOps: save_state: KVM_GET_NESTED_STATE failed");
                Vec::new()
            } else {
                buf
            }
        } else {
            Vec::new()
        };

        // TSC
        let tsc_query = kvm::kvm_msrs { nmsrs: 1, pad: 0 };
        let tsc_entry = kvm::kvm_msr_entry {
            index: kvm::MSR_IA32_TSC,
            reserved: 0,
            data: 0,
        };
        let mut tsc_buf = vec![0u8; 4096];
        unsafe {
            std::ptr::copy_nonoverlapping(
                &tsc_query as *const kvm::kvm_msrs as *const u8,
                tsc_buf.as_mut_ptr(),
                std::mem::size_of::<kvm::kvm_msrs>(),
            );
            std::ptr::copy_nonoverlapping(
                &tsc_entry as *const kvm::kvm_msr_entry as *const u8,
                tsc_buf
                    .as_mut_ptr()
                    .add(std::mem::size_of::<kvm::kvm_msrs>()),
                std::mem::size_of::<kvm::kvm_msr_entry>(),
            );
        }
        let ret = unsafe { libc::ioctl(fd, kvm::KVM_GET_MSRS as _, tsc_buf.as_mut_ptr()) };
        let tsc = if ret < 0 {
            debug!("VcpuOps: save_state: KVM_GET_MSRS (TSC) failed");
            0
        } else {
            let entry_ptr = unsafe {
                tsc_buf.as_ptr().add(std::mem::size_of::<kvm::kvm_msrs>())
                    as *const kvm::kvm_msr_entry
            };
            unsafe { std::ptr::read_unaligned(entry_ptr).data }
        };

        let state = state::tachyon_state::VcpuState {
            id: handle.id,
            vm_id: self.vm_id,
            vcpu_id: self.vcpu_id,
            regs,
            sregs,
            fpu,
            cpuid,
            lapic,
            xsave,
            xcrs,
            debugregs,
            events,
            mp_state,
            msrs,
            nested_state,
            tsc,
            sregs2,
        };

        let mut buf = Vec::new();
        state.encode(&mut buf).unwrap();

        let header = MsgHeader {
            msg_type: HandleType::Vcpu as u32,
            size: buf.len() as u32,
        };

        // SAFETY: MsgHeader is POD
        let header_slice = unsafe {
            std::slice::from_raw_parts(
                &header as *const MsgHeader as *const u8,
                std::mem::size_of::<MsgHeader>(),
            )
        };
        writer.write_all(header_slice)?;
        writer.write_all(&buf)?;
        Ok(())
    }

    fn get_type(&self) -> HandleType {
        HandleType::Vcpu
    }

    fn load_state(
        system: &Arc<System>,
        state: &[u8],
        channel: &Arc<rpc::Channel>,
    ) -> Result<Arc<Handle>, std::io::Error> {
        use prost::Message;
        let state = state::tachyon_state::VcpuState::decode(state).unwrap();
        let vm_handle = system
            .get_handle(state.vm_id)
            .ok_or_else(|| std::io::Error::other("VM handle not found"))?;
        let vm_fd = vm_handle.fd().unwrap();
        let vcpu_fd = unsafe {
            libc::ioctl(
                vm_fd,
                kvm::KVM_CREATE_VCPU as _,
                state.vcpu_id as libc::c_int,
            )
        };
        if vcpu_fd < 0 {
            return Err(std::io::Error::last_os_error());
        }

        let vm_ops = vm_handle
            .ops
            .as_any()
            .downcast_ref::<VmOps>()
            .ok_or_else(|| std::io::Error::other("VM handle is not VmOps"))?;
        let shm_entry = unsafe {
            &mut (*vm_ops.shared_memory.addr).vcpus[state.vcpu_id as usize] as *mut PerVcpuState
        };

        let set_state = |cmd: u64, data: &[u8]| -> Result<(), std::io::Error> {
            if data.is_empty() {
                return Ok(());
            }
            let ret = unsafe { libc::ioctl(vcpu_fd, cmd as _, data.as_ptr()) };
            if ret < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        };

        set_state(kvm::KVM_SET_CPUID2, &state.cpuid)?;
        set_state(kvm::KVM_SET_REGS, &state.regs)?;
        if !state.sregs2.is_empty() {
            set_state(kvm::KVM_SET_SREGS2, &state.sregs2)?;
        } else {
            set_state(kvm::KVM_SET_SREGS, &state.sregs)?;
        }
        set_state(kvm::KVM_SET_FPU, &state.fpu)?;
        set_state(kvm::KVM_SET_LAPIC, &state.lapic)?;
        set_state(kvm::KVM_SET_MP_STATE, &state.mp_state)?;
        set_state(kvm::KVM_SET_DEBUGREGS, &state.debugregs)?;

        if !state.events.is_empty() {
            let mut events = kvm::kvm_vcpu_events::default();
            unsafe {
                std::ptr::copy_nonoverlapping(
                    state.events.as_ptr(),
                    &mut events as *mut _ as *mut u8,
                    std::cmp::min(
                        state.events.len(),
                        std::mem::size_of::<kvm::kvm_vcpu_events>(),
                    ),
                );
            }
            let ret = unsafe { libc::ioctl(vcpu_fd, kvm::KVM_SET_VCPU_EVENTS as _, &events) };
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                debug!(
                    "VcpuOps: load_state: KVM_SET_VCPU_EVENTS failed: {}. Ignoring.",
                    err
                );
            }
        }

        set_state(kvm::KVM_SET_XCRS, &state.xcrs)?;
        set_state(kvm::KVM_SET_XSAVE, &state.xsave)?;

        set_state(kvm::KVM_SET_MSRS, &state.msrs)?;

        if !state.nested_state.is_empty() {
            // Ensure the buffer is aligned for the ioctl
            let mut aligned_buf = vec![0u8; state.nested_state.len()];
            aligned_buf.copy_from_slice(&state.nested_state);
            let ret = unsafe {
                libc::ioctl(
                    vcpu_fd,
                    kvm::KVM_SET_NESTED_STATE as _,
                    aligned_buf.as_ptr(),
                )
            };
            if ret < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }

        // Restore TSC last to ensure it's as accurate as possible and not overwritten.
        let tsc_query = kvm::kvm_msrs { nmsrs: 1, pad: 0 };
        let tsc_entry = kvm::kvm_msr_entry {
            index: kvm::MSR_IA32_TSC,
            reserved: 0,
            data: state.tsc,
        };
        let mut tsc_buf = vec![0u8; 4096];
        unsafe {
            std::ptr::copy_nonoverlapping(
                &tsc_query as *const kvm::kvm_msrs as *const u8,
                tsc_buf.as_mut_ptr(),
                std::mem::size_of::<kvm::kvm_msrs>(),
            );
            std::ptr::copy_nonoverlapping(
                &tsc_entry as *const kvm::kvm_msr_entry as *const u8,
                tsc_buf
                    .as_mut_ptr()
                    .add(std::mem::size_of::<kvm::kvm_msrs>()),
                std::mem::size_of::<kvm::kvm_msr_entry>(),
            );
        }
        let ret = unsafe { libc::ioctl(vcpu_fd, kvm::KVM_SET_MSRS as _, tsc_buf.as_mut_ptr()) };
        if ret < 0 {
            debug!("VcpuOps: load_state: KVM_SET_MSRS (TSC) failed");
        }

        let vcpu_ops = VcpuOps::new(
            state.vm_id,
            state.vcpu_id,
            vcpu_fd,
            channel.clone(),
            vm_ops.shared_memory.clone(),
            shm_entry,
        );
        Ok(Handle::new(
            Some(state.id),
            Some(vcpu_fd),
            Arc::new(vcpu_ops),
        ))
    }
}

impl HandleOps for VmOps {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn cleanup(&self, _handle: &Handle, system: &Arc<System>) {
        let vcpus = self.vcpus.lock().unwrap();
        debug!("VmOps: cleaning up {} VCPUs", vcpus.len());
        for &vcpu_id in vcpus.iter() {
            system.remove_handle(vcpu_id);
        }
    }

    fn handle_request(
        &self,
        handle: &Handle,
        system: &Arc<System>,
        msg: &Message,
        channel: &Arc<rpc::Channel>,
    ) -> Option<Message> {
        let op = Operation::from(msg.msg_type);
        trace!(
            "VmOps::handle_request: id=0x{:x}, op={:?}, cmd=0x{:x}",
            handle.id, op, msg.cmd
        );
        match op {
            Operation::Ioctl => self.handle_ioctl(handle, system, msg, channel),
            Operation::GetFileDescriptor => {
                let vm_fd = handle.fd().unwrap();
                let shm_fd = self.get_shm_fd();
                let mut resp = Message::reply(msg);
                resp.fds = Some(vec![shm_fd, vm_fd]);
                Some(resp)
            }
            _ => Some(Message::reply(msg).with_error(libc::ENOSYS as u64)),
        }
    }

    fn save_state(
        &self,
        handle: &Handle,
        _system: &Arc<System>,
        writer: &mut dyn Write,
    ) -> Result<(), std::io::Error> {
        use prost::Message;
        let regions = self.regions.lock().unwrap();
        let mut proto_regions = Vec::new();
        for m in regions.values() {
            proto_regions.push(state::tachyon_state::vm_state::MemoryRegion {
                slot: m.region.slot,
                flags: m.region.flags,
                guest_phys_addr: m.region.guest_phys_addr,
                memory_size: m.region.memory_size,
                guest_memfd: m.guest_memfd_handle,
                guest_memfd_offset: m.region.guest_memfd_offset,
                userspace_addr: m.addr,
            });
        }

        let mut irqchips = Vec::new();
        if self.has_irqchip.load(Ordering::Acquire) {
            for chip_id in 0..3 {
                let mut chip = kvm::kvm_irqchip {
                    chip_id,
                    ..Default::default()
                };
                let ret = unsafe {
                    libc::ioctl(handle.fd().unwrap(), kvm::KVM_GET_IRQCHIP as _, &mut chip)
                };
                if ret >= 0 {
                    let mut chip_buf = vec![0u8; std::mem::size_of::<kvm::kvm_irqchip>()];
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            &chip,
                            chip_buf.as_mut_ptr() as *mut kvm::kvm_irqchip,
                            1,
                        );
                    }
                    irqchips.push(state::tachyon_state::vm_state::IrqChip {
                        chip_id,
                        chip: chip_buf,
                    });
                }
            }
        }

        let mut pit_state = Vec::new();
        if self.has_pit.load(Ordering::Acquire) {
            let mut state = kvm::kvm_pit_state2::default();
            let ret =
                unsafe { libc::ioctl(handle.fd().unwrap(), kvm::KVM_GET_PIT2 as _, &mut state) };
            if ret >= 0 {
                pit_state = vec![0u8; std::mem::size_of::<kvm::kvm_pit_state2>()];
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        &state,
                        pit_state.as_mut_ptr() as *mut kvm::kvm_pit_state2,
                        1,
                    );
                }
            }
        }

        let mut proto_ioeventfds = Vec::new();
        let ioeventfds_configs = self.ioeventfds_configs.lock().unwrap();
        println!(
            "VmOps: save_state: Serializing {} ioeventfds",
            ioeventfds_configs.len()
        );
        for (ioeventfd, handle_id) in &*ioeventfds_configs {
            let mut config = vec![0u8; std::mem::size_of::<kvm_ioeventfd>()];
            unsafe {
                std::ptr::copy_nonoverlapping(
                    ioeventfd as *const _ as *const u8,
                    config.as_mut_ptr(),
                    config.len(),
                );
            }
            proto_ioeventfds.push(state::tachyon_state::vm_state::Ioeventfd {
                config,
                eventfd_handle: *handle_id,
            });
        }

        let mut proto_irqfds = Vec::new();
        for (irqfd, fd_handle_id, resamplefd_handle_id) in &*self.irqfds_configs.lock().unwrap() {
            let mut config = vec![0u8; std::mem::size_of::<kvm_irqfd>()];
            unsafe {
                std::ptr::copy_nonoverlapping(
                    irqfd as *const _ as *const u8,
                    config.as_mut_ptr(),
                    config.len(),
                );
            }
            proto_irqfds.push(state::tachyon_state::vm_state::Irqfd {
                config,
                eventfd_handle: *fd_handle_id,
                resamplefd_handle: *resamplefd_handle_id,
            });
        }

        let mut clock = vec![0u8; std::mem::size_of::<kvm::kvm_clock_data>()];
        let ret = unsafe {
            libc::ioctl(
                handle.fd().unwrap(),
                kvm::KVM_GET_CLOCK as _,
                clock.as_mut_ptr(),
            )
        };
        if ret < 0 {
            debug!("VmOps: save_state: KVM_GET_CLOCK failed");
            clock = Vec::new();
        }

        let luo_id = luo_preserve(self.shared_memory.fd());
        let state = state::tachyon_state::VmState {
            id: handle.id,
            regions: proto_regions,
            irqchips,
            msr_filter: self.msr_filter.lock().unwrap().clone().unwrap_or_default(),
            has_irqchip: self.has_irqchip.load(Ordering::Acquire),
            eventfds: Vec::new(),
            luo_id,
            has_pit: self.has_pit.load(Ordering::Acquire),
            pit_config: self.pit_config.lock().unwrap().clone().unwrap_or_default(),
            pit_state,
            enabled_caps: self.enabled_caps.lock().unwrap().clone(),
            gsi_routing: self.gsi_routing.lock().unwrap().clone().unwrap_or_default(),
            ioeventfds_configs: proto_ioeventfds,
            irqfds_configs: proto_irqfds,
            tss_addr: self.tss_addr.load(Ordering::Acquire),
            identity_map_addr: self.identity_map_addr.load(Ordering::Acquire),
            pmu_event_filter: self
                .pmu_event_filter
                .lock()
                .unwrap()
                .clone()
                .unwrap_or_default(),
            clock,
        };

        let mut buf = Vec::new();
        state.encode(&mut buf).unwrap();

        let header = MsgHeader {
            msg_type: HandleType::Vm as u32,
            size: buf.len() as u32,
        };

        // SAFETY: MsgHeader is POD
        let header_slice = unsafe {
            std::slice::from_raw_parts(
                &header as *const MsgHeader as *const u8,
                std::mem::size_of::<MsgHeader>(),
            )
        };
        writer.write_all(header_slice)?;
        writer.write_all(&buf)?;
        Ok(())
    }

    fn get_type(&self) -> HandleType {
        HandleType::Vm
    }

    fn load_state(
        system: &Arc<System>,
        state: &[u8],
        _channel: &Arc<rpc::Channel>,
    ) -> Result<Arc<Handle>, std::io::Error> {
        use prost::Message;
        let state = state::tachyon_state::VmState::decode(state).unwrap();
        let kvm_handle = system
            .get_handle(1)
            .ok_or_else(|| std::io::Error::other("KVM handle not found"))?;
        let kvm_fd = kvm_handle.fd().unwrap();
        let vm_fd = unsafe { libc::ioctl(kvm_fd, kvm::KVM_CREATE_VM as _, 0) };
        if vm_fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        warn!(
            "VmOps: load_state: Created new VM id=0x{:x}, fd={}",
            state.id, vm_fd
        );

        let shared_memory = if !state.luo_id.is_empty() {
            let fd = luo_retrieve(&state.luo_id).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("LUO ID {} for SHM not found", state.luo_id),
                )
            })?;
            Arc::new(VcpuSharedMemoryMapping::from_fd(fd))
        } else {
            Arc::new(VcpuSharedMemoryMapping::new())
        };

        let vm_ops = Arc::new(VmOps {
            regions: Mutex::new(HashMap::new()),
            vcpus: Mutex::new(Vec::new()),
            shared_memory,
            has_irqchip: std::sync::atomic::AtomicBool::new(false),
            has_pit: std::sync::atomic::AtomicBool::new(false),
            pit_config: Mutex::new(None),
            enabled_caps: Mutex::new(Vec::new()),
            gsi_routing: Mutex::new(None),
            msr_filter: Mutex::new(None),
            ioeventfds_configs: Mutex::new(Vec::new()),
            irqfds_configs: Mutex::new(Vec::new()),
            tss_addr: AtomicU64::new(0),
            identity_map_addr: AtomicU64::new(0),
            pmu_event_filter: Mutex::new(None),
        });

        if state.has_irqchip {
            let ret = unsafe { libc::ioctl(vm_fd, kvm::KVM_CREATE_IRQCHIP as _, 0) };
            if ret < 0 {
                return Err(std::io::Error::last_os_error());
            }
            vm_ops.has_irqchip.store(true, Ordering::SeqCst);
            for chip in state.irqchips {
                let ret =
                    unsafe { libc::ioctl(vm_fd, kvm::KVM_SET_IRQCHIP as _, chip.chip.as_ptr()) };
                if ret < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
        }

        if state.has_pit {
            let ret = if !state.pit_config.is_empty() {
                unsafe { libc::ioctl(vm_fd, kvm::KVM_CREATE_PIT2 as _, state.pit_config.as_ptr()) }
            } else {
                unsafe { libc::ioctl(vm_fd, kvm::KVM_CREATE_PIT as _, 0) }
            };
            if ret < 0 {
                return Err(std::io::Error::last_os_error());
            }
            vm_ops.has_pit.store(true, Ordering::SeqCst);
            if !state.pit_config.is_empty() {
                *vm_ops.pit_config.lock().unwrap() = Some(state.pit_config);
            }
            if !state.pit_state.is_empty() {
                let ret =
                    unsafe { libc::ioctl(vm_fd, kvm::KVM_SET_PIT2 as _, state.pit_state.as_ptr()) };
                if ret < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
        }

        for cap in state.enabled_caps {
            let ret = unsafe { libc::ioctl(vm_fd, kvm::KVM_ENABLE_CAP as _, cap.as_ptr()) };
            if ret < 0 {
                return Err(std::io::Error::last_os_error());
            }
            vm_ops.enabled_caps.lock().unwrap().push(cap);
        }

        if !state.gsi_routing.is_empty() {
            let ret = unsafe {
                libc::ioctl(
                    vm_fd,
                    kvm::KVM_SET_GSI_ROUTING as _,
                    state.gsi_routing.as_ptr(),
                )
            };
            if ret < 0 {
                return Err(std::io::Error::last_os_error());
            }
            *vm_ops.gsi_routing.lock().unwrap() = Some(state.gsi_routing);
        }

        if !state.msr_filter.is_empty() {
            let msg = crate::rpc::Message {
                body: state.msr_filter.clone(),
                ..Default::default()
            };
            let mut filter =
                unsafe { std::ptr::read(msg.body.as_ptr() as *const kvm::kvm_msr_filter) };
            let mut bitmaps = Vec::new();
            for range in filter.ranges.iter_mut() {
                if range.nmsrs == 0 {
                    continue;
                }
                let offset = range.bitmap as usize;
                let bitmap_size = range.nmsrs.div_ceil(8) as usize;
                let mut bitmap_buf = vec![0u8; bitmap_size];
                bitmap_buf.copy_from_slice(&msg.body[offset..offset + bitmap_size]);
                bitmaps.push(bitmap_buf);
                range.bitmap = bitmaps.last().unwrap().as_ptr() as u64;
            }
            let ret = unsafe { libc::ioctl(vm_fd, kvm::KVM_X86_SET_MSR_FILTER as _, &filter) };
            if ret < 0 {
                return Err(std::io::Error::last_os_error());
            }
            *vm_ops.msr_filter.lock().unwrap() = Some(state.msr_filter);
        }

        if state.tss_addr != 0 {
            let ret = unsafe {
                libc::ioctl(
                    vm_fd,
                    kvm::KVM_SET_TSS_ADDR as _,
                    state.tss_addr as libc::c_ulong,
                )
            };
            if ret < 0 {
                return Err(std::io::Error::last_os_error());
            }
            vm_ops.tss_addr.store(state.tss_addr, Ordering::Release);
        }

        if state.identity_map_addr != 0 {
            let ret = unsafe {
                libc::ioctl(
                    vm_fd,
                    kvm::KVM_SET_IDENTITY_MAP_ADDR as _,
                    &state.identity_map_addr,
                )
            };
            if ret < 0 {
                return Err(std::io::Error::last_os_error());
            }
            vm_ops
                .identity_map_addr
                .store(state.identity_map_addr, Ordering::Release);
        }

        if !state.pmu_event_filter.is_empty() {
            let ret = unsafe {
                libc::ioctl(
                    vm_fd,
                    kvm::KVM_SET_PMU_EVENT_FILTER as _,
                    state.pmu_event_filter.as_ptr(),
                )
            };
            if ret < 0 {
                return Err(std::io::Error::last_os_error());
            }
            *vm_ops.pmu_event_filter.lock().unwrap() = Some(state.pmu_event_filter);
        }

        if !state.clock.is_empty() {
            let ret = unsafe { libc::ioctl(vm_fd, kvm::KVM_SET_CLOCK as _, state.clock.as_ptr()) };
            if ret < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }

        // Restore regions
        for region in state.regions {
            if region.guest_memfd == 0 {
                error!(
                    "VmOps: load_state: Memory region slot {} has no guest_memfd handle",
                    region.slot
                );
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Missing guest_memfd handle",
                ));
            }

            // We need the memfd for the region.
            let mem_handle = system.get_handle(region.guest_memfd).ok_or_else(|| {
                error!(
                    "VmOps: load_state: Memfd handle id=0x{:x} not found for region slot {}",
                    region.guest_memfd, region.slot
                );
                std::io::Error::other("Memfd handle not found")
            })?;
            let mem_fd = mem_handle.fd().unwrap();

            let mmap_addr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    region.memory_size as usize,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED | libc::MAP_FILE,
                    mem_fd,
                    region.guest_memfd_offset as libc::off_t,
                )
            };

            if mmap_addr == libc::MAP_FAILED {
                let err = std::io::Error::last_os_error();
                error!(
                    "VmOps: load_state: mmap failed for region slot {}: {}",
                    region.slot, err
                );
                return Err(err);
            }

            let region2 = kvm::kvm_userspace_memory_region2 {
                slot: region.slot,
                flags: region.flags,
                guest_phys_addr: region.guest_phys_addr,
                memory_size: region.memory_size,
                userspace_addr: mmap_addr as u64,
                guest_memfd_offset: region.guest_memfd_offset,
                ..Default::default()
            };

            let ret =
                unsafe { libc::ioctl(vm_fd, kvm::KVM_SET_USER_MEMORY_REGION2 as _, &region2) };

            if ret < 0 {
                // Fallback to KVM_SET_USER_MEMORY_REGION
                let kvm_region = kvm_userspace_memory_region {
                    slot: region.slot,
                    flags: region.flags,
                    guest_phys_addr: region.guest_phys_addr,
                    memory_size: region.memory_size,
                    userspace_addr: mmap_addr as u64,
                };
                let ret = unsafe {
                    libc::ioctl(vm_fd, kvm::KVM_SET_USER_MEMORY_REGION as _, &kvm_region)
                };
                if ret < 0 {
                    let err = std::io::Error::last_os_error();
                    error!(
                        "VmOps: load_state: KVM_SET_USER_MEMORY_REGION failed for slot {}: {}",
                        region.slot, err
                    );
                    return Err(err);
                }
            }

            warn!(
                "VmOps: load_state: Memory region restored: slot={}, gpa=0x{:x}, size=0x{:x}, memfd_handle=0x{:x}",
                region.slot, region.guest_phys_addr, region.memory_size, region.guest_memfd
            );

            let mut regions = vm_ops.regions.lock().unwrap();
            regions.insert(
                region.slot as u64,
                MemoryMapping {
                    addr: mmap_addr as u64,
                    size: region.memory_size as usize,
                    region: region2,
                    guest_memfd_handle: region.guest_memfd,
                },
            );
        }

        warn!(
            "VmOps: load_state: Decoding {} ioeventfds",
            state.ioeventfds_configs.len()
        );
        // Restore ioeventfds
        for ioeventfd_state in state.ioeventfds_configs {
            let mut ioeventfd = unsafe {
                std::ptr::read(ioeventfd_state.config.as_ptr() as *const kvm::kvm_ioeventfd)
            };
            if ioeventfd_state.eventfd_handle != 0 {
                let eventfd_handle = system
                    .get_handle(ioeventfd_state.eventfd_handle)
                    .ok_or_else(|| {
                        error!(
                            "VmOps: load_state: Ioeventfd eventfd handle id=0x{:x} not found",
                            ioeventfd_state.eventfd_handle
                        );
                        std::io::Error::other("Ioeventfd eventfd handle not found")
                    })?;
                ioeventfd.fd = eventfd_handle.fd().unwrap();
                error!(
                    "VmOps: load_state: Attempting KVM_IOEVENTFD: addr=0x{:x}, len={}, fd={}, flags=0x{:x}, datamatch=0x{:x}",
                    ioeventfd.addr,
                    ioeventfd.len,
                    ioeventfd.fd,
                    ioeventfd.flags,
                    ioeventfd.datamatch
                );
            } else {
                if (ioeventfd.flags & kvm::KVM_IOEVENTFD_FLAG_DEASSIGN) != 0 {
                    ioeventfd.fd = -1;
                    error!(
                        "VmOps: load_state: Attempting KVM_IOEVENTFD (deassign): addr=0x{:x}, len={}, fd=-1, flags=0x{:x}, datamatch=0x{:x}",
                        ioeventfd.addr, ioeventfd.len, ioeventfd.flags, ioeventfd.datamatch
                    );
                } else {
                    error!(
                        "VmOps: load_state: Attempting KVM_IOEVENTFD (assignment without handle): addr=0x{:x}, len={}, fd={}, flags=0x{:x}, datamatch=0x{:x}",
                        ioeventfd.addr,
                        ioeventfd.len,
                        ioeventfd.fd,
                        ioeventfd.flags,
                        ioeventfd.datamatch
                    );
                }
            }

            let ret = unsafe { libc::ioctl(vm_fd, kvm::KVM_IOEVENTFD as _, &ioeventfd) };
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                error!(
                    "VmOps: load_state: KVM_IOEVENTFD failed: {} (addr=0x{:x}, fd={})",
                    err, ioeventfd.addr, ioeventfd.fd
                );
                return Err(err);
            }
            vm_ops
                .ioeventfds_configs
                .lock()
                .unwrap()
                .push((ioeventfd, ioeventfd_state.eventfd_handle));
        }

        warn!(
            "VmOps: load_state: Decoding {} irqfds",
            state.irqfds_configs.len()
        );
        // Restore irqfds
        for irqfd_state in state.irqfds_configs {
            let mut irqfd =
                unsafe { std::ptr::read(irqfd_state.config.as_ptr() as *const kvm::kvm_irqfd) };
            if irqfd_state.eventfd_handle != 0 {
                let eventfd_handle =
                    system
                        .get_handle(irqfd_state.eventfd_handle)
                        .ok_or_else(|| {
                            error!(
                                "VmOps: load_state: Irqfd eventfd handle id=0x{:x} not found",
                                irqfd_state.eventfd_handle
                            );
                            std::io::Error::other("Irqfd eventfd handle not found")
                        })?;
                irqfd.fd = eventfd_handle.fd().unwrap() as u32;
            }
            if irqfd_state.resamplefd_handle != 0 {
                let resamplefd_handle = system
                    .get_handle(irqfd_state.resamplefd_handle)
                    .ok_or_else(|| {
                        error!(
                            "VmOps: load_state: Irqfd resamplefd handle id=0x{:x} not found",
                            irqfd_state.resamplefd_handle
                        );
                        std::io::Error::other("Irqfd resamplefd handle not found")
                    })?;
                irqfd.resamplefd = resamplefd_handle.fd().unwrap() as u32;
            }

            error!(
                "VmOps: load_state: Attempting KVM_IRQFD: gsi={}, fd={}, resamplefd={}, flags=0x{:x}",
                irqfd.gsi, irqfd.fd, irqfd.resamplefd, irqfd.flags
            );
            let ret = unsafe { libc::ioctl(vm_fd, kvm::KVM_IRQFD as _, &irqfd) };
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                error!(
                    "VmOps: load_state: KVM_IRQFD failed: {} (gsi={}, fd={}, resamplefd={})",
                    err, irqfd.gsi, irqfd.fd, irqfd.resamplefd
                );
                return Err(err);
            }
            error!("VmOps: load_state: KVM_IRQFD success (gsi={})", irqfd.gsi);
            vm_ops.irqfds_configs.lock().unwrap().push((
                irqfd,
                irqfd_state.eventfd_handle,
                irqfd_state.resamplefd_handle,
            ));
        }

        Ok(Handle::new(Some(state.id), Some(vm_fd), vm_ops))
    }
}

impl Default for KvmDeviceOps {
    fn default() -> Self {
        Self::new()
    }
}

impl KvmDeviceOps {
    pub fn new() -> KvmDeviceOps {
        KvmDeviceOps {
            eventfds: Mutex::new(Vec::new()),
        }
    }
    fn handle_memory_file_create(
        &self,
        _handle: &Handle,
        system: &Arc<System>,
        msg: &Message,
    ) -> Message {
        debug!("KvmDeviceOps: MemoryFileCreate size={}", msg.arg);
        let name = std::ffi::CString::new("tachyon-memfd").unwrap();
        let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
        if fd < 0 {
            let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            debug!("KvmDeviceOps: memfd_create failed: errno={}", err);
            return Message::reply(msg).with_error(err as u64);
        }

        let size = msg.arg;
        if unsafe { libc::ftruncate(fd, size as libc::off_t) } < 0 {
            let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u64;
            debug!("KvmDeviceOps: ftruncate failed: errno={}", err);
            unsafe { libc::close(fd) };
            return Message::reply(msg).with_error(err);
        }

        let luo_id = luo_preserve(fd);
        let mem_handle = Handle::new(None, Some(fd), Arc::new(MemoryFileOps::new(size, luo_id)));
        let mem_handle_id = mem_handle.id();
        system.add_handle(mem_handle);
        debug!(
            "KvmDeviceOps: Created memfd id={}, fd={}",
            mem_handle_id, fd
        );

        let mut resp = Message::reply(msg);
        resp.handle = mem_handle_id;
        resp.fds = Some(vec![fd]);
        resp
    }

    fn handle_open_vfio_container(
        &self,
        handle: &Handle,
        system: &Arc<System>,
        msg: &Message,
    ) -> Message {
        let vfio_path = std::ffi::CString::new("/dev/vfio/vfio").unwrap();
        let vfio_fd = unsafe { libc::open(vfio_path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if vfio_fd < 0 {
            let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u64;
            return Message::reply(msg).with_error(err);
        }

        debug!(
            "KvmDeviceOps: open VFIO container on id={}, new fd={}",
            handle.id, vfio_fd
        );
        let vfio_ops = Arc::new(VfioContainerOps::new());
        let vfio_handle = Handle::new(None, Some(vfio_fd), vfio_ops);
        let vfio_handle_id = vfio_handle.id();
        system.add_handle(vfio_handle);

        let mut resp = Message::reply(msg);
        resp.handle = vfio_handle_id;
        resp
    }

    fn get_group_path(msg: &Message) -> String {
        format!("/dev/vfio/{}", msg.arg)
    }

    fn handle_open_vfio_group(
        &self,
        handle: &Handle,
        system: &Arc<System>,
        msg: &Message,
    ) -> Message {
        let vfio_path = std::ffi::CString::new({
            let p = Self::get_group_path(msg);
            debug!("VfioGroup: attempting to open {}", p);
            p
        })
        .unwrap();
        let vfio_fd = unsafe { libc::open(vfio_path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if vfio_fd < 0 {
            let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u64;
            return Message::reply(msg).with_error(err);
        }

        debug!(
            "KvmDeviceOps: open VFIO group on id={}, new fd={}",
            handle.id, vfio_fd
        );
        let vfio_ops = Arc::new(VfioGroupOps::new());
        let vfio_handle = Handle::new(None, Some(vfio_fd), vfio_ops);
        let vfio_handle_id = vfio_handle.id();
        system.add_handle(vfio_handle);

        let mut resp = Message::reply(msg);
        resp.handle = vfio_handle_id;
        resp
    }

    fn handle_create_vm(&self, handle: &Handle, system: &Arc<System>, msg: &Message) -> Message {
        let mut resp = handle.ioctl(msg, false);
        if resp.status == 0 {
            let vm_fd = resp.arg as RawFd;
            debug!(
                "KvmDeviceOps: KVM_CREATE_VM on id={}, new fd={}",
                handle.id, vm_fd
            );
            let vm_ops = Arc::new(VmOps::new());
            let shm_fd = vm_ops.get_shm_fd();
            let vm_handle = Handle::new(None, Some(vm_fd), vm_ops);
            let vm_handle_id = vm_handle.id();
            system.add_handle(vm_handle);
            resp.handle = vm_handle_id;
            resp.fds = Some(vec![shm_fd]);
        }
        resp
    }

    fn handle_ioctl(
        &self,
        handle: &Handle,
        system: &Arc<System>,
        msg: &Message,
    ) -> Option<Message> {
        match msg.cmd {
            kvm::KVM_GET_API_VERSION | kvm::KVM_GET_VCPU_MMAP_SIZE | kvm::KVM_CHECK_EXTENSION => {
                Some(handle.ioctl(msg, false))
            }
            kvm::KVM_GET_SUPPORTED_CPUID
            | kvm::KVM_GET_MSRS
            | kvm::KVM_GET_MSR_INDEX_LIST
            | kvm::KVM_GET_MSR_FEATURE_INDEX_LIST => Some(handle.ioctl(msg, true)),
            kvm::KVM_CREATE_VM => Some(self.handle_create_vm(handle, system, msg)),
            _ => Some(Message::reply(msg).with_error(libc::ENOSYS as u64)),
        }
    }
}

impl HandleOps for KvmDeviceOps {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn cleanup(&self, _handle: &Handle, system: &Arc<System>) {
        let eventfds = self.eventfds.lock().unwrap();
        debug!("KvmDeviceOps: cleaning up {} eventfds", eventfds.len());
        for &eventfd_id in eventfds.iter() {
            system.remove_handle(eventfd_id);
        }
    }

    fn handle_request(
        &self,
        handle: &Handle,
        system: &Arc<System>,
        msg: &Message,
        _channel: &Arc<rpc::Channel>,
    ) -> Option<Message> {
        let op = Operation::from(msg.msg_type);
        debug!(
            "KvmDeviceOps::handle_request: id=0x{:x}, op={:?}, cmd=0x{:x}",
            handle.id, op, msg.cmd
        );
        match op {
            Operation::GetFileDescriptor => Some(handle.get_fd_message(msg)),
            Operation::MemoryFileCreate => {
                Some(self.handle_memory_file_create(handle, system, msg))
            }
            Operation::OpenVfioContainer => {
                Some(self.handle_open_vfio_container(handle, system, msg))
            }
            Operation::OpenVfioGroup => Some(self.handle_open_vfio_group(handle, system, msg)),
            Operation::Ioctl => self.handle_ioctl(handle, system, msg),
            Operation::EventfdGet => {
                let mut resp = Message::reply(msg);
                match vmm_sys_util::eventfd::EventFd::new(libc::EFD_CLOEXEC) {
                    Ok(eventfd) => {
                        use std::os::unix::io::AsRawFd;
                        let fd = eventfd.as_raw_fd();
                        std::mem::forget(eventfd); // Prevent Drop from closing the FD
                        let eventfd_handle = Handle::new(None, Some(fd), Arc::new(EventfdOps));
                        let eventfd_handle_id = eventfd_handle.id();
                        system.add_handle(eventfd_handle);
                        self.eventfds.lock().unwrap().push(eventfd_handle_id);
                        resp.handle = eventfd_handle_id;
                        resp.fds = Some(vec![fd]);
                    }
                    Err(e) => {
                        resp.status = e.raw_os_error().unwrap_or(libc::EINVAL) as u64;
                    }
                }
                Some(resp)
            }
            _ => Some(Message::reply(msg).with_error(libc::ENOSYS as u64)),
        }
    }

    fn save_state(
        &self,
        _handle: &Handle,
        _system: &Arc<System>,
        writer: &mut dyn Write,
    ) -> Result<(), std::io::Error> {
        let header = MsgHeader {
            msg_type: HandleType::KvmDevice as u32,
            size: 0,
        };
        // SAFETY: MsgHeader is POD
        let header_slice = unsafe {
            std::slice::from_raw_parts(
                &header as *const MsgHeader as *const u8,
                std::mem::size_of::<MsgHeader>(),
            )
        };
        writer.write_all(header_slice)?;
        Ok(())
    }

    fn get_type(&self) -> HandleType {
        HandleType::KvmDevice
    }

    fn load_state(
        _system: &Arc<System>,
        _state: &[u8],
        _channel: &Arc<rpc::Channel>,
    ) -> Result<Arc<Handle>, std::io::Error> {
        let kvm_path = std::ffi::CString::new("/dev/kvm").unwrap();
        let kvm_fd = {
            let kvm_raw_fd =
                unsafe { libc::open(kvm_path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
            if kvm_raw_fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            unsafe { OwnedFd::from_raw_fd(kvm_raw_fd) }
        };
        Ok(Arc::new(Handle {
            id: 1,
            fd: Some(kvm_fd),
            ops: Arc::new(KvmDeviceOps::new()),
        }))
    }
}

#[derive(Debug)]
pub enum DispatchResult {
    Reply(Message),
    ReplyAndExit(Message),
    None,
}

impl DispatchResult {
    #[cfg(test)]
    pub fn unwrap(self) -> Message {
        match self {
            DispatchResult::Reply(msg) => msg,
            DispatchResult::ReplyAndExit(msg) => msg,
            DispatchResult::None => panic!("Called unwrap on DispatchResult::None"),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
pub enum SystemState {
    Running = 0,
    Paused = 1,
}

impl From<u32> for SystemState {
    fn from(v: u32) -> Self {
        match v {
            0 => SystemState::Running,
            1 => SystemState::Paused,
            _ => SystemState::Running,
        }
    }
}

pub struct System {
    handles: Mutex<HashMap<u64, Arc<Handle>>>,
    state: std::sync::atomic::AtomicU32,
    rpc_thread_pool: Mutex<Option<Arc<rpc::RpcThreadPool>>>,
}

impl System {
    /// Serializes the entire VMM state into a stream.
    ///
    /// The state is saved as a sequence of [Header][Payload] blocks.
    /// To ensure correct reconstruction, handles are serialized in a
    /// specific order based on their dependencies (e.g., VMs before VCPUs).
    pub fn save(self: &Arc<Self>, writer: &mut dyn Write) -> Result<(), std::io::Error> {
        let grouped_handles: HashMap<HandleType, Vec<Arc<Handle>>> = {
            let handles = self.handles.lock().unwrap();
            let mut gh: HashMap<HandleType, Vec<Arc<Handle>>> = HashMap::new();
            for handle in handles.values() {
                let h_type = handle.ops.get_type();
                gh.entry(h_type).or_default().push(handle.clone());
            }
            gh
        };

        let order = [
            HandleType::KvmDevice,
            HandleType::MemoryFile,
            HandleType::Eventfd,
            HandleType::Vm,
            HandleType::Vcpu,
            HandleType::RpcServer,
            HandleType::RpcChannel,
        ];

        for h_type in order {
            if let Some(h_list) = grouped_handles.get(&h_type) {
                for handle in h_list {
                    handle.ops.save_state(handle, self, writer)?;
                }
            }
        }
        Ok(())
    }

    pub fn new_empty() -> Arc<Self> {
        Arc::new(System {
            handles: Mutex::new(HashMap::new()),
            state: std::sync::atomic::AtomicU32::new(SystemState::Running as u32),
            rpc_thread_pool: Mutex::new(None),
        })
    }

    /// Reconstructs the VMM state from a serialized stream.
    ///
    /// This method reads the handle sequence and dispatches restoration
    /// to the appropriate `HandleOps::load_state` implementation. It also
    /// updates the global ID counter to prevent collisions with new handles.
    pub fn restore(
        system: &Arc<Self>,
        reader: &mut dyn std::io::Read,
        channel: Arc<rpc::Channel>,
    ) -> Result<(), std::io::Error> {
        let mut max_handle_id = 0;

        loop {
            let mut header = MsgHeader {
                msg_type: 0,
                size: 0,
            };
            // SAFETY: MsgHeader is POD
            let header_slice = unsafe {
                std::slice::from_raw_parts_mut(
                    &mut header as *mut MsgHeader as *mut u8,
                    std::mem::size_of::<MsgHeader>(),
                )
            };

            match reader.read_exact(header_slice) {
                Ok(_) => (),
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            }

            let mut body = vec![0u8; header.size as usize];
            if header.size > 0 {
                reader.read_exact(&mut body)?;
            }

            let handle = match header.msg_type {
                t if t == HandleType::KvmDevice as u32 => {
                    KvmDeviceOps::load_state(system, &body, &channel)?
                }
                t if t == HandleType::MemoryFile as u32 => {
                    MemoryFileOps::load_state(system, &body, &channel)?
                }
                t if t == HandleType::Eventfd as u32 => {
                    EventfdOps::load_state(system, &body, &channel)?
                }
                t if t == HandleType::Vm as u32 => VmOps::load_state(system, &body, &channel)?,
                t if t == HandleType::Vcpu as u32 => VcpuOps::load_state(system, &body, &channel)?,
                t if t == HandleType::RpcServer as u32 => {
                    RpcServerOps::load_state(system, &body, &channel)?
                }
                t if t == HandleType::RpcChannel as u32 => {
                    RpcChannelOps::load_state(system, &body, &channel)?
                }
                _ => {
                    return Err(std::io::Error::other(format!(
                        "Unknown handle type 0x{:x}",
                        header.msg_type
                    )));
                }
            };
            max_handle_id = std::cmp::max(max_handle_id, handle.id());
            system.add_handle(handle);
        }

        NEXT_HANDLE_ID.store(max_handle_id + 1, Ordering::SeqCst);
        Ok(())
    }

    pub fn new() -> std::io::Result<Arc<Self>> {
        debug!("Initializing System");
        let kvm_path = std::ffi::CString::new("/dev/kvm").unwrap();
        let kvm_fd = {
            let kvm_raw_fd =
                unsafe { libc::open(kvm_path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
            if kvm_raw_fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            unsafe { OwnedFd::from_raw_fd(kvm_raw_fd) }
        };

        debug!("System: Registering KVM device at id=0x1, fd={:?}", kvm_fd);

        let kvm_handle = Arc::new(Handle {
            id: 1,
            fd: Some(kvm_fd),
            ops: Arc::new(KvmDeviceOps::new()),
        });

        let mut handles = HashMap::new();
        handles.insert(kvm_handle.id(), kvm_handle);

        Ok(Arc::new(System {
            handles: Mutex::new(handles),
            state: std::sync::atomic::AtomicU32::new(SystemState::Running as u32),
            rpc_thread_pool: Mutex::new(None),
        }))
    }

    pub fn handle_channel(self: &Arc<Self>, channel: Arc<rpc::Channel>, handle_id: Option<u64>) {
        if let Some(id) = handle_id {
            let handles = self.handles.lock().unwrap();
            if let Some(h) = handles.get(&id)
                && let Some(ops) = h.ops.as_any().downcast_ref::<RpcChannelOps>()
            {
                *ops.channel.lock().unwrap() = Some(channel.clone());
            }
        }

        let mut pool_lock = self.rpc_thread_pool.lock().unwrap();
        if pool_lock.is_none() {
            match rpc::RpcThreadPool::new(self.clone(), DEFAULT_RPC_THREADS) {
                Ok(pool) => *pool_lock = Some(Arc::new(pool)),
                Err(e) => {
                    error!("Failed to initialize RPC Thread Pool: {:?}", e);
                    return;
                }
            }
        }

        let pool = pool_lock.as_ref().unwrap().clone();
        if let Err(e) = pool.add_channel(channel, handle_id) {
            error!("Failed to add channel to thread pool: {:?}", e);
        }
    }

    pub fn add_handle(&self, handle: Arc<Handle>) {
        trace!(
            "System: Adding handle id=0x{:x}, fd={:?}",
            handle.id, handle.fd
        );
        let mut handles = self.handles.lock().unwrap();
        handles.insert(handle.id(), handle);
    }

    pub fn broadcast_live_update_notification(&self) {
        debug!("System: Broadcasting Live Update Notification");
        let handles = self.handles.lock().unwrap();
        let msg = Message {
            msg_type: Operation::NotifyLiveUpdate as u32,
            request_id: 0,
            handle: 0,
            status: 0,
            arg: 0,
            cmd: 0,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };

        for h in handles.values() {
            if let Some(ops) = h.ops.as_any().downcast_ref::<RpcChannelOps>()
                && let Some(channel) = &*ops.channel.lock().unwrap()
                && let Err(e) = channel.send(&msg)
            {
                error!(
                    "System: Failed to send notification to handle 0x{:x}: {:?}",
                    h.id, e
                );
            }
        }
    }

    pub fn pause(&self) {
        self.state
            .store(SystemState::Paused as u32, Ordering::SeqCst);
        let handles = self.handles.lock().unwrap();
        for h in handles.values() {
            if h.ops.get_type() == HandleType::Vcpu
                && let Some(vcpu_ops) = h.ops.as_any().downcast_ref::<VcpuOps>()
            {
                vcpu_ops.pause();
            }
        }
    }

    pub fn unpause(&self) {
        self.state
            .store(SystemState::Running as u32, Ordering::SeqCst);
        let handles = self.handles.lock().unwrap();
        for h in handles.values() {
            if h.ops.get_type() == HandleType::Vcpu
                && let Some(vcpu_ops) = h.ops.as_any().downcast_ref::<VcpuOps>()
            {
                vcpu_ops.resume();
            }
        }
    }

    pub fn get_handle(&self, id: u64) -> Option<Arc<Handle>> {
        let handles = self.handles.lock().unwrap();
        handles.get(&id).cloned()
    }

    pub fn remove_handle(&self, id: u64) -> Option<Arc<Handle>> {
        debug!("System: Removing handle id=0x{:x}", id);
        let mut handles = self.handles.lock().unwrap();
        handles.remove(&id)
    }

    /// Routes an RPC request to the appropriate handle or system operation.
    ///
    /// When the system is in the `Paused` state, most VM-mutating commands
    /// are blocked and return `EAGAIN`, while administrative commands like
    /// `Save` or `LiveUpdateRestore` are allowed to proceed.
    pub fn dispatch(
        self: &Arc<Self>,
        msg: &Message,
        channel: &Arc<rpc::Channel>,
    ) -> DispatchResult {
        let handle_id = msg.handle;
        trace!(
            "System: Dispatching request type={}, handle=0x{:x}, cmd=0x{:x}",
            msg.msg_type, handle_id, msg.cmd
        );
        let handle = {
            let handles = self.handles.lock().unwrap();
            handles.get(&handle_id).cloned()
        };

        if self.state.load(Ordering::Acquire) == SystemState::Paused as u32
            && msg.msg_type != Operation::Unpause as u32
            && msg.msg_type != Operation::Save as u32
            && msg.msg_type != Operation::LiveUpdateSave as u32
            && msg.msg_type != Operation::LiveUpdateRestore as u32
            && msg.msg_type != Operation::GetFileDescriptor as u32
            && msg.msg_type != Operation::Close as u32
        {
            debug!(
                "System: Request type={} blocked because system is Paused",
                msg.msg_type
            );
            return DispatchResult::Reply(Message::reply(msg).with_error(libc::EAGAIN as u64));
        }

        if msg.msg_type == Operation::Pause as u32 {
            self.pause();
            return DispatchResult::Reply(Message::reply(msg));
        } else if msg.msg_type == Operation::Unpause as u32 {
            self.unpause();
            return DispatchResult::Reply(Message::reply(msg));
        }

        match handle {
            Some(h) => {
                if msg.msg_type == Operation::Close as u32 {
                    if handle_id == 1 {
                        debug!("System: Shutdown requested via RPC");
                        let resp = Message::reply(msg);
                        return DispatchResult::ReplyAndExit(resp);
                    }
                    h.ops.cleanup(&h, self);
                    self.remove_handle(handle_id);
                    return DispatchResult::Reply(Message::reply(msg));
                } else if msg.msg_type == Operation::Save as u32 {
                    let mut status = libc::EINVAL as u64;
                    if let Some(fds) = &msg.fds
                        && !fds.is_empty()
                    {
                        use std::os::unix::io::FromRawFd;
                        let mut file = unsafe { std::fs::File::from_raw_fd(fds[0]) };
                        status = match self.save(&mut file) {
                            Ok(_) => 0,
                            Err(e) => e.raw_os_error().unwrap_or(libc::EINVAL) as u64,
                        };
                    }
                    let mut resp = Message::reply(msg);
                    resp.status = status;
                    return DispatchResult::Reply(resp);
                } else if msg.msg_type == Operation::LiveUpdateSave as u32 {
                    debug!("System: Handling LiveUpdateSave");
                    // 1. Create a memfd for the state serialization
                    let name = std::ffi::CString::new("tachyon-state").unwrap();
                    let state_fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
                    if state_fd < 0 {
                        return DispatchResult::Reply(
                            Message::reply(msg).with_error(
                                std::io::Error::last_os_error()
                                    .raw_os_error()
                                    .unwrap_or(libc::EINVAL) as u64,
                            ),
                        );
                    }

                    // 2. Wrap state_fd in a File and save the state
                    use std::os::unix::io::{FromRawFd, IntoRawFd};
                    let mut state_file = unsafe { std::fs::File::from_raw_fd(state_fd) };
                    if let Err(e) = self.save(&mut state_file) {
                        // Fix leak on error path: state_file is dropped here and closes state_fd
                        return DispatchResult::Reply(
                            Message::reply(msg)
                                .with_error(e.raw_os_error().unwrap_or(libc::EINVAL) as u64),
                        );
                    }
                    let _ = state_file.into_raw_fd(); // Save succeeded, keep FD open

                    // 3. Preserve the state_fd and get its token (index)
                    let state_token = luo_preserve(state_fd);

                    // 4. Gather all preserved FDs from LUO
                    let fds = luo_get_fds();

                    // 5. Trigger shutdown of the old process after sending the response
                    let mut resp = Message::reply(msg);
                    resp.body = state_token.into_bytes();
                    resp.fds = Some(fds);

                    return DispatchResult::ReplyAndExit(resp);
                } else if msg.msg_type == Operation::LiveUpdateRestore as u32 {
                    debug!("System: Handling LiveUpdateRestore");
                    // 1. Populate LUO with received FDs
                    if let Some(fds) = &msg.fds {
                        luo_set_fds(fds.clone());
                    } else {
                        return DispatchResult::Reply(
                            Message::reply(msg).with_error(libc::EINVAL as u64),
                        );
                    }

                    // 2. Identify the state memfd from the token in the body
                    let state_token = String::from_utf8_lossy(&msg.body);
                    let state_fd = match luo_retrieve(&state_token) {
                        Some(fd) => fd,
                        None => {
                            return DispatchResult::Reply(
                                Message::reply(msg).with_error(libc::ENOENT as u64),
                            );
                        }
                    };

                    // 3. Seek state_fd to start
                    if unsafe { libc::lseek(state_fd, 0, libc::SEEK_SET) } < 0 {
                        return DispatchResult::Reply(
                            Message::reply(msg).with_error(
                                std::io::Error::last_os_error()
                                    .raw_os_error()
                                    .unwrap_or(libc::EINVAL) as u64,
                            ),
                        );
                    }

                    // 4. Restore the system state
                    use std::os::unix::io::FromRawFd;
                    let mut state_file = unsafe { std::fs::File::from_raw_fd(state_fd) };

                    // Clear existing handles to prepare for restoration
                    self.handles.lock().unwrap().clear();
                    // State should be Paused during restoration
                    self.state
                        .store(SystemState::Paused as u32, Ordering::SeqCst);

                    match System::restore(self, &mut state_file, channel.clone()) {
                        Ok(_) => {
                            self.broadcast_live_update_notification();
                            return DispatchResult::Reply(Message::reply(msg));
                        }
                        Err(e) => {
                            return DispatchResult::Reply(
                                Message::reply(msg)
                                    .with_error(e.raw_os_error().unwrap_or(libc::EINVAL) as u64),
                            );
                        }
                    }
                }
                match h.ops.handle_request(&h, self, msg, channel) {
                    Some(resp) => DispatchResult::Reply(resp),
                    None => DispatchResult::None,
                }
            }
            None => {
                debug!("System: Handle 0x{:x} not found", handle_id);
                DispatchResult::Reply(Message::reply(msg).with_error(libc::ENOENT as u64))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::{Channel, Message};

    fn setup_test_channel() -> (Arc<Channel>, Arc<Channel>) {
        // Create a connected pair of sockets
        let mut fds = [0; 2];
        unsafe {
            let ret = libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, fds.as_mut_ptr());
            if ret < 0 {
                let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                panic!("Failed to create socket pair: {err}");
            }
        };
        (
            Arc::new(Channel::new(unsafe { OwnedFd::from_raw_fd(fds[0]) })),
            Arc::new(Channel::new(unsafe { OwnedFd::from_raw_fd(fds[1]) })),
        )
    }

    #[test]
    fn test_close_memory_file() {
        let system = match System::new() {
            Ok(s) => s,
            Err(_) => return,
        };
        let (channel, _client) = setup_test_channel();

        // 1. Create a memory file
        let create_msg = Message {
            msg_type: Operation::MemoryFileCreate as u32,
            request_id: 1,
            handle: 1,
            status: 0,
            arg: 4096, // size
            cmd: 0,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };

        let resp_create = system.dispatch(&create_msg, &channel).unwrap();
        assert_eq!(resp_create.status, 0);
        let mem_handle_id = resp_create.handle;

        // Verify it's in the system
        {
            let handles = system.handles.lock().unwrap();
            assert!(handles.contains_key(&mem_handle_id));
        }

        // 2. Close the memory file
        let close_msg = Message {
            msg_type: Operation::Close as u32,
            request_id: 2,
            handle: mem_handle_id,
            status: 0,
            arg: 0,
            cmd: 0,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };

        let resp_close = system.dispatch(&close_msg, &channel).unwrap();
        assert_eq!(resp_close.status, 0);

        // Verify it's removed from the system
        {
            let handles = system.handles.lock().unwrap();
            assert!(!handles.contains_key(&mem_handle_id));
        }
    }

    #[test]
    fn test_kvm_get_api_version() {
        let system = match System::new() {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "Skipping test_kvm_get_api_version: could not open /dev/kvm: {}",
                    e
                );
                return;
            }
        };
        let (channel, _client) = setup_test_channel();

        let msg = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 1,
            handle: 1, // KVM handle ID
            status: 0,
            arg: 0,
            cmd: kvm::KVM_GET_API_VERSION,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };

        let resp = system.dispatch(&msg, &channel).unwrap();
        assert_eq!(resp.status, 0);
        assert_eq!(resp.cmd, kvm::KVM_GET_API_VERSION);
        assert_eq!(resp.arg, 12); // KVM_API_VERSION should be 12
    }

    #[test]
    fn test_kvm_get_vcpu_mmap_size() {
        let system = match System::new() {
            Ok(s) => s,
            Err(_) => return,
        };
        let (channel, _client) = setup_test_channel();

        let msg = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 2,
            handle: 1,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_GET_VCPU_MMAP_SIZE,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };

        let resp = system.dispatch(&msg, &channel).unwrap();
        assert_eq!(resp.status, 0);
        assert!(resp.arg > 0);
    }

    #[test]
    fn test_kvm_create_vm() {
        let system = match System::new() {
            Ok(s) => s,
            Err(_) => return,
        };
        let (channel, _client) = setup_test_channel();

        let msg = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 3,
            handle: 1,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_CREATE_VM,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };

        let resp = system.dispatch(&msg, &channel).unwrap();
        assert_eq!(resp.status, 0);
        assert!(resp.handle > 1);

        let vm_handle_id = resp.handle;
        let msg_check = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 4,
            handle: vm_handle_id,
            status: 0,
            arg: 4,
            cmd: kvm::KVM_CHECK_EXTENSION,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };

        let resp_check = system.dispatch(&msg_check, &channel).unwrap();
        assert_eq!(resp_check.status, 0);
    }

    #[test]
    fn test_kvm_create_vcpu() {
        let system = match System::new() {
            Ok(s) => s,
            Err(_) => return,
        };
        let (channel, _client) = setup_test_channel();

        let msg_vm = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 5,
            handle: 1,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_CREATE_VM,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };
        let resp_vm = system.dispatch(&msg_vm, &channel).unwrap();
        assert_eq!(resp_vm.status, 0);
        let vm_handle_id = resp_vm.handle;

        let msg_vcpu = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 6,
            handle: vm_handle_id,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_CREATE_VCPU,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };
        let resp_vcpu = system.dispatch(&msg_vcpu, &channel).unwrap();
        assert_eq!(resp_vcpu.status, 0);
        assert!(resp_vcpu.handle > vm_handle_id);

        let vcpu_handle_id = resp_vcpu.handle;
        let msg_regs = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 7,
            handle: vcpu_handle_id,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_GET_REGS,
            resp_size: 144,
            body: Vec::new(),
            fds: None,
        };

        let resp_regs = system.dispatch(&msg_regs, &channel).unwrap();
        assert_eq!(resp_regs.status, 0);
        assert_eq!(resp_regs.body.len(), 144);
    }

    #[test]
    fn test_memory_file_create() {
        let system = match System::new() {
            Ok(s) => s,
            Err(_) => return,
        };
        let (channel, _client) = setup_test_channel();

        let size = 4096u64;
        let msg = Message {
            msg_type: Operation::MemoryFileCreate as u32,
            request_id: 8,
            handle: 1,
            status: 0,
            arg: size,
            cmd: 0,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };

        let resp = system.dispatch(&msg, &channel).unwrap();
        assert_eq!(resp.status, 0);
        assert!(resp.handle > 1);
        let fds = resp.fds.expect("No FDs returned");
        assert_eq!(fds.len(), 1);

        let mem_handle_id = resp.handle;
        let handle = {
            let handles = system.handles.lock().unwrap();
            handles.get(&mem_handle_id).cloned().unwrap()
        };
        let fd = handle.fd().unwrap();
        let mut st = unsafe { std::mem::zeroed::<libc::stat>() };
        let ret = unsafe { libc::fstat(fd, &mut st) };
        assert_eq!(ret, 0);
        assert_eq!(st.st_size as u64, size);
    }

    #[test]
    fn test_get_file_descriptor() {
        let system = match System::new() {
            Ok(s) => s,
            Err(_) => return,
        };
        let (channel, _client) = setup_test_channel();

        let size = 8192u64;
        let msg_create = Message {
            msg_type: Operation::MemoryFileCreate as u32,
            request_id: 9,
            handle: 1,
            status: 0,
            arg: size,
            cmd: 0,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };
        let resp_create = system.dispatch(&msg_create, &channel).unwrap();
        assert_eq!(resp_create.status, 0);
        let mem_handle_id = resp_create.handle;

        let msg_get_fd = Message {
            msg_type: Operation::GetFileDescriptor as u32,
            request_id: 10,
            handle: mem_handle_id,
            status: 0,
            arg: 0,
            cmd: 0,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };
        let resp_get_fd = system.dispatch(&msg_get_fd, &channel).unwrap();
        assert_eq!(resp_get_fd.status, 0);
        let fds = resp_get_fd.fds.expect("No FDs returned");
        assert_eq!(fds.len(), 1);

        let mut st = unsafe { std::mem::zeroed::<libc::stat>() };
        let ret = unsafe { libc::fstat(fds[0], &mut st) };
        assert_eq!(ret, 0);
        assert_eq!(st.st_size as u64, size);
    }

    #[test]
    fn test_vcpu_interrupt() {
        let system = match System::new() {
            Ok(s) => s,
            Err(_) => return,
        };
        let (channel, client) = setup_test_channel();

        let msg_vm = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 11,
            handle: 1,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_CREATE_VM,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };
        let resp_vm = system.dispatch(&msg_vm, &channel).unwrap();
        let vm_handle_id = resp_vm.handle;

        let msg_vcpu = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 12,
            handle: vm_handle_id,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_CREATE_VCPU,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };
        let resp_vcpu = system.dispatch(&msg_vcpu, &channel).unwrap();
        let vcpu_handle_id = resp_vcpu.handle;

        // 1. Create a memory file and populate it with a busy loop (jmp .) instruction: 0xeb, 0xfe
        let size = 4096u64;
        let msg_mem = Message {
            msg_type: Operation::MemoryFileCreate as u32,
            request_id: 100,
            handle: 1,
            status: 0,
            arg: size,
            cmd: 0,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };
        let resp_mem = system.dispatch(&msg_mem, &channel).unwrap();
        let mem_handle_id = resp_mem.handle;
        let mem_fds = resp_mem.fds.expect("No FDs returned for memfd");

        let code = [0xebu8, 0xfeu8];
        unsafe {
            libc::pwrite(
                mem_fds[0],
                code.as_ptr() as *const libc::c_void,
                code.len(),
                0,
            );
        }

        let region2 = kvm::kvm_userspace_memory_region2 {
            slot: 0,
            flags: 0,
            guest_phys_addr: 0,
            memory_size: size,
            userspace_addr: 0,
            guest_memfd_offset: 0,
            ..Default::default()
        };

        let wrapper = kvm::kvm_userspace_memory_region2_wrapper {
            region2,
            guest_memfd_handle: mem_handle_id,
        };

        let mut body = vec![0u8; std::mem::size_of::<kvm::kvm_userspace_memory_region2_wrapper>()];
        unsafe {
            std::ptr::copy_nonoverlapping(
                &wrapper as *const _ as *const u8,
                body.as_mut_ptr(),
                body.len(),
            );
        }

        let msg_set_mem = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 101,
            handle: vm_handle_id,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_SET_USER_MEMORY_REGION2,
            resp_size: 0,
            body,
            fds: None,
        };
        let resp_set_mem = system.dispatch(&msg_set_mem, &channel).unwrap();
        assert_eq!(resp_set_mem.status, 0);

        // 2. Set up vCPU segment registers (sregs) and general registers (regs)
        let msg_get_sregs = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 102,
            handle: vcpu_handle_id,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_GET_SREGS,
            resp_size: std::mem::size_of::<kvm_sregs>() as u32,
            body: Vec::new(),
            fds: None,
        };
        let resp_get_sregs = system.dispatch(&msg_get_sregs, &channel).unwrap();
        assert_eq!(resp_get_sregs.status, 0);

        let mut sregs: kvm_sregs =
            unsafe { std::ptr::read(resp_get_sregs.body.as_ptr() as *const kvm_sregs) };
        sregs.cs.base = 0;
        sregs.cs.selector = 0;

        let mut sregs_body = vec![0u8; std::mem::size_of::<kvm_sregs>()];
        unsafe {
            std::ptr::copy_nonoverlapping(
                &sregs as *const _ as *const u8,
                sregs_body.as_mut_ptr(),
                sregs_body.len(),
            );
        }

        let msg_set_sregs = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 103,
            handle: vcpu_handle_id,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_SET_SREGS,
            resp_size: 0,
            body: sregs_body,
            fds: None,
        };
        let resp_set_sregs = system.dispatch(&msg_set_sregs, &channel).unwrap();
        assert_eq!(resp_set_sregs.status, 0);

        let msg_get_regs = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 104,
            handle: vcpu_handle_id,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_GET_REGS,
            resp_size: std::mem::size_of::<kvm_regs>() as u32,
            body: Vec::new(),
            fds: None,
        };
        let resp_get_regs = system.dispatch(&msg_get_regs, &channel).unwrap();
        assert_eq!(resp_get_regs.status, 0);

        let mut regs: kvm_regs =
            unsafe { std::ptr::read(resp_get_regs.body.as_ptr() as *const kvm_regs) };
        regs.rip = 0;
        regs.rflags = 0x2;

        let mut regs_body = vec![0u8; std::mem::size_of::<kvm_regs>()];
        unsafe {
            std::ptr::copy_nonoverlapping(
                &regs as *const _ as *const u8,
                regs_body.as_mut_ptr(),
                regs_body.len(),
            );
        }

        let msg_set_regs = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 105,
            handle: vcpu_handle_id,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_SET_REGS,
            resp_size: 0,
            body: regs_body,
            fds: None,
        };
        let resp_set_regs = system.dispatch(&msg_set_regs, &channel).unwrap();
        assert_eq!(resp_set_regs.status, 0);

        // 3. Spawn KVM_RUN on background thread
        let system_clone = system.clone();
        let channel_clone = channel.clone();
        let _handle = std::thread::spawn(move || {
            let msg_run = Message {
                msg_type: Operation::Ioctl as u32,
                request_id: 13,
                handle: vcpu_handle_id,
                status: 0,
                arg: 0,
                cmd: kvm::KVM_RUN,
                resp_size: 0,
                body: Vec::new(),
                fds: None,
            };
            system_clone.dispatch(&msg_run, &channel_clone)
        });

        // Sleep briefly to ensure vCPU has entered guest execution busy loop
        std::thread::sleep(std::time::Duration::from_millis(50));

        // 4. Send Operation::Interrupt to kick vCPU out of KVM_RUN
        let msg_interrupt = Message {
            msg_type: Operation::Interrupt as u32,
            request_id: 14,
            handle: vcpu_handle_id,
            status: 0,
            arg: 0,
            cmd: 0,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };
        let _resp_int = system.dispatch(&msg_interrupt, &channel);

        let mut resp_run = client.recv().unwrap().unwrap();
        while resp_run.request_id != 13 {
            resp_run = client.recv().unwrap().unwrap();
        }

        assert_eq!(resp_run.status, libc::EINTR as u64);
    }

    #[test]
    fn test_kvm_set_user_memory_region2() {
        let system = match System::new() {
            Ok(s) => s,
            Err(_) => return,
        };
        let (channel, _client) = setup_test_channel();

        let msg_vm = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 15,
            handle: 1,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_CREATE_VM,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };
        let resp_vm = system.dispatch(&msg_vm, &channel).unwrap();
        let vm_handle_id = resp_vm.handle;

        let size = 4096u64;
        let msg_mem = Message {
            msg_type: Operation::MemoryFileCreate as u32,
            request_id: 16,
            handle: 1,
            status: 0,
            arg: size,
            cmd: 0,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };
        let resp_mem = system.dispatch(&msg_mem, &channel).unwrap();
        let mem_handle_id = resp_mem.handle;

        let region2 = kvm::kvm_userspace_memory_region2 {
            slot: 0,
            flags: 0,
            guest_phys_addr: 0x1000,
            memory_size: size,
            userspace_addr: 0,
            guest_memfd_offset: 0,
            ..Default::default()
        };

        let wrapper = kvm::kvm_userspace_memory_region2_wrapper {
            region2,
            guest_memfd_handle: mem_handle_id,
        };

        let mut body = vec![0u8; std::mem::size_of::<kvm::kvm_userspace_memory_region2_wrapper>()];
        unsafe {
            std::ptr::copy_nonoverlapping(
                &wrapper as *const _ as *const u8,
                body.as_mut_ptr(),
                body.len(),
            );
        }

        let msg_set = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 17,
            handle: vm_handle_id,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_SET_USER_MEMORY_REGION2,
            resp_size: 0,
            body,
            fds: None,
        };

        let resp_set = system.dispatch(&msg_set, &channel).unwrap();
        assert_eq!(resp_set.status, 0);
    }

    #[test]
    fn test_kvm_regs() {
        let system = match System::new() {
            Ok(s) => s,
            Err(_) => return,
        };
        let (channel, _client) = setup_test_channel();

        let msg_vm = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 18,
            handle: 1,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_CREATE_VM,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };
        let resp_vm = system.dispatch(&msg_vm, &channel).unwrap();
        let vm_handle_id = resp_vm.handle;

        let msg_vcpu = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 19,
            handle: vm_handle_id,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_CREATE_VCPU,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };
        let resp_vcpu = system.dispatch(&msg_vcpu, &channel).unwrap();
        let vcpu_handle_id = resp_vcpu.handle;

        let msg_get = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 20,
            handle: vcpu_handle_id,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_GET_REGS,
            resp_size: std::mem::size_of::<kvm_regs>() as u32,
            body: Vec::new(),
            fds: None,
        };
        let resp_get = system.dispatch(&msg_get, &channel).unwrap();
        assert_eq!(resp_get.status, 0);
        assert_eq!(resp_get.body.len(), std::mem::size_of::<kvm_regs>());

        let mut regs: kvm_regs =
            unsafe { std::ptr::read(resp_get.body.as_ptr() as *const kvm_regs) };

        regs.rax = 0x12345678;
        let mut body = vec![0u8; std::mem::size_of::<kvm_regs>()];
        unsafe {
            std::ptr::copy_nonoverlapping(
                &regs as *const _ as *const u8,
                body.as_mut_ptr(),
                body.len(),
            );
        }

        let msg_set = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 21,
            handle: vcpu_handle_id,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_SET_REGS,
            resp_size: 0,
            body,
            fds: None,
        };
        let resp_set = system.dispatch(&msg_set, &channel).unwrap();
        assert_eq!(resp_set.status, 0);

        let msg_get2 = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 22,
            handle: vcpu_handle_id,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_GET_REGS,
            resp_size: std::mem::size_of::<kvm_regs>() as u32,
            body: Vec::new(),
            fds: None,
        };
        let resp_get2 = system.dispatch(&msg_get2, &channel).unwrap();
        assert_eq!(resp_get2.status, 0);
        let regs2: kvm_regs = unsafe { std::ptr::read(resp_get2.body.as_ptr() as *const kvm_regs) };
        assert_eq!(regs2.rax, 0x12345678);
        assert_eq!(regs2, regs);
    }

    #[test]
    fn test_kvm_set_cpuid2() {
        let system = match System::new() {
            Ok(s) => s,
            Err(_) => return,
        };
        let (channel, _client) = setup_test_channel();

        let msg_vm = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 32,
            handle: 1,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_CREATE_VM,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };
        let resp_vm = system.dispatch(&msg_vm, &channel).unwrap();
        let vm_handle_id = resp_vm.handle;

        let msg_vcpu = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 33,
            handle: vm_handle_id,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_CREATE_VCPU,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };
        let resp_vcpu = system.dispatch(&msg_vcpu, &channel).unwrap();
        let vcpu_handle_id = resp_vcpu.handle;

        // Get supported CPUID to have valid entries
        let mut body = vec![
            0u8;
            std::mem::size_of::<kvm_cpuid2>()
                + 100 * std::mem::size_of::<kvm_cpuid_entry2>()
        ];
        let cpuid = kvm_cpuid2 {
            nent: 100,
            padding: 0,
        };
        unsafe {
            std::ptr::copy_nonoverlapping(
                &cpuid as *const _ as *const u8,
                body.as_mut_ptr(),
                std::mem::size_of::<kvm_cpuid2>(),
            );
        }
        let msg_supported = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 331,
            handle: 1, // System handle
            status: 0,
            arg: 0,
            cmd: kvm::KVM_GET_SUPPORTED_CPUID, // KVM_GET_SUPPORTED_CPUID
            resp_size: body.len() as u32,
            body: body.clone(),
            fds: None,
        };
        let resp_supported = system.dispatch(&msg_supported, &channel).unwrap();
        assert_eq!(resp_supported.status, 0);

        let cpuid_res = unsafe { &*(resp_supported.body.as_ptr() as *const kvm_cpuid2) };
        let nent = cpuid_res.nent;
        let body_len = std::mem::size_of::<kvm_cpuid2>()
            + nent as usize * std::mem::size_of::<kvm_cpuid_entry2>();
        let mut final_body = resp_supported.body;
        final_body.truncate(body_len);

        let msg_set = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 34,
            handle: vcpu_handle_id,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_SET_CPUID2,
            resp_size: 0,
            body: final_body.clone(),
            fds: None,
        };
        let resp_set = system.dispatch(&msg_set, &channel).unwrap();
        assert_eq!(resp_set.status, 0);

        let msg_get = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 35,
            handle: vcpu_handle_id,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_GET_CPUID2,
            resp_size: body_len as u32,
            body: final_body, // Must include header with nent
            fds: None,
        };
        let resp_get = system.dispatch(&msg_get, &channel).unwrap();
        assert_eq!(resp_get.status, 0);
        assert_eq!(resp_get.body.len(), body_len);

        let cpuid2: kvm_cpuid2 =
            unsafe { std::ptr::read(resp_get.body.as_ptr() as *const kvm_cpuid2) };
        assert_eq!(cpuid2.nent, nent);
    }

    #[test]
    fn test_kvm_fpu() {
        let system = match System::new() {
            Ok(s) => s,
            Err(_) => return,
        };
        let (channel, _client) = setup_test_channel();

        let msg_vm = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 36,
            handle: 1,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_CREATE_VM,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };
        let resp_vm = system.dispatch(&msg_vm, &channel).unwrap();
        let vm_handle_id = resp_vm.handle;

        let msg_vcpu = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 37,
            handle: vm_handle_id,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_CREATE_VCPU,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };
        let resp_vcpu = system.dispatch(&msg_vcpu, &channel).unwrap();
        let vcpu_handle_id = resp_vcpu.handle;

        let msg_get = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 38,
            handle: vcpu_handle_id,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_GET_FPU,
            resp_size: std::mem::size_of::<kvm_fpu>() as u32,
            body: Vec::new(),
            fds: None,
        };
        let resp_get = system.dispatch(&msg_get, &channel).unwrap();
        assert_eq!(resp_get.status, 0);
        assert_eq!(resp_get.body.len(), std::mem::size_of::<kvm_fpu>());

        let fpu: kvm_fpu = unsafe { std::ptr::read(resp_get.body.as_ptr() as *const kvm_fpu) };

        let msg_set = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 39,
            handle: vcpu_handle_id,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_SET_FPU,
            resp_size: 0,
            body: resp_get.body,
            fds: None,
        };
        let resp_set = system.dispatch(&msg_set, &channel).unwrap();
        assert_eq!(resp_set.status, 0);

        let msg_get2 = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 40,
            handle: vcpu_handle_id,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_GET_FPU,
            resp_size: std::mem::size_of::<kvm_fpu>() as u32,
            body: Vec::new(),
            fds: None,
        };
        let resp_get2 = system.dispatch(&msg_get2, &channel).unwrap();
        assert_eq!(resp_get2.status, 0);
        let fpu2: kvm_fpu = unsafe { std::ptr::read(resp_get2.body.as_ptr() as *const kvm_fpu) };
        assert_eq!(fpu2, fpu);
    }

    #[test]
    fn test_kvm_xcrs() {
        let system = match System::new() {
            Ok(s) => s,
            Err(_) => return,
        };
        let (channel, _client) = setup_test_channel();

        let msg_vm = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 41,
            handle: 1,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_CREATE_VM,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };
        let resp_vm = system.dispatch(&msg_vm, &channel).unwrap();
        let vm_handle_id = resp_vm.handle;

        let msg_vcpu = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 42,
            handle: vm_handle_id,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_CREATE_VCPU,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };
        let resp_vcpu = system.dispatch(&msg_vcpu, &channel).unwrap();
        let vcpu_handle_id = resp_vcpu.handle;

        let mut body = vec![0u8; std::mem::size_of::<kvm_xcrs>()];
        let xcrs = kvm_xcrs {
            nr_xcrs: 1,
            flags: 0,
            xcrs: [
                kvm_xcr {
                    xcr: 0,
                    reserved: 0,
                    value: 1, // XCR0 = 1 (x87)
                },
                kvm_xcr::default(),
                kvm_xcr::default(),
                kvm_xcr::default(),
                kvm_xcr::default(),
                kvm_xcr::default(),
                kvm_xcr::default(),
                kvm_xcr::default(),
                kvm_xcr::default(),
                kvm_xcr::default(),
                kvm_xcr::default(),
                kvm_xcr::default(),
                kvm_xcr::default(),
                kvm_xcr::default(),
                kvm_xcr::default(),
                kvm_xcr::default(),
            ],
            padding: [0; 16],
        };
        unsafe {
            std::ptr::copy_nonoverlapping(
                &xcrs as *const _ as *const u8,
                body.as_mut_ptr(),
                body.len(),
            );
        }

        let msg_set = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 43,
            handle: vcpu_handle_id,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_SET_XCRS,
            resp_size: 0,
            body,
            fds: None,
        };
        let resp_set = system.dispatch(&msg_set, &channel).unwrap();
        // Hardware might not support XCRs, so we accept success or ENOSYS/EINVAL
        assert!(
            resp_set.status == 0
                || resp_set.status == libc::ENOSYS as u64
                || resp_set.status == libc::EINVAL as u64,
            "KVM_SET_XCRS failed with status: {}",
            resp_set.status
        );
    }

    #[test]
    fn test_kvm_mp_state() {
        let system = match System::new() {
            Ok(s) => s,
            Err(_) => return,
        };
        let (channel, _client) = setup_test_channel();

        let msg_vm = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 44,
            handle: 1,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_CREATE_VM,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };
        let resp_vm = system.dispatch(&msg_vm, &channel).unwrap();
        let vm_handle_id = resp_vm.handle;

        let msg_vcpu = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 45,
            handle: vm_handle_id,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_CREATE_VCPU,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };
        let resp_vcpu = system.dispatch(&msg_vcpu, &channel).unwrap();
        let vcpu_handle_id = resp_vcpu.handle;

        let mut body = vec![0u8; std::mem::size_of::<kvm_mp_state>()];
        let mp_state = kvm_mp_state {
            mp_state: 0, // KVM_MP_STATE_RUNNABLE
        };
        unsafe {
            std::ptr::copy_nonoverlapping(
                &mp_state as *const _ as *const u8,
                body.as_mut_ptr(),
                body.len(),
            );
        }

        let msg_set = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 46,
            handle: vcpu_handle_id,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_SET_MP_STATE,
            resp_size: 0,
            body,
            fds: None,
        };
        let resp_set = system.dispatch(&msg_set, &channel).unwrap();
        assert_eq!(resp_set.status, 0);

        let msg_get = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 47,
            handle: vcpu_handle_id,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_GET_MP_STATE,
            resp_size: std::mem::size_of::<kvm_mp_state>() as u32,
            body: Vec::new(),
            fds: None,
        };
        let resp_get = system.dispatch(&msg_get, &channel).unwrap();
        assert_eq!(resp_get.status, 0);
        let mp_state2: kvm_mp_state =
            unsafe { std::ptr::read(resp_get.body.as_ptr() as *const kvm_mp_state) };
        assert_eq!(mp_state2.mp_state, 0);
    }

    #[test]
    fn test_kvm_ioeventfd() {
        let system = match System::new() {
            Ok(s) => s,
            Err(_) => return,
        };
        let (channel, _client) = setup_test_channel();

        let msg_vm = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 48,
            handle: 1,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_CREATE_VM,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };
        let resp_vm = system.dispatch(&msg_vm, &channel).unwrap();
        let vm_handle_id = resp_vm.handle;

        // Get an eventfd handle from Tachyon
        let msg_eventfd_get = Message {
            msg_type: Operation::EventfdGet as u32,
            handle: 1,
            ..Default::default()
        };
        let resp_eventfd = system.dispatch(&msg_eventfd_get, &channel).unwrap();
        assert_eq!(resp_eventfd.status, 0);
        let eventfd_handle_id = resp_eventfd.handle;
        let event_fds = resp_eventfd.fds.expect("No FDs returned from EventfdGet");
        assert_eq!(event_fds.len(), 1);
        assert!(event_fds[0] >= 0);

        let ioeventfd = kvm::kvm_ioeventfd {
            addr: 0x1000,
            len: 8,
            fd: -1, // Will be replaced by Tachyon using the handle
            ..Default::default()
        };
        let wrapped = kvm::kvm_ioeventfd_wrapped {
            kvm: ioeventfd,
            fd_handle: eventfd_handle_id,
        };

        let mut body = vec![0u8; std::mem::size_of::<kvm::kvm_ioeventfd_wrapped>()];
        unsafe {
            std::ptr::copy_nonoverlapping(
                &wrapped as *const _ as *const u8,
                body.as_mut_ptr(),
                body.len(),
            );
        }

        let msg_ioeventfd = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 49,
            handle: vm_handle_id,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_IOEVENTFD,
            resp_size: 0,
            body,
            fds: None,
        };

        let resp = system.dispatch(&msg_ioeventfd, &channel).unwrap();
        assert_eq!(resp.status, 0);
    }

    #[test]
    fn test_vm_get_file_descriptor() {
        let system = match System::new() {
            Ok(s) => s,
            Err(_) => return,
        };
        let (channel, _client) = setup_test_channel();

        let msg_vm = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 28,
            handle: 1,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_CREATE_VM,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };
        let resp_vm = system.dispatch(&msg_vm, &channel).unwrap();
        let vm_handle_id = resp_vm.handle;

        let msg_get_fd = Message {
            msg_type: Operation::GetFileDescriptor as u32,
            request_id: 29,
            handle: vm_handle_id,
            status: 0,
            arg: 0,
            cmd: 0,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };
        let resp_get_fd = system.dispatch(&msg_get_fd, &channel).unwrap();
        assert_eq!(resp_get_fd.status, 0);
        let fds = resp_get_fd.fds.expect("No FDs returned");
        assert_eq!(fds.len(), 2);

        assert!(fds[0] >= 0);
        assert!(fds[1] >= 0);

        let mut st = unsafe { std::mem::zeroed::<libc::stat>() };
        let ret = unsafe { libc::fstat(fds[0], &mut st) };
        assert_eq!(ret, 0);

        let mut st2 = unsafe { std::mem::zeroed::<libc::stat>() };
        let ret2 = unsafe { libc::fstat(fds[1], &mut st2) };
        assert_eq!(ret2, 0);
    }

    #[test]
    fn test_kvm_sregs() {
        let system = match System::new() {
            Ok(s) => s,
            Err(_) => return,
        };
        let (channel, _client) = setup_test_channel();

        let msg_vm = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 23,
            handle: 1,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_CREATE_VM,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };
        let resp_vm = system.dispatch(&msg_vm, &channel).unwrap();
        assert_eq!(resp_vm.status, 0);
        let vm_handle_id = resp_vm.handle;

        let msg_vcpu = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 24,
            handle: vm_handle_id,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_CREATE_VCPU,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };
        let resp_vcpu = system.dispatch(&msg_vcpu, &channel).unwrap();
        assert_eq!(resp_vcpu.status, 0);
        let vcpu_handle_id = resp_vcpu.handle;

        let msg_get = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 25,
            handle: vcpu_handle_id,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_GET_SREGS,
            resp_size: std::mem::size_of::<kvm_sregs>() as u32,
            body: Vec::new(),
            fds: None,
        };
        let resp_get = system.dispatch(&msg_get, &channel).unwrap();
        assert_eq!(resp_get.status, 0);
        assert_eq!(resp_get.body.len(), std::mem::size_of::<kvm_sregs>());

        let sregs: kvm_sregs =
            unsafe { std::ptr::read(resp_get.body.as_ptr() as *const kvm_sregs) };

        let original_cr0 = sregs.cr0;
        let mut body = vec![0u8; std::mem::size_of::<kvm_sregs>()];
        unsafe {
            std::ptr::copy_nonoverlapping(
                &sregs as *const _ as *const u8,
                body.as_mut_ptr(),
                body.len(),
            );
        }

        let msg_set = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 26,
            handle: vcpu_handle_id,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_SET_SREGS,
            resp_size: 0,
            body,
            fds: None,
        };
        let resp_set = system.dispatch(&msg_set, &channel).unwrap();
        assert_eq!(resp_set.status, 0);

        let msg_get2 = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 27,
            handle: vcpu_handle_id,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_GET_SREGS,
            resp_size: std::mem::size_of::<kvm_sregs>() as u32,
            body: Vec::new(),
            fds: None,
        };
        let resp_get2 = system.dispatch(&msg_get2, &channel).unwrap();
        assert_eq!(resp_get2.status, 0);
        let sregs2: kvm_sregs =
            unsafe { std::ptr::read(resp_get2.body.as_ptr() as *const kvm_sregs) };
        assert_eq!(sregs2.cr0, original_cr0);
        assert_eq!(sregs2, sregs);
    }

    #[test]
    fn test_kvm_get_stats_fd() {
        let system = match System::new() {
            Ok(s) => s,
            Err(_) => return,
        };
        let (channel, client) = setup_test_channel();

        let msg_vm = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 30,
            handle: 1,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_CREATE_VM,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };
        let resp_vm = system.dispatch(&msg_vm, &channel).unwrap();
        let vm_handle_id = resp_vm.handle;

        let msg_stats = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 31,
            handle: vm_handle_id,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_GET_STATS_FD,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };
        let _ = system.dispatch(&msg_stats, &channel);
        let resp_stats = client.recv().unwrap().unwrap();
        assert_eq!(resp_stats.status, 0);
        let fds = resp_stats.fds.expect("No FDs returned");
        assert_eq!(fds.len(), 1);
        assert!(fds[0] >= 0);

        let mut header = [0u8; 8];
        let ret = unsafe { libc::read(fds[0], header.as_mut_ptr() as *mut libc::c_void, 8) };
        assert!(ret >= 0);

        // Because the stats fd was turned through the client (i.e., it was
        // sent over the socket, effectively dup()ed), close it now.
        unsafe { libc::close(fds[0]) };
    }

    #[test]
    fn test_kvm_set_msr_filter() {
        let system = match System::new() {
            Ok(s) => s,
            Err(_) => return,
        };
        let (channel, _client) = setup_test_channel();

        let msg_vm = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 50,
            handle: 1,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_CREATE_VM,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };
        let resp_vm = system.dispatch(&msg_vm, &channel).unwrap();
        let vm_handle_id = resp_vm.handle;

        let mut filter = kvm_msr_filter {
            flags: 0, // KVM_MSR_FILTER_DEFAULT_ALLOW
            ..Default::default()
        };

        let bitmap = vec![0xffu8; 1]; // allow first 8 MSRs
        filter.ranges[0] = kvm_msr_filter_range {
            flags: 3, // READ | WRITE
            nmsrs: 8,
            base: 0,
            bitmap: std::mem::size_of::<kvm_msr_filter>() as u64,
        };

        let mut body = vec![0u8; std::mem::size_of::<kvm_msr_filter>()];
        unsafe {
            std::ptr::copy_nonoverlapping(
                &filter as *const _ as *const u8,
                body.as_mut_ptr(),
                body.len(),
            );
        }
        body.extend_from_slice(&bitmap);

        let msg_set = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 51,
            handle: vm_handle_id,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_X86_SET_MSR_FILTER,
            resp_size: 0,
            body,
            fds: None,
        };

        let resp_set = system.dispatch(&msg_set, &channel).unwrap();
        // Hardware might not support MSR filter, but KVM_CAP_X86_MSR_FILTER should be checked.
        // For simplicity, we just check if it doesn't crash and returns a valid status.
        assert!(
            resp_set.status == 0
                || resp_set.status == libc::ENOTSUP as u64
                || resp_set.status == libc::ENOSYS as u64
        );
    }

    #[test]
    fn test_kvm_irqfd() {
        let system = match System::new() {
            Ok(s) => s,
            Err(_) => return,
        };
        let (channel, _client) = setup_test_channel();

        let msg_vm = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 52,
            handle: 1,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_CREATE_VM,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };
        let resp_vm = system.dispatch(&msg_vm, &channel).unwrap();
        let vm_handle_id = resp_vm.handle;

        let msg_irqchip = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 53,
            handle: vm_handle_id,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_CREATE_IRQCHIP,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };
        let _ = system.dispatch(&msg_irqchip, &channel);

        let msg_eventfd_get1 = Message {
            msg_type: Operation::EventfdGet as u32,
            handle: 1,
            ..Default::default()
        };
        let resp_eventfd1 = system.dispatch(&msg_eventfd_get1, &channel).unwrap();
        assert_eq!(resp_eventfd1.status, 0);
        let event_fd1_handle = resp_eventfd1.handle;

        let msg_eventfd_get2 = Message {
            msg_type: Operation::EventfdGet as u32,
            handle: 1,
            ..Default::default()
        };
        let resp_eventfd2 = system.dispatch(&msg_eventfd_get2, &channel).unwrap();
        assert_eq!(resp_eventfd2.status, 0);
        let event_fd2_handle = resp_eventfd2.handle;

        let irqfd = kvm::kvm_irqfd {
            fd: 0,
            gsi: 0,
            flags: kvm::KVM_IRQFD_FLAG_RESAMPLE,
            resamplefd: 0,
            ..Default::default()
        };

        let wrapper = kvm::kvm_irqfd_wrapped {
            kvm: irqfd,
            fd_handle: event_fd1_handle,
            resamplefd_handle: event_fd2_handle,
        };

        let mut body = vec![0u8; std::mem::size_of::<kvm::kvm_irqfd_wrapped>()];
        unsafe {
            std::ptr::copy_nonoverlapping(
                &wrapper as *const _ as *const u8,
                body.as_mut_ptr(),
                body.len(),
            );
        }

        let msg_irqfd = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 54,
            handle: vm_handle_id,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_IRQFD,
            resp_size: 0,
            body,
            fds: None,
        };

        let resp = system.dispatch(&msg_irqfd, &channel).unwrap();
        // Hardware might not support IRQFD, so we accept success or common errors.
        assert!(
            resp.status == 0
                || resp.status == libc::ENOSYS as u64
                || resp.status == libc::EINVAL as u64
        );
    }

    #[test]
    fn test_save_restore_mock() {
        use std::io::Cursor;
        let system = match System::new() {
            Ok(s) => s,
            Err(_) => return,
        };
        let (test_channel, _client) = setup_test_channel();

        // Create a memory file
        let memfd_name = std::ffi::CString::new("test-memfd").unwrap();
        let fd = unsafe { libc::memfd_create(memfd_name.as_ptr(), libc::MFD_CLOEXEC) };
        assert!(fd >= 0);
        let size = 0x1000;
        unsafe {
            libc::ftruncate(fd, size as libc::off_t);
        }

        let luo_id = luo_preserve(fd);
        let mem_handle = Handle::new(None, Some(fd), Arc::new(MemoryFileOps::new(size, luo_id)));
        let mem_id = mem_handle.id();
        system.add_handle(mem_handle);

        // Create a VM
        let kvm_handle = system.get_handle(1).unwrap();
        let vm_fd = unsafe { libc::ioctl(kvm_handle.fd().unwrap(), kvm::KVM_CREATE_VM as _, 0) };
        assert!(vm_fd >= 0);
        let vm_ops = VmOps::new();
        let shm_entry = unsafe { &mut (*vm_ops.shared_memory.addr).vcpus[0] as *mut PerVcpuState };

        // Map memory into VM
        let mmap_addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_FILE,
                fd,
                0,
            )
        };
        assert!(mmap_addr != libc::MAP_FAILED);

        let region2 = kvm::kvm_userspace_memory_region2 {
            slot: 0,
            flags: 0,
            guest_phys_addr: 0x1000,
            memory_size: size,
            userspace_addr: mmap_addr as u64,
            guest_memfd_offset: 0,
            ..Default::default()
        };

        let kvm_region = kvm_userspace_memory_region {
            slot: 0,
            flags: 0,
            guest_phys_addr: 0x1000,
            memory_size: size,
            userspace_addr: mmap_addr as u64,
        };
        let ret = unsafe { libc::ioctl(vm_fd, kvm::KVM_SET_USER_MEMORY_REGION as _, &kvm_region) };
        assert!(ret >= 0);

        {
            let mut regions = vm_ops.regions.lock().unwrap();
            regions.insert(
                0,
                MemoryMapping {
                    addr: mmap_addr as u64,
                    size: size as usize,
                    region: region2,
                    guest_memfd_handle: mem_id,
                },
            );
        }

        let vm_shm = vm_ops.shared_memory.clone();
        let vm_handle = Handle::new(None, Some(vm_fd), Arc::new(vm_ops));
        let vm_id = vm_handle.id();
        system.add_handle(vm_handle.clone());

        // Create IRQ chip
        let ret = unsafe { libc::ioctl(vm_fd, kvm::KVM_CREATE_IRQCHIP as _, 0) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            panic!("KVM_CREATE_IRQCHIP failed: {}", err);
        }
        vm_handle
            .ops
            .as_any()
            .downcast_ref::<VmOps>()
            .unwrap()
            .has_irqchip
            .store(true, Ordering::SeqCst);

        // Create a VCPU
        let vcpu_id = 0;
        let vcpu_fd =
            unsafe { libc::ioctl(vm_fd, kvm::KVM_CREATE_VCPU as _, vcpu_id as libc::c_int) };
        assert!(vcpu_fd >= 0);
        let vcpu_ops = VcpuOps::new(
            vm_id,
            vcpu_id,
            vcpu_fd,
            test_channel.clone(),
            vm_shm,
            shm_entry,
        );
        let vcpu_handle = Handle::new(None, Some(vcpu_fd), Arc::new(vcpu_ops));
        let vcpu_handle_id = vcpu_handle.id();
        system.add_handle(vcpu_handle);

        // Set VCPU registers
        let regs = kvm::kvm_regs {
            rax: 0x12345678,
            ..Default::default()
        };
        let ret = unsafe { libc::ioctl(vcpu_fd, kvm::KVM_SET_REGS as _, &regs) };
        assert!(ret >= 0);

        // Get an eventfd handle for ioeventfd
        let msg_eventfd_get = Message {
            msg_type: Operation::EventfdGet as u32,
            handle: 1,
            ..Default::default()
        };
        let resp_eventfd = system.dispatch(&msg_eventfd_get, &test_channel).unwrap();
        assert_eq!(resp_eventfd.status, 0);
        let event_fd_raw = unsafe { libc::dup(resp_eventfd.fds.unwrap()[0]) };

        // Register ioeventfd
        let ioeventfd = kvm::kvm_ioeventfd {
            addr: 0x80,
            len: 1,
            datamatch: 0,
            fd: event_fd_raw,
            flags: kvm::KVM_IOEVENTFD_FLAG_PIO,
            ..Default::default()
        };
        let wrapped_ioeventfd = kvm::kvm_ioeventfd_wrapped {
            kvm: ioeventfd,
            fd_handle: resp_eventfd.handle,
        };
        let mut ioeventfd_body = vec![0u8; std::mem::size_of::<kvm::kvm_ioeventfd_wrapped>()];
        unsafe {
            std::ptr::copy_nonoverlapping(
                &wrapped_ioeventfd,
                ioeventfd_body.as_mut_ptr() as *mut kvm::kvm_ioeventfd_wrapped,
                1,
            );
        }
        let msg_ioeventfd = Message {
            msg_type: Operation::Ioctl as u32,
            handle: vm_id,
            cmd: kvm::KVM_IOEVENTFD,
            body: ioeventfd_body,
            fds: Some(vec![event_fd_raw]),
            ..Default::default()
        };
        let resp_ioeventfd = system.dispatch(&msg_ioeventfd, &test_channel).unwrap();
        assert_eq!(resp_ioeventfd.status, 0);

        // Pause the system
        let pause_msg = Message {
            msg_type: Operation::Pause as u32,
            ..Default::default()
        };
        system.dispatch(&pause_msg, &test_channel);
        assert_eq!(
            system.state.load(Ordering::Acquire),
            SystemState::Paused as u32
        );

        // Save state
        let mut buffer = Vec::new();
        system.save(&mut buffer).expect("Save failed");

        // Restore state
        let (channel, _client) = setup_test_channel();

        let mut cursor = Cursor::new(buffer);
        let restored_system = System::new_empty();
        System::restore(&restored_system, &mut cursor, channel).expect("Restore failed");

        // Verify restored handles
        assert!(restored_system.get_handle(1).is_some());
        assert!(restored_system.get_handle(mem_id).is_some());
        assert!(restored_system.get_handle(vm_id).is_some());
        assert!(restored_system.get_handle(vcpu_handle_id).is_some());

        let restored_vcpu = restored_system.get_handle(vcpu_handle_id).unwrap();
        let restored_vcpu_fd = restored_vcpu.fd().unwrap();

        // Verify VCPU register
        let mut restored_regs = kvm::kvm_regs::default();
        let ret =
            unsafe { libc::ioctl(restored_vcpu_fd, kvm::KVM_GET_REGS as _, &mut restored_regs) };
        assert!(ret >= 0);
        assert_eq!(restored_regs.rax, 0x12345678);

        let restored_vm = restored_system.get_handle(vm_id).unwrap();
        assert_eq!(restored_vm.id(), vm_id);

        let restored_vm_ops = restored_vm
            .ops
            .as_any()
            .downcast_ref::<VmOps>()
            .expect("Not VmOps");
        assert_eq!(restored_vm_ops.ioeventfds_configs.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_vcpu_polling() {
        let system = match System::new() {
            Ok(s) => s,
            Err(_) => return,
        };
        let (channel, _client) = setup_test_channel();

        // 1. Create a VM
        let create_vm_msg = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 1,
            handle: 1,
            status: 0,
            arg: 0,
            cmd: kvm::KVM_CREATE_VM,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };
        let resp_vm = system.dispatch(&create_vm_msg, &channel).unwrap();
        assert_eq!(resp_vm.status, 0);
        let vm_handle_id = resp_vm.handle;
        let shm_fd = resp_vm.fds.unwrap()[0];

        // 2. Create a VCPU
        let vcpu_id = 0;
        let create_vcpu_msg = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 2,
            handle: vm_handle_id,
            status: 0,
            arg: vcpu_id as u64,
            cmd: kvm::KVM_CREATE_VCPU,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };
        let resp_vcpu = system.dispatch(&create_vcpu_msg, &channel).unwrap();
        assert_eq!(resp_vcpu.status, 0);
        let vcpu_handle_id = resp_vcpu.handle;

        // 3. Map shared memory to simulate the guest driver
        let shm_size = std::mem::size_of::<VcpuSharedMemory>();
        let shm_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                shm_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                shm_fd,
                0,
            )
        } as *mut VcpuSharedMemory;
        assert!(shm_ptr != libc::MAP_FAILED as *mut _);

        let shm = unsafe { &mut *shm_ptr };
        let state = &shm.vcpus[vcpu_id as usize];

        // 4. Request KVM_RUN via shared memory
        state.state.store(STATE_RUN_REQUESTED, Ordering::Release);

        // 5. Signal Ready if host is not polling
        if (state.state.load(Ordering::Acquire) & FLAG_HOST_POLLING) == 0 {
            let ready_msg = Message {
                msg_type: Operation::Ready as u32,
                request_id: 3,
                handle: vcpu_handle_id,
                status: 0,
                arg: 0,
                cmd: 0,
                resp_size: 0,
                body: Vec::new(),
                fds: None,
            };
            system.dispatch(&ready_msg, &channel);
        }

        // 6. Wait for completion
        let start = std::time::Instant::now();
        while (state.state.load(Ordering::Acquire) & STATE_MASK) != STATE_COMPLETED {
            if start.elapsed() > std::time::Duration::from_secs(5) {
                panic!(
                    "Host failed to complete KVM_RUN, state.state=0x{:x}",
                    state.state.load(Ordering::Acquire)
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        // 7. Cleanup
        let close_msg = Message {
            msg_type: Operation::Close as u32,
            request_id: 4,
            handle: vm_handle_id,
            status: 0,
            arg: 0,
            cmd: 0,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        };
        system.dispatch(&close_msg, &channel).unwrap();
        unsafe {
            libc::munmap(shm_ptr as *mut libc::c_void, shm_size);
        }
    }

    #[test]
    fn test_validate_vfio_argsz_valid() {
        let min_size = 32;
        let mut msg = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 1,
            handle: 1,
            status: 0,
            arg: 0,
            cmd: vfio::VFIO_DEVICE_GET_REGION_INFO,
            resp_size: 32,
            body: vec![0u8; 32],
            fds: None,
        };
        let valid_argsz: u32 = 32;
        msg.body[0..4].copy_from_slice(&valid_argsz.to_ne_bytes());
        assert!(validate_vfio_argsz(&msg, min_size).is_ok());
    }

    #[test]
    fn test_validate_vfio_argsz_too_small() {
        let min_size = 32;
        let msg = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 1,
            handle: 1,
            status: 0,
            arg: 0,
            cmd: vfio::VFIO_DEVICE_GET_REGION_INFO,
            resp_size: 32,
            body: vec![0u8; 16],
            fds: None,
        };
        assert_eq!(
            validate_vfio_argsz(&msg, min_size),
            Err(libc::EINVAL as u64)
        );
    }

    #[test]
    fn test_validate_vfio_argsz_out_of_bounds() {
        let min_size = 32;
        let mut msg = Message {
            msg_type: Operation::Ioctl as u32,
            request_id: 1,
            handle: 1,
            status: 0,
            arg: 0,
            cmd: vfio::VFIO_DEVICE_GET_REGION_INFO,
            resp_size: 32,
            body: vec![0u8; 32],
            fds: None,
        };
        let invalid_argsz: u32 = 40;
        msg.body[0..4].copy_from_slice(&invalid_argsz.to_ne_bytes());
        assert_eq!(
            validate_vfio_argsz(&msg, min_size),
            Err(libc::EINVAL as u64)
        );
    }
}
