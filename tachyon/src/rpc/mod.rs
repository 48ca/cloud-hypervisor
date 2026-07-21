// Copyright 2026 Google LLC
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::io::{Error, Result};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use flume;
use log::{debug, error, info, trace, warn};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub const MAX_MESSAGE_SIZE: usize = 65536;
pub const MAX_CONTROL_SIZE: usize = 8192;

use crate::{DispatchResult, Operation, System};

#[derive(IntoBytes, Immutable, FromBytes, KnownLayout)]
#[repr(C, packed)]
struct MessageHeader {
    pub msg_type: u32,
    pub len: u32,
    pub request_id: u64,
    pub handle: u64,
    pub status: u64,
    pub arg: u64,
    pub cmd: u64,
    pub resp_size: u32,
    pub padding1: u32,
    pub padding2: u64,
}

const MESSAGE_HEADER_SIZE: usize = {
    let sz = core::mem::size_of::<MessageHeader>();
    if sz != 64usize {
        panic!("MessageHeader should be 64 bytes");
    }
    sz
};

impl MessageHeader {
    pub fn as_slice(&self) -> &[u8; MESSAGE_HEADER_SIZE] {
        zerocopy::transmute_ref!(self)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Message {
    pub msg_type: u32,
    pub request_id: u64,
    pub handle: u64,
    pub status: u64,
    pub arg: u64,
    pub cmd: u64,
    pub resp_size: u32,
    pub body: Vec<u8>,
    pub fds: Option<Vec<RawFd>>,
}

impl Message {
    fn header(&self) -> MessageHeader {
        MessageHeader {
            msg_type: self.msg_type,
            len: self.body.len() as u32,
            request_id: self.request_id,
            handle: self.handle,
            status: self.status,
            arg: self.arg,
            cmd: self.cmd,
            resp_size: self.resp_size,
            padding1: 0,
            padding2: 0,
        }
    }

    pub fn reply(req: &Self) -> Self {
        Message {
            msg_type: req.msg_type,
            request_id: req.request_id,
            handle: req.handle,
            status: 0,
            arg: 0,
            cmd: req.cmd,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        }
    }

    pub fn new(msg_type: u32, handle: u64, cmd: u64, arg: u64) -> Self {
        Message {
            msg_type,
            request_id: 0, /* Filled by call() */
            handle,
            status: 0, /* Filled by reply */
            arg,
            cmd,
            resp_size: 0,
            body: Vec::new(),
            fds: None,
        }
    }

    pub fn simple(msg_type: u32, handle: u64) -> Self {
        Self::new(msg_type, handle, 0, 0)
    }

    pub fn ioctl(handle: u64, cmd: u64, arg: u64) -> Self {
        Self::new(Operation::Ioctl as u32, handle, cmd, arg)
    }

    pub fn get_file(handle: u64) -> Self {
        Self::simple(Operation::GetFileDescriptor as u32, handle)
    }

    pub fn with_error(mut self, err: u64) -> Self {
        self.status = err;
        self
    }

    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    pub fn with_resp(mut self, resp_size: u32) -> Self {
        self.resp_size = resp_size;
        self
    }

    pub fn with_fds(mut self, fds: Vec<RawFd>) -> Self {
        self.fds = Some(fds);
        self
    }
}

#[derive(Clone)]
pub struct Channel {
    fd: Arc<OwnedFd>,
    exit_on_close: Arc<AtomicBool>,
}

impl Channel {
    pub fn new(fd: OwnedFd) -> Self {
        Channel {
            fd: Arc::new(fd),
            exit_on_close: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn set_exit_on_close(&self, value: bool) {
        self.exit_on_close.store(value, Ordering::SeqCst);
    }

    pub fn exit_on_close(&self) -> bool {
        self.exit_on_close.load(Ordering::SeqCst)
    }

    pub fn send(&self, msg: &Message) -> Result<()> {
        if msg.body.len() + MESSAGE_HEADER_SIZE > MAX_MESSAGE_SIZE {
            return Err(Error::new(
                std::io::ErrorKind::InvalidInput,
                "Message too large",
            ));
        }

        trace!(
            "Channel::send: fd={:?}, type={}, req_id={}, handle=0x{:x}, cmd=0x{:x}, fds={:?}",
            self.fd, msg.msg_type, msg.request_id, msg.handle, msg.cmd, msg.fds
        );

        let mut buffer = [0u8; MAX_MESSAGE_SIZE];
        let header_sz = MESSAGE_HEADER_SIZE;
        buffer[0..header_sz].copy_from_slice(msg.header().as_slice());
        buffer[header_sz..header_sz + msg.body.len()].copy_from_slice(&msg.body);

        let iov = [libc::iovec {
            iov_base: buffer.as_ptr() as *mut libc::c_void,
            iov_len: MESSAGE_HEADER_SIZE + msg.body.len(),
        }];

        let mut msghdr: libc::msghdr = unsafe { std::mem::zeroed() };
        msghdr.msg_iov = iov.as_ptr() as *mut libc::iovec;
        msghdr.msg_iovlen = iov.len() as _;

        let mut control_buffer = [0u64; MAX_CONTROL_SIZE / 8];
        if let Some(fds) = &msg.fds
            && !fds.is_empty()
        {
            let space_needed =
                unsafe { libc::CMSG_SPACE((fds.len() * std::mem::size_of::<RawFd>()) as u32) }
                    as usize;
            if space_needed > MAX_CONTROL_SIZE {
                return Err(Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "Too many FDs to send: {}, space needed: {}",
                        fds.len(),
                        space_needed
                    ),
                ));
            }

            msghdr.msg_control = control_buffer.as_mut_ptr() as *mut libc::c_void;
            msghdr.msg_controllen = space_needed as _;

            let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msghdr) };
            if !cmsg.is_null() {
                unsafe {
                    (*cmsg).cmsg_level = libc::SOL_SOCKET;
                    (*cmsg).cmsg_type = libc::SCM_RIGHTS;
                    (*cmsg).cmsg_len =
                        libc::CMSG_LEN((fds.len() * std::mem::size_of::<RawFd>()) as u32) as _;
                    let data = libc::CMSG_DATA(cmsg) as *mut RawFd;
                    ptr::copy_nonoverlapping(fds.as_ptr(), data, fds.len());
                }
            }
        }

        let ret = unsafe { libc::sendmsg(self.fd.as_raw_fd(), &msghdr, 0) };
        if ret < 0 {
            return Err(Error::last_os_error());
        }

        if ret as usize != MESSAGE_HEADER_SIZE + msg.body.len() {
            return Err(Error::new(
                std::io::ErrorKind::WriteZero,
                "Failed to send complete message",
            ));
        }

        Ok(())
    }

    pub fn recv(&self) -> Result<Option<Message>> {
        let mut buffer = [0u8; MAX_MESSAGE_SIZE];
        let iov = [libc::iovec {
            iov_base: buffer.as_mut_ptr() as *mut libc::c_void,
            iov_len: MAX_MESSAGE_SIZE,
        }];

        let mut msghdr: libc::msghdr = unsafe { std::mem::zeroed() };
        msghdr.msg_iov = iov.as_ptr() as *mut libc::iovec;
        msghdr.msg_iovlen = iov.len() as _;

        let mut control_buffer = [0u64; MAX_CONTROL_SIZE / 8];
        msghdr.msg_control = control_buffer.as_mut_ptr() as *mut libc::c_void;
        msghdr.msg_controllen = MAX_CONTROL_SIZE as _;

        let ret = unsafe { libc::recvmsg(self.fd.as_raw_fd(), &mut msghdr, 0) };
        if ret < 0 {
            return Err(Error::last_os_error());
        }

        if (msghdr.msg_flags & libc::MSG_CTRUNC) != 0 {
            return Err(Error::new(
                std::io::ErrorKind::InvalidData,
                "Control data truncated (too many FDs)",
            ));
        }

        let bytes_read = ret as usize;
        if bytes_read == 0 {
            return Ok(None);
        } else if bytes_read < MESSAGE_HEADER_SIZE {
            return Err(Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Received message too short for header",
            ));
        }

        let header = MessageHeader::ref_from_bytes(&buffer[0..MESSAGE_HEADER_SIZE]).unwrap();
        let msg_size = header.len as usize;

        if bytes_read != MESSAGE_HEADER_SIZE + msg_size {
            return Err(Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Message size mismatch: header says {}, but read {}",
                    msg_size,
                    bytes_read - MESSAGE_HEADER_SIZE
                ),
            ));
        }

        let body = buffer[MESSAGE_HEADER_SIZE..MESSAGE_HEADER_SIZE + msg_size].to_vec();

        let mut fds = Vec::new();
        let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msghdr) };
        while !cmsg.is_null() {
            if unsafe {
                (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS
            } {
                let data = unsafe { libc::CMSG_DATA(cmsg) as *const RawFd };
                let len = unsafe { (*cmsg).cmsg_len as usize - libc::CMSG_LEN(0) as usize };
                let count = len / std::mem::size_of::<RawFd>();
                for i in 0..count {
                    fds.push(unsafe { *data.add(i) });
                }
            }
            cmsg = unsafe { libc::CMSG_NXTHDR(&msghdr, cmsg) };
        }

        let msg = Message {
            msg_type: header.msg_type,
            request_id: header.request_id,
            handle: header.handle,
            status: header.status,
            arg: header.arg,
            cmd: header.cmd,
            resp_size: header.resp_size,
            body,
            fds: if fds.is_empty() { None } else { Some(fds) },
        };

        trace!(
            "Channel::recv: fd={:?}, type={}, req_id={}, handle=0x{:x}, status={}, fds={:?}",
            self.fd, msg.msg_type, msg.request_id, msg.handle, msg.status, msg.fds
        );

        Ok(Some(msg))
    }
}

impl AsRawFd for Channel {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

pub struct Server {
    fd: OwnedFd,
}

impl Server {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        if path.exists() {
            std::fs::remove_file(path)?;
        }

        let fd = {
            let fd = unsafe {
                libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0)
            };
            if fd < 0 {
                return Err(Error::last_os_error());
            }
            unsafe { OwnedFd::from_raw_fd(fd) }
        };

        let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let path_bytes = path.to_str().unwrap().as_bytes();
        if path_bytes.len() >= addr.sun_path.len() {
            return Err(Error::new(
                std::io::ErrorKind::InvalidInput,
                "Path too long",
            ));
        }
        for (i, &b) in path_bytes.iter().enumerate() {
            addr.sun_path[i] = b as libc::c_char;
        }

        let len = std::mem::size_of::<libc::sa_family_t>() + path_bytes.len() + 1;
        let ret = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &addr as *const libc::sockaddr_un as *const libc::sockaddr,
                len as libc::socklen_t,
            )
        };
        if ret < 0 {
            let err = Error::last_os_error();
            return Err(err);
        }

        let ret = unsafe { libc::listen(fd.as_raw_fd(), 5) };
        if ret < 0 {
            let err = Error::last_os_error();
            return Err(err);
        }

        debug!("Server::new: listening on {path:?}, fd={fd:?}");
        Ok(Server { fd })
    }

    pub fn from_fd(fd: RawFd) -> Self {
        Server {
            fd: { unsafe { OwnedFd::from_raw_fd(fd) } },
        }
    }

    pub fn accept(&self) -> Result<Channel> {
        let client_fd = {
            let client_fd = unsafe {
                libc::accept4(
                    self.fd.as_raw_fd(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    libc::SOCK_CLOEXEC,
                )
            };
            if client_fd < 0 {
                return Err(Error::last_os_error());
            };
            debug!("Server::accept: accepted connection, fd={client_fd}");
            unsafe { OwnedFd::from_raw_fd(client_fd) }
        };
        Ok(Channel::new(client_fd))
    }
}

impl AsRawFd for Server {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

pub struct Client;

impl Client {
    pub fn connect<P: AsRef<Path>>(path: P) -> Result<Channel> {
        let fd = {
            let fd = unsafe {
                libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0)
            };
            if fd < 0 {
                return Err(Error::last_os_error());
            }
            unsafe { OwnedFd::from_raw_fd(fd) }
        };

        let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let path_bytes = path.as_ref().to_str().unwrap().as_bytes();
        if path_bytes.len() >= addr.sun_path.len() {
            return Err(Error::new(
                std::io::ErrorKind::InvalidInput,
                "Path too long",
            ));
        }
        for (i, &b) in path_bytes.iter().enumerate() {
            addr.sun_path[i] = b as libc::c_char;
        }

        let len = std::mem::size_of::<libc::sa_family_t>() + path_bytes.len() + 1;
        let ret = unsafe {
            libc::connect(
                fd.as_raw_fd(),
                &addr as *const libc::sockaddr_un as *const libc::sockaddr,
                len as libc::socklen_t,
            )
        };
        if ret < 0 {
            let err = Error::last_os_error();
            return Err(err);
        }

        debug!(
            "Client::connect: connected to {:?}, fd={:?}",
            path.as_ref(),
            fd
        );
        Ok(Channel::new(fd))
    }
}

type NotificationHandler = Arc<dyn Fn(Message) + Send + Sync>;

pub struct RpcClient {
    channel: Arc<Channel>,
    send_lock: Mutex<()>,
    next_request_id: AtomicU64,
    pending_requests: Arc<Mutex<HashMap<u64, flume::Sender<Message>>>>,
    notification_handler: Arc<Mutex<Option<NotificationHandler>>>,
}

impl RpcClient {
    pub fn new(channel: Channel) -> Self {
        let channel = Arc::new(channel);
        let pending_requests: Arc<Mutex<HashMap<u64, flume::Sender<Message>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let notification_handler: Arc<Mutex<Option<NotificationHandler>>> =
            Arc::new(Mutex::new(None));

        let channel_clone = channel.clone();
        let pending_requests_clone = pending_requests.clone();
        let notification_handler_clone = notification_handler.clone();

        let _ = std::thread::Builder::new()
            .name("rpc-client".to_string())
            .spawn(move || {
                loop {
                    match channel_clone.recv() {
                        Ok(Some(msg)) => {
                            if msg.request_id == 0 {
                                let handler = {
                                    let h_lock = notification_handler_clone.lock().unwrap();
                                    h_lock.clone()
                                };
                                if let Some(h) = handler {
                                    // Spawn a thread to avoid deadlock if handler calls RPC
                                    std::thread::spawn(move || {
                                        h(msg);
                                    });
                                }
                                continue;
                            }

                            let mut pending = pending_requests_clone.lock().unwrap();
                            if let Some(tx) = pending.remove(&msg.request_id) {
                                trace!(
                                    "RpcClient: received response for req_id={}",
                                    msg.request_id
                                );
                                let _ = tx.send(msg);
                            } else {
                                trace!(
                                    "RpcClient: received response for unknown req_id={}",
                                    msg.request_id
                                );
                            }
                        }
                        Ok(None) => {
                            info!("RpcClient receiver thread exiting: Connection closed by peer");
                            // Signal all pending requests that the connection is lost
                            let mut pending = pending_requests_clone.lock().unwrap();
                            pending.clear();
                            break;
                        }
                        Err(e) => {
                            error!("RpcClient receiver thread error: {:?}", e);
                            // Signal all pending requests that the connection is lost
                            let mut pending = pending_requests_clone.lock().unwrap();
                            pending.clear();
                            break;
                        }
                    }
                }
            });

        RpcClient {
            channel,
            send_lock: Mutex::new(()),
            next_request_id: AtomicU64::new(1),
            pending_requests,
            notification_handler,
        }
    }

    pub fn set_notification_handler<F>(&self, handler: F)
    where
        F: Fn(Message) + Send + Sync + 'static,
    {
        let mut h = self.notification_handler.lock().unwrap();
        *h = Some(Arc::new(handler));
    }

    pub fn fail_pending_requests(&self) {
        let mut pending = self.pending_requests.lock().unwrap();
        pending.clear();
    }

    pub fn call(&self, mut msg: Message) -> Result<Message> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::SeqCst);
        msg.request_id = request_id;

        trace!(
            "RpcClient::call: req_id={}, type={}, handle=0x{:x}, cmd=0x{:x}",
            request_id, msg.msg_type, msg.handle, msg.cmd
        );

        let (tx, rx) = flume::bounded(1);

        {
            let mut pending = self.pending_requests.lock().unwrap();
            pending.insert(request_id, tx);
        }

        {
            let _lock = self.send_lock.lock().unwrap();
            self.channel.send(&msg)?;
        }

        rx.recv().map_err(|_| {
            Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "Connection lost or request failed",
            )
        })
    }

    pub fn asynchronous_call(&self, mut msg: Message) -> Result<()> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::SeqCst);
        msg.request_id = request_id;

        trace!(
            "RpcClient::asynchronous_call: req_id={}, type={}, handle=0x{:x}, cmd=0x{:x}",
            request_id, msg.msg_type, msg.handle, msg.cmd
        );

        let _lock = self.send_lock.lock().unwrap();
        self.channel.send(&msg)
    }
}

type ChannelMap = HashMap<RawFd, (Arc<Channel>, Option<u64>)>;

pub struct RpcThreadPool {
    epoll_fd: RawFd,
    channels: Arc<Mutex<ChannelMap>>,
    work_sender: Option<flume::Sender<Arc<Channel>>>,
    reactor_thread: Option<std::thread::JoinHandle<()>>,
    worker_threads: Vec<std::thread::JoinHandle<()>>,
}

impl RpcThreadPool {
    pub fn new(system: Arc<System>, num_threads: usize) -> Result<Self> {
        let epoll_fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if epoll_fd < 0 {
            return Err(Error::last_os_error());
        }

        let channels: Arc<Mutex<ChannelMap>> = Arc::new(Mutex::new(HashMap::new()));
        let (work_sender, work_receiver) = flume::unbounded::<Arc<Channel>>();

        let channels_clone = channels.clone();
        let epoll_fd_clone = epoll_fd;
        let work_sender_clone = work_sender.clone();

        // Spawn Reactor Thread
        let reactor_thread = std::thread::Builder::new()
            .name("rpc-reactor".to_string())
            .spawn(move || {
                let mut events = vec![unsafe { std::mem::zeroed::<libc::epoll_event>() }; 64];
                loop {
                    let nfds = unsafe {
                        libc::epoll_wait(
                            epoll_fd_clone,
                            events.as_mut_ptr(),
                            events.len() as i32,
                            -1, // Block indefinitely
                        )
                    };

                    if nfds < 0 {
                        let err = Error::last_os_error();
                        if err.kind() == std::io::ErrorKind::Interrupted {
                            continue;
                        }
                        error!("epoll_wait error: {:?}", err);
                        break;
                    }

                    for event in events.iter().take(nfds as usize) {
                        let fd = event.u64 as RawFd;
                        let channel = {
                            let lock = channels_clone.lock().unwrap();
                            lock.get(&fd).map(|(c, _)| c.clone())
                        };

                        if let Some(chan) = channel
                            && let Err(e) = work_sender_clone.send(chan)
                        {
                            error!("Failed to send channel to work queue: {:?}", e);
                        }
                    }
                }
            })
            .expect("Failed to spawn reactor thread");

        let mut worker_threads = Vec::new();
        for i in 0..num_threads {
            let work_receiver = work_receiver.clone();
            let system = system.clone();
            let epoll_fd_clone = epoll_fd;
            let channels_clone = channels.clone();

            let worker = std::thread::Builder::new()
                .name(format!("rpc-worker-{}", i))
                .spawn(move || {
                    while let Ok(channel) = work_receiver.recv() {
                        let fd = channel.as_raw_fd();
                        match channel.recv() {
                            Ok(Some(msg)) => {
                                match system.dispatch(&msg, &channel) {
                                    DispatchResult::Reply(r) => {
                                        if let Err(e) = channel.send(&r) {
                                            error!("Worker {}: Failed to send response: {:?}", i, e);
                                        }
                                    }
                                    DispatchResult::ReplyAndExit(r) => {
                                        if let Err(e) = channel.send(&r) {
                                            error!("Worker {}: Failed to send response before exit: {:?}", i, e);
                                        }
                                        channel.set_exit_on_close(true);
                                    }
                                    DispatchResult::None => {}
                                }

                                // Re-arm in epoll
                                let mut event = libc::epoll_event {
                                    events: (libc::EPOLLIN | libc::EPOLLONESHOT) as u32,
                                    u64: fd as u64,
                                };
                                let ret = unsafe {
                                    libc::epoll_ctl(
                                        epoll_fd_clone,
                                        libc::EPOLL_CTL_MOD,
                                        fd,
                                        &mut event,
                                    )
                                };
                                if ret < 0 {
                                    error!("Worker {}: Failed to re-arm fd {}: {:?}", i, fd, Error::last_os_error());
                                }
                            }
                            Ok(None) => {
                                if channel.exit_on_close() {
                                    warn!("Worker {}: Exiting process after successful live update save / shutdown", i);
                                    std::process::exit(0);
                                }
                                warn!("Worker {}: Client disconnected (fd {})", i, fd);
                                Self::cleanup_channel(epoll_fd_clone, &channels_clone, &system, fd);
                            }
                            Err(e) => {
                                error!("Worker {}: Error reading from fd {}: {:?}", i, fd, e);
                                Self::cleanup_channel(epoll_fd_clone, &channels_clone, &system, fd);
                            }
                        }
                    }
                })
                .expect("Failed to spawn worker thread");
            worker_threads.push(worker);
        }

        Ok(RpcThreadPool {
            epoll_fd,
            channels,
            work_sender: Some(work_sender),
            reactor_thread: Some(reactor_thread),
            worker_threads,
        })
    }

    pub fn add_channel(&self, channel: Arc<Channel>, handle_id: Option<u64>) -> Result<()> {
        let fd = channel.as_raw_fd();
        {
            let mut lock = self.channels.lock().unwrap();
            lock.insert(fd, (channel, handle_id));
        }

        let mut event = libc::epoll_event {
            events: (libc::EPOLLIN | libc::EPOLLONESHOT) as u32,
            u64: fd as u64,
        };

        let ret = unsafe { libc::epoll_ctl(self.epoll_fd, libc::EPOLL_CTL_ADD, fd, &mut event) };

        if ret < 0 {
            let err = Error::last_os_error();
            let mut lock = self.channels.lock().unwrap();
            lock.remove(&fd);
            return Err(err);
        }

        Ok(())
    }

    fn cleanup_channel(
        epoll_fd: RawFd,
        channels: &Arc<Mutex<ChannelMap>>,
        system: &Arc<System>,
        fd: RawFd,
    ) {
        unsafe {
            libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_DEL, fd, std::ptr::null_mut());
        }
        let handle_id = {
            let mut lock = channels.lock().unwrap();
            lock.remove(&fd).and_then(|(_, id)| id)
        };
        if let Some(id) = handle_id {
            system.remove_handle(id);
        }
    }
}

impl Drop for RpcThreadPool {
    fn drop(&mut self) {
        debug!("Dropping RpcThreadPool");
        unsafe { libc::close(self.epoll_fd) };

        if let Some(t) = self.reactor_thread.take() {
            let _ = t.join();
        }

        self.work_sender.take();

        for t in self.worker_threads.drain(..) {
            let _ = t.join();
        }
        debug!("RpcThreadPool dropped");
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::unix::io::FromRawFd;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn test_rpc_communication() {
        let dir = tempdir().expect("Failed to create temp dir");
        let socket_path = dir.path().join("test.sock");
        let socket_path_clone = socket_path.clone();

        let server = Server::new(&socket_path).expect("Failed to create server");

        let thread = std::thread::spawn(move || {
            let channel = server.accept().expect("Failed to accept connection");
            let msg = channel
                .recv()
                .expect("Failed to receive message")
                .expect("EOF");
            assert_eq!(msg.msg_type, 1);
            assert_eq!(msg.handle, 500);
            assert_eq!(msg.body, b"hello");

            let response_body = b"world".to_vec();
            channel
                .send(&Message {
                    msg_type: 2,
                    request_id: msg.request_id,
                    handle: msg.handle,
                    status: 0,
                    arg: msg.arg,
                    cmd: msg.cmd,
                    resp_size: 0,
                    body: response_body,
                    fds: None,
                })
                .expect("Failed to send response");
        });

        let client_channel = Client::connect(&socket_path_clone).expect("Failed to connect");
        client_channel
            .send(&Message {
                msg_type: 1,
                request_id: 100,
                handle: 500,
                status: 0,
                arg: 700,
                cmd: 800,
                resp_size: 5,
                body: b"hello".to_vec(),
                fds: None,
            })
            .expect("Failed to send message");

        let resp = client_channel
            .recv()
            .expect("Failed to receive response")
            .expect("EOF");
        assert_eq!(resp.msg_type, 2);
        assert_eq!(resp.request_id, 100);
        assert_eq!(resp.handle, 500);
        assert_eq!(resp.status, 0);
        assert_eq!(resp.arg, 700);
        assert_eq!(resp.cmd, 800);
        assert_eq!(resp.body, b"world");

        thread.join().expect("Thread failed");
    }

    #[test]
    fn test_fd_passing() {
        let dir = tempdir().expect("Failed to create temp dir");
        let socket_path = dir.path().join("test_fd.sock");
        let socket_path_clone = socket_path.clone();

        let server = Server::new(&socket_path).expect("Failed to create server");

        let thread = std::thread::spawn(move || {
            let channel = server.accept().expect("Failed to accept connection");
            let msg = channel
                .recv()
                .expect("Failed to receive message")
                .expect("EOF");
            assert_eq!(msg.msg_type, 10);
            assert_eq!(msg.handle, 600);

            let fds = msg.fds.expect("No FDs received");
            assert_eq!(fds.len(), 1);

            let mut file = unsafe { File::from_raw_fd(fds[0]) };
            let mut content = String::new();
            file.read_to_string(&mut content)
                .expect("Failed to read from passed FD");
            assert_eq!(content, "test content");
        });

        let client_channel = Client::connect(&socket_path_clone).expect("Failed to connect");

        let mut temp_file = tempfile::NamedTempFile::new().expect("Failed to create temp file");
        write!(temp_file, "test content").expect("Failed to write to temp file");
        temp_file.flush().expect("Failed to flush");

        use std::io::Seek;
        temp_file
            .seek(std::io::SeekFrom::Start(0))
            .expect("Failed to seek");

        let fd = temp_file.as_raw_fd();

        client_channel
            .send(&Message {
                msg_type: 10,
                request_id: 200,
                handle: 600,
                status: 0,
                arg: 0,
                cmd: 0,
                resp_size: 0,
                body: b"fd passing".to_vec(),
                fds: Some(vec![fd]),
            })
            .expect("Failed to send message with FD");

        thread.join().expect("Thread failed");
    }

    #[test]
    fn test_rpc_client_concurrent() {
        let dir = tempdir().expect("Failed to create temp dir");
        let socket_path = dir.path().join("test_concurrent.sock");
        let socket_path_clone = socket_path.clone();

        let server = Server::new(&socket_path).expect("Failed to create server");

        let _server_thread = std::thread::spawn(move || {
            let channel = server.accept().expect("Failed to accept connection");
            loop {
                match channel.recv() {
                    Ok(Some(msg)) => {
                        // Echo the body back with msg_type + 1
                        channel
                            .send(&Message {
                                msg_type: msg.msg_type + 1,
                                request_id: msg.request_id,
                                handle: msg.handle,
                                status: 0,
                                arg: msg.arg,
                                cmd: msg.cmd,
                                resp_size: 0,
                                body: msg.body.clone(),
                                fds: None,
                            })
                            .expect("Server failed to send");
                    }
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
        });

        let client_channel = Client::connect(&socket_path_clone).expect("Failed to connect");
        let rpc_client = Arc::new(RpcClient::new(client_channel));

        let mut handles = vec![];
        for i in 0..20 {
            let client = rpc_client.clone();
            handles.push(std::thread::spawn(move || {
                for j in 0..50 {
                    let body = format!("thread {} msg {}", i, j).into_bytes();
                    let resp = client
                        .call(Message {
                            msg_type: i,
                            request_id: 0, // Will be overwritten
                            handle: i as u64,
                            status: 0,
                            arg: j as u64,
                            cmd: (i + j) as u64,
                            resp_size: body.len() as u32,
                            body: body.clone(),
                            fds: None,
                        })
                        .expect("Client call failed");

                    assert_eq!(resp.msg_type, i + 1);
                    assert_eq!(resp.handle, i as u64);
                    assert_eq!(resp.status, 0);
                    assert_eq!(resp.arg, j as u64);
                    assert_eq!(resp.cmd, (i + j) as u64);
                    assert_eq!(resp.body, body);
                }
            }));
        }

        for handle in handles {
            handle.join().expect("Client thread failed");
        }
    }
}
