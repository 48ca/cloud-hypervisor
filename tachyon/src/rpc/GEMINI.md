# Tachyon RPC Library Mandates

This document defines the foundational principles and technical requirements for the Tachyon RPC library. Adherence to these mandates is required for all future modifications and extensions.

## 1. Architectural Integrity
- **Transport Layer**: The protocol is strictly built on top of `SOCK_SEQPACKET` Unix domain sockets. This ensures message boundaries are preserved at the kernel level.
- **Single Syscall Guarantee**:
    - Every message must be sent using exactly one `sendmsg(2)` system call.
    - Every message must be received using exactly one `recvmsg(2)` system call.
    - Partial reads/writes are considered protocol errors.

## 2. Protocol Specification
- **Header Format**: Every message starts with a fixed-size 64-byte header:
    - `u32 type`: Identifies the command or message category.
    - `u32 size`: The size of the message body in bytes (excluding header).
    - `u64 request_id`: A unique identifier for matching responses to requests.
    - `u64 handle`: A handle to the target resource (e.g., VM, VCPU).
    - `u64 status`: Status code (usually used in responses).
    - `u64 arg`: General purpose argument for the command.
    - `u64 cmd`: Specific sub-command or ioctl number.
    - `u32 resp_size`: Expected response body size.
    - `u32 padding1`: Reserved for alignment.
    - `u64 padding2`: Reserved for alignment (ensures 64-byte fixed size).
- **Body**: A binary payload following the header, with a maximum size defined by `MAX_MESSAGE_SIZE - MESSAGE_HEADER_SIZE`.
- **FD Passing**: File descriptors must be transferred using Unix domain socket control messages (`SCM_RIGHTS`).

## 3. Concurrency & Thread Safety
- **Client-Side Multiplexing**: The `RpcClient` is designed to be shared across multiple threads.
    - **Request/Response Matching**: The `RpcClient` maintains an internal registry (multiplexer) to route responses back to the originating thread based on the `request_id`.
    - **Receiver Thread**: A dedicated background thread must be used to drain the socket and dispatch messages to pending request handlers.
- **Server-Side Multiplexing (RpcThreadPool)**:
    - **Fixed Thread Pool**: The server must handle multiple concurrent client connections using a fixed pool of worker threads.
    - **Reactor-Worker Model**: A single reactor thread must use `epoll` to monitor connection readability.
    - **Concurrency Safety**: Use `EPOLLONESHOT` when registering connection FDs in `epoll` to ensure that a connection is only processed by one worker thread at a time, preventing race conditions on concurrent reads.
    - **Re-arming**: Workers must explicitly re-arm the connection in `epoll` after processing a message.
- **Atomic Writes**: Access to the write side of the `Channel` must be synchronized (e.g., via `Mutex` or handled by atomic syscalls) to prevent message interleaving during concurrent operations.

## 4. Resource Management
- **Alignment**: Control buffers for `SCM_RIGHTS` must be properly aligned (e.g., using `u64` arrays) to satisfy architectural requirements for `cmsghdr` structures.
- **Connection Lifecycle**: If the connection is lost, all pending requests in the multiplexer must be notified/aborted immediately to avoid deadlocking waiting threads.
- **Asynchronous Notifications**:
    - Notifications are identified by `request_id = 0`.
    - `RpcClient` must support a registered notification handler callback.
    - **Deadlock Prevention**: Notification handlers must be executed in a separate thread from the receiver loop. This ensures that if a handler makes a nested RPC call, the receiver thread remains available to process the response.

## 5. Testing Standards
- All changes to the protocol or multiplexer must be verified with:
    - Functional tests for basic message exchange.
    - File descriptor passing validation.
    - Concurrent stress tests ensuring `request_id` isolation under high thread counts.
