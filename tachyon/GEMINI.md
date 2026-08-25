# Tachyon VMM Mandates

This document defines the architectural principles and implementation patterns for the Tachyon VMM.

> [!NOTE]
> Tachyon is currently in the initial development stage and is not yet used in production. Consequently, backward compatibility (e.g., for saved states or RPC protocols) is not maintained or required at this stage.

For details on the RPC protocol and communication layer, please refer to [src/rpc/GEMINI.md](src/rpc/GEMINI.md).

## 1. Core Architecture: Handle-Based Resource Management
Tachyon is designed as a proxy for KVM capabilities, managed through a centralized `System` registry of resources called **Handles**.

- **Global Registry**: All active resources (KVM device, VMs, VCPUs, memory files, etc.) must be stored in the `System` struct as `Arc<Handle>`.
- **Unique Identification**: Every resource is identified by a unique `u64` handle ID, atomically incremented upon creation.
- **Fixed Entry Point**: Handle ID `1` is reserved for the `KvmDevice`.
- **Ownership**: Handles own their underlying file descriptors and must ensure they are closed upon destruction (via the `Drop` trait).
- **State Management**: Specialized `HandleOps` (like `VmOps`) manage additional resources like memory mappings (`MemoryMapping`) and background workers.

## 2. Extension Pattern: Handle Operations (`HandleOps`)
New resource types must implement the `HandleOps` trait to define their behavior.

- **Request Dispatching**: The `System::dispatch` method routes incoming RPC messages to the target handle's `handle_request` implementation.
- **Return Type**: `handle_request` must return `Option<Message>`.
    - `Some(resp)` indicates an immediate response to be sent by the dispatcher.
    - `None` indicates the operation is asynchronous (like `Interrupt`) or being handled by a background worker (like `KVM_RUN`) that will send the response later.
- **Operation Enum**: Requests must map to the following core operations:
    - `Open`: Establish a new connection/session.
    - `Close`: Destroy a resource and its handle.
    - `Ioctl`: Execute a KVM ioctl on the handle's FD.
    - `MemoryFileCreate`: Create a `memfd` backed memory region.
    - `GetFileDescriptor`: Retrieve the raw FD associated with a handle.
    - `Interrupt`: Signal or "kick" a background worker (e.g., VCPU).

## 3. Ioctl Implementation & Data Protocol
Ioctls are the primary mechanism for KVM interactions.

- **Whitelist Only**: `HandleOps` implementations must only permit a specific set of supported ioctls. Return `libc::ENOSYS` for any unauthorized commands.
- **Data Transfer**: Use the `Message` `body` for input data and `resp_size` to request output data.
- **Longarg Pattern**: For ioctls requiring structured data (pointers), Tachyon copies the `body` into a local buffer, passes its pointer to the kernel, and copies the results back into the response `body` if `resp_size` is set.
- **Resource Lifecycle**: Ioctls that create new KVM resources (like `KVM_CREATE_VM` or `KVM_CREATE_VCPU`) must wrap the resulting FD in a new `Handle`, register it with the `System`, and return the new handle ID in the response.

## 4. Concurrency & VCPU Worker Model
- **Parallel Dispatch**: The VMM must support concurrent request processing. The server uses a fixed pool of RPC worker threads to process incoming requests.
- **VCPU Workers**: `KVM_RUN` operations must be offloaded to a dedicated `VcpuWorker` thread per VCPU.
- **Non-Blocking Interrupts**: `VcpuWorker` must support `SIGUSR2` interruptions to break out of blocking `KVM_RUN` calls. The worker uses `pthread_kill` with `SIGUSR2` when an `Interrupt` operation is received for its handle.
- **Signal Masking**: Workers must block `SIGUSR2` normally but allow it to be delivered during `KVM_RUN` using `KVM_SET_SIGNAL_MASK`.

## 5. Memory Management
- **Shared Memory regions**: Guest memory is managed via `MemoryFileCreate`, which creates a `memfd`.
- **FD Passing**: The `memfd` file descriptor must be sent to the client via the RPC `fds` field.
- **Mapping Flow**: For `KVM_SET_USER_MEMORY_REGION2`, Tachyon maps the `memfd` into its own address space using `mmap` before passing the resulting virtual address to the kernel KVM interface. Tachyon must track these mappings in `VmOps` and unmap them when the VM handle is closed.

## 6. Error Handling
- **Status Codes**: RPC responses must set the `status` field to `0` on success, or a positive `errno` value (retrieved via `std::io::Error::last_os_error().raw_os_error()`) on failure.
- **Validation**: Strict bounds checking on `body` lengths and `resp_size` is required to prevent buffer overflows or kernel faults.

## 7. KVM Interface & ABI
The `kvm.rs` module serves as the centralized source of truth for KVM-related constants and structures.

- **Centralized Definitions**: All KVM ioctls and their associated data structures must be defined in `src/kvm.rs`.
- **ABI Compatibility**: Data structures must use `#[repr(C)]` and implement `ByteValued` for safe memory transitions.
- **Macros**: Use provided `io_nr!`, `iow_nr!`, `ior_nr!`, and `iowr_nr!` macros to define ioctl constants consistently with the Linux kernel ABI.

## 8. Client Implementation: `virtio-kvm` (Guest Proxy)
The `virtio_kvm` device (located in `virtio-devices/src/virtio_kvm.rs`) serves as the client-side proxy running inside the guest. It translates guest requests into RPC calls to the Tachyon VMM.

- **Resource Mapping**: The guest maps KVM concepts (VMs, VCPUs, eventfds) into internal proxy structures (`VirtioKvmResource` enum containing `VirtioKvmVm`, `VirtioKvmVcpu`, etc.).
- **Handle Tracking**: The client maintains a map of guest-visible handles (`u64`) to Tachyon RPC handles (`tachyon_handle`).
- **Memory Translation**: All memory addresses received from the guest are Guest Physical Addresses (GPA). For ioctls involving pointers (e.g., via the `longarg` field), the client translates these GPAs to Host Virtual Addresses (HVA) or reads the data from guest memory to embed it into the RPC `body`. Crucially, if an input argument is multipart (i.e., the structure contains nested pointers to other structures, bitmaps, or arrays), those nested pointers are also GPAs. The client must explicitly perform GPA-to-HVA address translation for these nested pointers and handle them carefully to ensure all required data is correctly gathered, serialized, and passed to (or received from) the Tachyon VMM.
- **Asynchronous Execution (`KVM_RUN`)**: The client spawns a dedicated `VcpuWorker` thread per VCPU to handle the blocking `KVM_RUN` RPC call, allowing the main virtio queue processing thread to remain unblocked. It uses the VMM's interrupt mechanism (via `TachyonOp::Interrupt`) to kick the worker thread when the guest requests a VCPU exit (e.g., via a signal).
- **Event Notification**: Translates guest `KVM_IOEVENTFD` requests into corresponding `epoll` registrations on the host to bridge virtio interrupts to Tachyon.
- **Device BAR**: The device exposes a 64-bit prefetchable memory BAR (at index 4) that provides a continuous virtual address space region directly mapped to the VM. This BAR is used to proxy host memory mappings to the guest:
    - **Memory Files**: Memory regions created via `TachyonOp::MemoryFileCreate` have their underlying `memfd` mapped into the BAR at a specified offset.
    - **Host Proxying**: The BAR allows the guest to access host-side resources (like VCPU state or device-specific memory) by mapping them into this shared address space using `MAP_FIXED` on the host.
    - **Validation**: All `KVM_SET_USER_MEMORY_REGION` requests from the guest must use `userspace_addr` values that fall within this BAR's range.

## 9. Save/Restore (S/R) across kexec
Tachyon must support seamlessly saving and restoring its state across a host kexec to maintain guest execution.

- **Dual-Storage Strategy**:
    - **Live Update Orchestrator (LUO)**: Used to preserve file descriptors that persist across process boundaries (e.g., during Live Update). This includes `memfd`s for guest memory, `eventfd`s, and RPC sockets. **Note**: KVM device, VM, and VCPU file descriptors cannot be preserved via LUO as the kernel restricts them to the process that created them; these resources must be recreated in the new process and their state restored via KVM ioctls.
    - **Protobuf Serialization**: All other state (Handle metadata, VM mappings, VCPU KVM state) must be serialized into a protobuf stream.
- **Message Stream Format**: The serialized state file must contain a sequence of messages, each preceded by a fixed-size `MsgHeader`:
    - `u32 msg_type`: Maps to the `HandleType` enum.
    - `u32 size`: The size of the following protobuf payload.
- **HandleOps S/R Interface**:
    - `HandleOps` implementations must provide `save_state` to serialize their specific protobuf payload.
    - `HandleOps` implementations must provide a `load_state` method (with `Self: Sized`) to deserialize the payload, reconstruct the underlying OS resources (e.g., via KVM ioctls), and return an `Arc<Handle>`.
- **Restoration Ordering**: To satisfy resource dependencies, `System::restore` must reconstruct handles in a strict hierarchical order:
    1. **KVM Device** (`HandleType::KvmDevice`): Re-open `/dev/kvm`.
    2. **Memory Files** (`HandleType::MemoryFile`): Re-attach to preserved `memfd`s via LUO.
    3. **Virtual Machines** (`HandleType::Vm`): Re-create VM FDs and restore memory mappings using the restored memory files.
    4. **Virtual CPUs** (`HandleType::Vcpu`): Re-create VCPU FDs and restore all state (REGS, SREGS, FPU, LAPIC, CPUID, XSAVE/XSAVE2, etc.) using KVM `SET` ioctls.
- **XSAVE Dynamic Sizing**: When saving VCPU state, the size of the XSAVE buffer must be dynamically determined by querying KVM via `KVM_CHECK_EXTENSION` for `KVM_CAP_XSAVE2`. `KVM_GET_XSAVE2` should be preferred over `KVM_GET_XSAVE`.

## 10. Logging Principles
Tachyon prioritizes performance and clarity in its logging strategy. Adherence to these rules ensures that logging does not interfere with high-performance guest execution.

- **Silent Hot Paths**: Performance-critical operations (e.g., `KVM_RUN`, RPC `send`/`recv` loops, high-frequency ioctls) must not produce high-rate logs. Even the use of `trace!` should be considered carefully in these paths. The foundational principle is that a VM must be able to boot and operate in a reasonable timeframe even when the `trace` log level is enabled.
- **Log Level Intent**:
    - `error!`: Critical failures that prevent operation or cause resource leaks.
    - `warn!`: Unusual but recoverable events (e.g., `EINTR` on `ioctl`).
    - `info!`: Major system milestones (e.g., server start, VM created).
    - `debug!`: Structural state transitions (e.g., vCPU paused).
    - `trace!`: Detailed step-by-step execution for development debugging.
- **Structured Context**: All logs should include the relevant handle ID and subsystem prefix (e.g., `[VmOps 0x2]`).
- **Failure-Only Logging**: In request handlers, prefer logging only on failure. Successful completion should remain silent to keep logs focused and performant.

## 11. VMM Management Tooling: `tachyonctl`
`tachyonctl` is the centralized CLI tool for managing Tachyon VMM instances. It communicates with Tachyon via the RPC protocol to orchestrate complex operations.

- **Pause/Unpause**: Temporarily suspends or resumes guest execution and background vCPU workers. Essential for stabilizing state before a snapshot.
- **Save**: Serializes the current VMM state (including KVM registers, memory mappings, and handle metadata) into an image file for preservation across host `kexec`.
- **Live Update**: Orchestrates the seamless transition between a running Tachyon instance and a new binary. It manages the `Pause` -> `LiveUpdateSave` -> `Spawn New` -> `LiveUpdateRestore` -> `Unpause` sequence automatically.

## 12. Design Documentation
Detailed architectural designs and implementation plans for complex subsystems are maintained in the `docs/` directory:

- **Multi-Partition Tachyon Design** ([docs/MULTI_PARTITION_TACHYON_DESIGN.md](docs/MULTI_PARTITION_TACHYON_DESIGN.md)): Architecture and design for supporting multiple isolated Tachyon partitions and dynamic `/dev/kvm-<partition-id>` devices.
- **Polling Design** ([docs/KVM_RUN_POLLING_DESIGN.md](docs/KVM_RUN_POLLING_DESIGN.md)): High-performance polling scheme for `KVM_RUN` to bypass RPC overhead.
- **State Preservation & Restoration (S/R)** ([docs/SR_DESIGN.md](docs/SR_DESIGN.md)): Unified design for state preservation across host `kexec` and seamless Live Update.
- **S/R Implementation Plan** ([docs/wip/sr_implementation_plan.md](docs/wip/sr_implementation_plan.md)): Detailed roadmap and checklist for the S/R feature implementation.

## 13. Code Commenting Philosophy
Tachyon follows the Linux kernel's approach to code documentation:

- **The Goal of Obvious Code**: Try to not explain *how* your code works in a comment. Write the code so that its operation is obvious. Explaining badly written code is a waste of time - rewrite it instead.
- **Focus on *What* and *Why***: Generally, comments should tell *what* your code does, not *how*. Put these comments at the head of the function, describing its purpose and, if necessary, its rationale (*why*).
- **Function Body Discipline**: Avoid putting comments inside a function body. If a function is so complex that you need to separately comment parts of it, it should be refactored into smaller, simpler functions.
- **Exceptions for "Clever" Logic**: Small comments to note or warn about something particularly clever (or "ugly") are acceptable, but must not be used to excess.

## 14. Contribution Guidelines
Tachyon adheres to the broader Cloud Hypervisor contribution standards:

- **Coding Style**: Follow the Rust Style convention. Enforcement is via `rustfmt` and `clippy` (with `-D warnings`).
- **Commit Format**: Follow the `<component>: Change summary` header format. The body should explain the *why* and *how* of the change, wrapped to 72 characters.

