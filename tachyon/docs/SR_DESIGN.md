# Design Document: Tachyon State Preservation and Restoration (S/R)

## 1. Objective
Implement a unified mechanism for preserving and restoring the state of the Tachyon VMM and its guest-side (DOM0 vmm) proxy device (`virtio-kvm`). This covers three primary use cases:
1. **Tachyon Live Update**: Seamlessly updating the Tachyon VMM binary on a running host without interrupting guest execution.
2. **DOM0 VMM Live Update**: Enabling Cloud Hypervisor (CH) to suspend, snapshot, and resume virtual machines using the `virtio-kvm` device.
3. **Kexec S/R**: Persisting Tachyon and DOM0 states across a host kernel reboot (kexec).

---

## 2. Tachyon State Preservation

Tachyon utilizes a Handle-based resource management system. State preservation involves serializing the `System` registry of handles and their associated KVM/OS state.

### 2.1 Dual-Storage Strategy
Regardless of the scenario, Tachyon employs a two-pronged approach to state handover:
1. **Tachyon Live Update Orchestrator (T-LUO)**: Used to preserve file descriptors (FDs) that can survive the transition (e.g., guest memory `memfds`, `eventfds`, RPC sockets).
2. **Protobuf Serialization**: All metadata and KVM-specific state (REGS, SREGS, etc.) are serialized into a stream of protobuf-encoded messages.

### 2.2 Message Stream Format
To ensure extensibility, each protobuf message in the state stream is preceded by a fixed-size header:
- **Type (u32)**: Identifier for the handle type (e.g., VM, VCPU).
- **Size (u32)**: The size of the following serialized protobuf payload.

```
[Header: Type, Size][Protobuf Payload]
[Header: Type, Size][Protobuf Payload]
...
```

### 2.3 Execution Scenarios

#### 2.3.1 Kexec S/R (Cross-Kernel)
- **Trigger**: The host kernel update is initiated.
- **Storage**: State is serialized into a **single file** on an FS DAX (Direct Access File System) backed filesystem.
- **FD Preservation**: LUO handles the preservation of supported FDs across the kernel boundary.
- **Restoration**: The new Tachyon instances are started with the `--restore <image_path>` flag.

#### 2.3.2 Live Update (Cross-Process)
- **Trigger**: `tachyonctl liveupdate --tachyon-bin <path>`.
- **Storage**: The old process serializes the state stream into a **new `memfd`**.
- **Handover**: The `memfd` and all other preserved FDs are sent to the new process via Unix domain socket control messages (`SCM_RIGHTS`) during a `LiveUpdateSave`/`LiveUpdateRestore` RPC exchange.
- **Seamless Transition**: Active RPC client connections are preserved, allowing proxies (like `cloud-hypervisor`) to continue operation without reconnection.

### 2.4 Handle Serialization Interface
The `HandleOps` trait provides the contract for state management:

```rust
pub trait HandleOps: Send + Sync {
    // Write header and protobuf payload to the stream
    fn save_state(&self, handle: &Handle, writer: &mut dyn Write) -> Result<(), std::io::Error>;
    
    // Reconstruct the handle from the serialized payload
    fn restore_state(state: &[u8]) -> Result<Arc<Handle>, std::io::Error> where Self: Sized;
}
```

### 2.5 Restoration Ordering
To satisfy resource dependencies, restoration must follow a strict hierarchy:
1. **KVM Device**: Open `/dev/kvm`.
2. **Memory Files**: Reattach to preserved `memfds` via LUO.
3. **Virtual Machines**: Re-create VM FDs and restore memory mappings.
4. **Virtual CPUs**: Re-create VCPU FDs and restore full register state.
5. **Event Routing**: Re-register `ioeventfd` and `irqfd` configurations.
6. **RPC Resumption**: Resume acceptance loops and worker threads for inherited sockets.

### 2.6 File Descriptor Management (T-LUO)
The T-LUO interface manages the collection and mapping of FDs that survive the transition. Its capabilities vary by scenario:

- **Live Update (Cross-Process)**: LUO preserves a broad range of FDs, including guest memory `memfds`, `eventfds`, listening RPC sockets, and active `RpcChannel` FDs. This allows for a completely seamless transition where clients do not need to reconnect.
- **Kexec S/R (Cross-Kernel)**: The standard system-wide LUO daemon is used. LUO is restricted to preserving `memfds` and `vfio` FDs. Resources like `eventfds` and sockets cannot survive the kernel boundary via LUO and must be recreated or re-established by the client.

**Recreated (via OS/KVM)**: Regardless of the scenario, KVM-specific FDs (`/dev/kvm`, VM FDs, and VCPU FDs) must always be recreated in the new process as the kernel restricts them to the process that created them.

### 2.7 RPC Protocol Enhancements
- **LiveUpdate Operations**: `LiveUpdateSave` (old process) and `LiveUpdateRestore` (new process) commands.
- **Asynchronous Notification**: `NotifyLiveUpdate` (Op 14). After a successful `LiveUpdateRestore`, the system broadcasts this operation to all active RPC channels. This allows clients to perform post-restoration cleanup.
- **Persistent Handle IDs**: Tachyon preserves the exact numeric IDs of all handles. RPC structures are "wrapped" (e.g., `kvm_ioeventfd_wrapped`) to include these persistent IDs, allowing the source of truth for doorbells and IRQs to remain consistent across updates.
- **Redundant FD Elimination**: By using persistent handle IDs, the protocol eliminates the need for redundant FD transfers via `SCM_RIGHTS` for doorbell and IRQ registration, simplifying the interaction for proxy clients.

---

## 3. Guest-Side Device Suspend/Restore (`virtio-kvm` Client)

Enable Cloud Hypervisor (CH) to suspend and resume virtual machines that use the `virtio-kvm` device. This requires saving the internal state of `virtio-kvm` during a snapshot and recreating its resources, mappings, and connection to Tachyon upon restore.

### 3.1 State Identification
All shared KVM resources are owned and managed by the Tachyon process. Since Tachyon is designed as a persistent, long-running proxy, it remains active and preserves all host KVM resource attributes (sizes, offsets) and their exact `tachyon_handle` IDs across a guest suspend/restore cycle.

Therefore, `virtio-kvm`'s snapshot only needs to capture its *local* view and the references to the Tachyon handles so it can re-acquire them after restore.

The `VirtioKvmState` structure includes:
- **Virtio Features**: `avail_features` and `acked_features`.
- **Handle Counter**: The atomic `NEXT_HANDLE_ID` value to prevent collisions upon restore.
- **Resource Maps (Local to CH)**:
  - `vms`: Maps local CH `Handle`s to their corresponding resource type (VM, VCPU, Stats) and their preserved `tachyon_handle` IDs.
  - `eventfds`: Maps local handles to eventfd metadata and their `tachyon_handle` IDs.
  - `mem_files`: Maps local handles to memory file references and their `tachyon_handle` IDs.
  - `mappings`: BAR 4 mappings (`phys_offset`, `size`, `device_offset`) linking guest physical addresses to Tachyon resources (since PCI BAR layout is managed by Cloud Hypervisor).

### 3.2 Pause & Snapshot (Save) Process
When Cloud Hypervisor initiates a VM pause and subsequent snapshot, the `virtio-kvm` device's handlers are invoked:

1. **VCPU Pausing (Tachyon RPC)**: During `pause()`, `virtio-kvm` sends a `Pause` RPC command (Op 10) to Tachyon. This cleanly signals all background `VcpuWorker` threads to break out of their active `KVM_RUN` loops and enter the `Paused` state. This is critical to release the kernel's KVM `vcpu->mutex` locks so that restoration ioctls can be executed without deadlocking.
2. **In-Flight Request Flushing**: During `pause()`, `virtio-kvm` writes to `poll_wakeup_fd` to wake up the background `poll_worker_run` thread. If an asynchronous `EventfdPoll` (Op 11) request is active, the poll worker cleanly intercepts the wakeup, completes the request with `EINTR`, adds the descriptor chain to the used ring, and signals the guest. This ensures all in-flight descriptor chains are safely retired and written to guest memory *before* serialization, keeping the virtio queue indices perfectly in sync.
3. **State Serialization**: When `snapshot()` is called, `virtio-kvm` iterates over its internal maps (`vms`, `eventfds`, etc.) and serializes their local metadata into the expanded `VirtioKvmState`.

### 3.3 Restore & Resume Process
When Cloud Hypervisor is launched with `--restore`, `VirtioKvm::new()` is called with the deserialized `VirtioKvmState`.

1. **Reconnection**: `virtio-kvm` connects to the Tachyon socket (`/tmp/tachyon-api.sock`).
2. **Resource Re-attachment**: For each tracked resource in the restored state, `virtio-kvm` calls `GetFileDescriptor` (Op 4) using the preserved `tachyon_handle` ID to re-acquire the corresponding host file descriptor.
   - For `Vm` resources, standard `GetFileDescriptor` is optimized on the server side to return both the VM FD and the SHM FD sequentially.
   - For `Stats` resources, they are cleanly reconstructed by re-triggering `KVM_GET_STATS_FD` on their restored parent's (`Vm` or `Vcpu`) newly re-acquired host FD.
3. **Mapping Restoration**: `virtio-kvm` iterates through the saved `mappings` and executes `mmap` with `MAP_FIXED` to map the newly acquired FDs into the correct offsets within the PCI BAR 4 range.
4. **State Reconstruction**: The internal maps (`vms`, `eventfds`, `mem_files`, and `mappings`) are repopulated. The atomic `NEXT_HANDLE_ID` counter is restored to prevent handle ID collisions.
5. **Eventfd Registration**: During `activate()`, all restored eventfds are re-registered to the newly created epoll instance, and the local `fd_to_handle` mapping is rebuilt.
6. **Unpausing**: During `resume()`, `virtio-kvm` sends an `Unpause` RPC command (Op 11) to Tachyon to transition the VCPU worker threads back into their active `KVM_RUN` execution loop.

### 3.4 Live Update VCPU BAR 4 Mapping Refresh
Since KVM VCPU file descriptors cannot be shared across processes, any memory-mapped regions associated with them (such as the `kvm_run` structure mapped into BAR 4 in `virtio-kvm`) become invalid after a live update.

To address this:
1. **Notification**: The client receives a `NotifyLiveUpdate` message.
2. **FD Refresh**: The client iterates through all active VM and VCPU resources and calls `GetFileDescriptor` (Op 4) to retrieve the new FDs from the restored process.
3. **Fixed Mapping**: The client uses `mmap` with `MAP_FIXED` to overlay the new VCPU memory regions onto the existing BAR 4 offsets.
4. **Request Retry**: In-flight RPC requests are aborted during the refresh to ensure they are retried against the new Tachyon instance with valid mappings.

---

## 4. Tooling & CLI
- **VMM Support**: `--restore <path>` argument for direct file-based restoration.
- **`tachyonctl liveupdate`**: Orchestrates the process-to-process handover, including spawning the new binary and managing the RPC exchange.

## 5. Verification
- **Integration Tests**: Simulate both kexec (file-based) and Live Update (memfd/RPC-based) cycles.
- **State Validation**: Ensure guest execution (e.g., a running loop) continues accurately after the transition.
