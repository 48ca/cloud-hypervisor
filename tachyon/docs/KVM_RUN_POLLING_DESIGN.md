# KVM_RUN Shared Memory Polling Design

## 1. Objective
Introduce a high-performance polling scheme for handling the `KVM_RUN` ioctl. This bypasses the synchronous RPC overhead between the `virtio-kvm` guest driver and the Tachyon VMM by using a shared memory region to signal state changes and pass return codes.

## 2. Shared Memory Layout
A per-VM shared memory region will be created (e.g., via a `memfd` allocated by Tachyon and mapped into the guest's BAR, or via guest memory passed to Tachyon). To prevent false sharing between host vCPU threads, each vCPU's state and status are grouped into a structure padded to a typical CPU cache line size (64 bytes).

```rust
const MAX_VCPUS: usize = 256;

#[repr(C, align(64))]
pub struct PerVcpuState {
    pub state: u32,    // AtomicU32: Bits 0-3 Execution, Bits 4-7 Flags
    pub status: i32,   // Return code from KVM_RUN
    pub _padding: [u8; 56], 
}

#[repr(C)]
pub struct VcpuSharedMemory {
    pub vcpus: [PerVcpuState; MAX_VCPUS],
}
```

### 2.1 State & Flag Definitions
The `vcpus[vcpu_id].state` field is a bitmask:

*   **Execution State (Bits 0-3)**:
    *   `STATE_IDLE` (0x0): The vCPU is idle.
    *   `STATE_RUN_REQUESTED` (0x1): The guest requests `KVM_RUN`.
    *   `STATE_COMPLETED` (0x2): The host has completed `KVM_RUN`.
*   **Status Flags (Bits 4-7)**:
    *   `FLAG_HOST_POLLING` (0x10): Set by the host while it is actively busy-polling the state.

## 3. Host (Tachyon) Design
### 3.1 Polling VcpuWorker
The existing `VcpuWorker` thread for each vCPU will be modified:
1.  **Enter Polling**: Set `FLAG_HOST_POLLING` in `vcpus[vcpu_id].state` using atomic OR with `Release` ordering.
2.  **Polling Loop**: For a configured duration, check the execution state bits.
3.  **Run Execution**: If `STATE_RUN_REQUESTED` is observed (via atomic load `Acquire`):
    *   Execute `KVM_RUN` ioctl.
    *   On return, write exit code to `vcpus[vcpu_id].status`.
    *   Transition execution state to `STATE_COMPLETED` (atomic store `Release`).
4.  **Sleep Fallback**:
    *   Clear `FLAG_HOST_POLLING` using atomic AND with `Release` ordering.
    *   Re-check the execution state one last time. If `STATE_RUN_REQUESTED` is now set, skip the sleep and loop back to execution.
    *   Otherwise, call `std::thread::park()` to put the thread to sleep.
5. **Wakeup (Ready)**: A new operation `TachyonOp::Ready` will be introduced. When the RPC thread receives this command, it identifies the target `VcpuWorker` and calls `.unpark()` on its thread handle. Because `unpark()` tokens are persistent, if the guest calls `unpark()` just before the host calls `park()`, the host will not sleep.

## 4. Guest (`virtio-kvm`) Design

### 4.1 Submitting KVM_RUN
The guest proxy thread for a vCPU will no longer block on an RPC call to Tachyon.
1.  Set execution state to `STATE_RUN_REQUESTED` (atomic store `Release`).
2.  Check `FLAG_HOST_POLLING` in `vcpus[vcpu_id].state` (atomic load `Acquire`).
3.  If `FLAG_HOST_POLLING` is NOT set, send `TachyonOp::Ready` RPC to trigger the host's `unpark()`.

### 4.2 Guest Polling Thread (Kernel Driver)
Instead of per-vCPU threads blocking on RPC responses, the guest will utilize a single polling thread within the guest's `virtio-kvm` kernel driver. This thread is assumed to be always active and monitoring all vCPUs via the mapped shared memory.
1.  **Completion Detection**:
    *   The kernel polling thread continuously monitors the `vcpus[vcpu_id].state` field across all vCPUs.
    *   On observing `STATE_COMPLETED` (atomic load `Acquire`), it processes the result, completes the pending `KVM_RUN` request for that vCPU, and resets the execution state to `STATE_IDLE`.

## 5. Synchronization & Memory Ordering
To ensure correctness without mutexes, all reads and writes to the `vcpus[vcpu_id].state` field MUST use `std::sync::atomic::AtomicU32`.
*   Writes that signal a state transition (Guest -> `STATE_RUN_REQUESTED`, Host -> `STATE_COMPLETED`) must use `Ordering::Release`.
*   Reads that check for state transitions must use `Ordering::Acquire`.
*   `vcpus[vcpu_id].status` can be read/written as regular memory, as its access is protected by the synchronization of the `state` field.

## 6. Future Optimizations
*   **Adaptive Polling**: Both the host and guest can implement adaptive polling heuristics to dynamically adjust polling durations based on vCPU activity to balance latency and CPU usage.
