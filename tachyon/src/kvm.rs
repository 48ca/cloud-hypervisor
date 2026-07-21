// Copyright 2026 Google LLC
//
// SPDX-License-Identifier: Apache-2.0

use std::os::raw::c_uint;

use vm_memory::ByteValued;
use vmm_sys_util::ioctl::ioctl_expr;

pub const KVMIO: c_uint = 0xAE;

pub const IOC_NONE: c_uint = 0;
pub const IOC_WRITE: c_uint = 1;
pub const IOC_READ: c_uint = 2;
pub const IOC_INOUT: c_uint = 3;

macro_rules! io_nr {
    ($nr:expr) => {
        ioctl_expr(IOC_NONE, KVMIO, $nr, 0) as u64
    };
}

macro_rules! iow_nr {
    ($nr:expr, $type:ty) => {
        ioctl_expr(
            IOC_WRITE,
            KVMIO,
            $nr,
            std::mem::size_of::<$type>() as c_uint,
        ) as u64
    };
}

macro_rules! ior_nr {
    ($nr:expr, $type:ty) => {
        ioctl_expr(IOC_READ, KVMIO, $nr, std::mem::size_of::<$type>() as c_uint) as u64
    };
}

macro_rules! iowr_nr {
    ($nr:expr, $type:ty) => {
        ioctl_expr(
            IOC_INOUT,
            KVMIO,
            $nr,
            std::mem::size_of::<$type>() as c_uint,
        ) as u64
    };
}

pub const KVM_GET_API_VERSION: u64 = io_nr!(0x00);
pub const KVM_CREATE_VM: u64 = io_nr!(0x01);
pub const KVM_GET_MSR_INDEX_LIST: u64 = iowr_nr!(0x02, kvm_msr_list);
pub const KVM_GET_MSR_FEATURE_INDEX_LIST: u64 = iowr_nr!(0x0a, kvm_msr_list);
pub const KVM_CHECK_EXTENSION: u64 = io_nr!(0x03);
pub const KVM_GET_VCPU_MMAP_SIZE: u64 = io_nr!(0x04);
pub const KVM_GET_SUPPORTED_CPUID: u64 = iowr_nr!(0x05, kvm_cpuid2);

pub const KVM_CREATE_VCPU: u64 = io_nr!(0x41);
pub const KVM_GET_DIRTY_LOG: u64 = iow_nr!(0x42, kvm_dirty_log);
pub const KVM_SET_NR_MMU_PAGES: u64 = io_nr!(0x44);
pub const KVM_SET_USER_MEMORY_REGION: u64 = iow_nr!(0x46, kvm_userspace_memory_region);
pub const KVM_SET_TSS_ADDR: u64 = io_nr!(0x47);
pub const KVM_SET_IDENTITY_MAP_ADDR: u64 = iow_nr!(0x48, u64);
pub const KVM_SET_USER_MEMORY_REGION2: u64 = iow_nr!(0x49, kvm_userspace_memory_region2);

pub const KVM_CREATE_IRQCHIP: u64 = io_nr!(0x60);
pub const KVM_IRQ_LINE: u64 = iow_nr!(0x61, kvm_irq_level);
pub const KVM_GET_IRQCHIP: u64 = iowr_nr!(0x62, kvm_irqchip);
pub const KVM_SET_IRQCHIP: u64 = ior_nr!(0x63, kvm_irqchip);
pub const KVM_CREATE_PIT: u64 = io_nr!(0x64);
pub const KVM_GET_PIT: u64 = iowr_nr!(0x65, kvm_pit_state);
pub const KVM_SET_PIT: u64 = ior_nr!(0x66, kvm_pit_state);
pub const KVM_IRQ_LINE_STATUS: u64 = iowr_nr!(0x67, kvm_irq_level);
pub const KVM_REGISTER_COALESCED_MMIO: u64 = iow_nr!(0x67, kvm_coalesced_mmio_zone);
pub const KVM_UNREGISTER_COALESCED_MMIO: u64 = iow_nr!(0x68, kvm_coalesced_mmio_zone);
pub const KVM_SET_GSI_ROUTING: u64 = iow_nr!(0x6a, kvm_irq_routing);
pub const KVM_IRQFD: u64 = iow_nr!(0x76, kvm_irqfd);
pub const KVM_CREATE_PIT2: u64 = iow_nr!(0x77, kvm_pit_config);
pub const KVM_SET_BOOT_CPU_ID: u64 = io_nr!(0x78);
pub const KVM_IOEVENTFD: u64 = iow_nr!(0x79, kvm_ioeventfd);
pub const KVM_SET_CLOCK: u64 = iow_nr!(0x7b, kvm_clock_data);
pub const KVM_GET_CLOCK: u64 = ior_nr!(0x7c, kvm_clock_data);
pub const KVM_ENABLE_CAP: u64 = iow_nr!(0xa3, kvm_enable_cap);

pub const KVM_CAP_XSAVE2: u32 = 208;
pub const KVM_CAP_NESTED_STATE: u32 = 157;

pub const MSR_IA32_TSC: u32 = 0x10;

pub const KVM_RUN: u64 = io_nr!(0x80);
pub const KVM_GET_REGS: u64 = ior_nr!(0x81, kvm_regs);
pub const KVM_SET_REGS: u64 = iow_nr!(0x82, kvm_regs);
pub const KVM_GET_SREGS: u64 = ior_nr!(0x83, kvm_sregs);
pub const KVM_SET_SREGS: u64 = iow_nr!(0x84, kvm_sregs);
pub const KVM_TRANSLATE: u64 = iowr_nr!(0x85, kvm_translation);
pub const KVM_INTERRUPT: u64 = iow_nr!(0x86, kvm_interrupt);
pub const KVM_GET_MSRS: u64 = iowr_nr!(0x88, kvm_msrs);
pub const KVM_SET_MSRS: u64 = iow_nr!(0x89, kvm_msrs);
pub const KVM_SET_SIGNAL_MASK: u64 = iow_nr!(0x8b, _kvm_signal_mask);

// _kvm_signal_mask is used for KVM_SET_SIGNAL_MASK ioctl number calculation.
// The kernel expects the size of the struct without the flexible array member (sigset[]).
#[repr(C)]
pub struct _kvm_signal_mask {
    pub len: u32,
}
pub const KVM_GET_FPU: u64 = ior_nr!(0x8c, kvm_fpu);
pub const KVM_SET_FPU: u64 = iow_nr!(0x8d, kvm_fpu);
pub const KVM_GET_LAPIC: u64 = ior_nr!(0x8e, kvm_lapic_state);
pub const KVM_SET_LAPIC: u64 = iow_nr!(0x8f, kvm_lapic_state);
pub const KVM_SET_CPUID2: u64 = iow_nr!(0x90, kvm_cpuid2);
pub const KVM_GET_CPUID2: u64 = iowr_nr!(0x91, kvm_cpuid2);
pub const KVM_GET_MP_STATE: u64 = ior_nr!(0x98, kvm_mp_state);
pub const KVM_SET_MP_STATE: u64 = iow_nr!(0x99, kvm_mp_state);
pub const KVM_SET_GUEST_DEBUG: u64 = iow_nr!(0x9b, kvm_guest_debug);
pub const KVM_X86_SETUP_MCE: u64 = iow_nr!(0x9c, u64);
pub const KVM_X86_GET_MCE_CAP_SUPPORTED: u64 = ior_nr!(0x9d, u64);
pub const KVM_X86_SET_MCE: u64 = iow_nr!(0x9e, kvm_x86_mce);
pub const KVM_GET_PIT2: u64 = ior_nr!(0x9f, kvm_pit_state2);
pub const KVM_SET_PIT2: u64 = iow_nr!(0xa0, kvm_pit_state2);
pub const KVM_GET_VCPU_EVENTS: u64 = ior_nr!(0x9f, kvm_vcpu_events);
pub const KVM_SET_VCPU_EVENTS: u64 = iow_nr!(0xa0, kvm_vcpu_events);
pub const KVM_GET_DEBUGREGS: u64 = ior_nr!(0xa1, kvm_debugregs);
pub const KVM_SET_DEBUGREGS: u64 = iow_nr!(0xa2, kvm_debugregs);
pub const KVM_GET_TSC_KHZ: u64 = io_nr!(0xa3);
pub const KVM_SET_TSC_KHZ: u64 = io_nr!(0xa2);
pub const KVM_GET_XSAVE: u64 = ior_nr!(0xa4, kvm_xsave);
pub const KVM_SET_XSAVE: u64 = iow_nr!(0xa5, kvm_xsave);
pub const KVM_GET_XCRS: u64 = ior_nr!(0xa6, kvm_xcrs);
pub const KVM_SET_XCRS: u64 = iow_nr!(0xa7, kvm_xcrs);
pub const KVM_SIGNAL_MSI: u64 = iow_nr!(0xa5, kvm_msi);
pub const KVM_GET_ONE_REG: u64 = iow_nr!(0xab, kvm_one_reg);
pub const KVM_SET_ONE_REG: u64 = iow_nr!(0xac, kvm_one_reg);
pub const KVM_KVMCLOCK_CTRL: u64 = io_nr!(0xad);
pub const KVM_SET_PMU_EVENT_FILTER: u64 = iow_nr!(0xb2, kvm_pmu_event_filter);
pub const KVM_SMI: u64 = io_nr!(0xb7);
pub const KVM_GET_NESTED_STATE: u64 = iowr_nr!(0xbe, kvm_nested_state);
pub const KVM_SET_NESTED_STATE: u64 = iow_nr!(0xbf, kvm_nested_state);

pub const KVM_X86_SET_MSR_FILTER: u64 = iow_nr!(0xc6, kvm_msr_filter);
pub const KVM_RESET_DIRTY_RINGS: u64 = io_nr!(0xc7);
pub const KVM_GET_SREGS2: u64 = ior_nr!(0xcc, kvm_sregs2);
pub const KVM_SET_SREGS2: u64 = iow_nr!(0xcd, kvm_sregs2);
pub const KVM_GET_STATS_FD: u64 = io_nr!(0xce);
pub const KVM_GET_XSAVE2: u64 = ior_nr!(0xcf, kvm_xsave);
pub const KVM_CREATE_DEVICE: u64 = iowr_nr!(0xe0, kvm_create_device);

pub const KVM_TPR_ACCESS_REPORTING: u64 = iowr_nr!(0x92, kvm_tpr_access_ctl);
pub const KVM_SET_VAPIC_ADDR: u64 = iow_nr!(0x93, kvm_vapic_addr);

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub struct kvm_segment {
    pub base: u64,
    pub limit: u32,
    pub selector: u16,
    pub type_: u8,
    pub present: u8,
    pub dpl: u8,
    pub db: u8,
    pub s: u8,
    pub l: u8,
    pub g: u8,
    pub avl: u8,
    pub unusable: u8,
    pub padding: u8,
}
unsafe impl ByteValued for kvm_segment {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub struct kvm_dtable {
    pub base: u64,
    pub limit: u16,
    pub padding: [u16; 3],
}
unsafe impl ByteValued for kvm_dtable {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub struct kvm_sregs {
    pub cs: kvm_segment,
    pub ds: kvm_segment,
    pub es: kvm_segment,
    pub fs: kvm_segment,
    pub gs: kvm_segment,
    pub ss: kvm_segment,
    pub tr: kvm_segment,
    pub ldt: kvm_segment,
    pub gdt: kvm_dtable,
    pub idt: kvm_dtable,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    pub efer: u64,
    pub apic_base: u64,
    pub interrupt_bitmap: [u64; 4],
}
unsafe impl ByteValued for kvm_sregs {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub struct kvm_regs {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}
unsafe impl ByteValued for kvm_regs {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub struct kvm_fpu {
    pub fpr: [[u8; 16]; 8],
    pub fcw: u16,
    pub fsw: u16,
    pub ftwx: u8,
    pub pad1: u8,
    pub last_opcode: u16,
    pub last_ip: u64,
    pub last_dp: u64,
    pub xmm: [[u8; 16]; 16],
    pub mxcsr: u32,
    pub pad2: u32,
}
unsafe impl ByteValued for kvm_fpu {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub struct kvm_xcr {
    pub xcr: u32,
    pub reserved: u32,
    pub value: u64,
}
unsafe impl ByteValued for kvm_xcr {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub struct kvm_xcrs {
    pub nr_xcrs: u32,
    pub flags: u32,
    pub xcrs: [kvm_xcr; 16],
    pub padding: [u64; 16],
}
unsafe impl ByteValued for kvm_xcrs {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub struct kvm_mp_state {
    pub mp_state: u32,
}
unsafe impl ByteValued for kvm_mp_state {}

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct kvm_ioeventfd {
    pub datamatch: u64,
    pub addr: u64,
    pub len: u32,
    pub fd: i32,
    pub flags: u32,
    pub pad: [u8; 36],
}

impl Default for kvm_ioeventfd {
    fn default() -> Self {
        kvm_ioeventfd {
            datamatch: 0,
            addr: 0,
            len: 0,
            fd: 0,
            flags: 0,
            pad: [0; 36],
        }
    }
}
unsafe impl ByteValued for kvm_ioeventfd {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct kvm_cpuid_entry2 {
    pub function: u32,
    pub index: u32,
    pub flags: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub padding: [u32; 3],
}
unsafe impl ByteValued for kvm_cpuid_entry2 {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct kvm_cpuid2 {
    pub nent: u32,
    pub padding: u32,
}
unsafe impl ByteValued for kvm_cpuid2 {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct kvm_userspace_memory_region {
    pub slot: u32,
    pub flags: u32,
    pub guest_phys_addr: u64,
    pub memory_size: u64,
    pub userspace_addr: u64,
}
unsafe impl ByteValued for kvm_userspace_memory_region {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct kvm_userspace_memory_region2 {
    pub slot: u32,
    pub flags: u32,
    pub guest_phys_addr: u64,
    pub memory_size: u64,
    pub userspace_addr: u64,
    pub guest_memfd_offset: u64,
    pub guest_memfd: u32,
    pub pad1: u32,
    pub pad2: [u64; 14],
}
unsafe impl ByteValued for kvm_userspace_memory_region2 {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct kvm_userspace_memory_region2_wrapper {
    pub region2: kvm_userspace_memory_region2,
    pub guest_memfd_handle: u64,
}
unsafe impl ByteValued for kvm_userspace_memory_region2_wrapper {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct kvm_msr_list {
    pub nmsrs: u32,
}
unsafe impl ByteValued for kvm_msr_list {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct kvm_msr_entry {
    pub index: u32,
    pub reserved: u32,
    pub data: u64,
}
unsafe impl ByteValued for kvm_msr_entry {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct kvm_msrs {
    pub nmsrs: u32,
    pub pad: u32,
}
unsafe impl ByteValued for kvm_msrs {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct kvm_signal_mask {
    pub len: u32,
    pub sigset: [u8; 8],
}
unsafe impl ByteValued for kvm_signal_mask {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct kvm_irq_level {
    pub irq: u32,
    pub level: u32,
}
unsafe impl ByteValued for kvm_irq_level {}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct kvm_irqchip {
    pub chip_id: u32,
    pub pad: u32,
    pub chip: [u8; 512],
}

impl Default for kvm_irqchip {
    fn default() -> Self {
        kvm_irqchip {
            chip_id: 0,
            pad: 0,
            chip: [0; 512],
        }
    }
}
unsafe impl ByteValued for kvm_irqchip {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct kvm_msr_filter_range {
    pub flags: u32,
    pub nmsrs: u32,
    pub base: u32,
    pub bitmap: u64,
}
unsafe impl ByteValued for kvm_msr_filter_range {}

pub const KVM_MSR_FILTER_MAX_RANGES: usize = 16;
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct kvm_msr_filter {
    pub flags: u32,
    pub ranges: [kvm_msr_filter_range; KVM_MSR_FILTER_MAX_RANGES],
}
unsafe impl ByteValued for kvm_msr_filter {}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct kvm_lapic_state {
    pub regs: [std::os::raw::c_char; 1024],
}

impl Default for kvm_lapic_state {
    fn default() -> Self {
        kvm_lapic_state { regs: [0; 1024] }
    }
}
unsafe impl ByteValued for kvm_lapic_state {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct kvm_vcpu_events {
    pub exception: kvm_vcpu_events_exception,
    pub interrupt: kvm_vcpu_events_interrupt,
    pub nmi: kvm_vcpu_events_nmi,
    pub sipi_vector: u32,
    pub flags: u32,
    pub smi: kvm_vcpu_events_smi,
    pub triple_fault_pending: u8,
    pub reserved: [u8; 26],
    pub exception_has_payload: u8,
    pub exception_payload: u64,
}
unsafe impl ByteValued for kvm_vcpu_events {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct kvm_vcpu_events_exception {
    pub injected: u8,
    pub nr: u8,
    pub has_error_code: u8,
    pub pending: u8,
    pub error_code: u32,
}
unsafe impl ByteValued for kvm_vcpu_events_exception {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct kvm_vcpu_events_interrupt {
    pub injected: u8,
    pub nr: u8,
    pub soft: u8,
    pub shadow: u8,
}
unsafe impl ByteValued for kvm_vcpu_events_interrupt {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct kvm_vcpu_events_nmi {
    pub injected: u8,
    pub pending: u8,
    pub masked: u8,
    pub pad: u8,
}
unsafe impl ByteValued for kvm_vcpu_events_nmi {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct kvm_vcpu_events_smi {
    pub smm: u8,
    pub pending: u8,
    pub smm_inside_nmi: u8,
    pub latched_init: u8,
}
unsafe impl ByteValued for kvm_vcpu_events_smi {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct kvm_debugregs {
    pub db: [u64; 4],
    pub dr6: u64,
    pub dr7: u64,
    pub flags: u64,
    pub reserved: [u64; 9],
}
unsafe impl ByteValued for kvm_debugregs {}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct kvm_xsave {
    pub region: [u32; 1024],
}

impl Default for kvm_xsave {
    fn default() -> Self {
        kvm_xsave { region: [0; 1024] }
    }
}
unsafe impl ByteValued for kvm_xsave {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct kvm_sregs2 {
    pub cs: kvm_segment,
    pub ds: kvm_segment,
    pub es: kvm_segment,
    pub fs: kvm_segment,
    pub gs: kvm_segment,
    pub ss: kvm_segment,
    pub tr: kvm_segment,
    pub ldt: kvm_segment,
    pub gdt: kvm_dtable,
    pub idt: kvm_dtable,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    pub efer: u64,
    pub apic_base: u64,
    pub flags: u64,
    pub pdptrs: [u64; 4],
}
unsafe impl ByteValued for kvm_sregs2 {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct kvm_x86_mce {
    pub status: u64,
    pub addr: u64,
    pub misc: u64,
    pub mcg_status: u64,
    pub bank: u8,
    pub pad1: [u8; 7],
    pub pad2: [u64; 3],
}
unsafe impl ByteValued for kvm_x86_mce {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct kvm_nested_state {
    pub flags: u16,
    pub format: u16,
    pub size: u32,
    pub hdr: kvm_nested_state_hdr,
}
unsafe impl ByteValued for kvm_nested_state {}

#[repr(C)]
#[derive(Copy, Clone)]
pub union kvm_nested_state_hdr {
    pub vmx: kvm_vmx_nested_state_hdr,
    pub svm: kvm_svm_nested_state_hdr,
    pub pad: [u8; 120],
}

impl Default for kvm_nested_state_hdr {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

impl std::fmt::Debug for kvm_nested_state_hdr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("kvm_nested_state_hdr").finish()
    }
}
unsafe impl ByteValued for kvm_nested_state_hdr {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct kvm_vmx_nested_state_hdr {
    pub vmxon_pa: u64,
    pub vmcs12_pa: u64,
    pub smm_flags: u16,
    pub pad: u16,
    pub flags: u32,
    pub preemption_timer_deadline: u64,
}
unsafe impl ByteValued for kvm_vmx_nested_state_hdr {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct kvm_svm_nested_state_hdr {
    pub vmcb_pa: u64,
}
unsafe impl ByteValued for kvm_svm_nested_state_hdr {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct kvm_pit_state {
    pub channels: [kvm_pit_channel_state; 3],
}
unsafe impl ByteValued for kvm_pit_state {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct kvm_pit_channel_state {
    pub count: u32,
    pub latched_count: u16,
    pub count_latched: u8,
    pub status_latched: u8,
    pub status: u8,
    pub read_state: u8,
    pub write_state: u8,
    pub write_latch: u8,
    pub rw_mode: u8,
    pub mode: u8,
    pub bcd: u8,
    pub gate: u8,
    pub count_load_time: u64,
}
unsafe impl ByteValued for kvm_pit_channel_state {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct kvm_pit_state2 {
    pub channels: [kvm_pit_channel_state; 3],
    pub flags: u32,
    pub reserved: [u32; 9],
}
unsafe impl ByteValued for kvm_pit_state2 {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct kvm_pit_config {
    pub flags: u32,
    pub pad: [u32; 15],
}
unsafe impl ByteValued for kvm_pit_config {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct kvm_pmu_event_filter {
    pub action: u32,
    pub nevents: u32,
    pub fixed_counter_bitmap: u32,
    pub flags: u32,
    pub pad: [u32; 4],
}
unsafe impl ByteValued for kvm_pmu_event_filter {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct kvm_dirty_log {
    pub slot: u32,
    pub padding1: u32,
    pub dirty_bitmap: u64,
}
unsafe impl ByteValued for kvm_dirty_log {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct kvm_coalesced_mmio_zone {
    pub addr: u64,
    pub size: u32,
    pub pio: u32,
}
unsafe impl ByteValued for kvm_coalesced_mmio_zone {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct kvm_irq_routing {
    pub nr: u32,
    pub flags: u32,
}
unsafe impl ByteValued for kvm_irq_routing {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct kvm_irq_routing_entry {
    pub gsi: u32,
    pub r#type: u32,
    pub flags: u32,
    pub pad: u32,
    pub u: [u32; 8],
}
unsafe impl ByteValued for kvm_irq_routing_entry {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct kvm_irqfd {
    pub fd: u32,
    pub gsi: u32,
    pub flags: u32,
    pub resamplefd: u32,
    pub pad: [u8; 16],
}
unsafe impl ByteValued for kvm_irqfd {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct kvm_clock_data {
    pub clock: u64,
    pub flags: u32,
    pub pad0: u32,
    pub realtime: u64,
    pub host_tsc: u64,
    pub pad: [u32; 4],
}
unsafe impl ByteValued for kvm_clock_data {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct kvm_translation {
    pub linear_address: u64,
    pub physical_address: u64,
    pub valid: u8,
    pub writeable: u8,
    pub usermode: u8,
    pub pad: [u8; 5],
}
unsafe impl ByteValued for kvm_translation {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct kvm_interrupt {
    pub irq: u32,
}
unsafe impl ByteValued for kvm_interrupt {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct kvm_guest_debug_arch {
    pub debugreg: [u64; 8],
}
unsafe impl ByteValued for kvm_guest_debug_arch {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct kvm_guest_debug {
    pub control: u32,
    pub pad: u32,
    pub arch: kvm_guest_debug_arch,
}
unsafe impl ByteValued for kvm_guest_debug {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct kvm_msi {
    pub address_lo: u32,
    pub address_hi: u32,
    pub data: u32,
    pub flags: u32,
    pub devid: u32,
    pub pad: [u8; 12],
}
unsafe impl ByteValued for kvm_msi {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct kvm_one_reg {
    pub id: u64,
    pub addr: u64,
}
unsafe impl ByteValued for kvm_one_reg {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct kvm_create_device {
    pub r#type: u32,
    pub fd: u32,
    pub flags: u32,
}
unsafe impl ByteValued for kvm_create_device {}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct kvm_enable_cap {
    pub cap: u32,
    pub flags: u32,
    pub args: [u64; 4],
    pub pad: [u8; 64],
}

impl Default for kvm_enable_cap {
    fn default() -> Self {
        kvm_enable_cap {
            cap: 0,
            flags: 0,
            args: [0; 4],
            pad: [0; 64],
        }
    }
}
unsafe impl ByteValued for kvm_enable_cap {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct kvm_tpr_access_ctl {
    pub enabled: u32,
    pub flags: u32,
    pub reserved: [u32; 8],
}
unsafe impl ByteValued for kvm_tpr_access_ctl {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct kvm_vapic_addr {
    pub vapic_addr: u64,
}
unsafe impl ByteValued for kvm_vapic_addr {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct kvm_ioeventfd_wrapped {
    pub kvm: kvm_ioeventfd,
    pub fd_handle: u64,
}
unsafe impl ByteValued for kvm_ioeventfd_wrapped {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct kvm_irqfd_wrapped {
    pub kvm: kvm_irqfd,
    pub fd_handle: u64,
    pub resamplefd_handle: u64,
}
unsafe impl ByteValued for kvm_irqfd_wrapped {}

pub const KVM_IOEVENTFD_FLAG_PIO: u32 = 1 << 0;
pub const KVM_IOEVENTFD_FLAG_DATAMATCH: u32 = 1 << 1;
pub const KVM_IOEVENTFD_FLAG_DEASSIGN: u32 = 1 << 2;

pub const KVM_IRQFD_FLAG_DEASSIGN: u32 = 1 << 0;
pub const KVM_IRQFD_FLAG_RESAMPLE: u32 = 1 << 1;
