// Copyright 2026 Google LLC
//
// SPDX-License-Identifier: Apache-2.0

use std::os::raw::c_uint;

use vm_memory::ByteValued;
use vmm_sys_util::ioctl::ioctl_expr;

pub const VFIO_TYPE: c_uint = 0x3b;
/// ';'
pub const VFIO_BASE: c_uint = 100; // VFIO ioctl nr starts here

pub const VFIO_API_VERSION: c_uint = 0;

pub const IOC_NONE: c_uint = 0;
pub const IOC_WRITE: c_uint = 1;
pub const IOC_READ: c_uint = 2;
pub const IOC_INOUT: c_uint = 3;

macro_rules! io_nr {
    ($nr:expr) => {
        ioctl_expr(IOC_NONE, VFIO_TYPE, $nr, 0) as u64
    };
}

macro_rules! iow_nr {
    ($nr:expr, $type:ty) => {
        ioctl_expr(IOC_NONE, VFIO_TYPE, $nr, 0) as u64
        /*
        ioctl_expr(
            IOC_WRITE,
            VFIO_TYPE,
            $nr,
            std::mem::size_of::<$type>() as c_uint,
        ) as u64
        */
    };
}

macro_rules! ior_nr {
    ($nr:expr, $type:ty) => {
        ioctl_expr(IOC_NONE, VFIO_TYPE, $nr, 0) as u64
        /*
        ioctl_expr(IOC_READ, VFIO_TYPE, $nr, std::mem::size_of::<$type>() as c_uint) as u64
        */
    };
}

macro_rules! iowr_nr {
    ($nr:expr, $type:ty) => {
        ioctl_expr(IOC_NONE, VFIO_TYPE, $nr, 0) as u64
        /*
        ioctl_expr(
            IOC_INOUT,
            VFIO_TYPE,
            $nr,
            std::mem::size_of::<$type>() as c_uint,
        ) as u64
        */
    };
}

pub const VFIO_GET_API_VERSION: u64 = io_nr!(VFIO_BASE);

pub const VFIO_TYPE1_IOMMU: u32 = 1;
#[allow(non_upper_case_globals)]
pub const VFIO_TYPE1v2_IOMMU: u32 = 3;
pub const VFIO_CHECK_EXTENSION: u64 = io_nr!(VFIO_BASE + 0x01);

pub const VFIO_SET_IOMMU: u64 = io_nr!(VFIO_BASE + 0x02);

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct vfio_group_status {
    pub argsz: u32,
    pub flags: u32,
}
pub const VFIO_GROUP_GET_STATUS: u64 = iow_nr!(VFIO_BASE + 0x03, vfio_group_status);
pub const VFIO_GROUP_SET_CONTAINER: u64 = io_nr!(VFIO_BASE + 0x04);
pub const VFIO_GROUP_UNSET_CONTAINER: u64 = io_nr!(VFIO_BASE + 0x05);
pub const VFIO_GROUP_GET_DEVICE_FD: u64 = io_nr!(VFIO_BASE + 0x06);

// Device IOCTLs

pub const VFIO_DEVICE_FLAGS_RESET: u32 = 1 << 0;
pub const VFIO_DEVICE_FLAGS_PCI: u32 = 1 << 1;
pub const VFIO_DEVICE_FLAGS_CAPS: u32 = 1 << 7;

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct vfio_device_info {
    pub argsz: u32,
    pub flags: u32,
    pub num_regions: u32,
    pub num_irqs: u32,
    pub cap_offset: u32,
    pub pad: u32,
}

pub const VFIO_DEVICE_GET_INFO: u64 = ior_nr!(VFIO_BASE + 0x07, vfio_device_info);

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct vfio_region_info {
    pub argsz: u32,
    pub flags: u32,
    pub index: u32,
    pub cap_offset: u32,
    pub size: u64,
    pub offset: u64,
}

pub const VFIO_REGION_INFO_FLAG_READ: u32 = 1 << 0;
pub const VFIO_REGION_INFO_FLAG_WRITE: u32 = 1 << 1;
pub const VFIO_REGION_INFO_FLAG_MMAP: u32 = 1 << 2;
pub const VFIO_REGION_INFO_FLAG_CAPS: u32 = 1 << 3;

pub const VFIO_DEVICE_GET_REGION_INFO: u64 = iowr_nr!(VFIO_BASE + 0x08, vfio_region_info);

pub const VFIO_IRQ_INFO_EVENTFD: u32 = 1 << 0;
pub const VFIO_IRQ_INFO_MASKABLE: u32 = 1 << 1;
pub const VFIO_IRQ_INFO_AUTOMASKED: u32 = 1 << 2;
pub const VFIO_IRQ_INFO_NORESIZE: u32 = 1 << 3;

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct vfio_irq_info {
    pub argsz: u32,
    pub flags: u32,
    pub index: u32,
    pub count: u32,
}

pub const VFIO_DEVICE_GET_IRQ_INFO: u64 = iowr_nr!(VFIO_BASE + 0x09, vfio_irq_info);

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct vfio_irq_set {
    pub argsz: u32,
    pub flags: u32,
    pub index: u32,
    pub start: u32,
    pub count: u32,
    pub data: [u8; 0],
}

pub const VFIO_IRQ_SET_DATA_NONE: u32 = 1 << 0;
pub const VFIO_IRQ_SET_DATA_BOOL: u32 = 1 << 1;
pub const VFIO_IRQ_SET_DATA_EVENTFD: u32 = 1 << 2;
pub const VFIO_IRQ_SET_ACTION_MASK: u32 = 1 << 3;
pub const VFIO_IRQ_SET_ACTION_UNMASK: u32 = 1 << 4;
pub const VFIO_IRQ_SET_ACTION_TRIGGER: u32 = 1 << 5;

pub const VFIO_DEVICE_SET_IRQS: u64 = iow_nr!(VFIO_BASE + 0x0a, vfio_irq_set);

pub const VFIO_DEVICE_RESET: u64 = io_nr!(VFIO_BASE + 0x0b);

// -------- Fixed region and IRQ index mappings for VFIO-PCI
pub const VFIO_PCI_BAR0_REGION_INDEX: u32 = 0;
pub const VFIO_PCI_BAR1_REGION_INDEX: u32 = 1;
pub const VFIO_PCI_BAR2_REGION_INDEX: u32 = 2;
pub const VFIO_PCI_BAR3_REGION_INDEX: u32 = 3;
pub const VFIO_PCI_BAR4_REGION_INDEX: u32 = 4;
pub const VFIO_PCI_BAR5_REGION_INDEX: u32 = 5;
pub const VFIO_PCI_ROM_REGION_INDEX: u32 = 6;
pub const VFIO_PCI_CONFIG_REGION_INDEX: u32 = 7;
pub const VFIO_PCI_VGA_REGION_INDEX: u32 = 8;
pub const VFIO_PCI_NUM_REGIONS: u32 = 9;

pub const VFIO_PCI_INTX_IRQ_INDEX: u32 = 0;
pub const VFIO_PCI_MSI_IRQ_INDEX: u32 = 1;
pub const VFIO_PCI_MSIX_IRQ_INDEX: u32 = 2;
pub const VFIO_PCI_ERR_IRQ_INDEX: u32 = 3;
pub const VFIO_PCI_REQ_IRQ_INDEX: u32 = 4;
pub const VFIO_PCI_NUM_IRQS: u32 = 5;

// Type1 IOMMU
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct vfio_iommu_type1_info {
    pub argsz: u32,
    pub flags: u32,
    pub iova_pgsizes: u64,
}

pub const VFIO_IOMMU_INFO_PGSIZES: u32 = 1 << 0;
pub const VFIO_IOMMU_GET_INFO: u64 = io_nr!(VFIO_BASE + 12);

pub const VFIO_DMA_MAP_FLAG_READ: u32 = 1 << 0;
pub const VFIO_DMA_MAP_FLAG_WRITE: u32 = 1 << 1;

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct vfio_iommu_type1_dma_map {
    pub argsz: u32,
    pub flags: u32,
    pub vaddr: u64,
    pub iova: u64,
    pub size: u64,
}

pub const VFIO_IOMMU_MAP_DMA: u64 = ior_nr!(VFIO_BASE + 13, vfio_iommu_type1_dma_map);

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct vfio_iommu_type1_dma_unmap {
    pub argsz: u32,
    pub flags: u32,
    pub iova: u64,
    pub size: u64,
}

pub const VFIO_IOMMU_UNMAP_DMA: u64 = ior_nr!(VFIO_BASE + 14, vfio_iommu_type1_dma_unmap);

pub const VFIO_IOMMU_ENABLE: u64 = io_nr!(VFIO_BASE + 15);
pub const VFIO_IOMMU_DISABLE: u64 = io_nr!(VFIO_BASE + 16);

unsafe impl ByteValued for vfio_iommu_type1_info {}
unsafe impl ByteValued for vfio_iommu_type1_dma_map {}
unsafe impl ByteValued for vfio_iommu_type1_dma_unmap {}
unsafe impl ByteValued for vfio_group_status {}
unsafe impl ByteValued for vfio_device_info {}
unsafe impl ByteValued for vfio_region_info {}
unsafe impl ByteValued for vfio_irq_info {}
unsafe impl ByteValued for vfio_irq_set {}
