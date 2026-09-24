use anyhow::Result;
use std::ffi::c_void;

use crate::{
    kernel_call::{CallBy, KernelCallGuard},
    mapped_buffer::MapBuffer,
};

/// Primitives for read / write physical memory
pub(crate) trait ReadWritePhysicalMemory {
    fn read_phy_mem(&self, pa: *mut c_void, buffer: &mut [u8]) -> Result<usize>;

    fn write_phy_mem(&self, pa: *mut c_void, buffer: &[u8]) -> Result<usize>;
}

/// Primitives for read / write kernel virtual memory
pub trait ReadWriteVirtualMemory {
    fn read_kmem(&self, va: *mut c_void, buffer: &mut [u8]) -> Result<usize>;

    fn write_kmem(&self, va: *mut c_void, buffer: &[u8]) -> Result<usize>;
}

/// Primitive for getting a delegate "kernel call"
pub trait ExecuteKernelCall: ReadWriteVirtualMemory {
    fn get_call<F: Sized + Copy>(&'_ self, which: CallBy) -> Result<KernelCallGuard<'_, F, Self>>;
}

/// Define a component has ability to translate kernel virtual address to physical address
pub(crate) trait VaToPa {
    fn va_to_pa(&self, va: *mut c_void) -> Result<*mut c_void>;
}

/// Primitive for mapping kernel memory into suer space
pub trait MemoryMap: ExecuteKernelCall {
    fn mmap(&'_ self, va: *mut c_void, size: usize) -> Result<MapBuffer<'_, Self>>
    where
        Self: Sized;
}
