use anyhow::{Result, anyhow};
use std::ffi::c_void;
use std::fs;
use std::io::Read;

use crate::kernel_call::{CallBy, KernelCallGuard};

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

/// Define methods for loading a unsigned driver
pub trait DriverMap: ExecuteKernelCall {
    fn load_driver(
        &self,
        data: &[u8],
        arg1: Option<*mut c_void>,
        arg2: Option<*mut c_void>,
    ) -> Result<()> {
        Err(anyhow!("This version of vdem do not support this feature"))
    }

    fn load_driver_from_file(
        &self,
        file: &str,
        arg1: Option<*mut c_void>,
        arg2: Option<*mut c_void>,
    ) -> Result<()> {
        let mut drvfile = fs::File::open(file)?;

        let mut buffer = Vec::new();

        drvfile.read_to_end(&mut buffer)?;

        self.load_driver(&buffer, arg1, arg2)
    }
}

/// Define a component has ability to translate kernel virtual address to physical address
pub(crate) trait VaToPa {
    fn va_to_pa(&self, va: *mut c_void) -> Result<*mut c_void>;
}
