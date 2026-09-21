use std::{ffi::c_void, ops::Deref};

use anyhow::{Result, anyhow};

use crate::nt::PAGE_SIZE;

pub trait Provider {
    /// Return the name of provider
    fn name(&self) -> &str;

    /// Return the provider description
    fn description(&self) -> Option<&str> {
        None
    }

    /// Return the CVE number associated with this provider if any
    fn cve(&self) -> Option<&str> {
        None
    }

    /// Return the CWE number associated with this provider if any
    fn cwe(&self) -> Option<&str> {
        None
    }

    /// The max size a provider can support in one map, it must be power of PAGE_SIZE, the min value is PAGE_SIZE
    fn granularity(&self) -> usize {
        PAGE_SIZE
    }

    /// Define how to install thi provider
    fn install(&mut self) -> Result<()> {
        Err(anyhow!("Method not implmeneted"))
    }

    // Define how to uninstall this provider
    fn uninstall(&self) -> Result<()> {
        Err(anyhow!("Method not implmeneted"))
    }

    /// Start the provider
    fn start(&mut self) -> Result<()>;

    /// Stop the provider
    fn stop(&mut self) -> Result<()>;

    /// Indicates if this provider can do virtual address to physical address mapping
    /// like CorMem.sys
    fn can_translate(&self) -> bool {
        false
    }

    /// Translate virtual address to physical address(if vulnable driver provide one)
    fn translate(&self, va: *mut c_void) -> Result<usize> {
        Err(anyhow!("Method not implmeneted"))
    }

    /// Indicates if this provider can allocate kernel memory and map to user space
    fn can_allocate(&self) -> bool {
        false
    }

    // Allocate kernel memory and map to user space
    fn allocate(&mut self, size: usize) -> Result<*mut c_void> {
        Err(anyhow!("Method not implmeneted"))
    }

    // Dealloc kernel memory and unmap
    fn deallocate(&self, va: *mut c_void) -> Result<()> {
        Err(anyhow!("Method not implmeneted"))
    }

    /// Indicates if this provider can do the physical address read/write directly.
    /// like HwRwDrv.sys
    fn can_do_pmio(&self) -> bool {
        false
    }

    /// Read from physical address `phyaddr` into `buffer`(if vulnable driver provide one)
    fn pm_read(&self, phyaddr: *mut c_void, buffer: &mut [u8]) -> Result<usize> {
        Err(anyhow!("Method not implmeneted"))
    }

    /// Write to physical address `phyaddr` from `buffer`(if vulnable driver provide one)
    fn pm_write(&self, phyaddr: *mut c_void, buffer: &[u8]) -> Result<usize> {
        Err(anyhow!("Method not implmeneted"))
    }

    /// Indicates if a provider can map critical kernel memory region to user space or read directly
    ///
    /// # Note
    /// Not all the providers that can do this, especially those use MmMapIoSpace(Ex).
    /// instead, those use ZwMapViewOfSection works well
    fn can_read_critical_region(&self) -> bool {
        false
    }

    /// Map a phsical address to virtual address in current process address space
    ///
    /// # Return Parameters
    /// - The Mapped virtual address if no error
    fn map_va(&self, phyaddr: *mut c_void, len: usize) -> Result<*mut c_void> {
        Err(anyhow!("Method not implmeneted"))
    }

    /// Unmap `va` from current process address space
    fn unmap_va(&self, va: *mut c_void) -> Result<()> {
        Err(anyhow!("Method not implmeneted"))
    }

    /// Provide a MapGuard for manage mapping lifetime
    fn map(&self, phyaddr: *mut c_void, len: usize) -> Result<MapGuard<'_>> {
        Err(anyhow!("Method not implmeneted"))
    }
}

pub struct MapGuard<'a> {
    pub(crate) va: *mut c_void,
    pub(crate) vd: &'a dyn Provider,
}

impl<'a> MapGuard<'a> {
    pub fn new(pa: *mut c_void, len: usize, vd: &'a dyn Provider) -> Result<Self> {
        let virt = vd.map_va(pa, len)?;

        Ok(Self { va: virt, vd })
    }
}

impl<'a> Deref for MapGuard<'a> {
    type Target = *mut c_void;
    fn deref(&self) -> &Self::Target {
        &self.va
    }
}

impl<'a> Drop for MapGuard<'a> {
    fn drop(&mut self) {
        let _ = self.vd.unmap_va(self.va);
    }
}
