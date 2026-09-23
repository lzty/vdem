use std::{ffi::c_void, ops::Deref};

use crate::traits::ReadWriteVirtualMemory;

pub enum CallBy<'a> {
    Name(&'a str),
    Address(*mut c_void),
}

/// A call guard that is capable for calling a kernel function and handle the disposition
/// 
/// user can call the instance object just like a calling a normal function, arguments type must match
/// the signature of `F`
pub struct KernelCallGuard<'a, F: Sized + Copy, E>
where
    E: ReadWriteVirtualMemory + ?Sized,
{
    pub(crate) funcptr: F,
    pub(crate) restore_bytes: [u8; 14],
    pub(crate) restore_va: *mut c_void,
    pub(crate) exploit: &'a E,
}

impl<'a, F: Sized + Copy, E: ReadWriteVirtualMemory + ?Sized> Deref for KernelCallGuard<'_, F, E> {
    type Target = F;
    fn deref(&self) -> &Self::Target {
        &self.funcptr
    }
}

impl<'a, F: Sized + Copy, E: ReadWriteVirtualMemory + ?Sized> Drop for KernelCallGuard<'_, F, E> {
    fn drop(&mut self) {
        let _ = self
            .exploit
            .write_kmem(self.restore_va as _, &self.restore_bytes);
    }
}
