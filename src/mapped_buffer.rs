use std::ffi::c_void;

use crate::{kernel_call::CallBy, traits::ExecuteKernelCall};

pub struct MapBuffer<'a, E>
where
    E: ExecuteKernelCall,
{
    pub(crate) mdl: *mut c_void,
    pub(crate) virt_u: *mut c_void,
    pub(crate) exploit: &'a E,
}

impl<E: ExecuteKernelCall> MapBuffer<'_, E> {
    pub fn get(&self) -> *mut c_void {
        self.virt_u
    }
}

impl<E: ExecuteKernelCall> Drop for MapBuffer<'_, E> {
    fn drop(&mut self) {
        type FnIoFreeMdl = unsafe extern "C" fn(mdl: *mut c_void);
        type FnMmUnlockPages = unsafe extern "C" fn(mdl: *mut c_void);
        type FnMmUnmapLockedPages = unsafe extern "C" fn(va: *mut c_void, mdl: *mut c_void);

        let _ = self
            .exploit
            .get_call::<FnMmUnmapLockedPages>(CallBy::Name("MmUnmapLockedPages"))
            .inspect(|mm_unmap_locked_pages| {
                unsafe { mm_unmap_locked_pages(self.virt_u, self.mdl) };
            });

        let _ = self
            .exploit
            .get_call::<FnMmUnlockPages>(CallBy::Name("MmUnlockPages"))
            .inspect(|mm_unlock_pages| {
                unsafe { mm_unlock_pages(self.mdl) };
            });

        let _ = self
            .exploit
            .get_call::<FnIoFreeMdl>(CallBy::Name("IoFreeMdl"))
            .inspect(|io_free_mdl| {
                unsafe { io_free_mdl(self.mdl) };
            });
    }
}
