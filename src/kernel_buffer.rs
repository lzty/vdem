use crate::{kernel_call::CallBy, traits::ExecuteKernelCall};
use core::slice;
use std::{ffi::c_void, ptr};

pub struct KernelBuffer<'a, E>
where
    E: ExecuteKernelCall,
{
    pub(crate) mdl: *const c_void,
    pub(crate) virt_k: *mut c_void,
    pub(crate) virt_u: *mut c_void,
    pub(crate) exploit: &'a E,
}

impl<'a, E: ExecuteKernelCall> KernelBuffer<'a, E> {
    pub fn get_k(&self) -> *mut c_void {
        self.virt_k
    }

    pub fn get_u(&self) -> *mut c_void {
        self.virt_u
    }

    pub fn as_slice_u<T: Sized>(&self, len: usize) -> &[T] {
        unsafe { slice::from_raw_parts_mut(self.virt_u.cast::<T>(), len) }
    }

    pub fn as_mut_slice_u<T: Sized>(&self, len: usize) -> &mut [T] {
        unsafe { slice::from_raw_parts_mut(self.virt_u.cast::<T>(), len) }
    }

    pub fn leak(mut self) -> (*mut c_void, *mut c_void) {
        let ptr_k = self.virt_k;
        let ptr_u = self.virt_u;

        self.virt_k = ptr::null_mut();
        self.virt_u = ptr::null_mut();

        self.mdl = ptr::null_mut();

        (ptr_k, ptr_u)
    }
}

impl<E: ExecuteKernelCall> Drop for KernelBuffer<'_, E> {
    fn drop(&mut self) {
        type FnExFreePool = unsafe extern "C" fn(p: *const c_void);
        type FnMmFreePagesFromMdl = unsafe extern "C" fn(memory_descriptor_list: *const c_void);
        type FnMmUnmapLockedPages = unsafe extern "C" fn(
            base_address: *const c_void,
            memory_descriptor_list: *const c_void,
        );

        if !self.mdl.is_null() && !self.virt_k.is_null() && !self.virt_u.is_null() {
            let _ = self
                .exploit
                .get_call::<FnMmUnmapLockedPages>(CallBy::Name("MmUnmapLockedPages"))
                .inspect(|mm_unmap_locked_pages| unsafe {
                    mm_unmap_locked_pages(self.virt_k, self.mdl)
                });

            let _ = self
                .exploit
                .get_call::<FnMmFreePagesFromMdl>(CallBy::Name("MmFreePagesFromMdl"))
                .inspect(|mm_free_pages_from_mdl| unsafe { mm_free_pages_from_mdl(self.mdl) });

            let _ = self
                .exploit
                .get_call::<FnExFreePool>(CallBy::Name("ExFreePool"))
                .inspect(|ex_free_pool| unsafe { ex_free_pool(self.mdl) });
        }
    }
}
