use core::slice;
use std::ptr::{self};

use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VIRTUAL_FREE_TYPE, VirtualAlloc, VirtualFree,
};

pub(crate) struct NativeBuffer<T: Sized> {
    raw_ptr: *mut T,
    length: usize,
}

impl<T: Sized> NativeBuffer<T> {
    /// # TODO:
    /// return a Result for safety
    pub fn new(size: usize) -> Self {
        Self {
            raw_ptr: unsafe {
                VirtualAlloc(
                    None,
                    size as _,
                    MEM_RESERVE | MEM_COMMIT,
                    PAGE_EXECUTE_READWRITE,
                )
            }
            .cast(),

            length: size,
        }
    }

    pub fn valid(&self) -> bool {
        !self.raw_ptr.is_null()
    }

    pub fn as_ptr(&self) -> *const T {
        self.raw_ptr.cast()
    }

    pub fn as_mut_ptr(&mut self) -> *mut T {
        self.raw_ptr.cast()
    }

    pub fn as_slice(&self) -> &[T] {
        unsafe { slice::from_raw_parts(self.raw_ptr, self.length / size_of::<T>()) }
    }

    pub fn as_slice_mut(&mut self) -> &mut [T] {
        unsafe { slice::from_raw_parts_mut(self.raw_ptr, self.length / size_of::<T>()) }
    }

    pub fn leak(mut self) -> *mut T {
        let ptr = self.raw_ptr;

        self.raw_ptr = ptr::null_mut();

        ptr
    }
}

impl AsRef<[u8]> for NativeBuffer<u8> {
    fn as_ref(&self) -> &[u8] {
        unsafe { slice::from_raw_parts_mut(self.raw_ptr.cast(), self.length) }
    }
}

impl AsMut<[u8]> for NativeBuffer<u8> {
    fn as_mut(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.raw_ptr.cast(), self.length) }
    }
}

impl<T: Sized> Drop for NativeBuffer<T> {
    fn drop(&mut self) {
        if self.valid() {
            let _ =
                unsafe { VirtualFree(self.raw_ptr.cast(), self.length as _, VIRTUAL_FREE_TYPE(0)) };
        }
    }
}
