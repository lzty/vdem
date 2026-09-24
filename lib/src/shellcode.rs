use crate::{kernel_buffer::KernelBuffer, kernel_call::KernelCallGuard, traits::ExecuteKernelCall};
use anyhow::Result;
use std::ops::Deref;

pub struct ShellCodeGuard<'a, F: Sized + Copy, E: ExecuteKernelCall> {
    pub(crate) mem: KernelBuffer<'a, E>,
    pub(crate) func: KernelCallGuard<'a, F, E>,
}

impl<'a, F: Sized + Copy, E: ExecuteKernelCall> Deref for ShellCodeGuard<'a, F, E> {
    type Target = KernelCallGuard<'a, F, E>;

    fn deref(&self) -> &Self::Target {
        &self.func
    }
}

/// Primitive for executing arbitrary code
pub trait ShellCode: ExecuteKernelCall {
    /// # Arguments
    /// - F: by given the pre-allocated buffer, the callee fill in the shellcode and return where the execution will start
    /// - B: the build delegate signature
    /// - Return a safe CallGuard
    fn build_shellcode<'a, F: Sized + Copy, B: FnOnce(&mut [u8]) -> usize>(
        &'_ self,
        size_of_code: usize,
        builder: B,
    ) -> Result<ShellCodeGuard<'_, F, Self>>
    where
        Self: Sized;
}
