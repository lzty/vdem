use anyhow::Result;

use crate::{kernel_buffer::KernelBuffer, traits::ExecuteKernelCall};

pub trait Allocator {
    /// Allocate memory from kernel space
    fn allocate(&'_ self, size: usize) -> Result<KernelBuffer<'_, Self>>
    where
        Self: Sized + ExecuteKernelCall;
}
