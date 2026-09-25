use std::ffi::c_void;

use anyhow::Result;

use crate::{mapped_buffer::MapBuffer, shellcode::ShellCode};

/// Terminate a process no matter it is privileged or not
pub trait TerminateProcess {
    fn terminate_process(&self, process_id: u32) -> Result<()>
    where
        Self: ShellCode;
}

/// Suspend a process no matter it is privileged or not
pub trait SuspendProcess {
    fn suspend_process(&self, process_id: u32) -> Result<()>
    where
        Self: ShellCode;
}

pub trait ResumeProcess {
    fn resume_process(&self, process_id: u32) -> Result<()>
    where
        Self: ShellCode;
}

pub trait MapProcessMemory: ShellCode {
    fn mmap_process(
        &self,
        process_id: u32,
        address: *mut c_void,
        length: u32,
    ) -> Result<MapBuffer<'_, Self>>
    where
        Self: Sized;
}
