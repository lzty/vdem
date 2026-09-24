use anyhow::Result;

use crate::shellcode::ShellCode;

/// Terminate a process no matter it is privileged or not
pub trait TerminateProcess {
    fn terminate_process(&self, process_id: u32) -> Result<()> where Self: ShellCode;
}

/// Suspend a process no matter it is privileged or not
pub trait SuspendProcess {
    fn suspend_process(&self, process_id: u32) -> Result<()> where Self: ShellCode;   
}

pub trait ResumeProcess {
    fn resume_process(&self, process_id: u32) -> Result<()> where Self: ShellCode;
}