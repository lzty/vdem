use anyhow::Result;

use crate::shellcode::ShellCode;

/// Terminate privileged process
pub trait TerminateProcess {
    fn terminate_process(&self, process_id: u32) -> Result<()> where Self: ShellCode;
}