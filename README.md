VDEM is a framework for manage various of vulnerable driver providers.
Made by BinEvil

# Features
This library provides many useful features such as:
- directly read / write physical / virtual address(kernel)
- map kernel virtual address range out into user space as RW
- call arbitrary kernel function in user mode and get its results
- manually map and load a unsigned driver from memory or file
- execute arbitrary kernel code in user side
- terminate, suspend, resume a process no matter it is privileged or not
 
All these features based on the vulnerable providers(see trait Provider for details), a provider represent a kernel mode driver that has arbitrary memory R/W vulnerabilities.

# How to use
First you should implement your own provider, like this
```rust
use vdem::{ exploit::Exploit, provider::Provider };

struct MyProvider{}

impl Provider for MyProvider
{
  fn new() {
    Self{}
  }
   // ...
}
```
then register it to a exploit instance
```rust
// promote process privilege first
promote_privilege_to_debug_level();

// get a Exploit instance
let mut exploit = Exploit::instance().lock().unwrap();

// register our provider
exploit.register_provider(Box::new(MyProvider::new()));

// use it as current instance
exploit.select("BS_LED").unwrap();
```
and then do what you can by using that exploit instance

There are eight examples demonstrate how to use this library located in [examples](https://github.com/lzty/vdem/examples) directory

For other examples: see [here](https://github.com/lzty/CVE-2026-94128) and [here](https://github.com/lzty/CVE-2026-94129)

# What to do in next
- support read / write process memorys

# Disclaimer
This project is developed strictly for educational and security research purposes. 
The author takes no responsibility for any misuse, damage, or system instability caused by this software.
