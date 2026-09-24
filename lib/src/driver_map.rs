use std::{ffi::c_void, fs, io::Read};

use anyhow::Result;

use crate::traits::ExecuteKernelCall;

/// Define methods for mapping and loading a unsigned driver
pub trait DriverMap: ExecuteKernelCall {
    fn load_driver(
        &self,
        data: &[u8],
        arg1: Option<*mut c_void>,
        arg2: Option<*mut c_void>,
    ) -> Result<()>;

    fn load_driver_from_file(
        &self,
        file: &str,
        arg1: Option<*mut c_void>,
        arg2: Option<*mut c_void>,
    ) -> Result<()> {
        let mut drvfile = fs::File::open(file)?;

        let mut buffer = Vec::new();

        drvfile.read_to_end(&mut buffer)?;

        self.load_driver(&buffer, arg1, arg2)
    }
}
