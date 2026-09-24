use core::mem::size_of;
use std::path::Path;

use windows::{
    Win32::{
        Foundation::{
            ERROR_SUCCESS, RtlNtStatusToDosError, STATUS_OBJECT_NAME_COLLISION, WIN32_ERROR,
        },
        System::Registry::{
            HKEY, HKEY_LOCAL_MACHINE, REG_DWORD, REG_EXPAND_SZ, RegCreateKeyW, RegDeleteTreeW,
            RegSetKeyValueW,
        },
    },
    core::{Owned, PCWSTR, Result, w},
};

use crate::nt::{
    NtLoadDriver, NtUnloadDriver, RtlAdjustPrivilege, STATUS_SUCCESS, UNICODE_STRING, nt_success,
};

pub struct DriverService {
    pub(crate) svc_name: String,
    pub(crate) bin_path: String,
}

impl DriverService {
    pub fn name(&self) -> &str {
        &self.svc_name
    }

    pub fn bin_path(&self) -> &str {
        &self.bin_path
    }
}

impl Default for DriverService {
    fn default() -> Self {
        Self {
            svc_name: String::default(),
            bin_path: String::default(),
        }
    }
}

impl DriverService {
    /// Create a service for driver in the registry
    pub fn new(svc_name: &str, bin_path: &str) -> Result<DriverService> {
        let reg_root_path = Path::new("SYSTEM\\CurrentControlSet\\Services\\");

        let mut hkey = HKEY::default();

        let svc_path = reg_root_path
            .join(svc_name)
            .to_str()
            .unwrap()
            .encode_utf16()
            .chain([0u16])
            .collect::<Vec<u16>>();

        let mut status =
            unsafe { RegCreateKeyW(HKEY_LOCAL_MACHINE, PCWSTR(svc_path.as_ptr()), &mut hkey) };

        if status != ERROR_SUCCESS {
            return Err(status.into());
        }

        let h_reg_driver = unsafe { Owned::new(hkey) };

        let service_type_kernel: u32 = 1; // SERVICE_KERNEL_DRIVER
        let service_error_control: u32 = 1; // SERVICE_ERROR_NORMAL
        let service_start_demand: u32 = 3; // SERVICE_DEMAND_START

        let dos_image_path = ("\\??\\".to_owned() + bin_path)
            .encode_utf16()
            .chain([0u16])
            .collect::<Vec<u16>>();

        // set image path
        status = unsafe {
            RegSetKeyValueW(
                h_reg_driver.to_owned(),
                None,
                w!("ImagePath"),
                REG_EXPAND_SZ.0,
                Some(dos_image_path.as_ptr() as _),
                (dos_image_path.len() * core::mem::size_of::<u16>()) as _,
            )
        };

        if status != ERROR_SUCCESS {
            let _ = unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, PCWSTR(svc_path.as_ptr())) };
            return Err(status.into());
        }

        unsafe {
            status = RegSetKeyValueW(
                h_reg_driver.to_owned(),
                None,
                w!("Type"),
                REG_DWORD.0,
                Some(&service_type_kernel as *const _ as _),
                size_of::<u32>() as _,
            );

            if status != ERROR_SUCCESS {
                let _ = RegDeleteTreeW(HKEY_LOCAL_MACHINE, PCWSTR(svc_path.as_ptr()));
                return Err(status.into());
            }

            status = RegSetKeyValueW(
                h_reg_driver.to_owned(),
                None,
                w!("ErrorControl"),
                REG_DWORD.0,
                Some(&service_error_control as *const _ as _),
                size_of::<u32>() as _,
            );

            if status != ERROR_SUCCESS {
                let _ = RegDeleteTreeW(HKEY_LOCAL_MACHINE, PCWSTR(svc_path.as_ptr()));
                return Err(status.into());
            }

            status = RegSetKeyValueW(
                h_reg_driver.to_owned(),
                None,
                w!("Start"),
                REG_DWORD.0,
                Some(&service_start_demand as *const _ as _),
                size_of::<u32>() as _,
            );

            if status != ERROR_SUCCESS {
                let _ = RegDeleteTreeW(HKEY_LOCAL_MACHINE, PCWSTR(svc_path.as_ptr()));
                return Err(status.into());
            }
        }

        Ok(Self {
            svc_name: svc_name.to_owned(),
            bin_path: bin_path.to_owned(),
        })
    }

    pub fn start(&self) -> Result<()> {
        let reg_path = ("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\".to_owned()
            + &self.svc_name)
            .encode_utf16()
            .collect::<Vec<u16>>();

        let us_reg_path = UNICODE_STRING {
            length: (reg_path.len() * size_of::<u16>()) as _,
            maximum_length: (reg_path.len() * size_of::<u16>()) as _,
            buffer: reg_path.as_ptr() as _,
        };

        const SE_LOAD_DRIVER_PRIVILEGE: u32 = 10;

        let mut enabled = false;

        let mut status =
            unsafe { RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, true, false, &mut enabled) };

        if !nt_success(status) {
            return Err(WIN32_ERROR(unsafe { RtlNtStatusToDosError(status) }).into());
        }

        status = unsafe { NtLoadDriver(&us_reg_path as *const _ as _) };

        if !nt_success(status) {
            // driver already loaded, return success directly
            if status == STATUS_OBJECT_NAME_COLLISION {
                status = STATUS_SUCCESS;
            }
        }

        if nt_success(status) {
            Ok(())
        } else {
            println!("Start driver {} failed", &self.svc_name);

            Err(WIN32_ERROR(unsafe { RtlNtStatusToDosError(status) }).into())
        }
    }

    pub fn stop(&self) -> Result<()> {
        let reg_path = ("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\".to_owned()
            + &self.svc_name)
            .encode_utf16()
            .collect::<Vec<u16>>();

        let us_reg_path = UNICODE_STRING {
            length: (reg_path.len() * size_of::<u16>()) as _,
            maximum_length: (reg_path.len() * size_of::<u16>()) as _,
            buffer: reg_path.as_ptr() as _,
        };

        // NtUnloadDriver() requires fo SE_LOAD_DRIVER_PRIVILEGE privilege
        // NtUnloadDriver will wait for the driver unload process to complete
        let status = unsafe { NtUnloadDriver(&us_reg_path as *const _ as _) };

        if !nt_success(status) {
            Err(WIN32_ERROR(unsafe { RtlNtStatusToDosError(status) }).into())
        } else {
            Ok(())
        }
    }

    pub fn uninstall(&self) -> Result<()> {
        let reg_path = ("SYSTEM\\CurrentControlSet\\Services\\".to_owned() + &self.svc_name)
            .encode_utf16()
            .chain([0u16])
            .collect::<Vec<u16>>();

        let status = unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, PCWSTR(reg_path.as_ptr())) };

        if status == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(status.into())
        }
    }
}

#[test]
fn test_driver_service() {
    let ds = DriverService::new("fuck", "E:\\Fuck\\fuck.sys")
        .inspect_err(|e| {
            panic!("install driver service failed, err = {}", e.message());
        })
        .unwrap();

    let _ = ds.uninstall().inspect_err(|e| {
        println!("uninstall driver service failed, err = {}", e.message());
    });
}
