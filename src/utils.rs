use std::{
    env,
    fs::{File, OpenOptions},
    io::Write,
    os::windows::fs::OpenOptionsExt,
    path::Path,
};

use crate::{
    nt::{RtlAdjustPrivilege, SE_DEBUG_PRIVILEGE, SE_PROF_SINGLE_PROCESS_PRIVILEGE, nt_success},
    service::DriverService,
};
use rand::{Rng, seq::SliceRandom};

#[inline]
pub fn align_down(val: usize, alignment: usize) -> usize {
    assert!(alignment.is_power_of_two());
    val & !(alignment - 1)
}

#[inline]
pub fn align_up(val: usize, alignment: usize) -> usize {
    align_down(val + alignment - 1, alignment)
}

#[inline]
pub fn align_down_u64(val: u64, alignment: u64) -> u64 {
    assert!(alignment.is_power_of_two());
    val & !(alignment - 1)
}

#[inline]
pub fn align_up_u64(val: u64, alignment: u64) -> u64 {
    align_down_u64(val + alignment - 1, alignment)
}

pub fn generate_random_string(length: usize) -> String {
    let mut rng = rand::rng();
    let mut charset = vec![0u8; 36];

    charset[0..36].copy_from_slice(b"abcdefghijklmnopqrstuvwxyz0123456789");

    charset.shuffle(&mut rng);

    (0..length)
        .map(|_| {
            let idx = rng.random_range(0..charset.len());

            charset[idx] as char
        })
        .collect()
}

pub(crate) fn drop_vulnerable_driver(
    data: impl AsRef<[u8]>,
    file_path: impl AsRef<Path>,
) -> std::io::Result<()> {
    let mut file: File = File::create_new(file_path)?;

    file.write_all(data.as_ref())?;

    file.flush()?;

    Ok(())
}

pub fn create_vulndrv_service(data: impl AsRef<[u8]>) -> windows::core::Result<DriverService> {
    let svc_name = generate_random_string(8);

    let driver_path = env::temp_dir().as_path().join(svc_name.clone() + ".sys");

    drop_vulnerable_driver(data, &driver_path)?;

    DriverService::new(&svc_name, driver_path.to_str().unwrap())
}

pub fn str_to_wide(str: &str) -> Vec<u16> {
    let mut ret = str.encode_utf16().collect::<Vec<u16>>();

    ret.push(0u16);

    ret
}

pub fn promote_privilege_to_debug_level() -> bool {
    let mut old = false;

    if !nt_success(unsafe {
        RtlAdjustPrivilege(SE_PROF_SINGLE_PROCESS_PRIVILEGE, true, false, &mut old)
    }) {
        return false;
    }

    if !nt_success(unsafe { RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, true, false, &mut old) }) {
        return false;
    }

    true
}

pub fn get_system_dir() -> String {
    use crate::nt::wcslen;

    use windows::Win32::System::SystemInformation::GetSystemDirectoryW;

    let mut buffer = vec![0u16; 260];

    unsafe {
        GetSystemDirectoryW(Some(&mut buffer));
    }

    if cfg!(target_pointer_width = "32") {
        String::from_utf16_lossy(&buffer[..unsafe { wcslen(buffer.as_ptr()) }])
            .replace("system32", "sysnative")
    } else {
        String::from_utf16_lossy(&buffer[..unsafe { wcslen(buffer.as_ptr()) }])
    }
}

pub fn is_file_in_use(path: impl AsRef<Path>) -> bool {
    let result = OpenOptions::new()
        .read(true)
        .write(true)
        .create(false)
        .share_mode(0) // <-- exclusive access
        .open(path.as_ref());

    match result {
        Ok(_) => false, // we got exclusive access → not in use
        Err(err) => {
            let code = err.raw_os_error().unwrap_or(0);
            code == 32 || code == 33 // sharing violation or lock violation
        }
    }
}
