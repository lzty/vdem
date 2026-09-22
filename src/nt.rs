#![allow(non_snake_case)]

use anyhow::Result;
use core::slice;

use std::{
    ffi::{c_ushort, c_void},
    fmt::Debug,
    mem,
    path::Path,
    ptr,
    sync::{LazyLock, OnceLock},
};

use anyhow::anyhow;
use windows::{
    Win32::{
        Foundation::{HANDLE, NTSTATUS},
        System::LibraryLoader::{GetModuleHandleW, GetProcAddress},
    },
    core::{s, w},
};

use crate::{
    ldr,
    pe::{
        IMAGE_DIRECTORY_ENTRY_EXPORT, PIMAGE_DOS_HEADER, PIMAGE_EXPORT_DIRECTORY,
        PIMAGE_NT_HEADERS64,
    },
    utils::{self},
};

pub const STATUS_SUCCESS: NTSTATUS = NTSTATUS(0);

pub const NT_CURRENT_PROCESS: HANDLE = HANDLE(-1i64 as _);
pub const NT_CURRENT_THREAD: HANDLE = HANDLE(-2i64 as _);

pub const CURRENT_PROCESS: u32 = -1i32 as _;
pub const CURRENT_THREAD: u32 = -2i32 as _;

pub const PAGE_SIZE: usize = 0x1000;
pub const PAGE_SHIFT: usize = 12;

#[repr(C)]
#[derive(Default)]
pub struct UNICODE_STRING {
    pub(crate) length: u16,
    pub(crate) maximum_length: u16,
    pub(crate) buffer: *mut c_ushort,
}

#[inline]
pub fn nt_success(status: NTSTATUS) -> bool {
    status.0 >= STATUS_SUCCESS.0
}

#[inline]
pub fn handle_to_ulong(handle: HANDLE) -> u32 {
    handle.0 as i64 as _
}

#[inline]
pub fn ulong_to_handle(value: u32) -> HANDLE {
    HANDLE(value as i32 as i64 as _)
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RTL_PROCESS_MODULE_INFORMATION {
    pub Section: *mut c_void, // Not filled in
    pub MappedBase: *mut c_void,
    pub ImageBase: *mut c_void,
    pub ImageSize: u32,
    pub Flags: u32,
    pub LoadOrderIndex: u16,
    pub InitOrderIndex: u16,
    pub LoadCount: u16,
    pub OffsetToFileName: u16,
    pub FullPathName: [u8; 256],
}

unsafe extern "C" {
    pub fn strlen(ptr: *const c_void) -> usize;
    pub fn wcslen(ptr: *const u16) -> usize;
}

#[link(name = "ntdll")]
unsafe extern "system" {
    pub fn RtlSetLastWin32Error(error: u32);

    pub fn NtQuerySystemInformation(
        info_class: u32,
        buffer: *mut c_void,
        bufsize: u32,
        return_length: *mut u32,
    ) -> NTSTATUS;

    pub fn RtlAdjustPrivilege(
        Privilege: u32,
        Enable: bool,
        Client: bool,
        WasEnabled: *mut bool,
    ) -> NTSTATUS;

    pub fn NtLoadDriver(driver_service_name: *mut UNICODE_STRING) -> NTSTATUS;

    pub fn NtUnloadDriver(driver_service_name: *mut UNICODE_STRING) -> NTSTATUS;

    pub fn NtAddAtom(name: *const u16, length: u32, atom: *mut u16) -> NTSTATUS;

    pub fn RtlImageNtHeader(base: *mut c_void) -> *mut c_void;

    pub fn RtlImageDirectoryEntryToData(
        base: *mut std::ffi::c_void,
        mapped_as_image: u8,
        directory_entry: u16,
        size: *mut u32,
    ) -> *mut std::ffi::c_void;
}

impl Debug for RTL_PROCESS_MODULE_INFORMATION {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // maybe a wrong length if the buffer contains multi-byte character
        let len = unsafe { strlen(self.FullPathName.as_ptr().cast()) };

        write!(
            f,
            "RTL_PROCESS_MODULE_INFORMATION {{ {:p}, {:p}, {:p}, {}, {}, {}, {}, {}, {}, {} }}",
            self.Section,
            self.MappedBase,
            self.ImageBase,
            self.ImageSize,
            self.Flags,
            self.LoadOrderIndex,
            self.InitOrderIndex,
            self.LoadCount,
            self.OffsetToFileName,
            String::from_utf8_lossy(&self.FullPathName[0..len as _]).to_string()
        )
    }
}

pub type PRTL_PROCESS_MODULE_INFORMATION = *mut RTL_PROCESS_MODULE_INFORMATION;

#[repr(C)]
pub struct RTL_PROCESS_MODULES {
    pub NumberOfModules: u32,
    pub Modules: [RTL_PROCESS_MODULE_INFORMATION; 1],
}

impl Default for RTL_PROCESS_MODULES {
    fn default() -> Self {
        RTL_PROCESS_MODULES {
            ..unsafe { core::mem::zeroed() }
        }
    }
}

pub type PRTL_PROCESS_MODULES = *mut RTL_PROCESS_MODULES;

pub const SE_PROF_SINGLE_PROCESS_PRIVILEGE: u32 = 13;
pub const SE_DEBUG_PRIVILEGE: u32 = 20;

pub fn get_windows_version() -> Result<(u32, u32, u32)> {
    type FnRtlGetNtVersionNumbers =
        unsafe extern "system" fn(major: *mut u32, minor: *mut u32, build: *mut u32);

    let ntdll = unsafe { GetModuleHandleW(w!("ntdll.dll"))? };

    let proc = unsafe { GetProcAddress(ntdll, s!("RtlGetNtVersionNumbers")) }
        .ok_or(anyhow!("Windows API RtlGetNtVersionNumbers not found"))?;

    let RtlGetNtVersionNumbers = unsafe { mem::transmute::<_, FnRtlGetNtVersionNumbers>(proc) };

    let mut major = 0u32;
    let mut minor = 0u32;
    let mut build = 0u32;

    unsafe { RtlGetNtVersionNumbers(&mut major, &mut minor, &mut build) };

    Ok((major, minor, build & 0xFFFF))
}

static KERNEL_BASE: OnceLock<Option<usize>> = OnceLock::new();

pub fn get_kernelbase() -> Option<usize> {
    let _getter = || -> Option<usize> {
        let mut return_length: u32 = 0;
        let mut status =
            unsafe { NtQuerySystemInformation(0xb, ptr::null_mut(), 0, &mut return_length) };

        if status.0 < STATUS_SUCCESS.0 && return_length > 0 {
            let size_alloced: u32 = return_length;
            let mut buffer = vec![0u8; size_alloced as _];

            return_length = 0;

            status = unsafe {
                NtQuerySystemInformation(
                    0xb,
                    buffer.as_mut_ptr() as _,
                    size_alloced,
                    &mut return_length,
                )
            };

            if status.0 >= STATUS_SUCCESS.0 {
                let info = unsafe { (buffer.as_ptr() as PRTL_PROCESS_MODULES).as_ref().unwrap() };
                let mods: &[RTL_PROCESS_MODULE_INFORMATION] = unsafe {
                    slice::from_raw_parts(info.Modules.as_ptr(), info.NumberOfModules as _)
                };

                for i in 0..info.NumberOfModules as usize {
                    let mod_full_path = String::from_utf8_lossy(unsafe {
                        slice::from_raw_parts(
                            mods[i].FullPathName.as_ptr(),
                            strlen(mods[i].FullPathName.as_ptr().cast()),
                        )
                    })
                    .to_string();

                    if mod_full_path.ends_with("ntoskrnl.exe") {
                        if mods[i].ImageBase.is_null() {
                            #[cfg(debug_assertions)]
                            println!("[!] Please promote privilege of current process");

                            return None;
                        } else {
                            return Some(mods[i].ImageBase as _);
                        }
                    }
                }
            }
        }

        None
    };

    KERNEL_BASE.get_or_init(_getter).to_owned()
}

/// # Note:
/// The image mapped by `NTOSKRNL_EXE` resovle and fixup the relocations and imports,
/// just copy and map the sections since we only want to parse the exports not the other shit
static NTOSKRNL_EXE: LazyLock<Vec<u8>> = LazyLock::new(|| {
    let ntos_path_buf = Path::new(&utils::get_system_dir()).join("ntoskrnl.exe");

    let ntos_path = ntos_path_buf.to_str().unwrap();

    ldr::map_image(ntos_path).unwrap()
});

pub fn get_kernel_export(api_name: &str) -> Option<usize> {
    let krnl_base = get_kernelbase()?;

    let dos_header: PIMAGE_DOS_HEADER = NTOSKRNL_EXE.as_ptr() as *mut _;
    let local_base = dos_header as usize;

    let nt_header =
        unsafe { &*((local_base + (*dos_header).e_lfanew as usize) as PIMAGE_NT_HEADERS64) };

    let export_directory = unsafe {
        &*((local_base
            + nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
                as usize) as PIMAGE_EXPORT_DIRECTORY)
    };

    let names = (local_base + export_directory.AddressOfNames as usize) as *const u32;
    let functions = (local_base + export_directory.AddressOfFunctions as usize) as *const u32;
    let ordinals = (local_base + export_directory.AddressOfNameOrdinals as usize) as *const u16;

    for i in 0..(export_directory.NumberOfNames as usize) {
        let func_name_addr = local_base + unsafe { *names.wrapping_add(i) } as usize;

        let func_name = unsafe {
            slice::from_raw_parts(func_name_addr as *const u8, strlen(func_name_addr as _))
        };

        if api_name == str::from_utf8(func_name).ok()? {
            let offset =
                unsafe { *functions.wrapping_add(*ordinals.wrapping_add(i) as usize) } as usize;

            return Some(krnl_base + offset);
        }
    }

    None
}
