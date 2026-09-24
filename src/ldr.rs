use core::slice;
use std::{
    ffi::{CStr, c_char, c_void},
    fs::File,
    io::Read,
    ptr,
};

use anyhow::{Result, anyhow};

use crate::{
    nt::{
        NtQuerySystemInformation, PRTL_PROCESS_MODULES, RTL_PROCESS_MODULE_INFORMATION,
        RtlImageDirectoryEntryToData, RtlImageNtHeader, STATUS_SUCCESS, strlen,
    },
    pe::{
        self, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_EXPORT,
        IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_OPTIONAL_HDR64_MAGIC,
    },
    utils::get_system_dir,
};

pub(crate) fn map_image(path: &str) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;

    let file_size = file.metadata()?.len();

    let mut file_base = vec![0u8; file_size as _];

    file.read(&mut file_base)?;

    let hdr_dos = file_base.as_ptr().cast::<pe::IMAGE_DOS_HEADER>();

    let hdr_nt: *const pe::IMAGE_NT_HEADERS64 = unsafe {
        file_base
            .as_ptr()
            .byte_offset((*hdr_dos).e_lfanew as _)
            .cast::<pe::IMAGE_NT_HEADERS64>()
    };

    let mut mapped_base: Vec<u8> =
        Vec::with_capacity((unsafe { *hdr_nt }).OptionalHeader.SizeOfImage as _);

    map_image_at(file_base.as_slice(), mapped_base.as_mut_slice())?;

    Ok(mapped_base)
}

/// Load a PE image from disk for analysis, x64 only, leave the import table and relocations unfixed
pub(crate) fn map_image_at(file_base: &[u8], mapped_base: &mut [u8]) -> Result<()> {
    unsafe {
        let hdr_dos = file_base.as_ptr().cast::<pe::IMAGE_DOS_HEADER>();

        let hdr_nt: *const pe::IMAGE_NT_HEADERS64 = file_base
            .as_ptr()
            .byte_offset((*hdr_dos).e_lfanew as _)
            .cast::<pe::IMAGE_NT_HEADERS64>();

        if (*(file_base.as_ptr() as *const _ as *const pe::IMAGE_DOS_HEADER)).e_magic != 0x5A4D {
            return Err(anyhow!("Unexpected image format"));
        }

        let base = mapped_base.as_mut_ptr();

        let data = file_base.as_ptr();

        ptr::copy_nonoverlapping(data, base, (*hdr_nt).OptionalHeader.SizeOfHeaders as _);

        // Copy sections
        let first_section = hdr_nt.add(1) as *const pe::IMAGE_SECTION_HEADER;

        let mut section = first_section;

        for i in 0..(*hdr_nt).FileHeader.NumberOfSections as usize {
            let characteristics = (*section).Characteristics;
            let size_of_raw_data = (*section).SizeOfRawData;
            let pointer_to_raw_data = (*section).PointerToRawData;
            let virtual_address = (*section).VirtualAddress;

            // Skip invalid sections
            if (characteristics
                & (pe::IMAGE_SCN_MEM_READ | pe::IMAGE_SCN_MEM_WRITE | pe::IMAGE_SCN_MEM_EXECUTE))
                == 0
                || size_of_raw_data == 0
            {
                section = section.add(1);
                continue;
            }

            ptr::copy_nonoverlapping(
                data.add(pointer_to_raw_data as _),
                base.add(virtual_address as _),
                size_of_raw_data as _,
            );

            section = section.add(1);
        }

        Ok(())
    }
}

pub(crate) fn get_module_base(name: &str) -> Option<(*mut c_void, usize)> {
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
            let mods: &[RTL_PROCESS_MODULE_INFORMATION] =
                unsafe { slice::from_raw_parts(info.Modules.as_ptr(), info.NumberOfModules as _) };

            for i in 0..info.NumberOfModules as usize {
                let mod_full_path = String::from_utf8_lossy(unsafe {
                    slice::from_raw_parts(
                        mods[i].FullPathName.as_ptr(),
                        strlen(mods[i].FullPathName.as_ptr().cast()),
                    )
                })
                .to_string();

                if mod_full_path.ends_with(name) {
                    if mods[i].ImageBase.is_null() {
                        #[cfg(debug_assertions)]
                        println!("[!] Please promote privilege of current process");

                        return None;
                    } else {
                        return Some((mods[i].ImageBase as _, mods[i].ImageSize as _));
                    }
                }
            }
        }
    }

    None
}

pub(crate) fn relocate_image(base_u: *mut c_void, base_k: *mut c_void) -> Result<()> {
    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    struct IMAGE_RELOC {
        raw: u16,
    }

    impl IMAGE_RELOC {
        fn offset(&self) -> u16 {
            self.raw & 0x0FFF // Extract the lower 12 bits
        }

        fn type_(&self) -> u16 {
            (self.raw >> 12) & 0x0F // Extract the upper 4 bits
        }
    }

    unsafe {
        let header: *const pe::IMAGE_NT_HEADERS64 = RtlImageNtHeader(base_u).cast();
        if header.is_null() {
            return Err(anyhow!("Can not relocate image: Invalid image format"));
        }

        let base_offset =
            (base_k as usize).wrapping_sub((*header).OptionalHeader.ImageBase as usize);

        let data_dir = &(*header).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

        if base_offset != 0 && data_dir.Size != 0 {
            let mut relocation = (base_u as usize + data_dir.VirtualAddress as usize)
                as *mut pe::IMAGE_BASE_RELOCATION;

            while (*relocation).VirtualAddress != 0 {
                let mut reloc_list = (relocation.wrapping_offset(1)) as *mut IMAGE_RELOC;

                while (reloc_list as usize)
                    != (relocation as usize + (*relocation).SizeOfBlock as usize)
                {
                    let target_address = (base_u as usize
                        + (*relocation).VirtualAddress as usize
                        + (*reloc_list).offset() as usize)
                        as *mut usize;

                    // relocation code will trigger the rust `integer overflow check` and `misaligned pointer check`
                    // thus the code will not work in debug mode, disable overflow check(in Cargo.toml, by set overflow-checks = false)
                    // and using unaligned read/write to `bypass` these runtime checks
                    match (*reloc_list).type_() {
                        pe::IMAGE_REL_BASED_DIR64 => {
                            let val = (target_address as *mut usize).read_unaligned()
                                + base_offset as usize;
                            (target_address as *mut usize).write_unaligned(val);
                        }
                        pe::IMAGE_REL_BASED_HIGHLOW => {
                            let val = (target_address as *mut usize).read_unaligned()
                                + base_offset as usize;
                            (target_address as *mut usize).write_unaligned(val);
                        }
                        pe::IMAGE_REL_BASED_HIGH => {
                            *(target_address) += ((base_offset >> 16) & 0xFFFF) as usize;
                        }
                        pe::IMAGE_REL_BASED_LOW => {
                            *(target_address) += (base_offset & 0xFFFF) as usize;
                        }
                        _ => {}
                    }
                    reloc_list = reloc_list.wrapping_offset(1);
                }

                relocation = reloc_list as *mut pe::IMAGE_BASE_RELOCATION;
            }
        }

        Ok(())
    }
}

#[inline]
fn rva_to_va(mod_base: *mut std::ffi::c_void, rva: u32) -> *mut std::ffi::c_void {
    if rva == 0 {
        std::ptr::null_mut()
    } else {
        (unsafe { (mod_base as *mut u8).add(rva as usize) }) as *mut std::ffi::c_void
    }
}

pub(crate) fn copy_image(old_base: *const c_void, new_base: *mut c_void) {
    let dos_header = old_base.cast::<pe::IMAGE_DOS_HEADER>();

    let nt_header = old_base
        .wrapping_add(unsafe { *(dos_header) }.e_lfanew as _)
        .cast::<pe::IMAGE_NT_HEADERS64>();

    // Copy headers
    unsafe {
        ptr::copy_nonoverlapping(
            old_base,
            new_base,
            (*nt_header).OptionalHeader.SizeOfHeaders as _,
        );
    }

    // Copy sections
    unsafe {
        let mut p_section = nt_header.add(1) as *const pe::IMAGE_SECTION_HEADER;

        for _ in 0..(*nt_header).FileHeader.NumberOfSections as usize {
            let characteristics = (*p_section).Characteristics;
            let size_of_raw_data = (*p_section).SizeOfRawData;
            let pointer_to_raw_data = (*p_section).PointerToRawData;
            let virtual_address = (*p_section).VirtualAddress;

            // Skip invalid sections
            if (characteristics
                & (pe::IMAGE_SCN_MEM_READ | pe::IMAGE_SCN_MEM_WRITE | pe::IMAGE_SCN_MEM_EXECUTE))
                == 0
                || size_of_raw_data == 0
            {
                p_section = p_section.add(1);
                continue;
            }

            ptr::copy_nonoverlapping(
                old_base.wrapping_add(pointer_to_raw_data as _),
                new_base.wrapping_add(virtual_address as _),
                size_of_raw_data as _,
            );

            p_section = p_section.add(1);
        }
    }
}

pub(crate) fn get_module_export(
    base_u: *mut c_void,
    base_k: *mut c_void,
    api_name: &CStr,
) -> Option<*mut c_void> {
    if base_u.is_null() {
        return None;
    }

    let mut dir_size: u32 = 0;
    let export_dir_ptr = unsafe {
        RtlImageDirectoryEntryToData(
            base_u,
            1, // TRUE
            IMAGE_DIRECTORY_ENTRY_EXPORT as _,
            &mut dir_size,
        )
    } as *mut IMAGE_EXPORT_DIRECTORY;

    if export_dir_ptr.is_null() || dir_size == 0 {
        return None;
    }

    let export_dir = unsafe { &*export_dir_ptr };
    if export_dir.NumberOfNames == 0 {
        return None;
    }

    let names = rva_to_va(base_u, export_dir.AddressOfNames) as *const u32;
    let ordinals = rva_to_va(base_u, export_dir.AddressOfNameOrdinals) as *const u16;
    let functions = rva_to_va(base_u, export_dir.AddressOfFunctions) as *const u32;

    let exp_dir_start = export_dir_ptr as usize;
    let exp_dir_end = exp_dir_start + dir_size as usize;

    for i in 0..export_dir.NumberOfNames {
        let name_rva = unsafe { *names.add(i as usize) };
        let name_ptr = rva_to_va(base_u, name_rva) as *const c_char;

        if name_ptr.is_null() {
            continue;
        }

        let current_name = unsafe { CStr::from_ptr(name_ptr) };
        if current_name == api_name {
            let ordinal = unsafe { *ordinals.add(i as usize) };
            let func_rva = unsafe { *functions.add(ordinal as usize) };
            let func_va_k = rva_to_va(base_k, func_rva);
            let func_va_u = rva_to_va(base_u, func_rva);

            // Forwarded export check
            let func_addr = func_va_u as usize;
            if func_addr >= exp_dir_start && func_addr < exp_dir_end {
                // Target is a forwarder string, ignored
                return None;
            }

            return Some(func_va_k);
        }
    }

    None
}

/// # TODO
///
/// implement get_module_export like get_kernel_export, since it can simply calculated with a kernel module base and a export function offset,
/// then we can drop that ```if lib_name == "ntoskrnl.exe"``` branch
pub(crate) fn fixup_imports(base_u: *mut c_void) -> Result<()> {
    let mut import_desc_size: u32 = 0;

    let mut import_desc = unsafe {
        RtlImageDirectoryEntryToData(
            base_u,
            1,
            IMAGE_DIRECTORY_ENTRY_IMPORT as _,
            &mut import_desc_size,
        )
    } as *mut pe::IMAGE_IMPORT_DESCRIPTOR;

    if import_desc.is_null() {
        return Err(anyhow!("Can not fixup import table: invalid image format"));
    }

    unsafe {
        while (*import_desc).Name > 0 {
            let lib_name = CStr::from_ptr(rva_to_va(base_u, (*import_desc).Name) as *mut c_char)
                .to_string_lossy();

            let mut thunk =
                rva_to_va(base_u, (*import_desc).FirstThunk).cast::<pe::IMAGE_THUNK_DATA64>();
            let mut orig_thunk = rva_to_va(base_u, (*import_desc).u1.OriginalFirstThunk)
                .cast::<pe::IMAGE_THUNK_DATA64>();

            let mut modbase_u = map_system_image(&lib_name)?;

            let (modbase_k, _) = get_module_base(&lib_name).ok_or(anyhow!(
                "Can not fixup import table: module {lib_name} not found"
            ))?;

            while (*orig_thunk).u1.ForwarderString > 0 {
                let import_by_name = rva_to_va(base_u, (*orig_thunk).u1.AddressOfData as _)
                    .cast::<pe::IMAGE_IMPORT_BY_NAME>();

                let func_name = CStr::from_ptr((*import_by_name).Name.as_ptr());

                let func_addr =
                    get_module_export(modbase_u.as_mut_ptr().cast(), modbase_k, func_name).ok_or(
                        anyhow!(
                            "Can not fixup import table: import function {} not found",
                            func_name.to_string_lossy()
                        ),
                    )?;

                #[cfg(debug_assertions)]
                println!(
                    "[+] Import function: {:?}({:p}) fixed.",
                    func_name, func_addr
                );

                (*thunk).u1.Function = func_addr as _;

                thunk = thunk.wrapping_add(1);
                orig_thunk = orig_thunk.wrapping_add(1);
            }

            import_desc = import_desc.wrapping_add(1);
        }
    }

    Ok(())
}

pub(crate) fn get_image_entry_point(
    base_u: *mut c_void,
    base_k: *mut c_void,
) -> Result<*mut c_void> {
    unsafe {
        let header: *const pe::IMAGE_NT_HEADERS64 = RtlImageNtHeader(base_u).cast();
        if header.is_null() {
            Err(anyhow!("Can not relocate image: Invalid image format"))
        } else {
            Ok(base_k.wrapping_add((*header).OptionalHeader.AddressOfEntryPoint as _))
        }
    }
}

pub(crate) fn map_system_image(name: &str) -> Result<Vec<u8>> {
    let driver_path = if name == "ntoskrnl.exe" {
        get_system_dir() + &format!("\\{name}")
    } else {
        get_system_dir() + &format!("\\drivers\\{name}")
    };

    map_image(&driver_path)
}
