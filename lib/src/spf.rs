use windows::Win32::Foundation::{RtlNtStatusToDosError, STATUS_BUFFER_TOO_SMALL, WIN32_ERROR};

use crate::{
    nt::{NtQuerySystemInformation, nt_success},
    translator::AddressTranslator,
};
use anyhow::{Result, anyhow};
use bitflags::bitflags;
use core::mem;
use core::slice;
use std::{collections::HashMap, ffi::c_void, ptr};

const SYSTEM_SUPERFETCH_INFORMATION: u32 = 79;

#[repr(C)]
#[derive(Clone, Copy)]
pub enum SUPERFETCH_INFORMATION_CLASS {
    SuperFetchNonClass = 0,
    SuperfetchRetrieveTrace = 1,       // Query
    SuperfetchSystemParameters = 2,    // Query
    SuperfetchLogEvent = 3,            // Set
    SuperfetchGenerateTrace = 4,       // Set
    SuperfetchPrefetch = 5,            // Set
    SuperfetchPfnQuery = 6,            // Query
    SuperfetchPfnSetPriority = 7,      // Set
    SuperfetchPrivSourceQuery = 8,     // Query
    SuperfetchSequenceNumberQuery = 9, // Query
    SuperfetchScenarioPhase = 10,      // Set
    SuperfetchWorkerPriority = 11,     // Set
    SuperfetchScenarioQuery = 12,      // Query
    SuperfetchScenarioPrefetch = 13,   // Set
    SuperfetchRobustnessControl = 14,  // Set
    SuperfetchTimeControl = 15,        // Set
    SuperfetchMemoryListQuery = 16,    // Query
    SuperfetchMemoryRangesQuery = 17,  // Query
    SuperfetchTracingControl = 18,     // Set
    SuperfetchTrimWhileAgingControl = 19,
    SuperfetchInformationMax = 20,
}

bitflags! {
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct MEMORY_FRAME_INFORMATION : u64 {
        const UseDescription  = 0b0000_1111;
        const ListDescription = 0b0111_0000;
        const Reserved0       = 0b1000_0000;
        const Pinned          = 0b0001_0000_0000;
        const DontUse         = 0x0000_FFFF_FFFF_F000;
        const Priority        = 0x0007_0000_0000_0000;
        const Reserved        = 0x00F8_0000_0000_0000;
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct FILEOFFSET_INFORMATION: u64 {
        const DontUse  = 0x0000_0000_0000_01FF;
        const Offset   = 0x0000_FFFF_FFFF_FE00;
        const Reserved = 0x00FF_0000_0000_0000;
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct PAGEDIR_INFORMATION: u64 {
        const DontUse = 0x0000_0000_0000_01FF;
        const PageDirectoryBase = 0x0000_FFFF_FFFF_FE00;
        const Reserved = 0x00FF_0000_0000_0000;
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct UNIQUE_PROCESS_INFORMATION: u64 {
        const DontUse = 0x0000_0000_0000_01FF;
        const UniqueProcessKey = 0x0000_FFFF_FFFF_FE00;
        const Reserved = 0x00FF_0000_0000_0000;
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
union MMPFN_IDENTITY_u1 {
    e1: MEMORY_FRAME_INFORMATION,
    e2: FILEOFFSET_INFORMATION,
    e3: PAGEDIR_INFORMATION,
    e4: UNIQUE_PROCESS_INFORMATION,
}

bitflags! {
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct MMPFN_IDENTITY_u2_e1_Flags: u32 {
        const Image    = 0b1;
        const Mismatch = 0b10;
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct MMPFN_IDENTITY_u2_e1 {
    Bits: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
union MMPFN_IDENTITY_u2 {
    e1: MMPFN_IDENTITY_u2_e1,
    FileObject: *mut c_void,
    UniqueFileObjectKey: *mut c_void,
    ProtoPteAddress: *mut c_void,
    VirtualAddress: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct MMPFN_IDENTITY {
    u1: MMPFN_IDENTITY_u1,
    PageFrameIndex: usize,
    u2: MMPFN_IDENTITY_u2,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SYSTEM_MEMORY_LIST_INFORMATION {
    ZeroPageCount: usize,
    FreePageCount: usize,
    ModifiedPageCount: usize,
    ModifiedNoWritePageCount: usize,
    BadPageCount: usize,
    PageCountByPriority: [usize; 8],
    RepurposedPagesByPriority: [usize; 8],
    ModifiedPageCountPageFile: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PF_PFN_PRIO_REQUEST {
    Version: u32,
    RequestFlags: u32,
    PfnCount: usize,
    MemInfo: SYSTEM_MEMORY_LIST_INFORMATION,
    PageData: [MMPFN_IDENTITY; ANYSIZE_ARRAY],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SUPERFETCH_INFORMATION {
    Version: u32,
    Magic: u32,
    InfoClass: SUPERFETCH_INFORMATION_CLASS,
    Data: *mut c_void,
    Length: u32,
}

impl Default for SUPERFETCH_INFORMATION {
    fn default() -> Self {
        Self {
            Version: 45,
            Magic: u32::from_le_bytes(*b"Chuk"),
            ..unsafe { mem::zeroed() }
        }
    }
}

const ANYSIZE_ARRAY: usize = 1;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PF_PHYSICAL_MEMORY_RANGE {
    BasePfn: usize,
    PageCount: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PF_MEMORY_RANGE_INFO_V1 {
    Version: u32,
    RangeCount: u32,
    Ranges: [PF_PHYSICAL_MEMORY_RANGE; ANYSIZE_ARRAY],
}

impl Default for PF_MEMORY_RANGE_INFO_V1 {
    fn default() -> Self {
        Self {
            Version: 1,
            ..unsafe { mem::zeroed() }
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PF_MEMORY_RANGE_INFO_V2 {
    Version: u32,
    Flags: u32,
    RangeCount: u32,
    Ranges: [PF_PHYSICAL_MEMORY_RANGE; ANYSIZE_ARRAY],
}

impl Default for PF_MEMORY_RANGE_INFO_V2 {
    fn default() -> Self {
        Self {
            Version: 2,
            ..unsafe { mem::zeroed() }
        }
    }
}

fn _query_phymem_range_info<T: Sized + Default>(
    class: SUPERFETCH_INFORMATION_CLASS,
) -> Result<Box<T>> {
    let mut size_required = 0u32;
    let mut info_data = T::default();
    let mut superfetch_info = SUPERFETCH_INFORMATION::default();

    superfetch_info.InfoClass = class;
    superfetch_info.Data = &mut info_data as *mut _ as _;
    superfetch_info.Length = mem::size_of_val(&info_data) as _;

    let mut status = unsafe {
        NtQuerySystemInformation(
            SYSTEM_SUPERFETCH_INFORMATION,
            &mut superfetch_info as *mut _ as _,
            mem::size_of_val(&superfetch_info) as _,
            &mut size_required,
        )
    };

    match status {
        STATUS_BUFFER_TOO_SMALL => {
            let mut buffer = vec![0u8; size_required as _];

            superfetch_info.Data = buffer.as_mut_ptr().cast();
            superfetch_info.Length = size_required;

            unsafe { ptr::write(buffer.as_mut_ptr() as *mut T, T::default()) };

            status = unsafe {
                NtQuerySystemInformation(
                    SYSTEM_SUPERFETCH_INFORMATION,
                    &mut superfetch_info as *mut _ as _,
                    mem::size_of_val(&superfetch_info) as _,
                    &mut size_required,
                )
            };

            if nt_success(status) {
                let raw_ptr = Box::into_raw(buffer.into_boxed_slice()) as *mut T;

                Ok(unsafe { Box::<T>::from_raw(raw_ptr) })
            } else {
                Err(unsafe {
                    windows::core::Error::from(WIN32_ERROR(RtlNtStatusToDosError(status))).into()
                })
            }
        }
        _ => Err(unsafe {
            windows::core::Error::from(WIN32_ERROR(RtlNtStatusToDosError(status))).into()
        }),
    }
}

pub fn query_memory_ranges() -> Result<Vec<PF_PHYSICAL_MEMORY_RANGE>> {
    let phy_mem_range = _query_phymem_range_info::<PF_MEMORY_RANGE_INFO_V1>(
        SUPERFETCH_INFORMATION_CLASS::SuperfetchMemoryRangesQuery,
    );

    let convert_result_v1 = |r: Box<PF_MEMORY_RANGE_INFO_V1>| -> Vec<PF_PHYSICAL_MEMORY_RANGE> {
        let mut result: Vec<PF_PHYSICAL_MEMORY_RANGE> = Vec::new();

        let ranges = unsafe { slice::from_raw_parts(r.Ranges.as_ptr(), r.RangeCount as _) };

        for range in ranges {
            result.push(PF_PHYSICAL_MEMORY_RANGE {
                BasePfn: range.BasePfn,
                PageCount: range.PageCount,
            });
        }

        result
    };

    let convert_result_v2 = |r: Box<PF_MEMORY_RANGE_INFO_V2>| -> Vec<PF_PHYSICAL_MEMORY_RANGE> {
        let mut result: Vec<PF_PHYSICAL_MEMORY_RANGE> = Vec::new();

        let ranges = unsafe { slice::from_raw_parts(r.Ranges.as_ptr(), r.RangeCount as _) };

        for range in ranges {
            result.push(PF_PHYSICAL_MEMORY_RANGE {
                BasePfn: range.BasePfn,
                PageCount: range.PageCount,
            });
        }

        result
    };

    match phy_mem_range {
        Ok(result) => Ok(convert_result_v1(result)),
        Err(e) => {
            let phy_mem_range = _query_phymem_range_info::<PF_MEMORY_RANGE_INFO_V2>(
                SUPERFETCH_INFORMATION_CLASS::SuperfetchMemoryRangesQuery,
            )?;

            Ok(convert_result_v2(phy_mem_range))
        }
    }
}

fn query_superfetch_info<T: Sized>(
    class: SUPERFETCH_INFORMATION_CLASS,
    buffer: &T,
    length: usize,
) -> Result<()> {
    let mut superfetch_info = SUPERFETCH_INFORMATION::default();

    superfetch_info.InfoClass = class;
    superfetch_info.Data = buffer as *const _ as *mut _;
    superfetch_info.Length = length as _;

    let status = unsafe {
        NtQuerySystemInformation(
            SYSTEM_SUPERFETCH_INFORMATION,
            &mut superfetch_info as *mut _ as _,
            mem::size_of_val(&superfetch_info) as _,
            ptr::null_mut(),
        )
    };

    match nt_success(status) {
        true => Ok(()),
        false => Err(windows::core::Error::from(status).into()),
    }
}

pub struct SpfTranslator {
    ranges: Vec<PF_PHYSICAL_MEMORY_RANGE>,
    transitions: HashMap<u64, u64>,
}

impl SpfTranslator {
    fn new() -> Self {
        Self {
            ranges: Vec::new(),
            transitions: HashMap::new(),
        }
    }

    pub fn ready(&self) -> bool {
        !self.transitions.is_empty()
    }

    pub fn current() -> Result<Self> {
        let mut object = Self::new();

        object.populate()?;

        Ok(object)
    }
}

impl AddressTranslator for SpfTranslator {
    fn populate(&mut self) -> Result<()> {
        self.ranges.clear();
        self.transitions.clear();

        self.ranges = query_memory_ranges()?;

        for r in &self.ranges {
            let buffer_len = mem::size_of::<PF_PFN_PRIO_REQUEST>()
                + mem::size_of::<MMPFN_IDENTITY>() * r.PageCount;

            let mut buffer = vec![0u8; buffer_len];

            let request = unsafe { &mut *(buffer.as_mut_ptr() as *mut PF_PFN_PRIO_REQUEST) };

            request.Version = 1;
            request.RequestFlags = 1;
            request.PfnCount = r.PageCount;

            let page_data =
                unsafe { slice::from_raw_parts_mut(request.PageData.as_mut_ptr(), r.PageCount) };

            for i in 0..r.PageCount {
                page_data[i].PageFrameIndex = r.BasePfn + i;
            }

            query_superfetch_info(
                SUPERFETCH_INFORMATION_CLASS::SuperfetchPfnQuery,
                request,
                buffer_len,
            )?;

            for i in 0..r.PageCount {
                if !unsafe { page_data[i].u2.VirtualAddress }.is_null() {
                    self.transitions.insert(
                        unsafe { page_data[i].u2.VirtualAddress } as _,
                        ((r.BasePfn + i) as u64) << 12,
                    );
                }
            }
        }
        Ok(())
    }

    fn translate(&self, virt: u64) -> Result<u64> {
        // align it down to page boundary
        let addr = virt & (!0xFFFu64);
        let offset = virt & 0xFFFu64;

        match self.transitions.contains_key(&addr) {
            true => Ok(self.transitions[&addr] + offset),
            _ => Err(anyhow!(
                "Address translation failed, virtual address {:x} not in cache",
                virt
            )),
        }
    }
}

#[test]
fn teset_superfetch() {
    use crate::nt::get_kernelbase;
    use crate::utils::promote_privilege_to_debug_level;

    promote_privilege_to_debug_level();

    let _ = SpfTranslator::current().inspect(|mm| {
        let phyaddr = mm.translate(get_kernelbase().unwrap() as _).unwrap();
        println!("physical address of kernel base = {:x}", phyaddr);
    });
}
