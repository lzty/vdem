pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
pub const IMAGE_NT_SIGNATURE: u32 = 0x00004550;

pub const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x10b;
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20b;

pub const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;

pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
pub const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
pub const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;
pub const IMAGE_DIRECTORY_ENTRY_ARCHITECTURE: usize = 7;
pub const IMAGE_DIRECTORY_ENTRY_GLOBALPTR: usize = 8;
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
pub const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: usize = 10;
pub const IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT: usize = 11;
pub const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;
pub const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;
pub const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;

pub const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
pub const IMAGE_REL_BASED_HIGH: u16 = 1;
pub const IMAGE_REL_BASED_LOW: u16 = 2;
pub const IMAGE_REL_BASED_HIGHLOW: u16 = 3;
pub const IMAGE_REL_BASED_HIGHADJ: u16 = 4;
pub const IMAGE_REL_BASED_MIPS_JMPADDR: u16 = 5;
pub const IMAGE_REL_BASED_SECTION: u16 = 6;
pub const IMAGE_REL_BASED_REL32: u16 = 7;
pub const IMAGE_REL_BASED_MIPS_JMPADDR16: u16 = 9;
pub const IMAGE_REL_BASED_IA64_IMM64: u16 = 9;
pub const IMAGE_REL_BASED_DIR64: u16 = 10;

pub const IMAGE_SIZEOF_BASE_RELOCATION: usize = 8;

pub const IMAGE_FILE_RELOCS_STRIPPED: u16 = 0x0001;
pub const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
pub const IMAGE_FILE_LINE_NUMS_STRIPPED: u16 = 0x0004;
pub const IMAGE_FILE_LOCAL_SYMS_STRIPPED: u16 = 0x0008;
pub const IMAGE_FILE_AGGRESIVE_WS_TRIM: u16 = 0x0010;
pub const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;
pub const IMAGE_FILE_BYTES_REVERSED_LO: u16 = 0x0080;
pub const IMAGE_FILE_32BIT_MACHINE: u16 = 0x0100;
pub const IMAGE_FILE_DEBUG_STRIPPED: u16 = 0x0200;
pub const IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP: u16 = 0x0400;
pub const IMAGE_FILE_NET_RUN_FROM_SWAP: u16 = 0x0800;
pub const IMAGE_FILE_SYSTEM: u16 = 0x1000;
pub const IMAGE_FILE_DLL: u16 = 0x2000;
pub const IMAGE_FILE_UP_SYSTEM_ONLY: u16 = 0x4000;
pub const IMAGE_FILE_BYTES_REVERSED_HI: u16 = 0x8000;

pub const IMAGE_FILE_MACHINE_UNKNOWN: u16 = 0;
pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
pub const IMAGE_FILE_MACHINE_R3000: u16 = 0x0162;
pub const IMAGE_FILE_MACHINE_R4000: u16 = 0x0166;
pub const IMAGE_FILE_MACHINE_R10000: u16 = 0x0168;
pub const IMAGE_FILE_MACHINE_WCEMIPSV2: u16 = 0x0169;
pub const IMAGE_FILE_MACHINE_ALPHA: u16 = 0x0184;
pub const IMAGE_FILE_MACHINE_SH3: u16 = 0x01a2;
pub const IMAGE_FILE_MACHINE_SH3DSP: u16 = 0x01a3;
pub const IMAGE_FILE_MACHINE_SH3E: u16 = 0x01a4;
pub const IMAGE_FILE_MACHINE_SH4: u16 = 0x01a6;
pub const IMAGE_FILE_MACHINE_SH5: u16 = 0x01a8;
pub const IMAGE_FILE_MACHINE_ARM: u16 = 0x01c0;
pub const IMAGE_FILE_MACHINE_THUMB: u16 = 0x01c2;
pub const IMAGE_FILE_MACHINE_ARMNT: u16 = 0x01c4;
pub const IMAGE_FILE_MACHINE_AM33: u16 = 0x01d3;
pub const IMAGE_FILE_MACHINE_POWERPC: u16 = 0x01f0;
pub const IMAGE_FILE_MACHINE_POWERPCFP: u16 = 0x01f1;
pub const IMAGE_FILE_MACHINE_IA64: u16 = 0x0200;
pub const IMAGE_FILE_MACHINE_MIPS16: u16 = 0x0266;
pub const IMAGE_FILE_MACHINE_ALPHA64: u16 = 0x0284;
pub const IMAGE_FILE_MACHINE_MIPSFPU: u16 = 0x0366;
pub const IMAGE_FILE_MACHINE_MIPSFPU16: u16 = 0x0466;
pub const IMAGE_FILE_MACHINE_AXP64: u16 = IMAGE_FILE_MACHINE_ALPHA64;
pub const IMAGE_FILE_MACHINE_TRICORE: u16 = 0x0520;
pub const IMAGE_FILE_MACHINE_CEF: u16 = 0x0cef;
pub const IMAGE_FILE_MACHINE_EBC: u16 = 0x0ebc;
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
pub const IMAGE_FILE_MACHINE_M32R: u16 = 0x9041;
pub const IMAGE_FILE_MACHINE_CEE: u16 = 0xc0ee;

pub const IMAGE_ORDINAL_FLAG64: u64 = 0x8000000000000000;
pub const IMAGE_ORDINAL_FLAG32: u32 = 0x80000000;

pub fn IMAGE_ORDINAL64(Ordinal: u64) -> u16 {
    (Ordinal & 0xffff) as u16
}
pub fn IMAGE_ORDINAL32(Ordinal: u32) -> u16 {
    (Ordinal & 0xffff) as u16
}
pub fn IMAGE_SNAP_BY_ORDINAL64(Ordinal: u64) -> bool {
    (Ordinal & IMAGE_ORDINAL_FLAG64) != 0
}
pub fn IMAGE_SNAP_BY_ORDINAL32(Ordinal: u32) -> bool {
    (Ordinal & IMAGE_ORDINAL_FLAG32) != 0
}

pub const IMAGE_SCN_TYPE_NO_PAD: u32 = 0x00000008;
pub const IMAGE_SCN_CNT_CODE: u32 = 0x00000020;
pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x00000040;
pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x00000080;
pub const IMAGE_SCN_LNK_INFO: u32 = 0x00000200;
pub const IMAGE_SCN_LNK_REMOVE: u32 = 0x00000800;
pub const IMAGE_SCN_LNK_COMDAT: u32 = 0x00001000;
pub const IMAGE_SCN_NO_DEFER_SPEC_EXC: u32 = 0x00004000;
pub const IMAGE_SCN_GPREL: u32 = 0x00008000;
pub const IMAGE_SCN_MEM_PURGEABLE: u32 = 0x00020000;
pub const IMAGE_SCN_MEM_16BIT: u32 = 0x00020000;
pub const IMAGE_SCN_MEM_LOCKED: u32 = 0x00040000;
pub const IMAGE_SCN_MEM_PRELOAD: u32 = 0x00080000;
pub const IMAGE_SCN_ALIGN_1BYTES: u32 = 0x00100000;
pub const IMAGE_SCN_ALIGN_2BYTES: u32 = 0x00200000;
pub const IMAGE_SCN_ALIGN_4BYTES: u32 = 0x00300000;
pub const IMAGE_SCN_ALIGN_8BYTES: u32 = 0x00400000;
pub const IMAGE_SCN_ALIGN_16BYTES: u32 = 0x00500000;
pub const IMAGE_SCN_ALIGN_32BYTES: u32 = 0x00600000;
pub const IMAGE_SCN_ALIGN_64BYTES: u32 = 0x00700000;
pub const IMAGE_SCN_ALIGN_128BYTES: u32 = 0x00800000;
pub const IMAGE_SCN_ALIGN_256BYTES: u32 = 0x00900000;
pub const IMAGE_SCN_ALIGN_512BYTES: u32 = 0x00A00000;
pub const IMAGE_SCN_ALIGN_1024BYTES: u32 = 0x00B00000;
pub const IMAGE_SCN_ALIGN_2048BYTES: u32 = 0x00C00000;
pub const IMAGE_SCN_ALIGN_4096BYTES: u32 = 0x00D00000;
pub const IMAGE_SCN_ALIGN_8192BYTES: u32 = 0x00E00000;
pub const IMAGE_SCN_ALIGN_MASK: u32 = 0x00F00000;
pub const IMAGE_SCN_LNK_NRELOC_OVFL: u32 = 0x01000000;
pub const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x02000000;
pub const IMAGE_SCN_MEM_NOT_CACHED: u32 = 0x04000000;
pub const IMAGE_SCN_MEM_NOT_PAGED: u32 = 0x08000000;
pub const IMAGE_SCN_MEM_SHARED: u32 = 0x10000000;
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}

pub type PIMAGE_DOS_HEADER = *mut IMAGE_DOS_HEADER;

#[repr(C)]
pub struct IMAGE_SECTION_HEADER {
    pub Name: [u8; 8],
    pub Misc: union_Misc,
    pub VirtualAddress: u32,
    pub SizeOfRawData: u32,
    pub PointerToRawData: u32,
    pub PointerToRelocations: u32,
    pub PointerToLinenumbers: u32,
    pub NumberOfRelocations: u16,
    pub NumberOfLinenumbers: u16,
    pub Characteristics: u32,
}

pub type PIMAGE_SECTION_HEADER = *mut IMAGE_SECTION_HEADER;

#[repr(C)]
pub union union_Misc {
    pub PhysicalAddress: u32,
    pub VirtualSize: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IMAGE_FILE_HEADER {
    pub Machine: u16,
    pub NumberOfSections: u16,
    pub TimeDateStamp: u32,
    pub PointerToSymbolTable: u32,
    pub NumberOfSymbols: u32,
    pub SizeOfOptionalHeader: u16,
    pub Characteristics: u16,
}

type PIMAGE_FILE_HEADER = *mut IMAGE_FILE_HEADER;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress: u32,
    pub Size: u32,
}

pub type PIMAGE_DATA_DIRECTORY = *mut IMAGE_DATA_DIRECTORY;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IMAGE_OPTION_HEADER64 {
    pub Magic: u16,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub ImageBase: u64,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: u16,
    pub DllCharacteristics: u16,
    pub SizeOfStackReserve: u64,
    pub SizeOfStackCommit: u64,
    pub SizeOfHeapReserve: u64,
    pub SizeOfHeapCommit: u64,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

pub type PIMAGE_OPTION_HEADER64 = *mut IMAGE_OPTION_HEADER64;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IMAGE_OPTION_HEADER32 {
    pub Magic: u16,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub BaseOfData: u32,
    pub ImageBase: u32,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: u16,
    pub DllCharacteristics: u16,
    pub SizeOfStackReserve: u32,
    pub SizeOfStackCommit: u32,
    pub SizeOfHeapReserve: u32,
    pub SizeOfHeapCommit: u32,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

pub type PIMAGE_OPTION_HEADER32 = *mut IMAGE_OPTION_HEADER32;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IMAGE_NT_HEADERS64 {
    pub Signature: u32,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTION_HEADER64,
}

pub type PIMAGE_NT_HEADERS64 = *mut IMAGE_NT_HEADERS64;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IMAGE_NT_HEADERS32 {
    pub Signature: u32,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTION_HEADER32,
}

pub type PIMAGE_NT_HEADERS32 = *mut IMAGE_NT_HEADERS32;

#[repr(C)]
pub struct IMAGE_EXPORT_DIRECTORY {
    pub Characteristics: u32,
    pub TimeDateStamp: u32,
    pub MajorVersion: u16,
    pub MinorVersion: u16,
    pub Name: u32,
    pub Base: u32,
    pub NumberOfFunctions: u32,
    pub NumberOfNames: u32,
    pub AddressOfFunctions: u32,
    pub AddressOfNames: u32,
    pub AddressOfNameOrdinals: u32,
}

pub type PIMAGE_EXPORT_DIRECTORY = *mut IMAGE_EXPORT_DIRECTORY;

#[repr(C)]
pub union _U1 {
    pub Characteristics: u32,
    pub OriginalFirstThunk: u32,
}

#[repr(C)]
pub struct IMAGE_IMPORT_DESCRIPTOR {
    pub u1: _U1,
    pub TimeDateStamp: u32,
    pub ForwarderChain: u32,
    pub Name: u32,
    pub FirstThunk: u32, // RVA to IAT (if bound, this IAT has actual addresses)
}

// Type alias for a pointer to IMAGE_IMPORT_DESCRIPTOR
pub type PIMAGE_IMPORT_DESCRIPTOR = *mut IMAGE_IMPORT_DESCRIPTOR;

#[repr(C)]
pub struct IMAGE_THUNK_DATA64 {
    pub u1: IMAGE_THUNK_DATA64_U1,
}

#[repr(C)]
pub union IMAGE_THUNK_DATA64_U1 {
    pub ForwarderString: u64, // PBYTE
    pub Function: u64,        // PULONG
    pub Ordinal: u64,
    pub AddressOfData: u64, // PIMAGE_IMPORT_BY_NAME
}

pub type PIMAGE_THUNK_DATA64 = *mut IMAGE_THUNK_DATA64;

#[repr(C)]
pub struct IMAGE_THUNK_DATA32 {
    pub u1: IMAGE_THUNK_DATA32_U1,
}

#[repr(C)]
pub union IMAGE_THUNK_DATA32_U1 {
    pub ForwarderString: u32, // PBYTE
    pub Function: u32,        // PULONG
    pub Ordinal: u32,
    pub AddressOfData: u32, // PIMAGE_IMPORT_BY_NAME
}

pub type PIMAGE_THUNK_DATA32 = *mut IMAGE_THUNK_DATA32;

#[repr(C)]
pub struct IMAGE_TLS_DIRECTORY64 {
    pub StartAddressOfRawData: u64,
    pub EndAddressOfRawData: u64,
    pub AddressOfIndex: u64,     // PULONG
    pub AddressOfCallBacks: u64, // PIMAGE_TLS_CALLBACK *
    pub SizeOfZeroFill: u32,
    pub u1: IMAGE_TLS_DIRECTORY64_UNION,
}

#[repr(C)]
pub union IMAGE_TLS_DIRECTORY64_UNION {
    pub Characteristics: u32,
    pub Reserved: i32,
}

pub type PIMAGE_TLS_DIRECTORY64 = *mut IMAGE_TLS_DIRECTORY64;

#[repr(C)]
pub struct IMAGE_TLS_DIRECTORY32 {
    pub StartAddressOfRawData: u32,
    pub EndAddressOfRawData: u32,
    pub AddressOfIndex: u32,     // PULONG
    pub AddressOfCallBacks: u32, // PIMAGE_TLS_CALLBACK *
    pub SizeOfZeroFill: u32,
    pub u1: IMAGE_TLS_DIRECTORY32_UNION,
}

#[repr(C)]
pub union IMAGE_TLS_DIRECTORY32_UNION {
    pub Characteristics: u32,
    pub Reserved: i32,
}

#[repr(C)]
pub struct IMAGE_TLS_DIRECTORY32_STRUCT {
    pub Reserved0: i32, // 20 bits
    pub Alignment: i32, // 4 bits
    pub Reserved1: i32, // 8 bits
}

pub type PIMAGE_TLS_DIRECTORY32 = *mut IMAGE_TLS_DIRECTORY32;

#[repr(C)]
pub struct IMAGE_IMPORT_BY_NAME {
    pub Hint: u16,
    pub Name: [i8; 1], // A flexible array; typically replaced or extended as needed
}

pub type PIMAGE_IMPORT_BY_NAME = *mut IMAGE_IMPORT_BY_NAME;

#[repr(C)]
pub struct IMAGE_BASE_RELOCATION {
    pub VirtualAddress: u32,
    pub SizeOfBlock: u32,
}

#[repr(C)]
pub struct IMAGE_RUNTIME_FUNCTION_ENTRY {
    pub BeginAddress: u32,
    pub EndAddress: u32,
    pub u1: IMAGE_RUNTIME_FUNCTION_ENTRY_UNION,
}

#[repr(C)]
pub union IMAGE_RUNTIME_FUNCTION_ENTRY_UNION {
    pub UnwindInfoAddress: u32,
    pub UnwindData: u32,
}

pub type PIMAGE_RUNTIME_FUNCTION_ENTRY = *mut IMAGE_RUNTIME_FUNCTION_ENTRY;

// Flags
pub const UNW_FLAG_NHANDLER: u8 = 0x0;
pub const UNW_FLAG_EHANDLER: u8 = 0x1;
pub const UNW_FLAG_UHANDLER: u8 = 0x2;
pub const UNW_FLAG_CHAININFO: u8 = 0x4;

// Software-only flag
pub const UNW_FLAG_NO_EPILOGUE: u32 = 0x80000000; // Software-only flag

// Other constants
pub const UNWIND_CHAIN_LIMIT: u32 = 32;
pub const UNWIND_HISTORY_TABLE_SIZE: u32 = 12;

#[repr(C)]
pub struct UNWIND_HISTORY_TABLE_ENTRY {
    pub ImageBase: u64,
    pub FunctionEntry: *mut IMAGE_RUNTIME_FUNCTION_ENTRY, // Raw pointer to a struct
}

#[repr(C)]
pub struct _UNWIND_HISTORY_TABLE {
    pub Count: u32,
    pub LocalHint: u8,
    pub GlobalHint: u8,
    pub Search: u8,
    pub Once: u8,
    pub LowAddress: u64,
    pub HighAddress: u64,
    pub Entry: [UNWIND_HISTORY_TABLE_ENTRY; UNWIND_HISTORY_TABLE_SIZE as _],
}

pub type UNWIND_HISTORY_TABLE = _UNWIND_HISTORY_TABLE;
pub type PUNWIND_HISTORY_TABLE = *mut UNWIND_HISTORY_TABLE;