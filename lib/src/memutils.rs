use anyhow::Result;
use std::ffi::c_void;

use crate::traits::ReadWriteVirtualMemory;

/// Read a u8 from `va`
pub fn read_kmem_u8(va: *mut c_void, m: &impl ReadWriteVirtualMemory) -> Result<u8> {
    let mut buffer = [0u8; 1];

    m.read_kmem(va, &mut buffer)?;

    Ok(u8::from_le_bytes(buffer))
}

/// Read a u16 from `va`
pub fn read_kmem_u16(va: *mut c_void, m: &impl ReadWriteVirtualMemory) -> Result<u16> {
    let mut buffer = [0u8; 2];

    m.read_kmem(va, &mut buffer)?;

    Ok(u16::from_le_bytes(buffer))
}

/// Read a u32 from `va`
pub fn read_kmem_u32(va: *mut c_void, m: &impl ReadWriteVirtualMemory) -> Result<u32> {
    let mut buffer = [0u8; 4];

    m.read_kmem(va, &mut buffer)?;

    Ok(u32::from_le_bytes(buffer))
}

/// Read a u64 from `va`
pub fn read_kmem_u64(va: *mut c_void, m: &impl ReadWriteVirtualMemory) -> Result<u64> {
    let mut buffer = [0u8; 8];

    m.read_kmem(va, &mut buffer)?;

    Ok(u64::from_le_bytes(buffer))
}

/// Write a u8 into `va`
pub fn write_kmem_u8(va: *mut c_void, value: u8, m: &impl ReadWriteVirtualMemory) -> Result<()> {
    m.write_kmem(va, &value.to_le_bytes()).map(|_| ())
}

/// Write a u16 into `va`
pub fn write_kmem_u16(va: *mut c_void, value: u16, m: &impl ReadWriteVirtualMemory) -> Result<()> {
    m.write_kmem(va, &value.to_le_bytes()).map(|_| ())
}

/// Write a u32 into `va`
pub fn write_kmem_u32(va: *mut c_void, value: u32, m: &impl ReadWriteVirtualMemory) -> Result<()> {
    m.write_kmem(va, &value.to_le_bytes()).map(|_| ())
}

/// Write a u64 into `va`
pub fn write_kmem_u64(va: *mut c_void, value: u64, m: &impl ReadWriteVirtualMemory) -> Result<()> {
    m.write_kmem(va, &value.to_le_bytes()).map(|_| ())
}

pub fn read_kmem_as<T: Sized + Copy>(
    va: *mut c_void,
    m: &impl ReadWriteVirtualMemory,
) -> Result<T> {
    let mut buffer = vec![0u8; core::mem::size_of::<T>()];

    m.read_kmem(va, &mut buffer)?;

    Ok(unsafe { *buffer.as_ptr().cast::<T>() })
}
