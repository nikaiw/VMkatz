pub mod qcow2;
pub mod raw;
pub mod vdi;
pub mod vhd;
pub mod vhdx;
pub mod vmdk;
#[cfg(feature = "vmfs")]
pub mod vmfs;

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::error::Result;

// Shared File I/O helpers for disk image parsers.
// All disk formats need to read multi-byte integers from File handles.
// Little-endian variants for VDI, VHDX, VMDK; big-endian for VHD, QCOW2.

pub(crate) fn read_u16_le_file(f: &mut File) -> std::io::Result<u16> {
    let mut buf = [0u8; 2];
    f.read_exact(&mut buf)?;
    Ok(u16::from_le_bytes(buf))
}

pub(crate) fn read_u32_le_file(f: &mut File) -> std::io::Result<u32> {
    let mut buf = [0u8; 4];
    f.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

pub(crate) fn read_u64_le_file(f: &mut File) -> std::io::Result<u64> {
    let mut buf = [0u8; 8];
    f.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

pub(crate) fn read_u16_be_file(f: &mut File) -> std::io::Result<u16> {
    let mut buf = [0u8; 2];
    f.read_exact(&mut buf)?;
    Ok(u16::from_be_bytes(buf))
}

pub(crate) fn read_u32_be_file(f: &mut File) -> std::io::Result<u32> {
    let mut buf = [0u8; 4];
    f.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}

pub(crate) fn read_u64_be_file(f: &mut File) -> std::io::Result<u64> {
    let mut buf = [0u8; 8];
    f.read_exact(&mut buf)?;
    Ok(u64::from_be_bytes(buf))
}

/// A readable virtual disk image presenting a flat sector-addressable view.
pub trait DiskImage: Read + Seek {
    /// Total virtual disk size in bytes.
    fn disk_size(&self) -> u64;
}

/// Detected disk image format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiskFormat {
    Vdi,
    Vmdk,
    VmdkFlat,
    Qcow2,
    Vhdx,
    Vhd,
    Raw,
}

/// Detect disk format by reading magic bytes from the file header (and footer for VHD).
///
/// Probe order:
///   1. QCOW2: "QFI\xFB" at offset 0 (4 bytes, big-endian)
///   2. VMDK:  "KDMV" at offset 0 (4 bytes, little-endian)
///   3. VHDX:  "vhdxfile" at offset 0 (8 bytes, little-endian)
///   4. VDI:   0xBEDA107F at offset 0x40 (4 bytes, little-endian)
///   5. VHD:   "conectix" in last 512 bytes (footer)
///   6. None:  unrecognized → caller decides (raw or error)
fn detect_format_by_magic(path: &Path) -> Option<DiskFormat> {
    let mut f = File::open(path).ok()?;

    // Read the first 0x44 bytes — enough for all header-based magics.
    let mut header = [0u8; 0x44];
    f.read_exact(&mut header).ok()?;

    // QCOW2: magic "QFI\xFB" at offset 0 (big-endian u32)
    if u32::from_be_bytes(header[0..4].try_into().unwrap()) == 0x514649FB {
        return Some(DiskFormat::Qcow2);
    }

    // VMDK sparse extent: "KDMV" at offset 0 (little-endian u32)
    if u32::from_le_bytes(header[0..4].try_into().unwrap()) == 0x564D444B {
        return Some(DiskFormat::Vmdk);
    }

    // VHDX: "vhdxfile" at offset 0 (little-endian u64)
    if u64::from_le_bytes(header[0..8].try_into().unwrap()) == 0x656C_6966_7864_6876 {
        return Some(DiskFormat::Vhdx);
    }

    // VDI: magic 0xBEDA107F at offset 0x40
    if u32::from_le_bytes(header[0x40..0x44].try_into().unwrap()) == 0xBEDA_107F {
        return Some(DiskFormat::Vdi);
    }

    // VMDK text descriptor: starts with "# Disk DescriptorFile"
    if header.starts_with(b"# Disk Desc") {
        return Some(DiskFormat::Vmdk);
    }

    // VHD: "conectix" cookie in footer (last 512 bytes)
    let file_size = f.seek(SeekFrom::End(0)).ok()?;
    if file_size >= 512 {
        f.seek(SeekFrom::Start(file_size - 512)).ok()?;
        let mut cookie = [0u8; 8];
        f.read_exact(&mut cookie).ok()?;
        if &cookie == b"conectix" {
            return Some(DiskFormat::Vhd);
        }
    }

    None
}

/// Open a disk image, detecting format by extension first, then by magic bytes.
pub fn open_disk(path: &Path) -> Result<Box<dyn DiskImage>> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");

    // Extension hint → format (fast path, avoids re-reading header)
    let format = match ext.as_str() {
        "vdi" => DiskFormat::Vdi,
        "vmdk" if stem.ends_with("-flat") => DiskFormat::VmdkFlat,
        "vmdk" => DiskFormat::Vmdk,
        "qcow2" | "qcow" => DiskFormat::Qcow2,
        "vhdx" => DiskFormat::Vhdx,
        "vhd" => DiskFormat::Vhd,
        "raw" | "img" | "dd" => DiskFormat::Raw,
        _ => {
            // Unrecognized extension — probe magic bytes
            log::debug!("Unknown extension '{}', probing magic bytes", ext);
            detect_format_by_magic(path).unwrap_or(DiskFormat::Raw)
        }
    };

    open_disk_as(path, format)
}

fn open_disk_as(path: &Path, format: DiskFormat) -> Result<Box<dyn DiskImage>> {
    match format {
        DiskFormat::Vdi => Ok(Box::new(vdi::VdiDisk::open(path)?)),
        DiskFormat::Vmdk => Ok(Box::new(vmdk::VmdkDisk::open(path)?)),
        DiskFormat::VmdkFlat | DiskFormat::Raw => Ok(Box::new(raw::RawDisk::open(path)?)),
        DiskFormat::Qcow2 => Ok(Box::new(qcow2::QcowDisk::open(path)?)),
        DiskFormat::Vhdx => Ok(Box::new(vhdx::VhdxDisk::open(path)?)),
        DiskFormat::Vhd => Ok(Box::new(vhd::VhdDisk::open(path)?)),
    }
}
