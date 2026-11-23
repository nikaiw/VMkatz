use crate::utils::{u32_be, u32_le, u64_le};
pub mod aes_xts;
pub mod bitlocker_decrypt;
pub mod qcow2;
pub mod raw;
mod table;
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

/// Prevent unbounded recursion when snapshot descriptors contain parent cycles.
pub(crate) const fn check_backing_depth(depth: u32) -> Result<()> {
    if depth > 64 {
        return Err(crate::error::VmkatzError::DiskChainLimit);
    }
    Ok(())
}

/// Compute a logical seek without narrowing a u64 position to i64. Seeking past
/// EOF is permitted; negative positions and arithmetic overflow are errors.
pub(crate) fn seek_position(cursor: u64, end: u64, pos: SeekFrom) -> std::io::Result<u64> {
    let target = match pos {
        SeekFrom::Start(offset) => Some(offset),
        SeekFrom::Current(delta) => cursor.checked_add_signed(delta),
        SeekFrom::End(delta) => end.checked_add_signed(delta),
    };
    target.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "seek to a negative or overflowing position",
        )
    })
}

/// Clamp in u64 before narrowing, so large disks also work on 32-bit hosts.
pub(crate) fn read_len(remaining: u64, requested: usize) -> usize {
    remaining.min(requested as u64) as usize
}

// Shared File I/O helpers for disk image parsers.
// All disk formats need to read multi-byte integers from File handles.
// Little-endian variants for VDI, VHDX, VMDK; big-endian for VHD, QCOW2.

/// Parent paths and locator key/value fields must fit within 1 MiB each.
/// Large allocation tables need bounded, on-demand readers instead.
pub(crate) fn read_exact_alloc<R: Read>(r: &mut R, len: u64) -> std::io::Result<Vec<u8>> {
    const MAX_METADATA_BYTES: u64 = 1024 * 1024;
    if len > MAX_METADATA_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "disk metadata field exceeds 1 MiB",
        ));
    }
    let len = usize::try_from(len).map_err(std::io::Error::other)?;
    let mut buf = Vec::new();
    buf.try_reserve_exact(len)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::OutOfMemory, e))?;
    buf.resize(len, 0);
    r.read_exact(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod metadata_tests {
    use super::read_exact_alloc;
    use std::io::{Cursor, ErrorKind};

    #[test]
    fn oversized_metadata_is_refused_before_reading() {
        for length in [1024 * 1024 + 1, u64::MAX] {
            let mut input = Cursor::new([0; 16]);
            assert_eq!(
                read_exact_alloc(&mut input, length).unwrap_err().kind(),
                ErrorKind::InvalidData
            );
            assert_eq!(input.position(), 0);
        }
    }

    #[test]
    fn bounded_metadata_reads_preserve_exact_length_and_eof() -> std::io::Result<()> {
        let mut input = Cursor::new([0xAB; 512]);
        assert_eq!(read_exact_alloc(&mut input, 512)?, [0xAB; 512]);
        assert_eq!(input.position(), 512);
        assert!(read_exact_alloc(&mut input, 0)?.is_empty());
        assert_eq!(
            read_exact_alloc(&mut input, 1).unwrap_err().kind(),
            ErrorKind::UnexpectedEof
        );
        Ok(())
    }
}

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
    if u32_be(&header, 0) == 0x514649FB {
        return Some(DiskFormat::Qcow2);
    }

    // VMDK sparse extent: "KDMV" at offset 0 (little-endian u32)
    if u32_le(&header, 0) == 0x564D444B {
        return Some(DiskFormat::Vmdk);
    }

    // VHDX: "vhdxfile" at offset 0 (little-endian u64)
    if u64_le(&header, 0) == 0x656C_6966_7864_6876 {
        return Some(DiskFormat::Vhdx);
    }

    // VDI: magic 0xBEDA107F at offset 0x40
    if u32_le(&header, 0x40) == 0xBEDA_107F {
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
            log::debug!("Unknown extension '{ext}', probing magic bytes");
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
