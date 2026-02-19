pub mod qcow2;
pub mod raw;
pub mod vdi;
pub mod vhd;
pub mod vhdx;
pub mod vmdk;

use std::io::{Read, Seek};
use std::path::Path;

use crate::error::Result;

/// A readable virtual disk image presenting a flat sector-addressable view.
pub trait DiskImage: Read + Seek {
    /// Total virtual disk size in bytes.
    fn disk_size(&self) -> u64;
}

/// Open a disk image from a file path, auto-detecting format by extension.
pub fn open_disk(path: &Path) -> Result<Box<dyn DiskImage>> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");

    // Detect flat VMDK (e.g., "name-flat.vmdk") — raw disk, not sparse
    if ext == "vmdk" && stem.ends_with("-flat") {
        let disk = raw::RawDisk::open(path)?;
        return Ok(Box::new(disk));
    }

    match ext.as_str() {
        "vdi" => {
            let disk = vdi::VdiDisk::open(path)?;
            Ok(Box::new(disk))
        }
        "vmdk" => {
            let disk = vmdk::VmdkDisk::open(path)?;
            Ok(Box::new(disk))
        }
        "qcow2" | "qcow" => {
            let disk = qcow2::QcowDisk::open(path)?;
            Ok(Box::new(disk))
        }
        "vhdx" => {
            let disk = vhdx::VhdxDisk::open(path)?;
            Ok(Box::new(disk))
        }
        "vhd" => {
            let disk = vhd::VhdDisk::open(path)?;
            Ok(Box::new(disk))
        }
        "raw" | "img" | "dd" => {
            let disk = raw::RawDisk::open(path)?;
            Ok(Box::new(disk))
        }
        _ => Err(crate::error::GovmemError::ProcessNotFound(format!(
            "Unsupported disk format: .{}",
            ext
        ))),
    }
}
