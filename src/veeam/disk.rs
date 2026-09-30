//! Present a Veeam-stored disk image as a vmkatz [`DiskImage`].
//!
//! A backup holds one file per backed-up disk plus metadata. [`list_disk_images`]
//! picks out the disk images; [`VbkDisk`] wraps one so the credential pipeline
//! reads it on demand, without extracting it to a temp file first.

use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use crate::disk::DiskImage;
use crate::error::{Result, VmkatzError};
use crate::veeam::{LogicalFileReader, StoredItemKind, list_items_with_password};

/// Extensions vmkatz treats as Veeam backup containers.
pub fn is_veeam_path(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("vbk" | "vib" | "vrb")
    )
}

/// A single disk image discovered inside a backup: its catalogue path (used to
/// open it) plus the human-facing name for reporting.
#[derive(Debug, Clone)]
pub struct VeeamDiskEntry {
    /// Stable catalogue path, passed to [`VbkDisk::open`].
    pub path: String,
    /// Stored name for display (e.g. `DEV__dev_nvme1n1`, `disk-flat.vmdk`).
    pub name: String,
    /// Reconstructed size in bytes, when the catalogue records it.
    pub size: Option<u64>,
}

/// Enumerate the stored disk images in a Veeam backup.
///
/// Filters the catalogue to file records whose reconstructed sector 0 carries an
/// MBR or GPT signature — this cleanly separates real disk images (and VMware
/// `-flat.vmdk` extents) from metadata (`summary.xml`, tiny VMDK descriptors).
pub fn list_disk_images(path: &Path, password: Option<&str>) -> Result<Vec<VeeamDiskEntry>> {
    let catalog = list_items_with_password(path, password)
        .map_err(|e| VmkatzError::DecryptionError(format!("Veeam catalogue: {e}")))?;

    let mut disks = Vec::new();
    for item in catalog.items {
        if item.kind != StoredItemKind::File {
            continue;
        }
        // Skip records too small to hold a partition table (metadata/XML).
        if item.size.is_some_and(|s| s < 512) {
            continue;
        }
        // Confirm by reconstructing sector 0; skip anything we can't open.
        match LogicalFileReader::open(path, &item.path, password) {
            Ok(reader) if reader_looks_like_disk(&reader) => disks.push(VeeamDiskEntry {
                path: item.path,
                name: item.name,
                size: item.size,
            }),
            Ok(_) => {}
            Err(e) => log::debug!("Veeam: skip {:?}: {e}", item.name),
        }
    }
    Ok(disks)
}

/// True if sector 0 ends in the MBR boot signature or LBA 1 begins with the GPT
/// magic — the same check the disk layer uses to accept a raw image.
fn reader_looks_like_disk(reader: &LogicalFileReader) -> bool {
    let mut boot = [0u8; 1024]; // sector 0 (MBR sig at 510) + sector 1 (GPT magic at 512)
    let n = reader.read_at(&mut boot, 0).unwrap_or(0);
    if n >= 512 && boot[510] == 0x55 && boot[511] == 0xAA {
        return true;
    }
    n >= 512 + 8 && &boot[512..520] == b"EFI PART"
}

/// A Veeam-stored disk image as a flat, sector-addressable disk. Owns its
/// [`LogicalFileReader`]; each read is reconstructed (decompressed/decrypted).
pub struct VbkDisk {
    reader: LogicalFileReader,
    pos: u64,
    len: u64,
}

impl VbkDisk {
    /// Open one stored disk image by its catalogue path (from [`list_disk_images`]).
    pub fn open(path: &Path, item_path: &str, password: Option<&str>) -> Result<Self> {
        let reader = LogicalFileReader::open(path, item_path, password)
            .map_err(|e| VmkatzError::DecryptionError(format!("Veeam open {item_path:?}: {e}")))?;
        let len = reader.len();
        Ok(Self {
            reader,
            pos: 0,
            len,
        })
    }
}

impl Read for VbkDisk {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len {
            return Ok(0);
        }
        let n = self
            .reader
            .read_at(buf, self.pos)
            .map_err(|e| io::Error::other(format!("Veeam block read: {e}")))?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for VbkDisk {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        // Match File semantics: seeking past the end is allowed; reads there yield 0.
        let new = match pos {
            SeekFrom::Start(o) => o as i64,
            SeekFrom::End(o) => self.len as i64 + o,
            SeekFrom::Current(o) => self.pos as i64 + o,
        };
        if new < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        self.pos = new as u64;
        Ok(self.pos)
    }
}

impl DiskImage for VbkDisk {
    fn disk_size(&self) -> u64 {
        self.len
    }
}
