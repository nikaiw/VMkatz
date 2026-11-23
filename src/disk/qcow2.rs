use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use super::table::{Encoding, Table, TableCache};
use super::{read_u32_be_file, read_u64_be_file};
use crate::error::{Result, VmkatzError};

/// QCOW2 magic: "QFI\xFB" as big-endian u32.
const QCOW2_MAGIC: u32 = 0x514649FB;

/// Mask for extracting host cluster offset from L1/L2 entries (bits 9..55).
const OFFSET_MASK: u64 = 0x00FF_FFFF_FFFF_FE00;

/// Bit 62: compressed cluster flag.
const COMPRESSED_FLAG: u64 = 1 << 62;

/// Bit 0: "all zeroes" flag (QCOW_OFLAG_ZERO, qcow2 v3). The cluster reads as
/// zeros regardless of any backing file — it marks a sector explicitly cleared
/// over the parent. Reserved (always 0) in v2, so the check is safe there too.
const ZERO_FLAG: u64 = 1;

/// QCOW2 (QEMU Copy-On-Write v2/v3) disk image reader with backing file chain.
pub struct QcowDisk {
    file: File,
    cluster_bits: u32,
    cluster_size: u64,
    l2_bits: u32,
    l1_table: Table,
    disk_size: u64,
    cursor: u64,
    parent: Option<Box<Self>>,
    file_len: u64,
    table_cache: TableCache,
}

struct QcowHeader {
    version: u32,
    backing_file_offset: u64,
    backing_file_size: u32,
    cluster_bits: u32,
    disk_size: u64,
    l1_size: u32,
    l1_table_offset: u64,
}

fn parse_header(file: &mut File) -> Result<QcowHeader> {
    file.seek(SeekFrom::Start(0))?;

    let magic = read_u32_be_file(file)?;
    if magic != QCOW2_MAGIC {
        return Err(VmkatzError::InvalidMagic(magic));
    }

    let version = read_u32_be_file(file)?;
    if version != 2 && version != 3 {
        return Err(VmkatzError::DiskFormatError(format!(
            "Unsupported QCOW2 version: {version}"
        )));
    }

    let backing_file_offset = read_u64_be_file(file)?;
    let backing_file_size = read_u32_be_file(file)?;
    let cluster_bits = read_u32_be_file(file)?;

    // Sanity check cluster_bits (typically 9..24, default 16 = 64KB)
    if !(9..=24).contains(&cluster_bits) {
        return Err(VmkatzError::DiskFormatError(format!(
            "Invalid QCOW2 cluster_bits: {cluster_bits}"
        )));
    }

    let disk_size = read_u64_be_file(file)?;
    let encryption_method = read_u32_be_file(file)?;

    if encryption_method != 0 {
        return Err(VmkatzError::DiskFormatError(format!(
            "Encrypted QCOW2 not supported (method={encryption_method})"
        )));
    }

    let l1_size = read_u32_be_file(file)?;
    let l1_table_offset = read_u64_be_file(file)?;

    Ok(QcowHeader {
        version,
        backing_file_offset,
        backing_file_size,
        cluster_bits,
        disk_size,
        l1_size,
        l1_table_offset,
    })
}

impl QcowDisk {
    /// Open a QCOW2 disk image, recursively opening backing files.
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with_depth(path, 0)
    }

    /// Backing-file chain depth is bounded so a circular chain errors instead of
    /// recursing until the stack overflows.
    fn open_with_depth(path: &Path, depth: u32) -> Result<Self> {
        super::check_backing_depth(depth)?;

        let mut file = File::open(path)?;
        let header = parse_header(&mut file)?;

        let cluster_bits = header.cluster_bits;
        let cluster_size = 1u64 << cluster_bits;
        // Each L2 entry is 8 bytes, so entries per L2 table = cluster_size / 8
        let l2_bits = cluster_bits - 3;

        log::debug!(
            "QCOW2: v{} disk_size={} cluster_bits={} cluster_size={} l1_entries={}",
            header.version,
            header.disk_size,
            cluster_bits,
            cluster_size,
            header.l1_size,
        );

        let file_len = file.seek(SeekFrom::End(0))?;
        let l1_table = Table::new(
            header.l1_table_offset,
            u64::from(header.l1_size),
            Encoding::Be64,
            file_len,
        )?;

        // Open backing file if present
        let parent = if header.backing_file_offset != 0 && header.backing_file_size > 0 {
            file.seek(SeekFrom::Start(header.backing_file_offset))?;
            let name_buf = super::read_exact_alloc(&mut file, u64::from(header.backing_file_size))?;
            let backing_name = String::from_utf8_lossy(&name_buf).into_owned();

            let backing_path = resolve_backing_path(path, &backing_name);
            log::debug!("QCOW2: backing file: {}", backing_path.display());
            Some(Box::new(Self::open_with_depth(&backing_path, depth + 1)?))
        } else {
            None
        };

        Ok(Self {
            file,
            cluster_bits,
            cluster_size,
            l2_bits,
            l1_table,
            disk_size: header.disk_size,
            cursor: 0,
            parent,
            file_len,
            table_cache: TableCache::default(),
        })
    }

    /// Read data at a given virtual offset within a single cluster boundary.
    /// Returns bytes read.
    fn read_cluster(&mut self, virtual_offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let l1_idx = virtual_offset >> (self.l2_bits + self.cluster_bits);
        let l2_idx = (virtual_offset >> self.cluster_bits) & ((1 << self.l2_bits) - 1);
        let cluster_off = virtual_offset & (self.cluster_size - 1);

        // Check L1 bounds
        let Some(l1_entry) = self
            .table_cache
            .read(&mut self.file, self.l1_table, l1_idx)?
        else {
            return self.read_from_parent_or_zero(virtual_offset, buf);
        };
        let l2_table_offset = l1_entry & OFFSET_MASK;

        if l2_table_offset == 0 {
            // L1 entry unallocated -> parent or zeros
            return self.read_from_parent_or_zero(virtual_offset, buf);
        }

        let l2_table = Table::new(
            l2_table_offset,
            self.cluster_size / 8,
            Encoding::Be64,
            self.file_len,
        )?;
        let l2_entry = self
            .table_cache
            .read(&mut self.file, l2_table, l2_idx)?
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "QCOW2 L2 index out of bounds",
                )
            })?;

        if l2_entry & COMPRESSED_FLAG != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "QCOW2 compressed clusters not supported",
            ));
        }

        // Explicitly-zeroed cluster: reads as zeros, overriding the backing file.
        // Must be checked before falling back to the parent.
        if l2_entry & ZERO_FLAG != 0 {
            buf.fill(0);
            return Ok(buf.len());
        }

        let data_cluster_offset = l2_entry & OFFSET_MASK;

        if data_cluster_offset == 0 {
            // L2 entry unallocated -> parent or zeros
            return self.read_from_parent_or_zero(virtual_offset, buf);
        }

        // Read from data cluster
        let file_offset = data_cluster_offset + cluster_off;
        self.file.seek(SeekFrom::Start(file_offset))?;
        self.file.read(buf)
    }

    /// Read from parent backing file, or return zeros if no parent.
    fn read_from_parent_or_zero(
        &mut self,
        virtual_offset: u64,
        buf: &mut [u8],
    ) -> std::io::Result<usize> {
        if let Some(ref mut parent) = self.parent {
            parent.seek(SeekFrom::Start(virtual_offset))?;
            parent.read(buf)
        } else {
            buf.fill(0);
            Ok(buf.len())
        }
    }
}

impl Read for QcowDisk {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.cursor >= self.disk_size {
            return Ok(0);
        }

        let to_read = crate::disk::read_len(self.disk_size - self.cursor, buf.len());
        if to_read == 0 {
            return Ok(0);
        }

        let mut total = 0;
        while total < to_read {
            let pos = self.cursor;
            let cluster_off = pos & (self.cluster_size - 1);
            let avail_in_cluster = (self.cluster_size - cluster_off) as usize;
            let chunk = (to_read - total).min(avail_in_cluster);

            let n = self.read_cluster(pos, &mut buf[total..total + chunk])?;
            if n == 0 {
                break;
            }
            total += n;
            self.cursor += n as u64;
        }

        Ok(total)
    }
}

impl Seek for QcowDisk {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let target = crate::disk::seek_position(self.cursor, self.disk_size, pos)?;
        self.cursor = target;
        Ok(target)
    }
}

impl super::DiskImage for QcowDisk {
    fn disk_size(&self) -> u64 {
        self.disk_size
    }
}

/// Resolve backing file path relative to the current image's directory.
fn resolve_backing_path(image_path: &Path, backing_name: &str) -> std::path::PathBuf {
    let backing = std::path::Path::new(backing_name);
    if backing.is_absolute() {
        backing.to_path_buf()
    } else {
        let base_dir = image_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        base_dir.join(backing)
    }
}
