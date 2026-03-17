use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::error::{VmkatzError, Result};
use super::{read_u32_be_file, read_u64_be_file};

/// Maximum number of L2 tables kept in cache.
/// Each cached table holds `cluster_size / 8` entries of 8 bytes each,
/// so with a 64 KB cluster size this is 64 * 8 KB = 512 KB of cache.
const L2_CACHE_MAX_TABLES: usize = 64;

/// QCOW2 magic: "QFI\xFB" as big-endian u32.
const QCOW2_MAGIC: u32 = 0x514649FB;

/// Mask for extracting host cluster offset from L1/L2 entries (bits 9..55).
const OFFSET_MASK: u64 = 0x00FF_FFFF_FFFF_FE00;

/// Bit 62: compressed cluster flag.
const COMPRESSED_FLAG: u64 = 1 << 62;

/// QCOW2 (QEMU Copy-On-Write v2/v3) disk image reader with backing file chain.
pub struct QcowDisk {
    file: File,
    cluster_bits: u32,
    cluster_size: u64,
    l2_bits: u32,
    /// Number of u64 entries in one L2 table (= cluster_size / 8).
    l2_entries: usize,
    l1_table: Vec<u64>,
    disk_size: u64,
    cursor: u64,
    parent: Option<Box<QcowDisk>>,
    /// Cache of L2 tables keyed by their on-disk byte offset.
    /// Each value is the full L2 table decoded as big-endian u64 entries.
    l2_cache: HashMap<u64, Vec<u64>>,
}

struct QcowHeader {
    version: u32,
    backing_file_offset: u64,
    backing_file_size: u32,
    cluster_bits: u32,
    disk_size: u64,
    #[allow(dead_code)]
    encryption_method: u32,
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
            "Unsupported QCOW2 version: {}",
            version
        )));
    }

    let backing_file_offset = read_u64_be_file(file)?;
    let backing_file_size = read_u32_be_file(file)?;
    let cluster_bits = read_u32_be_file(file)?;

    // Sanity check cluster_bits (typically 9..24, default 16 = 64KB)
    if !(9..=24).contains(&cluster_bits) {
        return Err(VmkatzError::DiskFormatError(format!(
            "Invalid QCOW2 cluster_bits: {}",
            cluster_bits
        )));
    }

    let disk_size = read_u64_be_file(file)?;
    let encryption_method = read_u32_be_file(file)?;

    if encryption_method != 0 {
        return Err(VmkatzError::DiskFormatError(format!(
            "Encrypted QCOW2 not supported (method={})",
            encryption_method
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
        encryption_method,
        l1_size,
        l1_table_offset,
    })
}

impl QcowDisk {
    /// Open a QCOW2 disk image, recursively opening backing files.
    pub fn open(path: &Path) -> Result<Self> {
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

        // Read L1 table (big-endian u64 entries)
        file.seek(SeekFrom::Start(header.l1_table_offset))?;
        // Cap pre-allocation; actual entries are read one-by-one from file
        let mut l1_table = Vec::with_capacity((header.l1_size as usize).min(1 << 20));
        for _ in 0..header.l1_size {
            l1_table.push(read_u64_be_file(&mut file)?);
        }

        // Open backing file if present
        let parent = if header.backing_file_offset != 0 && header.backing_file_size > 0 {
            file.seek(SeekFrom::Start(header.backing_file_offset))?;
            let mut name_buf = vec![0u8; header.backing_file_size as usize];
            file.read_exact(&mut name_buf)?;
            let backing_name = String::from_utf8_lossy(&name_buf).into_owned();

            let backing_path = resolve_backing_path(path, &backing_name);
            log::debug!("QCOW2: backing file: {:?}", backing_path);
            Some(Box::new(QcowDisk::open(&backing_path)?))
        } else {
            None
        };

        let l2_entries = (cluster_size / 8) as usize;

        Ok(QcowDisk {
            file,
            cluster_bits,
            cluster_size,
            l2_bits,
            l2_entries,
            l1_table,
            disk_size: header.disk_size,
            cursor: 0,
            parent,
            l2_cache: HashMap::new(),
        })
    }

    /// Read data at a given virtual offset within a single cluster boundary.
    /// Returns bytes read.
    fn read_cluster(&mut self, virtual_offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let l1_idx = (virtual_offset >> (self.l2_bits + self.cluster_bits)) as usize;
        let l2_idx = ((virtual_offset >> self.cluster_bits) & ((1 << self.l2_bits) - 1)) as usize;
        let cluster_off = virtual_offset & (self.cluster_size - 1);

        // Check L1 bounds
        if l1_idx >= self.l1_table.len() {
            return self.read_from_parent_or_zero(virtual_offset, buf);
        }

        let l1_entry = self.l1_table[l1_idx];
        let l2_table_offset = l1_entry & OFFSET_MASK;

        if l2_table_offset == 0 {
            // L1 entry unallocated -> parent or zeros
            return self.read_from_parent_or_zero(virtual_offset, buf);
        }

        // Look up the L2 entry, using the cache to avoid per-cluster seeks.
        let l2_entry = self.cached_l2_lookup(l2_table_offset, l2_idx)?;

        if l2_entry & COMPRESSED_FLAG != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "QCOW2 compressed clusters not supported",
            ));
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

    /// Look up a single L2 entry, reading and caching the entire L2 table on miss.
    /// `l2_table_offset` is the on-disk byte offset of the L2 table.
    /// `l2_idx` is the index within that table.
    fn cached_l2_lookup(
        &mut self,
        l2_table_offset: u64,
        l2_idx: usize,
    ) -> std::io::Result<u64> {
        // Fast path: table already cached.
        if let Some(table) = self.l2_cache.get(&l2_table_offset) {
            return Ok(table[l2_idx]);
        }

        // Cache miss: read the full L2 table (one cluster worth of u64 entries).
        let l2_entries = self.l2_entries;
        let mut raw = vec![0u8; l2_entries * 8];
        self.file.seek(SeekFrom::Start(l2_table_offset))?;
        self.file.read_exact(&mut raw)?;

        let table: Vec<u64> = raw
            .chunks_exact(8)
            .map(|c| u64::from_be_bytes(c.try_into().unwrap()))
            .collect();

        let entry = table[l2_idx];

        // Evict the entire cache when it reaches the size limit.
        // This is simple and effective: the working set will quickly re-populate.
        if self.l2_cache.len() >= L2_CACHE_MAX_TABLES {
            self.l2_cache.clear();
        }

        self.l2_cache.insert(l2_table_offset, table);

        Ok(entry)
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

        let remaining = (self.disk_size - self.cursor) as usize;
        let to_read = buf.len().min(remaining);
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
        let new_pos = match pos {
            SeekFrom::Start(offset) => offset as i64,
            SeekFrom::End(offset) => self.disk_size as i64 + offset,
            SeekFrom::Current(offset) => self.cursor as i64 + offset,
        };
        if new_pos < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek to negative position",
            ));
        }
        self.cursor = new_pos as u64;
        Ok(self.cursor)
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
        let base_dir = image_path.parent().unwrap_or(std::path::Path::new("."));
        base_dir.join(backing)
    }
}
