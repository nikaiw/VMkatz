//! Native VMRS (Hyper-V Saved State) parser.
//!
//! Reverse-engineered from vmsavedstatedumpprovider.dll.
//! Parses the HyperVStorage key-value format used by .vmrs files
//! to extract guest physical memory (RAM blocks).
//!
//! File layout:
//! - [0..46]: Primary header (magic 0x01282014)
//! - [4096..4142]: Backup header (same format, alternate writes)
//! - [data_offset..]: Data region containing ObjectTable, KeyTables, values

use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::error::{Result, VmkatzError};
use crate::memory::PhysicalMemory;

const VMRS_MAGIC: u32 = 0x01282014;
const HEADER_SIZE: usize = 46;
const BACKUP_HEADER_OFFSET: u64 = 4096;
const RAM_BLOCK_SIZE: usize = 0x100000; // 1 MB

/// Parsed HyperVStorage header (46 bytes).
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct HvsHeader {
    magic: u32,
    crc32: u32,
    sequence: u16,
    version: u32,
    data_alignment: u32,
    data_offset: u64,
    data_size: u64,
    undo_size: u32,
}

/// ObjectTable entry (18 bytes on disk).
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ObjectTableEntry {
    entry_type: u8,
    crc32: u32,
    file_offset: u64,
    size: u32,
    flags: u8,
}

/// GPA memory chunk describing a contiguous physical memory region.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct GpaMemoryChunk {
    start_page_index: u64,
    page_count: u64,
}

/// Hyper-V VMRS memory layer.
pub struct VmrsLayer {
    /// Interior-mutable state for read operations (file + cache).
    inner: RefCell<VmrsInner>,
    /// Parsed header.
    header: HvsHeader,
    /// All object table entries.
    object_entries: Vec<ObjectTableEntry>,
    /// Key-to-value map: full key path → (file_offset, size) of value data.
    key_values: HashMap<String, (u64, u32)>,
    /// RAM block count.
    ram_block_count: u64,
    /// Memory chunks for GPA mapping.
    memory_chunks: Vec<GpaMemoryChunk>,
    /// Total physical memory size in bytes.
    phys_size: u64,
}

struct VmrsInner {
    file: fs::File,
    block_cache: HashMap<u64, Vec<u8>>,
    cache_limit: usize,
}

impl VmrsLayer {
    /// Open a .vmrs file and parse its structure.
    pub fn open(path: &Path) -> Result<Self> {
        let mut file = fs::File::open(path)?;
        let file_size = crate::utils::file_size(&mut file)?;

        if file_size < BACKUP_HEADER_OFFSET + HEADER_SIZE as u64 {
            return Err(VmkatzError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "File too small for VMRS format",
            )));
        }

        // Read and validate both header copies
        let header = Self::read_header(&mut file)?;
        log::info!(
            "VMRS: version={:#x}, alignment={:#x}, data_offset={:#x}, data_size={:#x}",
            header.version,
            header.data_alignment,
            header.data_offset,
            header.data_size
        );

        let mut layer = VmrsLayer {
            inner: RefCell::new(VmrsInner {
                file,
                block_cache: HashMap::new(),
                cache_limit: 64,
            }),
            header,
            object_entries: Vec::new(),
            key_values: HashMap::new(),
            ram_block_count: 0,
            memory_chunks: Vec::new(),
            phys_size: 0,
        };

        // Parse the data region
        layer.parse_data_region()?;

        // Determine RAM layout
        layer.build_memory_layout()?;

        log::info!(
            "VMRS: {} RAM blocks, {} memory chunks, {:.0} MB physical",
            layer.ram_block_count,
            layer.memory_chunks.len(),
            layer.phys_size as f64 / (1024.0 * 1024.0)
        );

        Ok(layer)
    }

    /// Read and validate the 46-byte header from both copies.
    fn read_header(file: &mut fs::File) -> Result<HvsHeader> {
        let primary = Self::read_header_at(file, 0);
        let backup = Self::read_header_at(file, BACKUP_HEADER_OFFSET);

        match (primary, backup) {
            (Ok(p), Ok(b)) => {
                // Both valid — pick the one with higher sequence (with wrap-around)
                let p_seq = p.sequence;
                let b_seq = b.sequence;
                if p_seq == b_seq.wrapping_add(1) {
                    Ok(p)
                } else if b_seq == p_seq.wrapping_add(1) {
                    Ok(b)
                } else if p_seq == b_seq {
                    // Equal sequence — both are valid, prefer primary
                    Ok(p)
                } else {
                    // Large gap — prefer the one with higher sequence
                    if p_seq > b_seq { Ok(p) } else { Ok(b) }
                }
            }
            (Ok(p), Err(_)) => Ok(p),
            (Err(_), Ok(b)) => Ok(b),
            (Err(e), Err(_)) => Err(e),
        }
    }

    fn read_header_at(file: &mut fs::File, offset: u64) -> Result<HvsHeader> {
        file.seek(SeekFrom::Start(offset))?;
        let mut buf = [0u8; HEADER_SIZE];
        file.read_exact(&mut buf)?;

        let magic = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        if magic != VMRS_MAGIC {
            return Err(VmkatzError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Bad VMRS magic: {:#x} (expected {:#x})", magic, VMRS_MAGIC),
            )));
        }

        let stored_crc = u32::from_le_bytes(buf[4..8].try_into().unwrap());

        // Verify CRC32: zero out the CRC field, compute over all 46 bytes
        let mut crc_buf = buf;
        crc_buf[4..8].fill(0);
        let computed_crc = hvs_crc32(&crc_buf);
        if stored_crc != computed_crc {
            return Err(VmkatzError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "VMRS header CRC mismatch at offset {:#x}: stored={:#x} computed={:#x}",
                    offset, stored_crc, computed_crc
                ),
            )));
        }

        let sequence = u16::from_le_bytes(buf[8..10].try_into().unwrap());
        let version = u32::from_le_bytes(buf[10..14].try_into().unwrap());
        let data_alignment = u32::from_le_bytes(buf[22..26].try_into().unwrap());
        let data_offset = u64::from_le_bytes(buf[26..34].try_into().unwrap());
        let data_size = u64::from_le_bytes(buf[34..42].try_into().unwrap());
        let undo_size = u32::from_le_bytes(buf[42..46].try_into().unwrap());

        // Validate alignment (0x1000 to 0x10000)
        if !(0x1000..=0x10000).contains(&data_alignment) {
            return Err(VmkatzError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Bad data_alignment: {:#x}", data_alignment),
            )));
        }

        // Validate version
        if version < 0x100 {
            return Err(VmkatzError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("VMRS version too low: {:#x}", version),
            )));
        }

        Ok(HvsHeader {
            magic,
            crc32: stored_crc,
            sequence,
            version,
            data_alignment,
            data_offset,
            data_size,
            undo_size,
        })
    }

    /// Parse the data region: ObjectTable → KeyTables → key-value map.
    fn parse_data_region(&mut self) -> Result<()> {
        let data_start = self.header.data_offset;
        if data_start == 0 {
            return Err(VmkatzError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "VMRS data_offset is 0 — empty or corrupt file",
            )));
        }

        // Read the root ObjectTable from data_start
        self.parse_object_table(data_start)?;

        // Now parse all KeyTables referenced by the ObjectTable
        self.parse_key_tables()?;

        Ok(())
    }

    /// Parse the ObjectTable at the given file offset.
    fn parse_object_table(&mut self, offset: u64) -> Result<()> {
        // Read ObjectTable header (8 bytes): [0:4] flags, [4:8] entry_count
        let mut inner = self.inner.borrow_mut();
        inner.file.seek(SeekFrom::Start(offset))?;
        let mut hdr = [0u8; 8];
        inner.file.read_exact(&mut hdr)?;

        let entry_count = u32::from_le_bytes(hdr[4..8].try_into().unwrap()) as usize;
        if entry_count > 100_000 {
            return Err(VmkatzError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("ObjectTable entry count too large: {}", entry_count),
            )));
        }

        log::debug!("VMRS: ObjectTable at {:#x} with {} entries", offset, entry_count);

        // Read entries (18 bytes each)
        let entries_size = entry_count * 18;
        let mut entries_buf = vec![0u8; entries_size];
        inner.file.read_exact(&mut entries_buf)?;

        self.object_entries.clear();
        for i in 0..entry_count {
            let e = &entries_buf[i * 18..(i + 1) * 18];
            let entry = ObjectTableEntry {
                entry_type: e[0],
                crc32: u32::from_le_bytes(e[1..5].try_into().unwrap()),
                file_offset: u64::from_le_bytes(e[5..13].try_into().unwrap()),
                size: u32::from_le_bytes(e[13..17].try_into().unwrap()),
                flags: e[17],
            };
            // Only store non-empty entries
            if entry.entry_type != 0 || entry.file_offset != 0 || entry.size != 0 {
                self.object_entries.push(entry);
            }
        }

        log::debug!("VMRS: {} non-empty object entries", self.object_entries.len());
        Ok(())
    }

    /// Parse all KeyTables referenced by ObjectTable entries (type=2).
    fn parse_key_tables(&mut self) -> Result<()> {
        // Collect key table entries (type 2) and other data entries
        let key_table_entries: Vec<ObjectTableEntry> = self
            .object_entries
            .iter()
            .filter(|e| e.entry_type == 2)
            .cloned()
            .collect();

        // Also collect type 1 entries (these reference ObjectTable sub-tables or data)
        let _data_entries: Vec<ObjectTableEntry> = self
            .object_entries
            .iter()
            .filter(|e| e.entry_type == 1 && e.file_offset > 0 && e.size > 0)
            .cloned()
            .collect();

        // Parse each key table and build the key-value map
        for kt_entry in &key_table_entries {
            if kt_entry.size < 10 || kt_entry.file_offset == 0 {
                continue;
            }
            if let Err(e) = self.parse_single_key_table(kt_entry) {
                log::debug!(
                    "VMRS: Failed to parse KeyTable at {:#x}: {}",
                    kt_entry.file_offset,
                    e
                );
            }
        }

        // If no keys found via KeyTable parsing, try brute-force scan
        if self.key_values.is_empty() {
            log::debug!("VMRS: No keys found via KeyTable parsing, trying scan approach");
            self.scan_for_ram_blocks()?;
        }

        Ok(())
    }

    /// Parse a single KeyTable and extract key-value mappings.
    fn parse_single_key_table(&mut self, entry: &ObjectTableEntry) -> Result<()> {
        let data = self.read_file_bytes(entry.file_offset, entry.size as usize)?;
        if data.len() < 10 {
            return Ok(());
        }

        // KeyTable header: [0:2] type=2, [2:4] kt_index, [4:10] reserved
        let kt_type = u16::from_le_bytes(data[0..2].try_into().unwrap());
        if kt_type != 2 {
            log::debug!(
                "VMRS: KeyTable at {:#x} has unexpected type {}",
                entry.file_offset,
                kt_type
            );
        }
        let _kt_index = u16::from_le_bytes(data[2..4].try_into().unwrap());

        // Walk entries starting at offset 10
        self.walk_key_entries(&data, 10, entry.file_offset, "")?;

        Ok(())
    }

    /// Walk key entries in a flat array, building the key path map.
    fn walk_key_entries(
        &mut self,
        data: &[u8],
        start: usize,
        base_file_offset: u64,
        parent_path: &str,
    ) -> Result<()> {
        let total = data.len();
        let mut offset = start;

        while offset + 21 < total {
            // Entry header
            let entry_type = data[offset];
            let _flags = data[offset + 1];
            let entry_total_size =
                u32::from_le_bytes(data[offset + 2..offset + 6].try_into().unwrap()) as usize;

            if entry_total_size == 0 {
                break;
            }
            if offset + entry_total_size > total {
                break;
            }

            // Skip free entries (type 1 with name_length 0)
            let name_length = data[offset + 20] as usize;

            if entry_type == 1 && name_length == 0 {
                // Free entry — skip
                offset += entry_total_size;
                continue;
            }

            // Extract key name
            if offset + 21 + name_length > total {
                break;
            }
            let key_name = if name_length > 0 {
                String::from_utf8_lossy(&data[offset + 21..offset + 21 + name_length])
                    .trim_end_matches('\0')
                    .to_string()
            } else {
                String::new()
            };

            if !key_name.is_empty() {
                let full_path = if parent_path.is_empty() {
                    key_name.clone()
                } else {
                    format!("{}/{}", parent_path, key_name)
                };

                // Extract value info based on type
                match entry_type {
                    3 | 4 | 5 | 9 => {
                        // Fixed-size value (8 bytes) at entry offset 12
                        // Store as inline: the value is at base_file_offset + offset + 12
                        self.key_values.insert(
                            full_path.clone(),
                            (base_file_offset + offset as u64 + 12, 8),
                        );
                    }
                    6 | 7 => {
                        // Variable-size value
                        let value_size_offset = offset + 21 + name_length;
                        if value_size_offset + 4 <= total {
                            let value_size = u32::from_le_bytes(
                                data[value_size_offset..value_size_offset + 4]
                                    .try_into()
                                    .unwrap(),
                            );
                            let value_data_offset = value_size_offset + 4;
                            if value_size > 0 {
                                self.key_values.insert(
                                    full_path.clone(),
                                    (
                                        base_file_offset + value_data_offset as u64,
                                        value_size,
                                    ),
                                );
                            }
                        }
                    }
                    8 => {
                        // 4-byte value at entry offset 12
                        self.key_values.insert(
                            full_path.clone(),
                            (base_file_offset + offset as u64 + 12, 4),
                        );
                    }
                    _ => {}
                }

                // Check for child key table reference
                // Bytes [6:8] = child count, [8:12] = child object table entry offset
                let child_obj_ref = u32::from_le_bytes(
                    data[offset + 8..offset + 12].try_into().unwrap(),
                );
                if child_obj_ref > 0 {
                    // Try to find and parse the child key table
                    if let Some(child_entry) = self.find_object_entry(child_obj_ref) {
                        let child_data = self.read_file_bytes(
                            child_entry.file_offset,
                            child_entry.size as usize,
                        );
                        if let Ok(child_data) = child_data {
                            let _ = self.walk_key_entries(
                                &child_data,
                                10,
                                child_entry.file_offset,
                                &full_path,
                            );
                        }
                    }
                }

                log::trace!("VMRS key: {} (type={}, size={})", full_path, entry_type, entry_total_size);
            }

            offset += entry_total_size;
        }

        Ok(())
    }

    /// Find an ObjectTableEntry by some reference (try as index, then as offset).
    fn find_object_entry(&self, reference: u32) -> Option<ObjectTableEntry> {
        // Try as index first
        if (reference as usize) < self.object_entries.len() {
            let e = &self.object_entries[reference as usize];
            if e.file_offset > 0 && e.size > 0 {
                return Some(e.clone());
            }
        }
        // Try to find by matching file offset
        self.object_entries
            .iter()
            .find(|e| e.file_offset == reference as u64 && e.size > 0)
            .cloned()
    }

    /// Brute-force scan: search the data region for RAM block patterns.
    /// This is a fallback when KeyTable parsing doesn't find the keys.
    fn scan_for_ram_blocks(&mut self) -> Result<()> {
        log::info!("VMRS: Scanning data region for RAM blocks...");

        // We need to scan the object table entries for large data blobs
        // that look like RAM blocks (size >= some threshold, <= 1MB)
        let data_entries: Vec<ObjectTableEntry> = self
            .object_entries
            .iter()
            .filter(|e| {
                (e.entry_type == 6 || e.entry_type == 7 || e.entry_type == 3)
                    && e.file_offset > 0
                    && e.size > 0
            })
            .cloned()
            .collect();

        // Try to read the partition state blob
        for entry in &data_entries {
            if entry.size > 64 && entry.size < RAM_BLOCK_SIZE as u32 {
                // Check if this looks like partition state
                let peek = self.read_file_bytes(entry.file_offset, 16.min(entry.size as usize))?;
                log::trace!(
                    "VMRS: Data entry type={} at {:#x} size={} peek={:02x?}",
                    entry.entry_type,
                    entry.file_offset,
                    entry.size,
                    &peek[..peek.len().min(16)]
                );
            }
        }

        // Count potential RAM blocks (entries with size <= 1MB but > 0)
        let ram_candidates: Vec<&ObjectTableEntry> = self
            .object_entries
            .iter()
            .filter(|e| e.size > 0 && e.size as usize <= RAM_BLOCK_SIZE && e.file_offset > 0)
            .collect();

        if !ram_candidates.is_empty() {
            log::info!(
                "VMRS: Found {} potential RAM block entries via scan",
                ram_candidates.len()
            );
        }

        Ok(())
    }

    /// Build the memory layout from parsed keys.
    fn build_memory_layout(&mut self) -> Result<()> {
        // Determine the key path prefix based on version
        let prefix = if self.header.version > 0x500 {
            "/savedstate/"
        } else {
            "" // Legacy format, prefix varies
        };

        // Count RAM blocks by probing keys
        let mut block_count = 0u64;
        let format_modern = format!("{}RamBlock", prefix);
        for key in self.key_values.keys() {
            if key.starts_with(&format_modern) || key.contains("RamBlock") {
                block_count += 1;
            }
        }

        if block_count == 0 {
            // Try to determine from partition state or just count large entries
            block_count = self
                .object_entries
                .iter()
                .filter(|e| e.size > 0 && e.size as usize <= RAM_BLOCK_SIZE && e.entry_type != 0)
                .count() as u64;
            if block_count > 10 {
                // Subtract a few for non-RAM entries (partition state, etc.)
                block_count = block_count.saturating_sub(5);
            }
        }

        self.ram_block_count = block_count;

        // Build simple identity mapping for now
        // Each block = 1MB = 256 pages (4096 bytes each)
        let pages_per_block = (RAM_BLOCK_SIZE / 4096) as u64;
        if block_count > 0 {
            self.memory_chunks.push(GpaMemoryChunk {
                start_page_index: 0,
                page_count: block_count * pages_per_block,
            });
            self.phys_size = block_count * RAM_BLOCK_SIZE as u64;
        }

        Ok(())
    }

    /// Read bytes from the file at a given offset.
    fn read_file_bytes(&self, offset: u64, size: usize) -> Result<Vec<u8>> {
        let mut inner = self.inner.borrow_mut();
        inner.file.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; size];
        inner.file.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Read and decompress a RAM block by index.
    fn read_ram_block(&self, block_index: u64) -> Result<Vec<u8>> {
        // Check cache first
        if let Some(cached) = self.inner.borrow().block_cache.get(&block_index) {
            return Ok(cached.clone());
        }

        // Try both key formats
        let key_paths = [
            format!("savedstate/RamBlock{}", block_index),
            format!("/savedstate/RamBlock{}", block_index),
            format!("RamBlock{}", block_index),
            format!("savedstate/RamMemoryBlock{}", block_index),
            format!("/savedstate/RamMemoryBlock{}", block_index),
        ];

        let mut value_info = None;
        for key in &key_paths {
            if let Some(&info) = self.key_values.get(key.as_str()) {
                value_info = Some(info);
                break;
            }
        }

        // If no key found, try sequential object table entries
        // (RAM blocks may be stored sequentially starting from some index)
        if value_info.is_none() {
            // Fallback: try to find the block by index in object entries
            // that have data type and appropriate size
            let ram_entries: Vec<&ObjectTableEntry> = self
                .object_entries
                .iter()
                .filter(|e| {
                    e.size > 0
                        && e.size as usize <= RAM_BLOCK_SIZE
                        && e.file_offset > 0
                        && e.entry_type != 0
                        && e.entry_type != 2  // not a key table
                        && e.entry_type != 4  // not free
                })
                .collect();

            if (block_index as usize) < ram_entries.len() {
                let entry = ram_entries[block_index as usize];
                value_info = Some((entry.file_offset, entry.size));
            }
        }

        let (file_offset, compressed_size) = value_info.ok_or_else(|| {
            VmkatzError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("RAM block {} not found", block_index),
            ))
        })?;

        // Read raw (potentially compressed) data
        let raw_data = self.read_file_bytes(file_offset, compressed_size as usize)?;

        // Decompress if needed
        let block = if compressed_size as usize == RAM_BLOCK_SIZE {
            // Uncompressed — direct copy
            raw_data
        } else {
            // Compressed — use VmCompressUnpack
            vm_compress_unpack(&raw_data)?
        };

        // Cache the result
        let mut inner = self.inner.borrow_mut();
        if inner.block_cache.len() >= inner.cache_limit {
            inner.block_cache.clear();
        }
        inner.block_cache.insert(block_index, block.clone());

        Ok(block)
    }
}

impl PhysicalMemory for VmrsLayer {
    fn read_phys(&self, phys_addr: u64, buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }

        let mut remaining = buf;
        let mut addr = phys_addr;

        while !remaining.is_empty() {
            let block_index = addr / RAM_BLOCK_SIZE as u64;
            let block_offset = (addr % RAM_BLOCK_SIZE as u64) as usize;
            let available = RAM_BLOCK_SIZE - block_offset;
            let to_copy = remaining.len().min(available);

            match self.read_ram_block(block_index) {
                Ok(block) => {
                    let end = (block_offset + to_copy).min(block.len());
                    if block_offset < block.len() {
                        let copy_len = end - block_offset;
                        remaining[..copy_len].copy_from_slice(&block[block_offset..end]);
                        if copy_len < to_copy {
                            remaining[copy_len..to_copy].fill(0);
                        }
                    } else {
                        remaining[..to_copy].fill(0);
                    }
                }
                Err(_) => {
                    // Block not available — fill with zeros
                    remaining[..to_copy].fill(0);
                }
            }

            remaining = &mut remaining[to_copy..];
            addr += to_copy as u64;
        }

        Ok(())
    }

    fn phys_size(&self) -> u64 {
        self.phys_size
    }
}

/// CRC32 implementation matching HvsComputeCrc32 (standard CRC32).
fn hvs_crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Decompress a VmCompressUnpack-encoded buffer into a 1MB block.
///
/// Format: sequence of tagged pages:
/// - 0xFFFFFFFF: end marker
/// - 0xFFFFFFFE: fill 1 page (4KB) with 8-byte repeating pattern
/// - 0xFFFFFFFD: fill N pages with pattern (read count, then pattern)
/// - 0xFFFFFFFC: variable page size
/// - other: compressed_size — if 4096, raw copy; else LZNT1 decompress
fn vm_compress_unpack(data: &[u8]) -> Result<Vec<u8>> {
    let mut output = vec![0u8; RAM_BLOCK_SIZE];
    let mut out_offset = 0usize;
    let mut in_offset = 0usize;

    while in_offset + 4 <= data.len() && out_offset < RAM_BLOCK_SIZE {
        let tag = u32::from_le_bytes(data[in_offset..in_offset + 4].try_into().unwrap());
        in_offset += 4;

        match tag {
            0xFFFFFFFF => {
                // End marker
                break;
            }
            0xFFFFFFFE => {
                // Fill 1 page with 8-byte pattern
                if in_offset + 8 > data.len() {
                    break;
                }
                let pattern = &data[in_offset..in_offset + 8];
                in_offset += 8;
                let page_end = (out_offset + 4096).min(RAM_BLOCK_SIZE);
                while out_offset + 8 <= page_end {
                    output[out_offset..out_offset + 8].copy_from_slice(pattern);
                    out_offset += 8;
                }
                // Handle remainder
                while out_offset < page_end {
                    output[out_offset] = pattern[(out_offset - (page_end - 4096)) % 8];
                    out_offset += 1;
                }
            }
            0xFFFFFFFD => {
                // Fill N pages with pattern
                if in_offset + 12 > data.len() {
                    break;
                }
                let count =
                    u32::from_le_bytes(data[in_offset..in_offset + 4].try_into().unwrap())
                        as usize;
                in_offset += 4;
                let pattern = &data[in_offset..in_offset + 8];
                in_offset += 8;
                for _ in 0..count {
                    if out_offset >= RAM_BLOCK_SIZE {
                        break;
                    }
                    let page_end = (out_offset + 4096).min(RAM_BLOCK_SIZE);
                    while out_offset + 8 <= page_end {
                        output[out_offset..out_offset + 8].copy_from_slice(pattern);
                        out_offset += 8;
                    }
                    while out_offset < page_end {
                        output[out_offset] = pattern[(out_offset - (page_end - 4096)) % 8];
                        out_offset += 1;
                    }
                }
            }
            0xFFFFFFFC => {
                // Variable page size: read page_size, then compressed data
                if in_offset + 4 > data.len() {
                    break;
                }
                let page_size = u32::from_le_bytes(
                    data[in_offset..in_offset + 4].try_into().unwrap(),
                ) as usize;
                in_offset += 4;
                if page_size == 0 || in_offset + page_size > data.len() {
                    break;
                }
                // Decompress with LZNT1
                let decompressed = lznt1_decompress(&data[in_offset..in_offset + page_size], 4096)?;
                let copy_len = decompressed.len().min(RAM_BLOCK_SIZE - out_offset);
                output[out_offset..out_offset + copy_len]
                    .copy_from_slice(&decompressed[..copy_len]);
                out_offset += 4096; // Always advance by page size
                in_offset += page_size;
            }
            compressed_size => {
                let compressed_size = compressed_size as usize;
                if compressed_size == 4096 {
                    // Uncompressed page — raw copy
                    if in_offset + 4096 > data.len() {
                        break;
                    }
                    let copy_len = 4096.min(RAM_BLOCK_SIZE - out_offset);
                    output[out_offset..out_offset + copy_len]
                        .copy_from_slice(&data[in_offset..in_offset + copy_len]);
                    out_offset += 4096;
                    in_offset += 4096;
                } else if compressed_size > 0 && compressed_size < 4096 {
                    // LZNT1 compressed page
                    if in_offset + compressed_size > data.len() {
                        break;
                    }
                    let decompressed =
                        lznt1_decompress(&data[in_offset..in_offset + compressed_size], 4096)?;
                    let copy_len = decompressed.len().min(RAM_BLOCK_SIZE - out_offset);
                    output[out_offset..out_offset + copy_len]
                        .copy_from_slice(&decompressed[..copy_len]);
                    out_offset += 4096;
                    in_offset += compressed_size;
                } else {
                    // Invalid tag
                    log::warn!("VMRS: Invalid compression tag {:#x} at offset {}", tag, in_offset - 4);
                    break;
                }
            }
        }
    }

    Ok(output)
}

/// LZNT1 decompression (Windows RtlDecompressBuffer algorithm 2/COMPRESSION_FORMAT_LZNT1).
///
/// LZNT1 format:
/// - Data is split into chunks, each starting with a 2-byte header
/// - Chunk header: bit 15 = compressed flag, bits 0-11 = chunk data size - 1
/// - Uncompressed chunk: raw bytes follow
/// - Compressed chunk: mix of flag bytes and literal/backreference tokens
fn lznt1_decompress(input: &[u8], max_output: usize) -> Result<Vec<u8>> {
    let mut output = Vec::with_capacity(max_output);
    let mut in_pos = 0;

    while in_pos + 2 <= input.len() && output.len() < max_output {
        let chunk_header = u16::from_le_bytes(input[in_pos..in_pos + 2].try_into().unwrap());
        in_pos += 2;

        if chunk_header == 0 {
            break;
        }

        let chunk_size = ((chunk_header & 0x0FFF) + 1) as usize;
        let is_compressed = (chunk_header & 0x8000) != 0;

        if in_pos + chunk_size > input.len() {
            break;
        }

        if !is_compressed {
            // Uncompressed chunk
            let copy_len = chunk_size.min(max_output - output.len());
            output.extend_from_slice(&input[in_pos..in_pos + copy_len]);
            in_pos += chunk_size;
        } else {
            // Compressed chunk
            let chunk_end = in_pos + chunk_size;
            let chunk_start_output = output.len();

            while in_pos < chunk_end && output.len() < max_output {
                if in_pos >= chunk_end {
                    break;
                }
                let flags = input[in_pos];
                in_pos += 1;

                for bit in 0..8 {
                    if in_pos >= chunk_end || output.len() >= max_output {
                        break;
                    }

                    if (flags >> bit) & 1 == 0 {
                        // Literal byte
                        output.push(input[in_pos]);
                        in_pos += 1;
                    } else {
                        // Backreference
                        if in_pos + 2 > chunk_end {
                            in_pos = chunk_end;
                            break;
                        }
                        let ref_token =
                            u16::from_le_bytes(input[in_pos..in_pos + 2].try_into().unwrap());
                        in_pos += 2;

                        // Calculate displacement and length bits based on output position
                        // within the current chunk
                        let pos_in_chunk = output.len() - chunk_start_output;
                        let displacement_bits = lznt1_displacement_bits(pos_in_chunk);
                        let length_bits = 16 - displacement_bits;
                        let length_mask = (1u16 << length_bits) - 1;

                        let displacement = ((ref_token >> length_bits) + 1) as usize;
                        let length = ((ref_token & length_mask) + 3) as usize;

                        // Copy from back-reference
                        for _ in 0..length {
                            if output.len() >= max_output {
                                break;
                            }
                            if displacement > output.len() {
                                output.push(0);
                            } else {
                                let byte = output[output.len() - displacement];
                                output.push(byte);
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(output)
}

/// LZNT1 displacement bits for a given position in the uncompressed chunk.
/// Per MS-XCA §2.4.1.1.1: 4 bits up to pos 15, then +1 bit each time pos
/// reaches the next power of two (16, 32, 64, ...).
fn lznt1_displacement_bits(pos_in_chunk: usize) -> u32 {
    let mut bits = 4u32;
    let mut threshold = 16usize;
    while threshold <= pos_in_chunk && bits < 12 {
        bits += 1;
        threshold <<= 1;
    }
    bits
}

/// Check if a file starts with the VMRS magic.
pub fn is_vmrs_file(path: &Path) -> bool {
    let Ok(mut f) = fs::File::open(path) else {
        return false;
    };
    let mut buf = [0u8; 4];
    if f.read_exact(&mut buf).is_err() {
        return false;
    }
    u32::from_le_bytes(buf) == VMRS_MAGIC
}
