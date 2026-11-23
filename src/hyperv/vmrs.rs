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
//!
//! Each RamBlock decompresses (XPRESS) to a full 1 MB page. Two subtleties matter
//! for virtual-address translation:
//!
//! 1. RamBlock references live in several KeyTable copies; some appear only in the
//!    inline/early tables, so all must be swept (`parse_ramblock_references`).
//! 2. The guest GPA space has a low MMIO gap: RAM under it is remapped above 4 GB,
//!    so read_phys maps GPA -> RAM offset across the gap (`gpa_to_ram_offset`).

use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::error::{Result, VmkatzError};
use crate::memory::PhysicalMemory;
use crate::utils::{u16_le, u32_le, u64_le};

mod budget;
mod compression;
#[cfg(test)]
mod memory_tests;
mod metadata;
mod scan;

use compression::vm_compress_unpack;

const VMRS_MAGIC: u32 = 0x01282014;
const HEADER_SIZE: usize = 46;
const BACKUP_HEADER_OFFSET: u64 = 4096;
const RAM_BLOCK_SIZE: usize = 0x100000; // 1 MB

/// Hyper-V Gen1 low MMIO gap: RAM that would sit at [0xF800_0000, 0x1_0000_0000)
/// is remapped above 4 GB. Applied only when total RAM exceeds the gap base.
const MMIO_GAP_BASE: u64 = 0xF800_0000;
const MMIO_GAP_END: u64 = 0x1_0000_0000;

fn advance_address(address: u64, byte_count: usize) -> Result<u64> {
    let byte_count =
        u64::try_from(byte_count).map_err(|_| VmkatzError::UnmappablePhysical(address))?;
    address
        .checked_add(byte_count)
        .ok_or(VmkatzError::UnmappablePhysical(address))
}

/// RamBlock reference sweep: scan chunk size and the overlap padding that keeps
/// each entry (21-byte header + name + 12-byte reference) within one buffer.
const SWEEP_CHUNK: usize = 32 * 1024 * 1024;
const SWEEP_PAD: usize = 64;

/// Parsed HyperVStorage header (46 bytes). `magic` and the CRC32 are validated
/// at parse time via locals, so they are not stored here.
#[derive(Debug, Clone)]
struct HvsHeader {
    sequence: u16,
    version: u32,
    data_alignment: u32,
    data_offset: u64,
    data_size: u64,
}

/// ObjectTable entry (18 bytes on disk).
#[derive(Debug, Clone)]
struct ObjectTableEntry {
    entry_type: u8,
    #[expect(dead_code, reason = "on-disk entry CRC, not verified yet")]
    crc32: u32,
    file_offset: u64,
    size: u32,
    #[expect(dead_code, reason = "on-disk entry flags, unused")]
    flags: u8,
}

/// GPA memory chunk describing a contiguous physical memory region.
#[derive(Debug, Clone)]
struct GpaMemoryChunk {
    #[expect(
        dead_code,
        reason = "mapping GPA identité: réservé à un mapping fin ultérieur"
    )]
    start_page_index: u64,
    #[expect(
        dead_code,
        reason = "mapping GPA identité: réservé à un mapping fin ultérieur"
    )]
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
    key_bytes: usize,
    /// RAM block count.
    ram_block_count: u64,
    /// Memory chunks for GPA mapping.
    memory_chunks: Vec<GpaMemoryChunk>,
    /// Total physical (GPA) address span in bytes, including any MMIO gap.
    phys_size: u64,
    /// Base GPA of the low MMIO gap (0 = no gap; RAM is a flat identity map).
    mmio_gap_base: u64,
    /// Size of the low MMIO gap in bytes. RAM at GPA >= `mmio_gap_base +
    /// mmio_gap_size` is stored at file RAM-offset `gpa - mmio_gap_size`.
    mmio_gap_size: u64,
    /// Set once a RAM block read failed and was zero-filled, to warn a single
    /// time instead of silently presenting missing memory as valid zeros.
    read_masked: std::cell::Cell<bool>,
}

struct VmrsInner {
    file: fs::File,
    cache: BlockCache,
}

/// One cached decompressed RAM block plus its LRU links (by block index).
struct CacheNode {
    data: Vec<u8>,
    newer: Option<u64>, // toward the head (most-recently used)
    older: Option<u64>, // toward the tail (least-recently used)
}

/// Intrusive O(1) LRU cache of decompressed RAM blocks. FIFO evicted the hot
/// working set — the page tables the LSASS scan re-walks constantly — forcing
/// repeated decompression; LRU keeps them resident under the same block budget.
struct BlockCache {
    map: HashMap<u64, CacheNode>,
    head: Option<u64>, // most-recently used
    tail: Option<u64>, // least-recently used
    limit: usize,
}

impl BlockCache {
    fn with_limit(limit: usize) -> Self {
        Self {
            map: HashMap::new(),
            head: None,
            tail: None,
            limit,
        }
    }

    /// Unlink node `k` from the LRU list (leaves it in `map`).
    fn detach(&mut self, k: u64) {
        let Some(n) = self.map.get(&k) else {
            return;
        };
        let (newer, older) = (n.newer, n.older);
        match newer {
            Some(x) => {
                if let Some(node) = self.map.get_mut(&x) {
                    node.older = older;
                }
            }
            None => self.head = older,
        }
        match older {
            Some(x) => {
                if let Some(node) = self.map.get_mut(&x) {
                    node.newer = newer;
                }
            }
            None => self.tail = newer,
        }
    }

    /// Link node `k` (already in `map`) at the head (most-recently used).
    fn push_front(&mut self, k: u64) {
        if !self.map.contains_key(&k) {
            return;
        }
        let old_head = self.head;
        if let Some(n) = self.map.get_mut(&k) {
            n.newer = None;
            n.older = old_head;
        }
        if let Some(h) = old_head {
            if let Some(node) = self.map.get_mut(&h) {
                node.newer = Some(k);
            }
        }
        self.head = Some(k);
        if self.tail.is_none() {
            self.tail = Some(k);
        }
    }

    /// Look up a block and mark it most-recently used.
    fn get(&mut self, k: u64) -> Option<&[u8]> {
        if !self.map.contains_key(&k) {
            return None;
        }
        if self.head != Some(k) {
            self.detach(k);
            self.push_front(k);
        }
        self.map.get(&k).map(|node| node.data.as_slice())
    }

    fn evict_to_limit(&mut self) {
        while self.map.len() > self.limit {
            let Some(t) = self.tail else { break };
            self.detach(t);
            self.map.remove(&t);
        }
    }

    /// Insert (or refresh) a block as most-recently used, evicting the LRU tail.
    fn insert(&mut self, k: u64, data: Vec<u8>) {
        if self.limit == 0 {
            return;
        }
        if let Some(n) = self.map.get_mut(&k) {
            n.data = data;
            if self.head != Some(k) {
                self.detach(k);
                self.push_front(k);
            }
            return;
        }
        self.map.insert(
            k,
            CacheNode {
                data,
                newer: None,
                older: None,
            },
        );
        self.push_front(k);
        self.evict_to_limit();
    }

    fn set_limit(&mut self, limit: usize) {
        self.limit = limit;
        self.evict_to_limit();
    }
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

        let mut layer = Self {
            inner: RefCell::new(VmrsInner {
                file,
                cache: BlockCache::with_limit(budget::cache_blocks()),
            }),
            header,
            object_entries: Vec::new(),
            key_values: HashMap::new(),
            key_bytes: 0,
            ram_block_count: 0,
            memory_chunks: Vec::new(),
            phys_size: 0,
            mmio_gap_base: 0,
            mmio_gap_size: 0,
            read_masked: std::cell::Cell::new(false),
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

        let magic = u32_le(&buf, 0);
        if magic != VMRS_MAGIC {
            return Err(VmkatzError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Bad VMRS magic: {magic:#x} (expected {VMRS_MAGIC:#x})"),
            )));
        }

        let stored_crc = u32_le(&buf, 4);

        // Verify CRC32: zero out the CRC field, compute over all 46 bytes
        let mut crc_buf = buf;
        crc_buf[4..8].fill(0);
        let computed_crc = hvs_crc32(&crc_buf);
        if stored_crc != computed_crc {
            return Err(VmkatzError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "VMRS header CRC mismatch at offset {offset:#x}: stored={stored_crc:#x} computed={computed_crc:#x}"
                ),
            )));
        }

        let sequence = u16_le(&buf, 8);
        let version = u32_le(&buf, 10);
        let data_alignment = u32_le(&buf, 22);
        let data_offset = u64_le(&buf, 26);
        let data_size = u64_le(&buf, 34);

        // Validate alignment (0x1000 to 0x10000)
        if !(0x1000..=0x10000).contains(&data_alignment) {
            return Err(VmkatzError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Bad data_alignment: {data_alignment:#x}"),
            )));
        }

        // Validate version
        if version < 0x100 {
            return Err(VmkatzError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("VMRS version too low: {version:#x}"),
            )));
        }

        Ok(HvsHeader {
            sequence,
            version,
            data_alignment,
            data_offset,
            data_size,
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

        // Read the root ObjectTable from data_start. Some VMRS versions (e.g.
        // 0x400) put a root superblock at data_offset instead of an ObjectTable,
        // so this can fail or yield nothing — fall back to scanning the whole
        // data region for ObjectTables (header [flags:4][count:4] + CRC-valid
        // 18-byte entries).
        match self.parse_object_table(data_start) {
            Ok(()) if !self.object_entries.is_empty() => {}
            Ok(()) => {
                log::debug!("VMRS: no entries at data_offset, scanning for ObjectTables");
                self.scan_object_tables()?;
            }
            Err(e) if e.is_resource_limit() => return Err(e),
            Err(e) => {
                log::debug!("VMRS: ObjectTable at data_offset unusable ({e}), scanning");
                self.scan_object_tables()?;
            }
        }

        // Now parse all KeyTables referenced by the ObjectTable
        self.parse_key_tables()?;

        // Recover RamBlocks not referenced by any ObjectTable (see the fn doc).
        self.parse_ramblock_references()?;

        Ok(())
    }

    /// Recover every `RamBlock<N>` reference by sweeping the whole file.
    ///
    /// The low-memory leaf (RamBlock0..15) and ~200 scattered indices live only in
    /// KeyTables not referenced by any ObjectTable (inline, near the file start, or
    /// backup copies); without them low GPA memory — the kernel page tables backing
    /// KUSER_SHARED_DATA — is absent and VA translation fails. So scan for
    /// `RamBlock<N>` entries and resolve each in place rather than locating every
    /// KeyTable header. A RamBlock is a reference entry (type 7, flag bit0) whose
    /// NUL-terminated name is followed by `{ u32 size; u64 file_offset }` (see
    /// the KeyTable parser). Strict checks reject coincidental "RamBlock"
    /// bytes in compressed page data; inserts keep the first valid reference.
    fn parse_ramblock_references(&mut self) -> Result<()> {
        let file_size = {
            let mut inner = self.inner.borrow_mut();
            crate::utils::file_size(&mut inner.file)?
        };
        let before = self.key_values.len();
        let needle = b"RamBlock";
        let finder = memchr::memmem::Finder::new(needle);

        // Chunked scan with padding so each match's full entry (21-byte header
        // before the name, plus name and 12-byte reference after) is in-buffer.
        let mut start = 0u64;
        while start < file_size {
            let lo = start.saturating_sub(SWEEP_PAD as u64);
            let core_end_file = start + (file_size - start).min(SWEEP_CHUNK as u64);
            let hi = core_end_file
                .saturating_add(SWEEP_PAD as u64)
                .min(file_size);
            let read_len = usize::try_from(hi - lo).map_err(|_| {
                VmkatzError::DiskFormatError("VMRS sweep window does not fit memory".into())
            })?;
            let buf = self.read_file_bytes(lo, read_len)?;
            let core_begin = usize::try_from(start - lo).map_err(|_| {
                VmkatzError::DiskFormatError("VMRS sweep offset does not fit memory".into())
            })?;
            let core_end = usize::try_from(core_end_file - lo).map_err(|_| {
                VmkatzError::DiskFormatError("VMRS sweep end does not fit memory".into())
            })?;

            for m in finder.find_iter(&buf) {
                // Only own matches whose name starts in this chunk's core.
                if m < core_begin || m >= core_end {
                    continue;
                }
                let name_start = m;
                let mut j = name_start + needle.len();
                let ds = j;
                while j < buf.len() && buf[j].is_ascii_digit() {
                    j += 1;
                }
                if j == ds || j - ds > 7 {
                    continue;
                }
                let Ok(index) = std::str::from_utf8(&buf[ds..j])
                    .unwrap_or("")
                    .parse::<u64>()
                else {
                    continue;
                };
                if name_start < 21 {
                    continue;
                }
                let entry_off = name_start - 21;
                let name_bytes = j - name_start; // "RamBlock" + digits, no NUL
                let name_length = buf[entry_off + 20] as usize;
                // Reference entry, reference flag set, NUL-terminated name length.
                if buf[entry_off] != 7
                    || buf[entry_off + 1] & 1 == 0
                    || name_length != name_bytes + 1
                {
                    continue;
                }
                let ref_off = entry_off + 21 + name_length;
                if ref_off + 12 > buf.len() {
                    continue;
                }
                let size = u32_le(&buf, ref_off);
                let file_offset = u64_le(&buf, ref_off + 4);
                if size == 0
                    || size > RAM_BLOCK_SIZE as u32
                    || file_offset == 0
                    || file_offset
                        .checked_add(u64::from(size))
                        .is_none_or(|end| end > file_size)
                {
                    continue;
                }
                let key = format!("RamBlock{index}");
                if !self.key_values.contains_key(&key) {
                    self.insert_key(key, (file_offset, size))?;
                }
            }

            start = core_end_file;
        }

        log::info!(
            "VMRS: RamBlock reference sweep recovered {} additional blocks (total {})",
            self.key_values.len() - before,
            self.key_values.len()
        );
        Ok(())
    }

    /// Scan the whole data region for ObjectTables. Used when `data_offset`
    /// points to a root superblock rather than a plain ObjectTable.
    ///
    /// An ObjectTable is `[flags:u32][count:u32]` followed by `count` 18-byte
    /// entries, each self-validating via its embedded CRC32. We locate tables by
    /// finding an 8-byte header whose declared count fits and whose first few
    /// entries pass CRC, then collect every entry. The 32-bit per-entry CRC makes
    /// false positives negligible.
    fn scan_object_tables(&mut self) -> Result<()> {
        const MAX_ENTRIES: usize = 100_000;
        const MAX_TABLE_SIZE: usize = 8 + MAX_ENTRIES * 18;
        const SCAN_CHUNK: u64 = 32 * 1024 * 1024;

        let mut file = self.inner.borrow_mut();
        let file_size = crate::utils::file_size(&mut file.file)?;
        let data_end = self
            .header
            .data_offset
            .checked_add(self.header.data_size)
            .filter(|&end| end <= file_size)
            .ok_or_else(|| {
                VmkatzError::DiskFormatError("VMRS data region extends beyond the file".into())
            })?;
        drop(file);

        let entry_crc_ok = |e: &[u8]| -> bool {
            let stored = u32_le(e, 1);
            if stored == 0 {
                return false;
            }
            let mut buf = [0u8; 18];
            buf.copy_from_slice(e);
            buf[1..5].fill(0);
            hvs_crc32(&buf) == stored
        };

        let mut tables = 0usize;
        let mut core_start = self.header.data_offset;
        let mut skip_until = core_start;
        while core_start < data_end {
            let core_end = core_start + (data_end - core_start).min(SCAN_CHUNK);
            let window_end = core_end.saturating_add(MAX_TABLE_SIZE as u64).min(data_end);
            let window_size = usize::try_from(window_end - core_start).map_err(|_| {
                VmkatzError::DiskFormatError("VMRS scan window does not fit memory".into())
            })?;
            let region = self.read_file_bytes(core_start, window_size)?;
            let core_len = usize::try_from(core_end - core_start).map_err(|_| {
                VmkatzError::DiskFormatError("VMRS scan chunk does not fit memory".into())
            })?;
            let mut off = usize::try_from(skip_until.saturating_sub(core_start))
                .unwrap_or(usize::MAX)
                .min(core_len);

            while off < core_len {
                let Some(header_end) = off.checked_add(8) else {
                    break;
                };
                if header_end > region.len() {
                    break;
                }
                let count = usize::try_from(u32_le(&region, off + 4)).unwrap_or(usize::MAX);
                let Some(table_size) = count.checked_mul(18).and_then(|size| size.checked_add(8))
                else {
                    off += 1;
                    continue;
                };
                let Some(table_end) = off.checked_add(table_size) else {
                    off += 1;
                    continue;
                };
                if count == 0
                    || count > MAX_ENTRIES
                    || table_size > MAX_TABLE_SIZE
                    || table_end > region.len()
                {
                    off += 1;
                    continue;
                }

                // Confirm this is a real table header: first up-to-8 entries pass CRC.
                let probe = count.min(8);
                let base = off + 8;
                let ok = (0..probe).all(|i| {
                    let entry_start = base + i * 18;
                    entry_crc_ok(&region[entry_start..entry_start + 18])
                });
                if !ok {
                    off += 1;
                    continue;
                }

                for i in 0..count {
                    let entry_start = base + i * 18;
                    let e = &region[entry_start..entry_start + 18];
                    let entry = ObjectTableEntry {
                        entry_type: e[0],
                        crc32: u32_le(e, 1),
                        file_offset: u64_le(e, 5),
                        size: u32_le(e, 13),
                        flags: e[17],
                    };
                    // Empty slots don't count when resolving KeyTable references.
                    if entry.entry_type != 0 || entry.file_offset != 0 || entry.size != 0 {
                        metadata::reserve_object(&mut self.object_entries)?;
                        self.object_entries.push(entry);
                    }
                }
                tables += 1;
                let table_end_abs = u64::try_from(table_end).map_err(|_| {
                    VmkatzError::DiskFormatError("VMRS ObjectTable size overflow".into())
                })?;
                skip_until = core_start.checked_add(table_end_abs).ok_or_else(|| {
                    VmkatzError::DiskFormatError("VMRS ObjectTable offset overflow".into())
                })?;
                off = table_end;
            }
            core_start = core_end;
        }

        log::info!(
            "VMRS: scanned {tables} ObjectTables, {} entries",
            self.object_entries.len()
        );
        Ok(())
    }

    /// Parse the ObjectTable at the given file offset.
    fn parse_object_table(&mut self, offset: u64) -> Result<()> {
        // Read ObjectTable header (8 bytes): [0:4] flags, [4:8] entry_count
        let mut inner = self.inner.borrow_mut();
        inner.file.seek(SeekFrom::Start(offset))?;
        let mut hdr = [0u8; 8];
        inner.file.read_exact(&mut hdr)?;

        let entry_count = u32_le(&hdr, 4) as usize;
        if entry_count > 100_000 {
            return Err(VmkatzError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("ObjectTable entry count too large: {entry_count}"),
            )));
        }

        log::debug!("VMRS: ObjectTable at {offset:#x} with {entry_count} entries");

        // Read entries (18 bytes each)
        let entries_size = entry_count.checked_mul(18).ok_or_else(|| {
            VmkatzError::DiskFormatError("VMRS ObjectTable entry size overflow".into())
        })?;
        let mut entries_buf = crate::utils::zeroed_buffer(entries_size)?;
        inner.file.read_exact(&mut entries_buf)?;

        self.object_entries.clear();
        for i in 0..entry_count {
            let e = &entries_buf[i * 18..(i + 1) * 18];
            let entry = ObjectTableEntry {
                entry_type: e[0],
                crc32: u32_le(e, 1),
                file_offset: u64_le(e, 5),
                size: u32_le(e, 13),
                flags: e[17],
            };
            // Only store non-empty entries
            if entry.entry_type != 0 || entry.file_offset != 0 || entry.size != 0 {
                metadata::reserve_object(&mut self.object_entries)?;
                self.object_entries.push(entry);
            }
        }

        log::debug!(
            "VMRS: {} non-empty object entries",
            self.object_entries.len()
        );
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
            .find(|e| e.file_offset == u64::from(reference) && e.size > 0)
            .cloned()
    }

    /// Brute-force scan: search the data region for RAM block patterns.
    /// This is a fallback when KeyTable parsing doesn't find the keys.
    fn scan_for_ram_blocks(&self) -> Result<()> {
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
        // RamBlock<N> keys are sparse (gaps for never-touched RAM), so the guest's
        // physical extent is (max index + 1) * 1MB — NOT the key count. Using the
        // count truncates high memory (e.g. kernel pool above the count), which made
        // the System EPROCESS unreachable.
        let mut block_count = 0u64;
        let mut max_block = 0u64;
        for key in self.key_values.keys() {
            if let Some(pos) = key.rfind("RamBlock") {
                let digits: String = key[pos + "RamBlock".len()..]
                    .chars()
                    .take_while(char::is_ascii_digit)
                    .collect();
                if let Ok(idx) = digits.parse::<u64>() {
                    max_block = max_block.max(idx);
                    block_count += 1;
                }
            }
        }

        if block_count == 0 {
            block_count = self
                .object_entries
                .iter()
                .filter(|e| e.size > 0 && e.size as usize <= RAM_BLOCK_SIZE && e.entry_type != 0)
                .count() as u64;
            if block_count > 10 {
                block_count = block_count.saturating_sub(5);
            }
            max_block = block_count.saturating_sub(1);
        }

        self.ram_block_count = block_count;

        // Physical extent spans block 0 .. max_block inclusive.
        let pages_per_block = (RAM_BLOCK_SIZE / 4096) as u64;
        if block_count > 0 {
            let blocks_extent = max_block.checked_add(1).ok_or_else(|| {
                VmkatzError::DiskFormatError("VMRS RamBlock index overflow".into())
            })?;
            let ram_size = blocks_extent
                .checked_mul(RAM_BLOCK_SIZE as u64)
                .ok_or_else(|| VmkatzError::DiskFormatError("VMRS RAM size overflow".into()))?;
            let page_count = blocks_extent.checked_mul(pages_per_block).ok_or_else(|| {
                VmkatzError::DiskFormatError("VMRS RAM page count overflow".into())
            })?;
            self.memory_chunks.push(GpaMemoryChunk {
                start_page_index: 0,
                page_count,
            });

            // RamBlock indices are contiguous RAM offsets, but a Hyper-V guest's
            // GPA space has a low MMIO gap: RAM that would sit under it is remapped
            // above 4 GB. GPA above 4 GB maps to RAM offset (gpa - gap_size), so the
            // GPA span exceeds RAM size. Without this, high-memory page-table entries
            // (e.g. the nonpaged pool holding EPROCESS structures) translate to
            // out-of-range physical addresses and the process list can't be walked.
            //
            // The gap base differs by VM generation (Gen1 = 0xF800_0000; Gen2 varies),
            // so derive its size from the guest's own page tables when RAM extends
            // above 4 GB, and fall back to the Gen1 default otherwise.
            let gap_size =
                self.detect_mmio_gap_size(ram_size)
                    .unwrap_or(if ram_size > MMIO_GAP_BASE {
                        MMIO_GAP_END - MMIO_GAP_BASE
                    } else {
                        0
                    });
            if gap_size > 0 {
                self.mmio_gap_base = MMIO_GAP_END - gap_size;
                self.mmio_gap_size = gap_size;
                // GPA span = 4 GB + (RAM remapped above 4 GB).
                self.phys_size = ram_size
                    .checked_sub(self.mmio_gap_base)
                    .and_then(|above_gap| MMIO_GAP_END.checked_add(above_gap))
                    .ok_or_else(|| {
                        VmkatzError::DiskFormatError("VMRS physical address range overflow".into())
                    })?;
            } else {
                self.phys_size = ram_size;
            }
            log::info!(
                "VMRS: RAM {} MB, MMIO gap base={:#x} size={:#x}, GPA span {} MB",
                ram_size / (1024 * 1024),
                self.mmio_gap_base,
                self.mmio_gap_size,
                self.phys_size / (1024 * 1024)
            );
        }
        Ok(())
    }

    /// Derive the low MMIO gap size from the guest's page tables, generation-agnostic.
    ///
    /// A Windows CR3 is a PML4 page with a recursive self-map entry whose PFN is the
    /// page's own guest-physical address. For a PML4 stored at RAM offset `r` at or
    /// above the gap, that GPA is `r + gap_size`, so `gap_size = self_map_gpa - r`.
    /// RAM offsets >= 4 GB are always above the gap (which ends at 4 GB), so scanning
    /// there and taking the agreed delta yields the exact gap for any generation.
    /// Returns `None` when RAM does not extend past 4 GB or no consensus is found
    /// (callers then fall back to the Gen1 default).
    fn detect_mmio_gap_size(&self, ram_size: u64) -> Option<u64> {
        const HIGH: u64 = 0x1_0000_0000; // 4 GB — RAM offsets here are above any gap
        const MAX_GAP: u64 = 0x4000_0000; // 1 GB upper bound on the gap
        const SCAN_CAP: u64 = 1024; // blocks to scan before giving up
        const MIN_PML4: u32 = 8; // PML4 pages to sample before trusting a majority
        if ram_size <= HIGH {
            return None;
        }
        let block_sz = RAM_BLOCK_SIZE as u64;
        let start_block = HIGH / block_sz;
        let end_block = ram_size / block_sz;
        let mut votes: HashMap<u64, u32> = HashMap::new();
        let mut pml4_seen = 0u32;
        let mut scanned = 0u64;
        // The self-map delta appears in EVERY process PML4 (once each), while a
        // coincidental kernel-entry delta shows up in only a few — so the true gap
        // is the value a clear majority of sampled PML4 pages agree on.
        let mut candidates: Vec<u64> = Vec::new();
        for block in start_block..end_block {
            let Ok(data) = self.read_ram_block(block) else {
                continue;
            };
            scanned += 1;
            let base = block * block_sz;
            for page in 0..(RAM_BLOCK_SIZE / 4096) {
                let po = page * 4096;
                if po + 4096 > data.len() {
                    break;
                }
                let pg = &data[po..po + 4096];
                let r = base + po as u64;
                let mut kernel = 0u32;
                candidates.clear();
                for i in 0..512 {
                    let e = u64_le(pg, i * 8);
                    if e & 1 == 0 {
                        continue;
                    }
                    if i >= 256 {
                        kernel += 1;
                    }
                    // Self-map candidate: entry PFN (a GPA) just above this page's
                    // RAM offset, by a small, 2 MB-aligned amount (the gap).
                    let pfn_gpa = e & 0x000F_FFFF_FFFF_F000;
                    if pfn_gpa > r {
                        let d = pfn_gpa - r;
                        if d <= MAX_GAP && d.is_multiple_of(0x20_0000) && !candidates.contains(&d) {
                            candidates.push(d);
                        }
                    }
                }
                // A real PML4 has several shared kernel-half entries plus the self-map.
                if kernel >= 6 && !candidates.is_empty() {
                    pml4_seen += 1;
                    for &d in &candidates {
                        *votes.entry(d).or_default() += 1;
                    }
                }
            }
            // Trust a value only once enough PML4s are sampled and one holds a
            // strict majority of them (the self-map is in 100% of real PML4s).
            if pml4_seen >= MIN_PML4 {
                if let Some((&d, &c)) = votes.iter().max_by_key(|(_, c)| **c) {
                    if c * 2 > pml4_seen {
                        return Some(d);
                    }
                }
            }
            if scanned >= SCAN_CAP {
                break;
            }
        }
        votes
            .into_iter()
            .filter(|&(_, c)| pml4_seen > 0 && c * 2 > pml4_seen)
            .max_by_key(|&(_, c)| c)
            .map(|(d, _)| d)
    }

    /// Map a guest physical address to a flat RAM offset (into the RamBlock space),
    /// accounting for the low MMIO gap. Returns `None` for addresses inside the gap
    /// (MMIO, no backing RAM).
    const fn gpa_to_ram_offset(&self, gpa: u64) -> Option<u64> {
        if self.mmio_gap_size == 0 || gpa < self.mmio_gap_base {
            return Some(gpa);
        }
        let Some(gap_end) = self.mmio_gap_base.checked_add(self.mmio_gap_size) else {
            return None;
        };
        if gpa < gap_end {
            return None; // inside the MMIO gap
        }
        Some(gpa - self.mmio_gap_size)
    }

    /// Check file bounds before allocating exactly one bounded read buffer.
    fn read_file_bytes(&self, offset: u64, size: usize) -> Result<Vec<u8>> {
        if size > crate::memory::reader::MAX_READ_BYTES {
            return Err(VmkatzError::AllocTooLarge {
                what: "VMRS file read",
                requested: size,
                limit: crate::memory::reader::MAX_READ_BYTES,
            });
        }
        let mut inner = self.inner.borrow_mut();
        let file_size = inner.file.seek(SeekFrom::End(0))?;
        if offset
            .checked_add(size as u64)
            .is_none_or(|end| end > file_size)
        {
            return Err(VmkatzError::DiskFormatError(format!(
                "VMRS read past end: wanted {size} bytes at {offset:#x}"
            )));
        }
        inner.file.seek(SeekFrom::Start(offset))?;
        let mut buf = crate::utils::zeroed_buffer(size)?;
        inner.file.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Read and decompress a RAM block by index.
    /// Decompress one RAM block from the file (no cache access).
    fn decompress_block(&self, block_index: u64) -> Result<Vec<u8>> {
        let key_paths = [
            format!("savedstate/RamBlock{block_index}"),
            format!("/savedstate/RamBlock{block_index}"),
            format!("RamBlock{block_index}"),
            format!("savedstate/RamMemoryBlock{block_index}"),
            format!("/savedstate/RamMemoryBlock{block_index}"),
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
            value_info = usize::try_from(block_index)
                .ok()
                .and_then(|index| {
                    self.object_entries
                        .iter()
                        .filter(|e| {
                            e.size > 0
                                && e.size <= RAM_BLOCK_SIZE as u32
                                && e.file_offset > 0
                                && !matches!(e.entry_type, 0 | 2 | 4)
                        })
                        .nth(index)
                })
                .map(|entry| (entry.file_offset, entry.size));
        }

        let (file_offset, compressed_size) = value_info.ok_or_else(|| {
            VmkatzError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("RAM block {block_index} not found"),
            ))
        })?;

        let compressed_size = usize::try_from(compressed_size).map_err(|_| {
            VmkatzError::DiskFormatError("VMRS RAM block size does not fit memory".into())
        })?;
        if compressed_size > RAM_BLOCK_SIZE {
            return Err(VmkatzError::DiskFormatError(format!(
                "VMRS RAM block is too large: {compressed_size} bytes"
            )));
        }
        let raw_data = self.read_file_bytes(file_offset, compressed_size)?;
        Ok(if compressed_size == RAM_BLOCK_SIZE {
            raw_data
        } else {
            vm_compress_unpack(&raw_data)
        })
    }

    fn read_ram_block(&self, block_index: u64) -> Result<Vec<u8>> {
        if let Some(cached) = self.inner.borrow_mut().cache.get(block_index) {
            return Ok(cached.to_vec());
        }
        let block = self.decompress_block(block_index)?;
        self.inner
            .borrow_mut()
            .cache
            .insert(block_index, block.clone());
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
            // Translate GPA -> flat RAM offset (skipping the MMIO gap). The gap base
            // is 1 MB-aligned, so a single block never straddles it.
            let Some(ram_offset) = self.gpa_to_ram_offset(addr) else {
                // Inside the MMIO gap: no backing RAM.
                let gap_end = self
                    .mmio_gap_base
                    .checked_add(self.mmio_gap_size)
                    .ok_or(VmkatzError::UnmappablePhysical(addr))?;
                let to_gap_end = gap_end.saturating_sub(addr).max(1);
                let remaining_u64 = u64::try_from(remaining.len())
                    .map_err(|_| VmkatzError::UnmappablePhysical(addr))?;
                let to_copy = usize::try_from(to_gap_end.min(remaining_u64))
                    .map_err(|_| VmkatzError::UnmappablePhysical(addr))?;
                remaining[..to_copy].fill(0);
                remaining = &mut remaining[to_copy..];
                addr = advance_address(addr, to_copy)?;
                continue;
            };
            let block_index = ram_offset / RAM_BLOCK_SIZE as u64;
            let block_offset = (ram_offset % RAM_BLOCK_SIZE as u64) as usize;
            let available = RAM_BLOCK_SIZE - block_offset;
            let to_copy = remaining.len().min(available);

            // Fast path: on a cache hit copy the needed slice directly (marking the
            // block most-recently used), avoiding a full 1 MB block clone. The scans
            // issue thousands of tiny reads, so cloning per read would dominate.
            {
                let mut inner = self.inner.borrow_mut();
                if let Some(block) = inner.cache.get(block_index) {
                    let end = (block_offset + to_copy).min(block.len());
                    if block_offset < block.len() {
                        let copy_len = end - block_offset;
                        remaining[..copy_len].copy_from_slice(&block[block_offset..end]);
                        remaining[copy_len..to_copy].fill(0);
                    } else {
                        remaining[..to_copy].fill(0);
                    }
                    drop(inner);
                    remaining = &mut remaining[to_copy..];
                    addr = advance_address(addr, to_copy)?;
                    continue;
                }
            }

            // Miss: decompress (no cache borrow), copy the slice, then cache it.
            if let Ok(block) = self.decompress_block(block_index) {
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
                self.inner.borrow_mut().cache.insert(block_index, block);
            } else {
                // Block failed to read/decompress — zero-fill, best-effort,
                // but warn once so missing memory isn't taken as valid zeros.
                remaining[..to_copy].fill(0);
                if !self.read_masked.replace(true) {
                    log::warn!(
                        "VMRS: RAM block {block_index} unreadable, zero-filled — memory image may be incomplete"
                    );
                }
            }

            remaining = &mut remaining[to_copy..];
            addr = advance_address(addr, to_copy)?;
        }

        Ok(())
    }

    fn phys_size(&self) -> u64 {
        self.phys_size
    }

    fn par_scan(&self, f: &(dyn Fn(u64, &[u8]) -> bool + Sync)) -> bool {
        self.scan_ram(f)
    }
}

/// CRC32 implementation matching HvsComputeCrc32 (standard CRC32).
fn hvs_crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        crc ^= u32::from(byte);
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
