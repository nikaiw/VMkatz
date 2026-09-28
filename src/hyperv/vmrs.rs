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
//! Memory reconstruction is byte-exact: every RamBlock decompresses (XPRESS) to
//! a full 1 MB page. Two subtleties are essential for virtual-address translation:
//!
//! 1. RamBlock references live in several KeyTable copies — ObjectTable-referenced
//!    leaves, tables inline in the data region, and a set near the file start. The
//!    low-memory leaf (RamBlock0..15) and ~200 scattered indices appear only in the
//!    inline/early tables, so all of them must be swept (see
//!    [`VmrsLayer::parse_ramblock_references`]); otherwise kernel page tables (e.g.
//!    behind KUSER_SHARED_DATA) are missing and translation fails.
//!
//! 2. RamBlock indices are contiguous RAM offsets, but the guest's GPA space has a
//!    low MMIO gap: RAM under it is remapped above 4 GB. read_phys therefore maps
//!    GPA -> RAM offset across the gap (see [`VmrsLayer::gpa_to_ram_offset`]).
//!    Without this, high-memory page-table entries translate out of range and the
//!    EPROCESS list can't be walked.

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

/// Hyper-V Gen1 low MMIO gap: RAM that would sit at [0xF800_0000, 0x1_0000_0000)
/// is remapped above 4 GB. Applied only when total RAM exceeds the gap base.
const MMIO_GAP_BASE: u64 = 0xF800_0000;
const MMIO_GAP_END: u64 = 0x1_0000_0000;

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
    #[expect(
        dead_code,
        reason = "CRC on-disk de l'entrée, non vérifié pour l'instant"
    )]
    crc32: u32,
    file_offset: u64,
    size: u32,
    #[expect(dead_code, reason = "flags on-disk de l'entrée, non exploités")]
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
    /// Path to the .vmrs file, so parallel workers can open their own handles.
    path: std::path::PathBuf,
}

struct VmrsInner {
    file: fs::File,
    block_cache: HashMap<u64, Vec<u8>>,
    /// FIFO of cached block indices, for single-entry eviction (clearing the whole
    /// cache thrashes the random access done during registry-hive reconstruction).
    cache_order: std::collections::VecDeque<u64>,
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

        let mut layer = Self {
            inner: RefCell::new(VmrsInner {
                file,
                block_cache: HashMap::new(),
                cache_order: std::collections::VecDeque::new(),
                // 1 GB of decompressed blocks: enough to keep registry-hive bins and
                // page tables hot during the random access of reconstruction/walking.
                cache_limit: 1024,
            }),
            header,
            object_entries: Vec::new(),
            key_values: HashMap::new(),
            ram_block_count: 0,
            memory_chunks: Vec::new(),
            phys_size: 0,
            mmio_gap_base: 0,
            mmio_gap_size: 0,
            path: path.to_path_buf(),
        };

        // Parse the data region
        layer.parse_data_region()?;

        // Determine RAM layout
        layer.build_memory_layout();

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
                format!("Bad VMRS magic: {magic:#x} (expected {VMRS_MAGIC:#x})"),
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
                    "VMRS header CRC mismatch at offset {offset:#x}: stored={stored_crc:#x} computed={computed_crc:#x}"
                ),
            )));
        }

        let sequence = u16::from_le_bytes(buf[8..10].try_into().unwrap());
        let version = u32::from_le_bytes(buf[10..14].try_into().unwrap());
        let data_alignment = u32::from_le_bytes(buf[22..26].try_into().unwrap());
        let data_offset = u64::from_le_bytes(buf[26..34].try_into().unwrap());
        let data_size = u64::from_le_bytes(buf[34..42].try_into().unwrap());

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
            Err(e) => {
                log::debug!("VMRS: ObjectTable at data_offset unusable ({e}), scanning");
                self.scan_object_tables()?;
            }
        }

        // Now parse all KeyTables referenced by the ObjectTable
        self.parse_key_tables()?;

        // Some RAM blocks (the low-memory leaf covering RamBlock0..15 plus scattered
        // indices) live in KeyTables not referenced by any ObjectTable entry — inline
        // in the data region, near the file start, or in backup copies. Without them
        // low guest physical memory (e.g. the kernel page tables backing
        // KUSER_SHARED_DATA) is missing and virtual-address translation fails. Sweep
        // the file to recover every RamBlock reference.
        self.parse_ramblock_references()?;

        Ok(())
    }

    /// Recover every `RamBlock<N>` reference by sweeping the whole file.
    ///
    /// A VMRS stores its KeyTables in several places: ObjectTable-referenced leaf
    /// tables (handled by [`Self::parse_key_tables`]), a primary set inline in the
    /// data region, an early set near the start of the file (the first blocks
    /// flushed during save), and backup copies. The low-memory leaf (RamBlock0..15)
    /// and ~200 scattered indices live only in the inline/early tables, so without
    /// them low guest physical memory — including the kernel page tables backing
    /// KUSER_SHARED_DATA — is absent and virtual-address translation fails. Missing
    /// a page-table page also yields garbage PFNs that translate out of range.
    ///
    /// Rather than locate every KeyTable header exactly, scan the file for
    /// `RamBlock<N>` entries and resolve each in place. A RamBlock entry is a
    /// reference entry (type 7, flag bit0 set) whose NUL-terminated name is
    /// immediately followed by the 12-byte descriptor `{ u32 size; u64 file_offset }`
    /// (see [`Self::walk_key_entries`]). Strict checks (exact name-length field,
    /// entry type/flags, reference bounds) reject the rare coincidental "RamBlock"
    /// byte sequence inside compressed page data. Inserts keep the first valid
    /// reference, so entries already found via KeyTables are preserved.
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
            let hi = (start + SWEEP_CHUNK as u64 + SWEEP_PAD as u64).min(file_size);
            let buf = self.read_file_bytes(lo, (hi - lo) as usize)?;
            let core_begin = (start - lo) as usize;
            let core_end = ((start + SWEEP_CHUNK as u64).min(file_size) - lo) as usize;

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
                let size = u32::from_le_bytes(buf[ref_off..ref_off + 4].try_into().unwrap());
                let file_offset =
                    u64::from_le_bytes(buf[ref_off + 4..ref_off + 12].try_into().unwrap());
                if size == 0
                    || size as usize > RAM_BLOCK_SIZE
                    || file_offset == 0
                    || file_offset + u64::from(size) > file_size
                {
                    continue;
                }
                self.key_values
                    .entry(format!("RamBlock{index}"))
                    .or_insert((file_offset, size));
            }

            start += SWEEP_CHUNK as u64;
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
        let region =
            self.read_file_bytes(self.header.data_offset, self.header.data_size as usize)?;
        let n = region.len();
        let entry_crc_ok = |e: &[u8]| -> bool {
            let stored = u32::from_le_bytes(e[1..5].try_into().unwrap());
            if stored == 0 {
                return false;
            }
            let mut buf = [0u8; 18];
            buf.copy_from_slice(e);
            buf[1..5].fill(0);
            hvs_crc32(&buf) == stored
        };

        let mut tables = 0usize;
        let mut off = 0usize;
        while off + 8 <= n {
            let count = u32::from_le_bytes(region[off + 4..off + 8].try_into().unwrap()) as usize;
            if count == 0 || count > 100_000 || off + 8 + count * 18 > n {
                off += 1;
                continue;
            }
            // Confirm this is a real table header: first up-to-8 entries must pass CRC.
            let probe = count.min(8);
            let base = off + 8;
            let ok = (0..probe).all(|i| entry_crc_ok(&region[base + i * 18..base + (i + 1) * 18]));
            if !ok {
                off += 1;
                continue;
            }
            for i in 0..count {
                let e = &region[base + i * 18..base + (i + 1) * 18];
                let entry = ObjectTableEntry {
                    entry_type: e[0],
                    crc32: u32::from_le_bytes(e[1..5].try_into().unwrap()),
                    file_offset: u64::from_le_bytes(e[5..13].try_into().unwrap()),
                    size: u32::from_le_bytes(e[13..17].try_into().unwrap()),
                    flags: e[17],
                };
                // Skip empty slots: KeyTable reference indices count only populated
                // entries (matches how the root ObjectTable is enumerated).
                if entry.entry_type != 0 || entry.file_offset != 0 || entry.size != 0 {
                    self.object_entries.push(entry);
                }
            }
            tables += 1;
            off = base + count * 18;
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

        let entry_count = u32::from_le_bytes(hdr[4..8].try_into().unwrap()) as usize;
        if entry_count > 100_000 {
            return Err(VmkatzError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("ObjectTable entry count too large: {entry_count}"),
            )));
        }

        log::debug!("VMRS: ObjectTable at {offset:#x} with {entry_count} entries");

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

        log::debug!(
            "VMRS: {} non-empty object entries",
            self.object_entries.len()
        );
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
        self.walk_key_entries(&data, 10, entry.file_offset, "");

        Ok(())
    }

    /// Walk key entries in a flat array, building the key path map. Returns the
    /// offset at which walking stopped (table end), so a caller scanning several
    /// concatenated tables can resume past this one.
    fn walk_key_entries(
        &mut self,
        data: &[u8],
        start: usize,
        base_file_offset: u64,
        parent_path: &str,
    ) -> usize {
        let total = data.len();
        let mut offset = start;

        while offset + 21 < total {
            // Entry header
            let entry_type = data[offset];
            // data[offset + 1]: entry flags (non exploité)
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
                    format!("{parent_path}/{key_name}")
                };

                // Reference entry (flag bit 0 set): the value is a 12-byte descriptor
                // that directly locates the data blob (this is how RamBlock<N> keys
                // point at their compressed page data). Per HyperVStorage::GetValueInternal
                // (reversed from vmwp.exe/vmsavedstatedumpprovider), for such an entry:
                //   value_size  = u32 at entry + 0x15 + name_length
                //   file_offset = u64 at entry + 0x19 + name_length
                // The name occupies [offset+21 .. offset+21+name_length], so the 12-byte
                // reference struct { u32 size; u64 file_offset } follows it directly.
                let entry_flags = data[offset + 1];
                let is_reference = entry_flags & 1 != 0;
                let ref_off = offset + 21 + name_length; // 0x15 + name_length
                let resolved_reference = if is_reference && ref_off + 12 <= total {
                    let size = u32::from_le_bytes(data[ref_off..ref_off + 4].try_into().unwrap());
                    let file_offset =
                        u64::from_le_bytes(data[ref_off + 4..ref_off + 12].try_into().unwrap());
                    if file_offset != 0 && size != 0 {
                        Some((file_offset, size))
                    } else {
                        None
                    }
                } else {
                    None
                };

                // Extract value info based on type
                if let Some((foff, size)) = resolved_reference {
                    self.key_values.insert(full_path.clone(), (foff, size));
                } else {
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
                                        (base_file_offset + value_data_offset as u64, value_size),
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
                }

                // Check for child key table reference
                // Bytes [6:8] = child count, [8:12] = child object table entry offset
                let child_obj_ref =
                    u32::from_le_bytes(data[offset + 8..offset + 12].try_into().unwrap());
                if child_obj_ref > 0 {
                    // Try to find and parse the child key table
                    if let Some(child_entry) = self.find_object_entry(child_obj_ref) {
                        let child_data = self
                            .read_file_bytes(child_entry.file_offset, child_entry.size as usize);
                        if let Ok(child_data) = child_data {
                            self.walk_key_entries(
                                &child_data,
                                10,
                                child_entry.file_offset,
                                &full_path,
                            );
                        }
                    }
                }

                log::trace!("VMRS key: {full_path} (type={entry_type}, size={entry_total_size})");
            }

            offset += entry_total_size;
        }
        offset
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
    fn build_memory_layout(&mut self) {
        // Determine the key path prefix based on version
        let prefix = if self.header.version > 0x500 {
            "/savedstate/"
        } else {
            "" // Legacy format, prefix varies
        };

        let _ = prefix;
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
            let blocks_extent = max_block + 1;
            let ram_size = blocks_extent * RAM_BLOCK_SIZE as u64;
            self.memory_chunks.push(GpaMemoryChunk {
                start_page_index: 0,
                page_count: blocks_extent * pages_per_block,
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
                self.phys_size = MMIO_GAP_END + (ram_size - self.mmio_gap_base);
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
                    let e = u64::from_le_bytes(pg[i * 8..i * 8 + 8].try_into().unwrap());
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
        let gap_end = self.mmio_gap_base + self.mmio_gap_size;
        if gpa < gap_end {
            return None; // inside the MMIO gap
        }
        Some(gpa - self.mmio_gap_size)
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
                        && e.entry_type != 4 // not free
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
                format!("RAM block {block_index} not found"),
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
            vm_compress_unpack(&raw_data)
        };

        // Cache the result with single-entry FIFO eviction.
        let mut inner = self.inner.borrow_mut();
        while inner.block_cache.len() >= inner.cache_limit {
            if let Some(old) = inner.cache_order.pop_front() {
                inner.block_cache.remove(&old);
            } else {
                break;
            }
        }
        if inner
            .block_cache
            .insert(block_index, block.clone())
            .is_none()
        {
            inner.cache_order.push_back(block_index);
        }

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
                let to_gap_end = (self.mmio_gap_base + self.mmio_gap_size).saturating_sub(addr);
                let to_copy = remaining.len().min(to_gap_end.max(1) as usize);
                remaining[..to_copy].fill(0);
                remaining = &mut remaining[to_copy..];
                addr += to_copy as u64;
                continue;
            };
            let block_index = ram_offset / RAM_BLOCK_SIZE as u64;
            let block_offset = (ram_offset % RAM_BLOCK_SIZE as u64) as usize;
            let available = RAM_BLOCK_SIZE - block_offset;
            let to_copy = remaining.len().min(available);

            // Fast path: on a cache hit copy the needed slice directly, avoiding a
            // full 1 MB block clone. Reassembly issues thousands of tiny reads, so
            // cloning the whole block per read would dominate the run time.
            {
                let inner = self.inner.borrow();
                if let Some(block) = inner.block_cache.get(&block_index) {
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
                    addr += to_copy as u64;
                    continue;
                }
            }

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

    /// Decompress and scan every RAM block in parallel. Each block's location is
    /// resolved up front (from the immutable key/object tables), then worker
    /// threads — each with its own file handle and positioned reads — pull blocks
    /// off a shared counter, decompress, and hand the bytes to `f` at the block's
    /// GPA. XPRESS decompression is the scan's bottleneck, so this spreads it over
    /// all cores; block scans are independent, so no ordering is needed.
    fn par_scan(&self, f: &(dyn Fn(u64, &[u8]) -> bool + Sync)) -> bool {
        use std::os::unix::fs::FileExt;
        use std::sync::atomic::{AtomicUsize, Ordering};

        if self.ram_block_count == 0 {
            return false;
        }
        // Object-table fallback list (used when RamBlock<N> keys are absent).
        let ram_entries: Vec<(u64, u32)> = self
            .object_entries
            .iter()
            .filter(|e| {
                e.size > 0
                    && e.size as usize <= RAM_BLOCK_SIZE
                    && e.file_offset > 0
                    && e.entry_type != 0
                    && e.entry_type != 2
                    && e.entry_type != 4
            })
            .map(|e| (e.file_offset, e.size))
            .collect();
        // Resolve every block to (index, gpa, file_offset, compressed_size) up front.
        let mut jobs: Vec<(u64, u64, u64, u32)> = Vec::new();
        for bi in 0..self.ram_block_count {
            let loc = [
                format!("savedstate/RamBlock{bi}"),
                format!("/savedstate/RamBlock{bi}"),
                format!("RamBlock{bi}"),
                format!("savedstate/RamMemoryBlock{bi}"),
                format!("/savedstate/RamMemoryBlock{bi}"),
            ]
            .iter()
            .find_map(|k| self.key_values.get(k.as_str()).copied())
            .or_else(|| ram_entries.get(bi as usize).copied());
            if let Some((foff, csize)) = loc {
                let ram_offset = bi * RAM_BLOCK_SIZE as u64;
                let gpa = if self.mmio_gap_size == 0 || ram_offset < self.mmio_gap_base {
                    ram_offset
                } else {
                    ram_offset + self.mmio_gap_size
                };
                jobs.push((bi, gpa, foff, csize));
            }
        }
        if jobs.is_empty() {
            return false;
        }

        let path = &self.path;
        let counter = AtomicUsize::new(0);
        // Blocks the callback flagged (they hold hive bins) are kept so the later
        // reassembly reads hit the cache instead of re-decompressing — that random
        // re-decompression, not the scan, is what a cold cache makes pathological.
        let keep: std::sync::Mutex<Vec<(u64, Vec<u8>)>> = std::sync::Mutex::new(Vec::new());
        let nthreads = std::thread::available_parallelism()
            .map_or(4, std::num::NonZeroUsize::get)
            .min(jobs.len());
        std::thread::scope(|s| {
            for _ in 0..nthreads {
                s.spawn(|| {
                    let Ok(fh) = fs::File::open(path) else {
                        return;
                    };
                    loop {
                        let idx = counter.fetch_add(1, Ordering::Relaxed);
                        let Some(&(bi, gpa, foff, csize)) = jobs.get(idx) else {
                            break;
                        };
                        let mut raw = vec![0u8; csize as usize];
                        if fh.read_exact_at(&mut raw, foff).is_err() {
                            continue;
                        }
                        let block = if csize as usize == RAM_BLOCK_SIZE {
                            raw
                        } else {
                            vm_compress_unpack(&raw)
                        };
                        if f(gpa, &block) {
                            keep.lock().unwrap().push((bi, block));
                        }
                    }
                });
            }
        });

        // Warm the cache with the retained hive blocks and raise the limit so they
        // are not evicted during reassembly.
        let kept = keep.into_inner().unwrap();
        let mut inner = self.inner.borrow_mut();
        inner.cache_limit = inner.cache_limit.max(kept.len() + 16);
        for (bi, block) in kept {
            if inner.block_cache.insert(bi, block).is_none() {
                inner.cache_order.push_back(bi);
            }
        }
        true
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

/// Plain XPRESS (LZ77) decompression — `RtlDecompressBufferEx` with
/// `COMPRESSION_FORMAT_XPRESS` (3), per [MS-XCA] §2.4. This is what Hyper-V's
/// `VmCompressUnpack` uses for each saved-state RAM page (NOT LZNT1). Writes
/// decompressed bytes into `out` and returns the count written.
fn xpress_decompress(input: &[u8], out: &mut [u8]) -> usize {
    let mut in_pos = 0usize;
    let mut out_pos = 0usize;
    let mut flags: u32 = 0;
    let mut flag_count = 0u32;
    let mut last_len_halfbyte = 0usize;

    loop {
        if flag_count == 0 {
            if in_pos + 4 > input.len() {
                break;
            }
            flags = u32::from_le_bytes(input[in_pos..in_pos + 4].try_into().unwrap());
            in_pos += 4;
            flag_count = 32;
        }
        let is_match = flags & 0x8000_0000 != 0;
        flags <<= 1;
        flag_count -= 1;

        if !is_match {
            if in_pos >= input.len() || out_pos >= out.len() {
                break;
            }
            out[out_pos] = input[in_pos];
            in_pos += 1;
            out_pos += 1;
            continue;
        }

        // Match: 16-bit (length:3, offset:13)
        if in_pos + 2 > input.len() {
            break;
        }
        let match_bytes = u16::from_le_bytes([input[in_pos], input[in_pos + 1]]) as usize;
        in_pos += 2;
        let match_offset = (match_bytes >> 3) + 1;
        let mut match_length = match_bytes & 7;
        if match_length == 7 {
            if last_len_halfbyte == 0 {
                if in_pos >= input.len() {
                    break;
                }
                match_length = (input[in_pos] & 0xf) as usize;
                last_len_halfbyte = in_pos;
                in_pos += 1;
            } else {
                match_length = (input[last_len_halfbyte] >> 4) as usize;
                last_len_halfbyte = 0;
            }
            if match_length == 15 {
                if in_pos >= input.len() {
                    break;
                }
                match_length = input[in_pos] as usize;
                in_pos += 1;
                if match_length == 255 {
                    if in_pos + 2 > input.len() {
                        break;
                    }
                    match_length = u16::from_le_bytes([input[in_pos], input[in_pos + 1]]) as usize;
                    in_pos += 2;
                    match_length = match_length.wrapping_sub(15 + 7);
                }
                match_length += 15;
            }
            match_length += 7;
        }
        match_length += 3;

        if match_offset > out_pos {
            break; // invalid back-reference
        }
        for _ in 0..match_length {
            if out_pos >= out.len() {
                break;
            }
            out[out_pos] = out[out_pos - match_offset];
            out_pos += 1;
        }
    }
    out_pos
}

/// Decompress a VmCompressUnpack-encoded buffer into a 1MB block.
///
/// Format: sequence of tagged pages:
/// - 0xFFFFFFFF: end marker
/// - 0xFFFFFFFE: fill 1 page (4KB) with 8-byte repeating pattern
/// - 0xFFFFFFFD: fill N pages with pattern (read count, then pattern)
/// - 0xFFFFFFFC: variable page size
/// - other: compressed_size — if page size, raw copy; else XPRESS decompress
fn vm_compress_unpack(data: &[u8]) -> Vec<u8> {
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
                // Fill N pages with an 8-byte pattern. Layout per VmCompressUnpack:
                // [pattern: u64][count: u32] (pattern FIRST, then count).
                if in_offset + 12 > data.len() {
                    break;
                }
                let pattern = data[in_offset..in_offset + 8].to_vec();
                let count =
                    u32::from_le_bytes(data[in_offset + 8..in_offset + 12].try_into().unwrap())
                        as usize;
                in_offset += 12;
                for _ in 0..count {
                    let page_end = (out_offset + 4096).min(RAM_BLOCK_SIZE);
                    if out_offset >= page_end {
                        break;
                    }
                    let mut k = 0;
                    while out_offset < page_end {
                        output[out_offset] = pattern[k % 8];
                        out_offset += 1;
                        k += 1;
                    }
                }
            }
            0xFFFFFFFC => {
                // Variable-size page. Layout per VmCompressUnpack:
                // [uncompressed_size: u32 (<=0xfff)][compressed_size: u32][data].
                // Output advances by uncompressed_size (NOT a full 4096 page).
                if in_offset + 8 > data.len() {
                    break;
                }
                let uncomp =
                    u32::from_le_bytes(data[in_offset..in_offset + 4].try_into().unwrap()) as usize;
                let comp =
                    u32::from_le_bytes(data[in_offset + 4..in_offset + 8].try_into().unwrap())
                        as usize;
                in_offset += 8;
                if uncomp == 0 || comp > uncomp || in_offset + comp > data.len() {
                    break;
                }
                let end = (out_offset + uncomp).min(RAM_BLOCK_SIZE);
                if comp == uncomp {
                    let n = end - out_offset;
                    output[out_offset..end].copy_from_slice(&data[in_offset..in_offset + n]);
                } else {
                    xpress_decompress(
                        &data[in_offset..in_offset + comp],
                        &mut output[out_offset..end],
                    );
                }
                out_offset += uncomp;
                in_offset += comp;
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
                    // XPRESS compressed page (RtlDecompressBufferEx format 3)
                    if in_offset + compressed_size > data.len() {
                        break;
                    }
                    let end = (out_offset + 4096).min(RAM_BLOCK_SIZE);
                    xpress_decompress(
                        &data[in_offset..in_offset + compressed_size],
                        &mut output[out_offset..end],
                    );
                    out_offset += 4096;
                    in_offset += compressed_size;
                } else {
                    // Invalid tag
                    log::warn!(
                        "VMRS: Invalid compression tag {:#x} at offset {}",
                        tag,
                        in_offset - 4
                    );
                    break;
                }
            }
        }
    }

    output
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

#[cfg(test)]
mod xpress_tests {
    use super::xpress_decompress;

    // Plain XPRESS (MS-XCA §2.4): "AB" then a match (offset 2, length 3) => "ABABA".
    // flags=0x20000000 (bit29 set = 3rd symbol is a match); match u16 = (off-1<<3)|(len-3).
    #[test]
    fn xpress_match_basic() {
        let input = [0x00, 0x00, 0x00, 0x20, b'A', b'B', 0x08, 0x00];
        let mut out = [0u8; 5];
        let n = xpress_decompress(&input, &mut out);
        assert_eq!(&out[..n], b"ABABA", "got {:?}", &out[..n]);
    }

    // All-literal: flags=0 => 4 literal bytes.
    #[test]
    fn xpress_literals() {
        let input = [0x00, 0x00, 0x00, 0x00, b'W', b'X', b'Y', b'Z'];
        let mut out = [0u8; 4];
        let n = xpress_decompress(&input, &mut out);
        assert_eq!(&out[..n], b"WXYZ");
    }

    // RLE via offset-1 match: "A" then match(off1,len4) => "AAAAA".
    #[test]
    fn xpress_rle() {
        // match u16 = ((1-1)<<3)|(4-3) = 1
        let input = [0x00, 0x00, 0x00, 0x40, b'A', 0x01, 0x00];
        let mut out = [0u8; 5];
        let n = xpress_decompress(&input, &mut out);
        assert_eq!(&out[..n], b"AAAAA", "got {:?}", &out[..n]);
    }
}
