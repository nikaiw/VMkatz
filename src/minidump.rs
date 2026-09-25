//! LSASS minidump (.dmp) parser.
//!
//! Parses Windows minidump files (MDMP format) produced by procdump, Task Manager,
//! or vmkatz's own `--dump lsass` mode, and exposes the memory regions as a
//! [`VirtualMemory`] implementation for credential extraction.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::path::Path;

use crate::error::{Result, VmkatzError};
use crate::lsass::types::Arch;
use crate::memory::VirtualMemory;
use crate::windows::peb::LoadedModule;

// ── Minidump constants ──────────────────────────────────────────────────────

const MDMP_SIGNATURE: u32 = 0x504D_444D; // "MDMP"
const STREAM_TYPE_SYSTEM_INFO: u32 = 7;
const STREAM_TYPE_MODULE_LIST: u32 = 4;
const STREAM_TYPE_MEMORY64_LIST: u32 = 9;

// ── Parsed structures ───────────────────────────────────────────────────────

/// Parsed minidump file ready for virtual memory reads.
pub struct Minidump {
    /// Raw file data (memory-mapped or loaded).
    data: Vec<u8>,
    /// Sorted list of (start_va, size, file_offset) for memory regions.
    regions: Vec<MemRegion>,
    /// B-tree mapping start_va → region index for fast lookup.
    region_index: BTreeMap<u64, usize>,
    /// Loaded modules from ModuleListStream.
    pub modules: Vec<LoadedModule>,
    /// Windows build number from SystemInfoStream.
    pub build_number: u32,
    /// Major OS version.
    pub major_version: u32,
    /// Minor OS version.
    pub minor_version: u32,
    /// Processor architecture (from SYSTEM_INFO).
    pub arch: Arch,
    /// Cached last region index for spatial locality optimization.
    last_region: Cell<usize>,
}

#[derive(Debug, Clone)]
struct MemRegion {
    start_va: u64,
    size: u64,
    file_offset: u64,
}

// ── Parsing ─────────────────────────────────────────────────────────────────

impl Minidump {
    /// Open and parse a minidump file.
    pub fn open(path: &Path) -> Result<Self> {
        let data = std::fs::read(path).map_err(VmkatzError::Io)?;
        Self::parse(data)
    }

    /// Number of memory regions in the dump.
    pub const fn region_count(&self) -> usize {
        self.regions.len()
    }

    /// Return all memory region VA ranges as (start_va, size) pairs.
    /// Used for fallback credential scanning over all dump regions.
    pub fn region_ranges(&self) -> Vec<(u64, u64)> {
        self.regions.iter().map(|r| (r.start_va, r.size)).collect()
    }

    /// Parse minidump from raw bytes.
    pub fn parse(data: Vec<u8>) -> Result<Self> {
        if data.len() < 32 {
            return Err(VmkatzError::InvalidMagic(0));
        }

        let signature = crate::utils::read_u32_le(&data, 0).unwrap_or(0);
        if signature != MDMP_SIGNATURE {
            return Err(VmkatzError::InvalidMagic(signature));
        }

        // Header fields
        let num_streams = crate::utils::read_u32_le(&data, 8).unwrap_or(0);
        let stream_dir_rva = crate::utils::read_u32_le(&data, 12).unwrap_or(0) as usize;

        let mut modules = Vec::new();
        let mut regions = Vec::new();
        let mut build_number = 0u32;
        let mut major_version = 0u32;
        let mut minor_version = 0u32;
        let mut processor_arch = 9u16; // default AMD64

        // Parse stream directory
        for i in 0..num_streams as usize {
            let entry_off = stream_dir_rva + i * 12;
            if entry_off + 12 > data.len() {
                break;
            }
            let stream_type = read_u32(&data, entry_off);
            let stream_size = read_u32(&data, entry_off + 4) as usize;
            let stream_rva = read_u32(&data, entry_off + 8) as usize;

            if stream_rva + stream_size > data.len() {
                log::warn!("Minidump stream {i} (type {stream_type}) extends past EOF, skipping");
                continue;
            }

            match stream_type {
                STREAM_TYPE_SYSTEM_INFO => {
                    if stream_size >= 24 {
                        // ProcessorArchitecture at offset 0 (u16): 0=i386, 9=AMD64
                        processor_arch = read_u16(&data, stream_rva);
                        major_version = read_u32(&data, stream_rva + 8);
                        minor_version = read_u32(&data, stream_rva + 12);
                        build_number = read_u32(&data, stream_rva + 16);
                    }
                }
                STREAM_TYPE_MODULE_LIST => {
                    modules = parse_module_list(&data, stream_rva);
                }
                STREAM_TYPE_MEMORY64_LIST => {
                    regions = parse_memory64_list(&data, stream_rva, stream_size);
                }
                _ => {
                    // ThreadListStream, ExceptionStream, etc. — not needed for credential extraction
                }
            }
        }

        // Build B-tree index for fast VA lookup
        let mut region_index = BTreeMap::new();
        for (i, r) in regions.iter().enumerate() {
            region_index.insert(r.start_va, i);
        }

        let arch = if processor_arch == 0 {
            Arch::X86
        } else {
            Arch::X64
        };

        log::info!(
            "Minidump: {} memory regions, {} modules, build {}, arch={:?}",
            regions.len(),
            modules.len(),
            build_number,
            arch,
        );

        Ok(Self {
            data,
            regions,
            region_index,
            modules,
            build_number,
            major_version,
            minor_version,
            arch,
            last_region: Cell::new(0),
        })
    }

    /// Find the memory region containing `va` and return (region, offset within region).
    /// Uses a cached last-hit index to exploit spatial locality in struct walking.
    fn find_region(&self, va: u64) -> Option<(&MemRegion, u64)> {
        // Fast path: check cached region first (high hit rate during struct field reads)
        let cached = self.last_region.get();
        if cached < self.regions.len() {
            let r = &self.regions[cached];
            if va >= r.start_va {
                let offset = va - r.start_va;
                if offset < r.size {
                    return Some((r, offset));
                }
            }
        }

        // Slow path: BTreeMap lookup
        let (&start, &idx) = self.region_index.range(..=va).next_back()?;
        let region = &self.regions[idx];
        let offset = va - start;
        if offset < region.size {
            self.last_region.set(idx);
            Some((region, offset))
        } else {
            None
        }
    }
}

impl VirtualMemory for Minidump {
    fn read_virt(&self, vaddr: u64, buf: &mut [u8]) -> Result<()> {
        let len = buf.len();
        let mut bytes_read = 0;

        while bytes_read < len {
            let current_va = vaddr + bytes_read as u64;
            let (region, offset) = self
                .find_region(current_va)
                .ok_or(VmkatzError::PageFault(current_va, "minidump"))?;

            let Some(file_off) = region.file_offset.checked_add(offset) else {
                return Err(VmkatzError::PageFault(current_va, "minidump-overflow"));
            };
            let available = (region.size - offset) as usize;
            let to_copy = (len - bytes_read).min(available);

            let end = (file_off as usize).saturating_add(to_copy);
            if end > self.data.len() {
                return Err(VmkatzError::PageFault(current_va, "minidump-eof"));
            }

            buf[bytes_read..bytes_read + to_copy]
                .copy_from_slice(&self.data[file_off as usize..end]);
            bytes_read += to_copy;
        }

        Ok(())
    }
}

// ── Stream parsers ──────────────────────────────────────────────────────────

/// Parse MINIDUMP_MODULE_LIST (stream type 4).
fn parse_module_list(data: &[u8], rva: usize) -> Vec<LoadedModule> {
    let mut modules = Vec::new();
    if rva + 4 > data.len() {
        return modules;
    }

    let count = read_u32(data, rva) as usize;
    // Cap module count to prevent excessive iteration on malformed dumps
    if count > 4096 {
        log::warn!("Module count {count} too large, capping at 4096");
        return modules;
    }
    let entries_start = rva + 4;

    for i in 0..count {
        let Some(off) = entries_start.checked_add(i.saturating_mul(108)) else {
            break;
        };
        if off + 108 > data.len() {
            break;
        }

        let base = read_u64(data, off);
        let size = read_u32(data, off + 8);
        // MINIDUMP_MODULE layout: BaseOfImage(8) + SizeOfImage(4) + CheckSum(4) +
        // TimeDateStamp(4) + ModuleNameRva(4) at offset 20
        let name_rva = read_u32(data, off + 20) as usize;

        let full_name = read_minidump_string(data, name_rva);
        let base_name = full_name
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(&full_name)
            .to_lowercase();

        modules.push(LoadedModule {
            base,
            size,
            full_name,
            base_name,
        });
    }

    modules
}

/// Parse MINIDUMP_MEMORY64_LIST (stream type 9).
///
/// Layout:
/// - NumberOfMemoryRanges: u64
/// - BaseRva: u64 (file offset where the first memory region's data starts)
/// - N * MINIDUMP_MEMORY_DESCRIPTOR64: (StartOfMemoryRange: u64, DataSize: u64)
fn parse_memory64_list(data: &[u8], rva: usize, _stream_size: usize) -> Vec<MemRegion> {
    let mut regions = Vec::new();
    if rva + 16 > data.len() {
        return regions;
    }

    let count = read_u64(data, rva) as usize;
    // Cap region count to prevent excessive iteration on malformed dumps
    if count > 1_000_000 {
        log::warn!("Memory64 region count {count} too large, capping");
        return regions;
    }
    let base_rva = read_u64(data, rva + 8);

    let descs_start = rva + 16;
    let mut current_file_offset = base_rva;

    for i in 0..count {
        let Some(desc_off) = descs_start.checked_add(i.saturating_mul(16)) else {
            break;
        };
        if desc_off + 16 > data.len() {
            break;
        }

        let start_va = read_u64(data, desc_off);
        let size = read_u64(data, desc_off + 8);

        regions.push(MemRegion {
            start_va,
            size,
            file_offset: current_file_offset,
        });

        current_file_offset = match current_file_offset.checked_add(size) {
            Some(v) => v,
            None => break, // overflow — bail out
        };
    }

    regions
}

/// Read a MINIDUMP_STRING (Length: u32 in bytes, then UTF-16LE data).
fn read_minidump_string(data: &[u8], rva: usize) -> String {
    if rva + 4 > data.len() {
        return String::new();
    }
    let byte_len = read_u32(data, rva) as usize;
    let str_start = rva + 4;
    if str_start + byte_len > data.len() || byte_len == 0 {
        return String::new();
    }
    crate::utils::utf16le_decode(&data[str_start..str_start + byte_len])
}

// ── Helpers (delegate to crate::utils, defaulting to 0 on failure) ──────────

fn read_u16(data: &[u8], off: usize) -> u16 {
    crate::utils::read_u16_le(data, off).unwrap_or(0)
}

fn read_u32(data: &[u8], off: usize) -> u32 {
    crate::utils::read_u32_le(data, off).unwrap_or(0)
}

fn read_u64(data: &[u8], off: usize) -> u64 {
    crate::utils::read_u64_le(data, off).unwrap_or(0)
}
