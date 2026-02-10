//! File-backed page resolution for demand-paged DLL sections.
//!
//! When Windows removes DLL .text pages from the working set, it zeros the PTE
//! knowing the data can be re-read from the DLL file on disk. This module reads
//! DLL files from a disk image via NTFS and serves those pages on zero-PTE faults.

use std::cell::Cell;
use std::io::{Read, Seek};
use std::path::Path;

use crate::disk;
use crate::error::{GovmemError, Result};
use crate::windows::peb::LoadedModule;

/// IMAGE_SCN_MEM_WRITE — skip writable sections (in-memory content differs from disk).
const SCN_MEM_WRITE: u32 = 0x8000_0000;

/// Pre-read DLL section mapped to a virtual address range.
struct BackedSection {
    va_start: u64,
    data: Vec<u8>, // page-aligned size
}

/// Resolves demand-paged DLL pages by serving data from on-disk PE files.
pub struct FileBackedResolver {
    sections: Vec<BackedSection>, // sorted by va_start
    total_bytes: usize,
    pages_resolved: Cell<u64>,
}

impl FileBackedResolver {
    /// Build a resolver by reading DLL files from a disk image's NTFS System32.
    pub fn from_disk_and_modules(disk_path: &Path, modules: &[LoadedModule]) -> Result<Self> {
        let mut disk = disk::open_disk(disk_path)?;
        let partitions = crate::sam::find_ntfs_partitions(&mut disk)?;

        let mut sections = Vec::new();

        for &partition_offset in &partitions {
            match Self::try_load_from_partition(&mut disk, partition_offset, modules, &mut sections)
            {
                Ok(()) => break,
                Err(e) => {
                    log::debug!(
                        "File-backed: partition 0x{:x}: {}",
                        partition_offset,
                        e
                    );
                }
            }
        }

        let total_bytes: usize = sections.iter().map(|s| s.data.len()).sum();
        sections.sort_by_key(|s| s.va_start);

        Ok(Self {
            sections,
            total_bytes,
            pages_resolved: Cell::new(0),
        })
    }

    fn try_load_from_partition(
        disk: &mut Box<dyn disk::DiskImage>,
        partition_offset: u64,
        modules: &[LoadedModule],
        sections: &mut Vec<BackedSection>,
    ) -> Result<()> {
        let mut part_reader = crate::sam::PartitionReader::new(disk, partition_offset);

        let ntfs = ntfs::Ntfs::new(&mut part_reader)
            .map_err(|e| GovmemError::DecryptionError(format!("NTFS: {}", e)))?;
        let root = ntfs
            .root_directory(&mut part_reader)
            .map_err(|e| GovmemError::DecryptionError(format!("NTFS root: {}", e)))?;

        // Navigate to Windows\System32
        let windows = crate::sam::find_entry(&ntfs, &root, &mut part_reader, "Windows")?;
        let sys32 = crate::sam::find_entry(&ntfs, &windows, &mut part_reader, "System32")?;

        let mut loaded_count = 0usize;
        for module in modules {
            let dll_name = &module.base_name;
            if dll_name.is_empty() {
                continue;
            }

            match crate::sam::find_entry(&ntfs, &sys32, &mut part_reader, dll_name) {
                Ok(file) => {
                    match Self::read_pe_sections(&file, &mut part_reader, module.base) {
                        Ok(secs) => {
                            let bytes: usize = secs.iter().map(|s| s.data.len()).sum();
                            log::debug!(
                                "File-backed: {} @ 0x{:x}: {} sections, {} KB",
                                dll_name,
                                module.base,
                                secs.len(),
                                bytes / 1024
                            );
                            loaded_count += 1;
                            sections.extend(secs);
                        }
                        Err(e) => {
                            log::debug!("File-backed: {} PE parse: {}", dll_name, e);
                        }
                    }
                }
                Err(_) => {
                    log::debug!("File-backed: {} not in System32", dll_name);
                }
            }
        }

        if loaded_count > 0 {
            Ok(())
        } else {
            Err(GovmemError::DecryptionError(
                "No DLLs found on disk".to_string(),
            ))
        }
    }

    /// Read PE file from NTFS and extract non-writable section data.
    fn read_pe_sections<R: Read + Seek>(
        file: &ntfs::NtfsFile,
        reader: &mut R,
        module_base: u64,
    ) -> Result<Vec<BackedSection>> {
        let pe_data = crate::sam::read_file_data(file, reader)?;
        Self::parse_pe_sections(&pe_data, module_base)
    }

    /// Parse PE headers, return non-writable sections mapped to module_base.
    fn parse_pe_sections(pe_data: &[u8], module_base: u64) -> Result<Vec<BackedSection>> {
        if pe_data.len() < 0x40 {
            return Err(GovmemError::DecryptionError("PE too small".to_string()));
        }

        // DOS header
        if u16::from_le_bytes([pe_data[0], pe_data[1]]) != 0x5A4D {
            return Err(GovmemError::DecryptionError("Not a PE (no MZ)".to_string()));
        }
        let e_lfanew = u32::from_le_bytes(pe_data[0x3C..0x40].try_into().unwrap()) as usize;
        if e_lfanew + 24 > pe_data.len() {
            return Err(GovmemError::DecryptionError("Invalid e_lfanew".to_string()));
        }

        // PE signature
        if u32::from_le_bytes(pe_data[e_lfanew..e_lfanew + 4].try_into().unwrap()) != 0x0000_4550
        {
            return Err(GovmemError::DecryptionError(
                "Invalid PE signature".to_string(),
            ));
        }

        // COFF header
        let num_sections =
            u16::from_le_bytes(pe_data[e_lfanew + 6..e_lfanew + 8].try_into().unwrap()) as usize;
        let opt_hdr_size = u16::from_le_bytes(
            pe_data[e_lfanew + 20..e_lfanew + 22].try_into().unwrap(),
        ) as usize;

        let section_table = e_lfanew + 24 + opt_hdr_size;
        let mut sections = Vec::new();

        for i in 0..num_sections {
            let off = section_table + i * 40;
            if off + 40 > pe_data.len() {
                break;
            }

            let virt_size =
                u32::from_le_bytes(pe_data[off + 8..off + 12].try_into().unwrap()) as usize;
            let virt_addr =
                u32::from_le_bytes(pe_data[off + 12..off + 16].try_into().unwrap()) as u64;
            let raw_size =
                u32::from_le_bytes(pe_data[off + 16..off + 20].try_into().unwrap()) as usize;
            let raw_offset =
                u32::from_le_bytes(pe_data[off + 20..off + 24].try_into().unwrap()) as usize;
            let characteristics =
                u32::from_le_bytes(pe_data[off + 36..off + 40].try_into().unwrap());

            // Skip writable sections (in-memory content modified by process)
            if characteristics & SCN_MEM_WRITE != 0 {
                continue;
            }
            if raw_size == 0 || raw_offset == 0 || virt_size == 0 {
                continue;
            }
            if raw_offset.saturating_add(raw_size) > pe_data.len() {
                continue;
            }

            // Copy raw data, page-aligned to VirtualSize
            let copy_size = std::cmp::min(raw_size, virt_size);
            let padded_size = (virt_size + 0xFFF) & !0xFFF;
            let mut data = vec![0u8; padded_size];
            data[..copy_size].copy_from_slice(&pe_data[raw_offset..raw_offset + copy_size]);

            sections.push(BackedSection {
                va_start: module_base + virt_addr,
                data,
            });
        }

        Ok(sections)
    }

    /// Resolve a page from file-backed DLL data. Returns page contents if the
    /// virtual address falls within a known non-writable DLL section.
    pub fn resolve_page(&self, vaddr: u64) -> Option<[u8; 4096]> {
        let page_base = vaddr & !0xFFF;

        let idx = match self.sections.binary_search_by(|s| {
            let s_end = s.va_start + s.data.len() as u64;
            if page_base < s.va_start {
                std::cmp::Ordering::Greater
            } else if page_base >= s_end {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        }) {
            Ok(i) => i,
            Err(_) => return None,
        };

        let section = &self.sections[idx];
        let offset = (page_base - section.va_start) as usize;
        if offset + 4096 > section.data.len() {
            return None;
        }

        let mut page = [0u8; 4096];
        page.copy_from_slice(&section.data[offset..offset + 4096]);
        self.pages_resolved.set(self.pages_resolved.get() + 1);
        Some(page)
    }

    pub fn pages_resolved(&self) -> u64 {
        self.pages_resolved.get()
    }

    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub fn section_count(&self) -> usize {
        self.sections.len()
    }
}
