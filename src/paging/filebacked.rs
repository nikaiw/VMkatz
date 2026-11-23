//! File-backed page resolution for demand-paged DLL sections.
//!
//! When Windows removes DLL .text pages from the working set, it zeros the PTE
//! knowing the data can be re-read from the DLL file on disk. This module reads
//! DLL files from a disk image via NTFS and serves those pages on zero-PTE faults.

use std::cell::Cell;
use std::io::{Read, Seek};
use std::path::Path;

use crate::disk;
use crate::error::{Result, VmkatzError};
use crate::utils::{u16_le, u32_le};
use crate::windows::peb::LoadedModule;

/// IMAGE_SCN_MEM_WRITE — skip writable sections (in-memory content differs from disk).
const SCN_MEM_WRITE: u32 = 0x8000_0000;
const MAX_SECTION_BYTES: usize = 128 * 1024 * 1024;

#[cfg(test)]
mod tests;

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
        let partitions = crate::fs::find_ntfs_partitions(&mut disk)?;

        let mut sections = Vec::new();

        for &partition_offset in &partitions {
            match Self::try_load_from_partition(&mut disk, partition_offset, modules, &mut sections)
            {
                Ok(()) => break,
                Err(e) if e.is_resource_limit() => return Err(e),
                Err(e) => {
                    log::debug!("File-backed: partition 0x{partition_offset:x}: {e}");
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
        let mut part_reader = crate::fs::PartitionReader::new(disk, partition_offset);

        let ntfs = ntfs::Ntfs::new(&mut part_reader)
            .map_err(|e| VmkatzError::DecryptionError(format!("NTFS: {e}")))?;
        let root = ntfs
            .root_directory(&mut part_reader)
            .map_err(|e| VmkatzError::DecryptionError(format!("NTFS root: {e}")))?;

        // Navigate to Windows\System32
        let windows = crate::fs::find_entry(&ntfs, &root, &mut part_reader, "Windows")?;
        let sys32 = crate::fs::find_entry(&ntfs, &windows, &mut part_reader, "System32")?;

        let mut loaded_count = 0usize;
        for module in modules {
            let dll_name = &module.base_name;
            if dll_name.is_empty() {
                continue;
            }

            match crate::fs::find_entry(&ntfs, &sys32, &mut part_reader, dll_name) {
                Ok(file) => match Self::read_pe_sections(
                    &file,
                    &mut part_reader,
                    module.base,
                    MAX_SECTION_BYTES - sections.iter().map(|s| s.data.len()).sum::<usize>(),
                ) {
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
                    Err(e) if e.is_resource_limit() => return Err(e),
                    Err(e) => {
                        log::debug!("File-backed: {dll_name} PE parse: {e}");
                    }
                },
                Err(_) => {
                    log::debug!("File-backed: {dll_name} not in System32");
                }
            }
        }

        if loaded_count > 0 {
            Ok(())
        } else {
            Err(VmkatzError::DecryptionError(
                "No DLLs found on disk".to_string(),
            ))
        }
    }

    /// Read only PE headers and retained sections, sharing a budget across DLLs.
    fn read_pe_sections<R: Read + Seek>(
        file: &ntfs::NtfsFile,
        reader: &mut R,
        module_base: u64,
        budget: usize,
    ) -> Result<Vec<BackedSection>> {
        crate::fs::with_file_data(file, reader, |stream, len| {
            let mut stream = crate::fs::ntfs::ResilientReader::new(stream, len);
            Self::read_sections(&mut stream, len, module_base, budget)
        })
    }

    fn read_sections<R: Read + Seek>(
        reader: &mut R,
        len: u64,
        module_base: u64,
        mut budget: usize,
    ) -> Result<Vec<BackedSection>> {
        use std::io::SeekFrom;
        let mut dos = [0; 64];
        reader.seek(SeekFrom::Start(0))?;
        reader.read_exact(&mut dos)?;
        if u16_le(&dos, 0) != 0x5A4D {
            return Err(VmkatzError::DecryptionError("Not a PE (no MZ)".into()));
        }
        let pe_offset = u64::from(u32_le(&dos, 0x3C));
        if pe_offset + 24 > len {
            return Err(VmkatzError::DecryptionError("Invalid e_lfanew".into()));
        }
        let mut header = [0; 24];
        reader.seek(SeekFrom::Start(pe_offset))?;
        reader.read_exact(&mut header)?;
        if u32_le(&header, 0) != 0x0000_4550 {
            return Err(VmkatzError::DecryptionError("Invalid PE signature".into()));
        }
        let count = u64::from(u16_le(&header, 6));
        let section_table = pe_offset + 24 + u64::from(u16_le(&header, 20));
        let mut sections = Vec::new();
        for i in 0..count {
            let offset = section_table + i * 40;
            if offset + 40 > len {
                break;
            }
            let mut section = [0; 40];
            reader.seek(SeekFrom::Start(offset))?;
            reader.read_exact(&mut section)?;
            if u32_le(&section, 36) & SCN_MEM_WRITE != 0 {
                continue;
            }
            let virt_size = u64::from(u32_le(&section, 8));
            let raw_size = u64::from(u32_le(&section, 16));
            let raw_offset = u64::from(u32_le(&section, 20));
            if virt_size == 0 || raw_size == 0 || raw_offset == 0 || raw_offset + raw_size > len {
                continue;
            }
            let padded = (virt_size + 0xFFF) & !0xFFF;
            if padded > budget as u64 {
                return Err(VmkatzError::AllocTooLarge {
                    what: "file-backed DLL sections",
                    requested: usize::try_from(padded).unwrap_or(usize::MAX),
                    limit: budget,
                });
            }
            let va_start = module_base
                .checked_add(u64::from(u32_le(&section, 12)))
                .filter(|start| start.checked_add(padded).is_some())
                .ok_or_else(|| {
                    VmkatzError::DecryptionError("PE section address overflow".into())
                })?;
            let mut data = crate::utils::zeroed_buffer(padded as usize)?;
            reader.seek(SeekFrom::Start(raw_offset))?;
            reader.read_exact(&mut data[..raw_size.min(virt_size) as usize])?;
            budget -= data.len();
            sections
                .try_reserve(1)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::OutOfMemory, e))?;
            sections.push(BackedSection { va_start, data });
        }
        Ok(sections)
    }

    /// Resolve a page from file-backed DLL data. Returns page contents if the
    /// virtual address falls within a known non-writable DLL section.
    pub fn resolve_page(&self, vaddr: u64) -> Option<[u8; 4096]> {
        let page_base = vaddr & !0xFFF;

        let Ok(idx) = self.sections.binary_search_by(|s| {
            let s_end = s.va_start + s.data.len() as u64;
            if page_base < s.va_start {
                std::cmp::Ordering::Greater
            } else if page_base >= s_end {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        }) else {
            return None;
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

    pub const fn pages_resolved(&self) -> u64 {
        self.pages_resolved.get()
    }

    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub const fn section_count(&self) -> usize {
        self.sections.len()
    }
}
