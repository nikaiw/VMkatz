use std::cell::RefCell;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use ntfs::attribute_value::NtfsAttributeValue;

use crate::disk::{self, DiskImage};
use crate::error::{GovmemError, Result};
use crate::paging::entry::PageTableEntry;

/// Pre-built data run map entry mapping pagefile byte ranges to absolute disk positions.
struct PagefileDataRun {
    file_offset: u64,
    disk_offset: u64,
    length: u64,
}

/// Reads pages from pagefile.sys on a virtual disk image.
///
/// Pre-extracts NTFS data runs at construction time to avoid keeping ntfs crate
/// types alive (which would create self-referential struct issues). Uses RefCell
/// for interior mutability since read_virt(&self) is immutable but disk seeks need &mut.
pub struct PagefileReader {
    disk: RefCell<Box<dyn DiskImage>>,
    data_runs: Vec<PagefileDataRun>,
    pagefile_size: u64,
    pages_resolved: std::cell::Cell<u64>,
}

impl PagefileReader {
    /// Open pagefile.sys from a disk image, extracting its NTFS data runs.
    pub fn open(disk_path: &Path) -> Result<Self> {
        let mut disk = disk::open_disk(disk_path)?;
        let (data_runs, pagefile_size) = extract_pagefile_data_runs(&mut disk)?;

        log::info!(
            "Pagefile: {:.1} MB, {} data runs",
            pagefile_size as f64 / (1024.0 * 1024.0),
            data_runs.len()
        );

        Ok(Self {
            disk: RefCell::new(disk),
            data_runs,
            pagefile_size,
            pages_resolved: std::cell::Cell::new(0),
        })
    }

    pub fn pagefile_size(&self) -> u64 {
        self.pagefile_size
    }

    pub fn pages_resolved(&self) -> u64 {
        self.pages_resolved.get()
    }

    /// Read a 4KB page from the pagefile at the given byte offset.
    pub fn read_page(&self, byte_offset: u64) -> Result<[u8; 4096]> {
        if byte_offset + 4096 > self.pagefile_size {
            return Err(GovmemError::DecryptionError(format!(
                "Pagefile offset 0x{:x} + 4096 exceeds size 0x{:x}",
                byte_offset, self.pagefile_size
            )));
        }

        // Binary search for the data run containing this offset
        let idx = match self.data_runs.binary_search_by(|run| {
            if byte_offset < run.file_offset {
                std::cmp::Ordering::Greater
            } else if byte_offset >= run.file_offset + run.length {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        }) {
            Ok(i) => i,
            Err(_) => {
                // Sparse region: return zeros
                return Ok([0u8; 4096]);
            }
        };

        let run = &self.data_runs[idx];
        let run_offset = byte_offset - run.file_offset;
        let disk_pos = run.disk_offset + run_offset;

        let mut disk = self.disk.borrow_mut();
        disk.seek(SeekFrom::Start(disk_pos))?;
        let mut buf = [0u8; 4096];
        disk.read_exact(&mut buf)?;

        self.pages_resolved.set(self.pages_resolved.get() + 1);
        Ok(buf)
    }

    /// Resolve a pagefile PTE: check if it points to pagefile #0 and read the page.
    pub fn resolve_pte(&self, raw_pte: u64) -> Option<[u8; 4096]> {
        let pte = PageTableEntry(raw_pte);
        if !pte.is_pagefile() || pte.pagefile_number() != 0 {
            return None;
        }
        self.read_page(pte.pagefile_offset()).ok()
    }
}

/// Extract pagefile.sys data runs from the disk image.
fn extract_pagefile_data_runs(
    disk: &mut Box<dyn DiskImage>,
) -> Result<(Vec<PagefileDataRun>, u64)> {
    let partitions = crate::sam::find_ntfs_partitions(disk)?;

    for &partition_offset in &partitions {
        match try_extract_from_partition(disk, partition_offset) {
            Ok(result) => return Ok(result),
            Err(e) => {
                log::debug!("No pagefile at partition 0x{:x}: {}", partition_offset, e);
            }
        }
    }

    Err(GovmemError::DecryptionError(
        "pagefile.sys not found on any NTFS partition".to_string(),
    ))
}

/// Try to extract pagefile.sys data runs from a specific NTFS partition.
fn try_extract_from_partition(
    disk: &mut Box<dyn DiskImage>,
    partition_offset: u64,
) -> Result<(Vec<PagefileDataRun>, u64)> {
    let mut part_reader = crate::sam::PartitionReader::new(disk, partition_offset);

    let ntfs = ntfs::Ntfs::new(&mut part_reader)
        .map_err(|e| GovmemError::DecryptionError(format!("NTFS parse error: {}", e)))?;

    let root = ntfs
        .root_directory(&mut part_reader)
        .map_err(|e| GovmemError::DecryptionError(format!("NTFS root dir error: {}", e)))?;

    let pagefile = crate::sam::find_entry(&ntfs, &root, &mut part_reader, "pagefile.sys")?;

    let data_item = pagefile
        .data(&mut part_reader, "")
        .ok_or_else(|| {
            GovmemError::DecryptionError("pagefile.sys: no $DATA attribute".to_string())
        })?
        .map_err(|e| GovmemError::DecryptionError(format!("pagefile.sys $DATA error: {}", e)))?;

    let data_attr = data_item.to_attribute().map_err(|e| {
        GovmemError::DecryptionError(format!("pagefile.sys to_attribute error: {}", e))
    })?;

    let data_value = data_attr
        .value(&mut part_reader)
        .map_err(|e| GovmemError::DecryptionError(format!("pagefile.sys value error: {}", e)))?;

    let pagefile_size = data_value.len();

    // Extract data runs from non-resident attribute
    match data_value {
        NtfsAttributeValue::NonResident(nr) => {
            let mut runs = Vec::new();
            let mut cumulative_offset = 0u64;

            for run_result in nr.data_runs() {
                let run = run_result.map_err(|e| {
                    GovmemError::DecryptionError(format!("pagefile.sys data run error: {}", e))
                })?;

                let allocated = run.allocated_size();

                if let Some(pos) = run.data_position().value() {
                    runs.push(PagefileDataRun {
                        file_offset: cumulative_offset,
                        disk_offset: partition_offset + pos.get(),
                        length: allocated,
                    });
                }

                cumulative_offset += allocated;
            }

            Ok((runs, pagefile_size))
        }
        _ => Err(GovmemError::DecryptionError(
            "pagefile.sys: $DATA is not non-resident (unexpected for a pagefile)".to_string(),
        )),
    }
}
