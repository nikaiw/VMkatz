use std::cell::RefCell;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use ntfs::attribute_value::NtfsAttributeValue;

use crate::disk::{self, DiskImage};
use crate::error::{Result, VmkatzError};
use crate::paging::entry::PageTableEntry;

/// Maximum number of pagefiles Windows supports (0-15).
const MAX_PAGEFILES: usize = 16;

/// Pre-built data run map entry mapping pagefile byte ranges to absolute disk positions.
struct PagefileDataRun {
    file_offset: u64,
    disk_offset: u64,
    length: u64,
}

/// Per-file state for a single pagefile (pagefile.sys, pagefile2.sys, etc.).
struct SinglePagefile {
    data_runs: Vec<PagefileDataRun>,
    pagefile_size: u64,
}

/// Reads pages from Windows pagefiles on a virtual disk image.
///
/// Supports up to 16 pagefiles (pagefile.sys as #0, pagefile2.sys through
/// pagefile16.sys as #1-15). Pre-extracts NTFS data runs at construction time
/// to avoid keeping ntfs crate types alive (which would create self-referential
/// struct issues). Uses RefCell for interior mutability since read_virt(&self)
/// is immutable but disk seeks need &mut.
pub struct PagefileReader {
    disk: RefCell<Box<dyn DiskImage>>,
    pagefiles: Vec<Option<SinglePagefile>>, // indexed by pagefile number (0-15)
    pages_resolved: std::cell::Cell<u64>,
}

impl PagefileReader {
    /// Open pagefiles from a disk image, extracting NTFS data runs.
    ///
    /// The primary pagefile.sys (#0) is required. Secondary pagefiles
    /// (pagefile2.sys through pagefile16.sys, #1-15) are optional and
    /// extremely rare in practice.
    pub fn open(disk_path: &Path) -> Result<Self> {
        let mut disk = disk::open_disk(disk_path)?;

        // Primary pagefile.sys is required
        let primary = extract_named_pagefile_data_runs(&mut disk, "pagefile.sys")?;
        log::info!(
            "Pagefile #0: {:.1} MB, {} data runs",
            primary.pagefile_size as f64 / (1024.0 * 1024.0),
            primary.data_runs.len()
        );

        let mut pagefiles: Vec<Option<SinglePagefile>> = Vec::with_capacity(MAX_PAGEFILES);
        pagefiles.push(Some(primary));

        // Try secondary pagefiles #1-15 (optional)
        for i in 1..MAX_PAGEFILES {
            let filename = format!("pagefile{}.sys", i + 1);
            match extract_named_pagefile_data_runs(&mut disk, &filename) {
                Ok(pf) => {
                    log::info!(
                        "Pagefile #{}: {:.1} MB, {} data runs ({})",
                        i,
                        pf.pagefile_size as f64 / (1024.0 * 1024.0),
                        pf.data_runs.len(),
                        filename
                    );
                    pagefiles.push(Some(pf));
                }
                Err(e) => {
                    log::debug!("No {filename}: {e}");
                    pagefiles.push(None);
                }
            }
        }

        Ok(Self {
            disk: RefCell::new(disk),
            pagefiles,
            pages_resolved: std::cell::Cell::new(0),
        })
    }

    /// Total size across all open pagefiles.
    pub fn pagefile_size(&self) -> u64 {
        self.pagefiles
            .iter()
            .filter_map(|pf| pf.as_ref())
            .map(|pf| pf.pagefile_size)
            .sum()
    }

    pub const fn pages_resolved(&self) -> u64 {
        self.pages_resolved.get()
    }

    /// Read a 4KB page from the specified pagefile's data runs.
    fn read_page_internal(&self, pf: &SinglePagefile, byte_offset: u64) -> Result<[u8; 4096]> {
        if byte_offset + 4096 > pf.pagefile_size {
            return Err(VmkatzError::DecryptionError(format!(
                "Pagefile offset 0x{:x} + 4096 exceeds size 0x{:x}",
                byte_offset, pf.pagefile_size
            )));
        }

        // Binary search for the data run containing this offset
        let Ok(idx) = pf.data_runs.binary_search_by(|run| {
            if byte_offset < run.file_offset {
                std::cmp::Ordering::Greater
            } else if byte_offset >= run.file_offset + run.length {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        }) else {
            // Sparse region: return zeros
            return Ok([0u8; 4096]);
        };

        let run = &pf.data_runs[idx];
        let run_offset = byte_offset - run.file_offset;
        let disk_pos = run.disk_offset + run_offset;

        let mut disk = self.disk.borrow_mut();
        disk.seek(SeekFrom::Start(disk_pos))?;
        let mut buf = [0u8; 4096];
        disk.read_exact(&mut buf)?;

        self.pages_resolved.set(self.pages_resolved.get() + 1);
        Ok(buf)
    }

    /// Resolve a pagefile PTE: route to the correct pagefile by number and read the page.
    pub fn resolve_pte(&self, raw_pte: u64) -> Option<[u8; 4096]> {
        let pte = PageTableEntry(raw_pte);
        if !pte.is_pagefile() {
            return None;
        }
        let pf_num = pte.pagefile_number() as usize;
        let pf = self.pagefiles.get(pf_num)?.as_ref()?;
        self.read_page_internal(pf, pte.pagefile_offset()).ok()
    }
}

/// Extract data runs for a named pagefile from the disk image.
///
/// Searches all NTFS partitions for the given filename (e.g. "pagefile.sys",
/// "pagefile2.sys") in the root directory.
fn extract_named_pagefile_data_runs(
    disk: &mut Box<dyn DiskImage>,
    filename: &str,
) -> Result<SinglePagefile> {
    let partitions = crate::sam::find_ntfs_partitions(disk)?;

    for &partition_offset in &partitions {
        match try_extract_from_partition(disk, partition_offset, filename) {
            Ok(result) => return Ok(result),
            Err(e) => {
                log::debug!("No {filename} at partition 0x{partition_offset:x}: {e}");
            }
        }
    }

    Err(VmkatzError::DecryptionError(format!(
        "{filename} not found on any NTFS partition"
    )))
}

/// Try to extract pagefile data runs from a specific NTFS partition.
fn try_extract_from_partition(
    disk: &mut Box<dyn DiskImage>,
    partition_offset: u64,
    filename: &str,
) -> Result<SinglePagefile> {
    let mut part_reader = crate::sam::PartitionReader::new(disk, partition_offset);

    let ntfs = ntfs::Ntfs::new(&mut part_reader)
        .map_err(|e| VmkatzError::DecryptionError(format!("NTFS parse error: {e}")))?;

    let root = ntfs
        .root_directory(&mut part_reader)
        .map_err(|e| VmkatzError::DecryptionError(format!("NTFS root dir error: {e}")))?;

    let pagefile_entry = crate::sam::find_entry(&ntfs, &root, &mut part_reader, filename)?;

    let data_item = pagefile_entry
        .data(&mut part_reader, "")
        .ok_or_else(|| VmkatzError::DecryptionError(format!("{filename}: no $DATA attribute")))?
        .map_err(|e| VmkatzError::DecryptionError(format!("{filename} $DATA error: {e}")))?;

    let data_attr = data_item
        .to_attribute()
        .map_err(|e| VmkatzError::DecryptionError(format!("{filename} to_attribute error: {e}")))?;

    let data_value = data_attr
        .value(&mut part_reader)
        .map_err(|e| VmkatzError::DecryptionError(format!("{filename} value error: {e}")))?;

    let pagefile_size = data_value.len();

    // Extract data runs from non-resident attribute
    match data_value {
        NtfsAttributeValue::NonResident(nr) => {
            let mut runs = Vec::new();
            let mut cumulative_offset = 0u64;

            for run_result in nr.data_runs() {
                let run = run_result.map_err(|e| {
                    VmkatzError::DecryptionError(format!("{filename} data run error: {e}"))
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

            Ok(SinglePagefile {
                data_runs: runs,
                pagefile_size,
            })
        }
        _ => Err(VmkatzError::DecryptionError(format!(
            "{filename}: $DATA is not non-resident (unexpected for a pagefile)"
        ))),
    }
}
