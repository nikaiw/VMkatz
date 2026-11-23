//! MFTMirr bootstrap, bounded traversal and target-file search.

use std::io::{Read, Seek, SeekFrom};

use crate::error::{Result, VmkatzError};
use crate::fs::recovery::ScanBudget;

#[cfg(any(feature = "sam", test))]
use super::data::{read_mft_record, try_read_file_start};
#[cfg(any(feature = "sam", test))]
use super::records::{DataRun, extract_filename};
use super::records::{NtfsParams, extract_data_attribute, fixup_file_record, parse_boot_sector};

/// Read into `buf` in block-sized chunks. On I/O error, zero-fill the failing
/// block and continue. `block_size` is the logical record size (e.g., MFT record size).
fn resilient_read_blocks<R: Read>(reader: &mut R, buf: &mut [u8], block_size: usize) {
    let mut offset = 0;
    while offset < buf.len() {
        let end = (offset + block_size).min(buf.len());
        match reader.read_exact(&mut buf[offset..end]) {
            Ok(()) => {}
            Err(_) => {
                buf[offset..end].fill(0);
            }
        }
        offset = end;
    }
}

/// MFT access bootstrapped via $MFTMirr.
pub(super) struct MftBootstrap {
    pub(super) params: NtfsParams,
    #[cfg(any(feature = "sam", test))]
    pub(super) mft_runs: Vec<DataRun>,
    /// Accessible MFT segments: (absolute offset, first record, record count)
    pub(super) accessible_segments: Vec<(u64, u64, u64)>,
}

/// Bootstrap MFT access via $MFTMirr: parse the boot sector, read the mirrored
/// $MFT record, and map which MFT segments are accessible on this disk.
pub(super) fn mftmirr_bootstrap<R: Read + Seek>(
    reader: &mut R,
    partition_offset: u64,
) -> Result<MftBootstrap> {
    // Read and parse NTFS boot sector
    reader.seek(SeekFrom::Start(partition_offset))?;
    let mut boot = [0u8; 512];
    reader.read_exact(&mut boot)?;
    let params = parse_boot_sector(&boot)?;

    log::info!(
        "MFTMirr fallback: cluster={}B, record={}B, MFT@0x{:x}, MFTMirr@0x{:x}",
        params.cluster_size,
        params.record_size,
        params.mft_position,
        params.mftmirr_position,
    );

    // Read $MFTMirr (contains copies of MFT records 0-3)
    let mftmirr_abs = partition_offset
        .checked_add(params.mftmirr_position)
        .ok_or_else(|| VmkatzError::DecryptionError("MFTMirr offset overflow".into()))?;
    reader.seek(SeekFrom::Start(mftmirr_abs)).map_err(|e| {
        VmkatzError::DecryptionError(format!("Cannot seek to MFTMirr at 0x{mftmirr_abs:x}: {e}"))
    })?;
    let mut mftmirr_data = vec![0u8; params.record_size as usize * 4];
    reader
        .read_exact(&mut mftmirr_data)
        .map_err(|e| VmkatzError::DecryptionError(format!("Cannot read MFTMirr: {e}")))?;

    // Parse record 0 ($MFT) from MFTMirr
    let mut mft_record = mftmirr_data[..params.record_size as usize].to_vec();
    if !fixup_file_record(&mut mft_record) {
        return Err(VmkatzError::DecryptionError(
            "MFTMirr: invalid $MFT record (fixup failed)".into(),
        ));
    }

    // Get $MFT data runs — tells us where all MFT data is on disk
    let (mft_runs, mft_size) = extract_data_attribute(&mft_record)
        .ok_or_else(|| VmkatzError::DecryptionError("MFTMirr: no $DATA in $MFT record".into()))?;

    let total_records = mft_size / u64::from(params.record_size);
    log::info!(
        "MFT: {} data runs, {} bytes ({} records)",
        mft_runs.len(),
        mft_size,
        total_records,
    );

    // Determine accessible MFT segments
    let mut accessible_segments: Vec<(u64, u64, u64)> = Vec::new(); // (abs_offset, first_record, num_records)
    for run in &mft_runs {
        let Some(abs_offset) = run
            .lcn_start
            .checked_mul(params.cluster_size)
            .and_then(|n| partition_offset.checked_add(n))
        else {
            continue;
        };
        let Some(vcn_bytes) = run.vcn_start.checked_mul(params.cluster_size) else {
            continue;
        };
        let first_record = vcn_bytes / u64::from(params.record_size);
        let run_bytes = run.vcn_length.saturating_mul(params.cluster_size);
        let num_records = (run_bytes / u64::from(params.record_size))
            .min(total_records.saturating_sub(first_record));
        if num_records == 0 {
            continue;
        }

        // Test accessibility by trying to seek to the segment
        // (don't require FILE signature — live VMs may have transient I/O on first record)
        let accessible = reader.seek(SeekFrom::Start(abs_offset)).is_ok();

        log::info!(
            "  MFT run: records #{}-{} at disk 0x{:x} ({})",
            first_record,
            first_record + num_records - 1,
            abs_offset,
            if accessible {
                "accessible"
            } else {
                "inaccessible"
            },
        );

        if accessible {
            accessible_segments.push((abs_offset, first_record, num_records));
        }
    }

    if accessible_segments.is_empty() {
        return Err(VmkatzError::DecryptionError(
            "MFTMirr: no accessible MFT segments found".into(),
        ));
    }

    Ok(MftBootstrap {
        params,
        #[cfg(any(feature = "sam", test))]
        mft_runs,
        accessible_segments,
    })
}

/// Visit every in-use, parseable MFT record in the accessible segments.
/// The callback receives (record number, fixed-up record) and returns `true`
/// to stop the scan early.
pub(super) fn for_each_accessible_record<R: Read + Seek>(
    reader: &mut R,
    bootstrap: &MftBootstrap,
    budget: &mut ScanBudget,
    mut visit: impl FnMut(u64, &[u8]) -> bool,
) -> Result<()> {
    let rs = bootstrap.params.record_size as usize;
    let batch_records = 256usize.min(1024 * 1024 / rs);
    for &(abs_offset, first_rec, num_recs) in &bootstrap.accessible_segments {
        let mut rec_idx = 0u64;
        while rec_idx < num_recs {
            let batch = (batch_records as u64).min(num_recs - rec_idx) as usize;
            budget.charge((batch * rs) as u64, batch as u64)?;
            let read_pos = abs_offset
                .checked_add(rec_idx.saturating_mul(rs as u64))
                .ok_or_else(|| VmkatzError::DecryptionError("MFT scan offset overflow".into()))?;
            if reader.seek(SeekFrom::Start(read_pos)).is_err() {
                rec_idx += batch as u64;
                continue;
            }
            let mut batch_data = vec![0u8; batch * rs];
            resilient_read_blocks(reader, &mut batch_data, rs);
            for i in 0..batch {
                let mut record = batch_data[i * rs..(i + 1) * rs].to_vec();
                if !fixup_file_record(&mut record) {
                    continue;
                }
                let flags = u16::from_le_bytes([record[0x16], record[0x17]]);
                if flags & 1 == 0 {
                    continue;
                }
                if visit(first_rec + rec_idx + i as u64, &record) {
                    return Ok(());
                }
            }
            rec_idx += batch as u64;
        }
    }
    Ok(())
}

/// A file the MFTMirr scan looks for, with its expected parent chain
/// (parent ← grandparent) and a content signature for validation when
/// parent records are inaccessible.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg(any(feature = "sam", test))]
pub(super) enum ScanTarget {
    Sam,
    System,
    Security,
    NtdsDit,
}

#[cfg(any(feature = "sam", test))]
impl ScanTarget {
    /// Filename as stored in $FILE_NAME (compared case-insensitively).
    const fn file_name(self) -> &'static str {
        match self {
            Self::Sam => "SAM",
            Self::System => "SYSTEM",
            Self::Security => "SECURITY",
            Self::NtdsDit => "ntds.dit",
        }
    }

    /// Name used in log messages.
    const fn log_name(self) -> &'static str {
        match self {
            Self::Sam => "SAM",
            Self::System => "SYSTEM",
            Self::Security => "SECURITY",
            Self::NtdsDit => "NTDS.DIT",
        }
    }

    /// Expected parent and grandparent directory names.
    const fn parent_chain(self) -> (&'static str, &'static str) {
        match self {
            Self::Sam | Self::System | Self::Security => ("config", "System32"),
            Self::NtdsDit => ("NTDS", "Windows"),
        }
    }

    /// Validate the first bytes of file data (used when the parent records
    /// are inaccessible and the directory chain cannot be verified).
    fn content_signature_ok(self, data: &[u8]) -> bool {
        match self {
            Self::Sam | Self::System | Self::Security => data.len() >= 4 && &data[0..4] == b"regf",
            // ESE database header magic at offset 4 (see crate::ntds::ese)
            Self::NtdsDit => data.len() >= 8 && data[4..8] == [0xEF, 0xCD, 0xAB, 0x89],
        }
    }
}

/// MFT records found by the scan, per target.
#[derive(Default)]
#[cfg(any(feature = "sam", test))]
pub(super) struct ScanRecords {
    records: Vec<(ScanTarget, Vec<u8>)>,
}

#[cfg(any(feature = "sam", test))]
impl ScanRecords {
    pub(super) fn get(&self, target: ScanTarget) -> Option<&Vec<u8>> {
        self.records
            .iter()
            .find(|(t, _)| *t == target)
            .map(|(_, record)| record)
    }

    fn is_found(&self, target: ScanTarget) -> bool {
        self.records.iter().any(|(t, _)| *t == target)
    }

    fn insert(&mut self, target: ScanTarget, record: Vec<u8>) {
        self.records.push((target, record));
    }

    fn all_found(&self, wanted: &[ScanTarget]) -> bool {
        wanted.iter().all(|&target| self.is_found(target))
    }
}

/// Verify that a parent record chain matches the expected directory names.
/// Checks 2 levels up: parent=expected_parent, grandparent=expected_grandparent
/// (e.g. config/System32 for registry hives, NTDS/Windows for ntds.dit).
#[cfg(any(feature = "sam", test))]
fn verify_parent_chain<R: Read + Seek>(
    reader: &mut R,
    parent_ref: u64,
    mft_runs: &[DataRun],
    params: &NtfsParams,
    partition_offset: u64,
    expected_parent: &str,
    expected_grandparent: &str,
) -> bool {
    // Read parent record
    let Some(parent) = read_mft_record(reader, parent_ref, mft_runs, params, partition_offset)
    else {
        return false;
    };
    let Some((parent_name, grandparent_ref)) = extract_filename(&parent) else {
        return false;
    };
    if !parent_name.eq_ignore_ascii_case(expected_parent) {
        return false;
    }

    // Read grandparent record
    let Some(grandparent) =
        read_mft_record(reader, grandparent_ref, mft_runs, params, partition_offset)
    else {
        return false;
    };
    let Some((gp_name, _)) = extract_filename(&grandparent) else {
        return false;
    };
    gp_name.eq_ignore_ascii_case(expected_grandparent)
}

/// Scan accessible MFT segments for records matching the wanted targets.
///
/// Verify parent paths when requested; otherwise check readable content signatures.
/// An unreadable prefix is deferred to the resilient file reader.
#[cfg(any(feature = "sam", test))]
fn scan_mft_segments<R: Read + Seek>(
    reader: &mut R,
    bootstrap: &MftBootstrap,
    partition_offset: u64,
    wanted: &[ScanTarget],
    records: &mut ScanRecords,
    verify_parents: bool,
    budget: &mut ScanBudget,
) -> Result<()> {
    let rs = bootstrap.params.record_size as usize;
    let batch_records = 256usize.min(1024 * 1024 / rs);

    'segments: for &(abs_offset, first_rec, num_recs) in &bootstrap.accessible_segments {
        let mut rec_idx = 0u64;
        while rec_idx < num_recs {
            let batch = (batch_records as u64).min(num_recs - rec_idx) as usize;
            budget.charge((batch * rs) as u64, batch as u64)?;
            let read_pos = abs_offset
                .checked_add(rec_idx.saturating_mul(rs as u64))
                .ok_or_else(|| VmkatzError::DecryptionError("MFT scan offset overflow".into()))?;

            if reader.seek(SeekFrom::Start(read_pos)).is_err() {
                rec_idx += batch as u64;
                continue;
            }
            let mut batch_data = vec![0u8; batch * rs];
            // Use resilient read: zero-fill blocks that fail (live VM I/O errors)
            resilient_read_blocks(reader, &mut batch_data, rs);

            for i in 0..batch {
                let mut record = batch_data[i * rs..(i + 1) * rs].to_vec();
                if !fixup_file_record(&mut record) {
                    continue;
                }

                // Check in-use flag; skip directories (flag bit 0x02)
                let flags = u16::from_le_bytes([record[0x16], record[0x17]]);
                if flags & 1 == 0 || flags & 2 != 0 {
                    continue;
                }

                let Some((name, parent_ref)) = extract_filename(&record) else {
                    continue;
                };

                let Some(&target) = wanted.iter().find(|&&target| {
                    !records.is_found(target) && name.eq_ignore_ascii_case(target.file_name())
                }) else {
                    continue;
                };

                let rec_num = first_rec + rec_idx + i as u64;

                if verify_parents {
                    let (parent, grandparent) = target.parent_chain();
                    if verify_parent_chain(
                        reader,
                        parent_ref,
                        &bootstrap.mft_runs,
                        &bootstrap.params,
                        partition_offset,
                        parent,
                        grandparent,
                    ) {
                        log::info!(
                            "MFTMirr scan: found {} at MFT record #{rec_num} (parent verified)",
                            target.log_name()
                        );
                        records.insert(target, record);
                    } else {
                        log::debug!(
                            "MFTMirr scan: {} at record #{rec_num} — parent chain mismatch, skipping",
                            target.log_name()
                        );
                    }
                } else {
                    // Without parent check, validate the file's content signature
                    match try_read_file_start(reader, &record, &bootstrap.params, partition_offset)
                    {
                        Some(start) if target.content_signature_ok(&start) => {
                            log::info!(
                                "MFTMirr scan: found {} at MFT record #{rec_num} (content-validated)",
                                target.log_name()
                            );
                            records.insert(target, record);
                        }
                        Some(_) => {
                            log::info!(
                                "MFTMirr scan: found {} at MFT record #{rec_num} (wrong content signature, skipping)",
                                target.log_name()
                            );
                        }
                        None => {
                            // Keep the candidate; the file reader zero-fills failed 4 KiB blocks.
                            log::info!(
                                "MFTMirr scan: found {} at MFT record #{rec_num} (first extent check failed, accepting for resilient read)",
                                target.log_name()
                            );
                            records.insert(target, record);
                        }
                    }
                }

                if records.all_found(wanted) {
                    break 'segments;
                }
            }

            rec_idx += batch as u64;
        }
    }
    Ok(())
}

/// Retry without parent checks if any required target is missing.
/// Both passes share one scan budget.
#[cfg(any(feature = "sam", test))]
pub(super) fn scan_for_targets<R: Read + Seek>(
    reader: &mut R,
    bootstrap: &MftBootstrap,
    partition_offset: u64,
    wanted: &[ScanTarget],
    required: &[ScanTarget],
) -> Result<ScanRecords> {
    let mut budget = ScanBudget::new();
    let mut records = ScanRecords::default();
    scan_mft_segments(
        reader,
        bootstrap,
        partition_offset,
        wanted,
        &mut records,
        true,
        &mut budget,
    )?;

    // Parent records may be inaccessible even when the file data is readable.
    if required.iter().any(|&target| !records.is_found(target)) {
        log::info!(
            "MFTMirr: retrying without parent verification (parent records may be inaccessible)"
        );
        scan_mft_segments(
            reader,
            bootstrap,
            partition_offset,
            wanted,
            &mut records,
            false,
            &mut budget,
        )?;
    }
    Ok(records)
}
