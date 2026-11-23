//! MFTMirr-based NTFS fallback for reading registry hives and NTDS.dit from
//! incomplete disks.
//!
//! When the primary MFT start is inaccessible (e.g., truncated/missing extent),
//! this module bootstraps MFT access via $MFTMirr:
//! 1. Parse NTFS boot sector → locate $MFTMirr
//! 2. Read $MFT record from MFTMirr → parse $DATA data runs
//! 3. Scan accessible MFT segments for FILE records named SAM/SYSTEM/SECURITY
//!    (and ntds.dit for the NTDS workflow)
//! 4. Read file contents via their $DATA data runs

use std::io::{Read, Seek};

use crate::error::{Result, VmkatzError};
use crate::fs::ntfs::finalize;
use crate::fs::recovery::{MAX_CANDIDATES, ScanBudget};
use crate::fs::{DirEntry, EntryKind};

#[cfg(any(feature = "sam", test))]
mod data;
mod mft;
mod records;
#[cfg(test)]
pub mod tests;

#[cfg(any(feature = "sam", test))]
use data::read_file_from_record;
#[cfg(any(feature = "sam", test))]
use mft::{ScanTarget, scan_for_targets};
use mft::{for_each_accessible_record, mftmirr_bootstrap};
use records::{filename_info_from_attr, find_all_attributes};

#[cfg(any(feature = "sam", test))]
type HiveFiles = (Vec<u8>, Vec<u8>, Option<Vec<u8>>);

/// Enumerate directory entries by scanning accessible MFT records for
/// `$FILE_NAME` parent references, for when the directory index is unreadable.
///
/// `Ok(None)` means a path component could not be resolved from accessible
/// records; `Err` reports I/O, metadata or recovery-limit failures.
pub fn list_path_degraded<R: Read + Seek>(
    reader: &mut R,
    partition_offset: u64,
    path: &str,
) -> Result<Option<Vec<DirEntry>>> {
    let bootstrap = mftmirr_bootstrap(reader, partition_offset)?;

    let mut budget = ScanBudget::new();
    // Resolve the path to a directory record number (root = record 5).
    let mut current = 5u64;
    for comp in path.split(['\\', '/']).filter(|c| !c.is_empty()) {
        let mut found = None;
        for_each_accessible_record(reader, &bootstrap, &mut budget, |rec_num, record| {
            if record[0x16] & 0x02 == 0 || rec_num == current {
                return false;
            }
            let hit = find_all_attributes(record, 0x30)
                .into_iter()
                .any(|(pos, _)| {
                    filename_info_from_attr(record, pos).is_some_and(|(name, parent, _)| {
                        parent == current && name.eq_ignore_ascii_case(comp)
                    })
                });
            if hit {
                found = Some(rec_num);
            }
            hit
        })?;
        match found {
            Some(n) => current = n,
            None => return Ok(None),
        }
    }

    let mut raw = Vec::new();
    for_each_accessible_record(reader, &bootstrap, &mut budget, |rec_num, record| {
        // Skip the directory's own self-reference (root lists itself as a child).
        if rec_num == current {
            return false;
        }
        let is_dir = record[0x16] & 0x02 != 0;
        for (pos, _) in find_all_attributes(record, 0x30) {
            if let Some((name, parent, size)) = filename_info_from_attr(record, pos) {
                if parent == current {
                    let kind = if is_dir {
                        EntryKind::Dir
                    } else {
                        EntryKind::File { size }
                    };
                    raw.push(DirEntry { name, kind });
                }
            }
        }
        raw.len() >= MAX_CANDIDATES
    })?;
    if raw.len() >= MAX_CANDIDATES {
        return Err(VmkatzError::RecoveryLimit(
            "directory listing exceeds 65536 candidates",
        ));
    }
    Ok(Some(finalize(raw, true)))
}

/// Try to read registry hives via $MFTMirr bootstrap.
///
/// This is the main entry point for SAM/SYSTEM/SECURITY. Called when
/// `ntfs.root_directory()` fails because the primary MFT start is in an
/// inaccessible disk region.
#[cfg(any(feature = "sam", test))]
pub fn try_mftmirr_fallback<R: Read + Seek>(
    reader: &mut R,
    partition_offset: u64,
) -> Result<HiveFiles> {
    let bootstrap = mftmirr_bootstrap(reader, partition_offset)?;
    let wanted = [ScanTarget::Sam, ScanTarget::System, ScanTarget::Security];
    // SECURITY is optional — do not rescan the whole MFT for it alone
    let required = [ScanTarget::Sam, ScanTarget::System];
    let records = scan_for_targets(reader, &bootstrap, partition_offset, &wanted, &required)?;

    // Read file data from found records
    let sam_data = match records.get(ScanTarget::Sam) {
        Some(rec) => read_file_from_record(
            reader,
            rec,
            "SAM",
            &bootstrap.mft_runs,
            &bootstrap.params,
            partition_offset,
        )?,
        None => {
            return Err(VmkatzError::DecryptionError(
                "MFTMirr: SAM hive not found in accessible MFT segments".into(),
            ));
        }
    };
    let system_data = match records.get(ScanTarget::System) {
        Some(rec) => read_file_from_record(
            reader,
            rec,
            "SYSTEM",
            &bootstrap.mft_runs,
            &bootstrap.params,
            partition_offset,
        )?,
        None => {
            return Err(VmkatzError::DecryptionError(
                "MFTMirr: SYSTEM hive not found in accessible MFT segments".into(),
            ));
        }
    };
    let security_data = records.get(ScanTarget::Security).and_then(|rec| {
        read_file_from_record(
            reader,
            rec,
            "SECURITY",
            &bootstrap.mft_runs,
            &bootstrap.params,
            partition_offset,
        )
        .ok()
    });

    // Validate hive data — accept "regf" header or "hbin" blocks (regf may be zero-filled
    // on live block devices where the first 4KB was temporarily locked)
    if sam_data.len() < 0x1000
        || (&sam_data[0..4] != b"regf" && sam_data[0x1000..].get(..4).is_none_or(|s| s != b"hbin"))
    {
        return Err(VmkatzError::DecryptionError(
            "MFTMirr: SAM data is not a valid registry hive".into(),
        ));
    }
    if system_data.len() < 0x1000
        || (&system_data[0..4] != b"regf"
            && system_data[0x1000..].get(..4).is_none_or(|s| s != b"hbin"))
    {
        return Err(VmkatzError::DecryptionError(
            "MFTMirr: SYSTEM data is not a valid registry hive".into(),
        ));
    }

    log::info!(
        "MFTMirr: SAM {} bytes, SYSTEM {} bytes{}",
        sam_data.len(),
        system_data.len(),
        if let Some(ref sec) = security_data {
            format!(", SECURITY {} bytes", sec.len())
        } else {
            String::new()
        },
    );

    Ok((sam_data, system_data, security_data))
}

/// Try to read NTDS.dit + SYSTEM hive via $MFTMirr bootstrap.
///
/// Mirrors `try_mftmirr_fallback` for domain controllers: ntds.dit lives in
/// \Windows\NTDS, so its parent chain is NTDS/Windows instead of config/System32.
#[cfg(any(feature = "sam", test))]
pub fn try_mftmirr_fallback_ntds<R: Read + Seek>(
    reader: &mut R,
    partition_offset: u64,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let bootstrap = mftmirr_bootstrap(reader, partition_offset)?;
    let wanted = [ScanTarget::NtdsDit, ScanTarget::System];
    let records = scan_for_targets(reader, &bootstrap, partition_offset, &wanted, &wanted)?;

    // NTDS.dit is heavily fragmented on real DCs — read_file_from_record
    // resolves $ATTRIBUTE_LIST extension records as needed.
    let ntds_data = match records.get(ScanTarget::NtdsDit) {
        Some(rec) => read_file_from_record(
            reader,
            rec,
            "NTDS.dit",
            &bootstrap.mft_runs,
            &bootstrap.params,
            partition_offset,
        )?,
        None => {
            return Err(VmkatzError::DecryptionError(
                "MFTMirr: ntds.dit not found in accessible MFT segments".into(),
            ));
        }
    };
    let system_data = match records.get(ScanTarget::System) {
        Some(rec) => read_file_from_record(
            reader,
            rec,
            "SYSTEM",
            &bootstrap.mft_runs,
            &bootstrap.params,
            partition_offset,
        )?,
        None => {
            return Err(VmkatzError::DecryptionError(
                "MFTMirr: SYSTEM hive not found in accessible MFT segments".into(),
            ));
        }
    };

    // Validate NTDS data — ESE database header magic at offset 4
    if ntds_data.len() < 0x1000 || ntds_data[4..8] != [0xEF, 0xCD, 0xAB, 0x89] {
        return Err(VmkatzError::DecryptionError(
            "MFTMirr: NTDS.dit data is not a valid ESE database".into(),
        ));
    }
    // Validate SYSTEM hive — same rule as the hive fallback (regf may be
    // zero-filled on live block devices)
    if system_data.len() < 0x1000
        || (&system_data[0..4] != b"regf"
            && system_data[0x1000..].get(..4).is_none_or(|s| s != b"hbin"))
    {
        return Err(VmkatzError::DecryptionError(
            "MFTMirr: SYSTEM data is not a valid registry hive".into(),
        ));
    }

    log::info!(
        "MFTMirr: NTDS.dit {} bytes, SYSTEM {} bytes",
        ntds_data.len(),
        system_data.len()
    );

    Ok((ntds_data, system_data))
}
