pub mod bootkey;
pub mod cache;
pub mod cm_hive;
mod disk_fallbacks;
pub mod hashes;
pub mod hive;
pub use crate::fs::listing;
pub mod lsa;
pub mod mem_hive;
use crate::fs::recovery;
mod ntds_stream;
mod ntfs_reader;
mod security;
pub use ntds_stream::{NtdsReadResult, with_ntds_bootkey};
use security::process_security_hive;

mod vmdk_scan;

pub use listing::{ListOutcome, list_path};

pub use crate::disk::{aes_xts, bitlocker_decrypt};

use crate::fs::{find_ntfs_partitions, is_bitlocker_partition, select_partition};
use std::io::{Read, Seek};
use std::path::Path;

use crate::error::Result;

/// SAM + SYSTEM + optional SECURITY hive file data.
type HiveFiles = (Vec<u8>, Vec<u8>, Option<Vec<u8>>);

pub use crate::secrets::{DiskSecrets, SamEntry};

/// Extract secrets from a disk, trying FVEK keys for BitLocker partitions.
///
/// When BitLocker-encrypted partitions are detected and FVEK candidates are
/// available, each candidate is tried until one successfully decrypts a valid
/// NTFS volume. Falls back to standard (non-BitLocker) extraction if no
/// encrypted partition is found or no key works.
pub fn extract_disk_secrets_with_bitlocker(
    path: &Path,
    fvek_keys: &[crate::lsass::bitlocker::BitLockerKey],
) -> Result<DiskSecrets> {
    extract_disk_secrets_with_bitlocker_scoped(path, fvek_keys, None)
}

/// Like [`extract_disk_secrets_with_bitlocker`], restricted to one partition offset.
pub fn extract_disk_secrets_with_bitlocker_scoped(
    path: &Path,
    fvek_keys: &[crate::lsass::bitlocker::BitLockerKey],
    partition_filter: Option<u64>,
) -> Result<DiskSecrets> {
    let mut disk = crate::disk::open_disk(path)?;
    extract_secrets_with_bitlocker(&mut disk, fvek_keys, partition_filter)
}

/// Reader-based BitLocker-aware SAM extraction, usable by VMFS-backed disks.
pub fn extract_disk_secrets_from_reader_with_bitlocker<R: Read + Seek>(
    reader: &mut R,
    fvek_keys: &[crate::lsass::bitlocker::BitLockerKey],
    partition_filter: Option<u64>,
) -> Result<DiskSecrets> {
    extract_secrets_with_bitlocker(reader, fvek_keys, partition_filter)
}

/// Core BitLocker-aware extraction for SAM/LSA secrets.
fn extract_secrets_with_bitlocker<R: Read + Seek>(
    reader: &mut R,
    fvek_keys: &[crate::lsass::bitlocker::BitLockerKey],
    partition_filter: Option<u64>,
) -> Result<DiskSecrets> {
    let partitions = select_partition(find_ntfs_partitions(reader)?, partition_filter)?;

    for &partition_offset in &partitions {
        // Try unencrypted first
        if !is_bitlocker_partition(reader, partition_offset) {
            log::info!("Trying NTFS partition at offset 0x{partition_offset:x}");
            match ntfs_reader::read_secrets(reader, partition_offset) {
                Ok(parsed) => return parsed,
                Err(e) if e.is_resource_limit() => return Err(e),
                Err(e) => {
                    log::info!("Partition at 0x{partition_offset:x}: {e}");
                }
            }
            continue;
        }

        // BitLocker-encrypted partition — try each FVEK candidate
        log::info!(
            "BitLocker partition at 0x{:x} — trying {} FVEK candidate(s)",
            partition_offset,
            fvek_keys.len()
        );

        if let Some(secrets) = try_bitlocker_fvek_candidates(
            reader,
            partition_offset,
            fvek_keys,
            |bl_reader, _offset| ntfs_reader::read_secrets(bl_reader, 0),
        )? {
            return secrets;
        }
    }

    Err(crate::error::VmkatzError::DecryptionError(
        "No secrets found (BitLocker-aware scan exhausted all partitions and FVEK candidates)"
            .to_string(),
    ))
}

/// Try each FVEK candidate on a BitLocker-encrypted partition.
///
/// For each candidate, validates the NTFS signature after decryption,
/// then calls `extract_fn` to perform the actual extraction.
/// Returns the first successful result, or `None` if no key works.
fn try_bitlocker_fvek_candidates<R, T, F>(
    reader: &mut R,
    partition_offset: u64,
    fvek_keys: &[crate::lsass::bitlocker::BitLockerKey],
    extract_fn: F,
) -> Result<Option<T>>
where
    R: Read + Seek,
    F: Fn(&mut bitlocker_decrypt::BitLockerReader<&mut R>, u64) -> Result<T>,
{
    for (i, key) in fvek_keys.iter().enumerate() {
        let Some(xts_key) = bitlocker_decrypt::build_xts_key(key) else {
            log::info!(
                "BitLocker: skipping FVEK #{} — unsupported method 0x{:04x} ({})",
                i,
                key.method,
                key.cipher
            );
            continue;
        };

        // Validate by decrypting sector 0 and checking NTFS signature
        let mut bl_reader = bitlocker_decrypt::BitLockerReader::new(
            &mut *reader,
            partition_offset,
            xts_key.clone(),
        );

        if !bl_reader.validate_ntfs_signature() {
            log::info!(
                "BitLocker: FVEK #{} ({}) — NTFS signature mismatch after decryption",
                i,
                key.cipher
            );
            continue;
        }

        log::info!(
            "BitLocker: FVEK #{} ({}) unlocked partition at 0x{:x}",
            i,
            key.cipher,
            partition_offset
        );

        // Re-create reader (validate consumed a seek) and extract
        let mut bl_reader =
            bitlocker_decrypt::BitLockerReader::new(&mut *reader, partition_offset, xts_key);

        match extract_fn(&mut bl_reader, partition_offset) {
            Ok(result) => return Ok(Some(result)),
            Err(e) if e.is_resource_limit() => return Err(e),
            Err(e) => {
                log::warn!("BitLocker: FVEK #{i} decrypted NTFS header but extraction failed: {e}");
            }
        }
    }

    Ok(None)
}

/// Extract both SAM hashes and LSA secrets from a disk image.
pub fn extract_disk_secrets(path: &Path) -> Result<DiskSecrets> {
    extract_disk_secrets_scoped(path, None)
}

/// Like [`extract_disk_secrets`], restricted to the NTFS partition at `partition_filter`.
/// When a filter is set, all whole-disk fallbacks are disabled.
pub fn extract_disk_secrets_scoped(
    path: &Path,
    partition_filter: Option<u64>,
) -> Result<DiskSecrets> {
    let mut disk = crate::disk::open_disk(path)?;
    // Do not turn an unsupported/Linux disk into a raw recovery scan.
    find_ntfs_partitions(&mut disk)?;
    match extract_secrets_from_reader_scoped(&mut disk, partition_filter) {
        Ok(secrets) => return Ok(secrets),
        Err(e)
            if partition_filter.is_some()
                || e.is_resource_limit()
                || matches!(
                    e,
                    crate::error::VmkatzError::RecoveryLimit(_)
                        | crate::error::VmkatzError::NtfsEntryNotFound(_)
                ) =>
        {
            return Err(e);
        }
        Err(e) => {
            log::info!("Standard extraction failed: {e}");
        }
    }

    // Fallback 3 (VMDK only): scan allocated grains directly.
    // This is faster for incomplete VMDK images (missing extents) since it
    // only reads physically present grain data instead of the full virtual disk.
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    if ext == "vmdk" && partition_filter.is_none() {
        recovery::check_raw_size(disk.disk_size())?;
        log::info!("Trying VMDK grain-direct scan for registry hives");
        let mut vmdk = crate::disk::vmdk::VmdkDisk::open(path)?;
        match vmdk_scan::scan_vmdk_grains_for_hives(&mut vmdk) {
            Ok(((sam_data, system_data, security_data), scattered_bootkey)) => {
                return process_hive_data_with_bootkey(
                    &sam_data,
                    &system_data,
                    security_data.as_deref(),
                    scattered_bootkey,
                );
            }
            Err(e) => {
                log::info!("VMDK grain scan failed: {e}");
                return Err(e);
            }
        }
    }

    Err(crate::error::VmkatzError::DecryptionError(
        "All extraction methods failed".to_string(),
    ))
}

/// Extract SAM hashes via NTFS partitions only (no fallback raw scans).
/// Faster for batch scanning where most VMDKs are sparse or non-Windows.
pub fn extract_secrets_ntfs_only<R: Read + Seek>(reader: &mut R) -> Result<DiskSecrets> {
    extract_secrets_ntfs_only_scoped(reader, None)
}

/// Like [`extract_secrets_ntfs_only`], restricted to one partition offset.
pub fn extract_secrets_ntfs_only_scoped<R: Read + Seek>(
    reader: &mut R,
    partition_filter: Option<u64>,
) -> Result<DiskSecrets> {
    let partitions = select_partition(find_ntfs_partitions(reader)?, partition_filter)?;
    let mut bitlocker_found = false;
    for &partition_offset in &partitions {
        if is_bitlocker_partition(reader, partition_offset) {
            log::warn!("Partition at offset 0x{partition_offset:x} is BitLocker-encrypted");
            bitlocker_found = true;
            continue;
        }
        log::info!("Trying NTFS partition at offset 0x{partition_offset:x}");
        match ntfs_reader::read_secrets(reader, partition_offset) {
            Ok(parsed) => return parsed,
            Err(e) if e.is_resource_limit() => return Err(e),
            Err(e) => {
                log::info!("Partition at 0x{partition_offset:x}: {e}");
            }
        }
    }
    if bitlocker_found {
        return Err(crate::error::VmkatzError::DecryptionError(
            "Windows partition is BitLocker-encrypted. Provide the recovery key or extract the VMK from memory first.".to_string(),
        ));
    }
    Err(crate::error::VmkatzError::DecryptionError(
        "No registry hives found on NTFS partitions".to_string(),
    ))
}

/// Extract SAM hashes + LSA secrets from any Read+Seek source.
pub fn extract_secrets_from_reader<R: Read + Seek>(reader: &mut R) -> Result<DiskSecrets> {
    extract_secrets_from_reader_scoped(reader, None)
}

/// Like [`extract_secrets_from_reader`], restricted to one partition offset.
/// When a filter is set, the raw regf/hbin whole-disk fallbacks are skipped.
pub fn extract_secrets_from_reader_scoped<R: Read + Seek>(
    reader: &mut R,
    partition_filter: Option<u64>,
) -> Result<DiskSecrets> {
    let partitions = select_partition(find_ntfs_partitions(reader)?, partition_filter)?;
    let mut bitlocker_found = false;
    let mut damaged = false;

    for &partition_offset in &partitions {
        if is_bitlocker_partition(reader, partition_offset) {
            log::warn!("Partition at offset 0x{partition_offset:x} is BitLocker-encrypted");
            bitlocker_found = true;
            continue;
        }
        log::info!("Trying NTFS partition at offset 0x{partition_offset:x}");
        match ntfs_reader::read_secrets(reader, partition_offset) {
            Ok(parsed) => return parsed,
            Err(e) if e.is_resource_limit() => return Err(e),
            Err(crate::error::VmkatzError::NtfsEntryNotFound(_)) => {}
            Err(e) => {
                damaged = true;
                log::info!("Partition at 0x{partition_offset:x}: {e}");
            }
        }
    }

    if partition_filter.is_some() {
        return Err(if bitlocker_found {
            crate::error::VmkatzError::DecryptionError(
                "Windows partition is BitLocker-encrypted. Provide the recovery key or extract the VMK from memory first.".to_string(),
            )
        } else {
            crate::error::VmkatzError::DecryptionError(
                "No registry hives found on the selected NTFS partition".to_string(),
            )
        });
    }

    if bitlocker_found {
        return Err(crate::error::VmkatzError::DecryptionError(
            "BitLocker-encrypted volume; raw recovery skipped".into(),
        ));
    }
    if !damaged {
        return Err(crate::error::VmkatzError::NtfsEntryNotFound(
            "registry hives on readable partitions".into(),
        ));
    }
    recovery::check_raw_size(reader.seek(std::io::SeekFrom::End(0))?)?;

    // Fallback 1: scan raw disk for "regf" hive signatures (contiguous hives).
    log::info!("NTFS approach failed, trying raw regf scan fallback");
    match disk_fallbacks::scan_for_hives(reader) {
        Ok((sam_data, system_data, security_data)) => {
            return process_hive_data(&sam_data, &system_data, security_data.as_deref());
        }
        Err(e) if e.is_resource_limit() => return Err(e),
        Err(e) => {
            log::info!("Raw regf scan failed: {e}");
        }
    }

    // Fallback 2: scan for hbin blocks with offset=0 (first block of each hive).
    // Handles NTFS-fragmented hives where regf header is at one disk location
    // but hbin data starts at a different, non-contiguous location.
    log::info!("Trying hbin-based fallback scan for fragmented hives");
    match disk_fallbacks::scan_for_hbin_roots(reader) {
        Ok((sam_data, system_data, security_data)) => {
            process_hive_data(&sam_data, &system_data, security_data.as_deref())
        }
        Err(e) => {
            log::info!("hbin scan failed: {e}");
            if bitlocker_found {
                Err(crate::error::VmkatzError::DecryptionError(
                    "Windows partition is BitLocker-encrypted. Provide the recovery key or extract the VMK from memory first.".to_string(),
                ))
            } else {
                Err(e)
            }
        }
    }
}

/// Process extracted hive data into DiskSecrets.
fn process_hive_data(
    sam_data: &[u8],
    system_data: &[u8],
    security_data: Option<&[u8]>,
) -> Result<DiskSecrets> {
    process_hive_data_with_bootkey(sam_data, system_data, security_data, None)
}

/// Process extracted hive data with an optional pre-extracted bootkey.
fn process_hive_data_with_bootkey(
    sam_data: &[u8],
    system_data: &[u8],
    security_data: Option<&[u8]>,
    precomputed_bootkey: Option<[u8; 16]>,
) -> Result<DiskSecrets> {
    log::info!(
        "SAM hive: {} bytes, SYSTEM hive: {} bytes",
        sam_data.len(),
        system_data.len()
    );

    // Extract bootkey: prefer precomputed, fall back to SYSTEM hive
    let boot_key = match precomputed_bootkey {
        Some(bk) => {
            log::info!("Using precomputed bootkey: {}", hex::encode(bk));
            bk
        }
        None => bootkey::extract_bootkey(system_data)?,
    };
    log::info!("Bootkey: {}", hex::encode(boot_key));

    // Extract SAM hashes
    let sam_entries = hashes::extract_hashes(sam_data, &boot_key)?;
    let machine_sid = hashes::extract_machine_sid(sam_data);
    if machine_sid.is_none() {
        log::info!("SAM: account-domain SID not found in Domains\\Account\\V");
    }

    // Extract LSA secrets from SECURITY hive (optional)
    let (lsa_secrets, cached_credentials) = if let Some(sec_data) = security_data {
        log::info!("SECURITY hive: {} bytes", sec_data.len());
        let secrets = match lsa::extract_lsa_secrets(sec_data, &boot_key) {
            Ok(secrets) => {
                log::info!("Extracted {} LSA secrets", secrets.len());
                secrets
            }
            Err(e) => {
                log::warn!("LSA secrets extraction failed: {e}");
                Vec::new()
            }
        };

        // Extract cached credentials (DCC2) using NL$KM from LSA secrets
        let cached = extract_dcc2_from_secrets(sec_data, &secrets);

        (secrets, cached)
    } else {
        log::info!("SECURITY hive not found, skipping LSA secrets");
        (Vec::new(), Vec::new())
    };

    Ok(DiskSecrets {
        sam_entries,
        lsa_secrets,
        cached_credentials,
        machine_sid,
    })
}

/// Extract DCC2 cached credentials using NL$KM from LSA secrets.
fn extract_dcc2_from_secrets(
    security_data: &[u8],
    secrets: &[lsa::LsaSecret],
) -> Vec<cache::CachedCredential> {
    // Find NL$KM key in LSA secrets
    let nlkm_key = secrets.iter().find_map(|s| {
        if let lsa::LsaSecretType::CachedDomainKey { key } = &s.parsed {
            Some(key.as_slice())
        } else {
            None
        }
    });

    let nlkm_key = match nlkm_key {
        Some(k) if k.len() >= 32 => k,
        Some(k) => {
            log::info!("NL$KM key too short ({} bytes), skipping DCC2", k.len());
            return Vec::new();
        }
        None => {
            log::info!("NL$KM key not found in LSA secrets, skipping DCC2");
            return Vec::new();
        }
    };

    match cache::extract_cached_credentials(security_data, nlkm_key) {
        Ok(creds) => {
            if !creds.is_empty() {
                log::info!("Extracted {} cached credential(s)", creds.len());
            }
            creds
        }
        Err(e) => {
            log::warn!("DCC2 extraction failed: {e}");
            Vec::new()
        }
    }
}
