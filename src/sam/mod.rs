pub mod bootkey;
pub mod cache;
pub mod hashes;
pub mod hive;
pub mod lsa;
mod ntfs_fallback;
mod partition;
mod ntfs_reader;
mod disk_fallbacks;
mod vmdk_scan;

pub mod dpapi_masterkey;

// Re-export pub(crate) items used by other modules (paging/pagefile, paging/filebacked)
pub(crate) use partition::{find_ntfs_partitions, is_bitlocker_partition};
pub(crate) use ntfs_reader::{find_entry, read_file_data, PartitionReader};

use std::io::{Read, Seek};
use std::path::Path;

use crate::error::Result;

/// SAM + SYSTEM + optional SECURITY hive file data.
type HiveFiles = (Vec<u8>, Vec<u8>, Option<Vec<u8>>);

/// NTDS + SYSTEM files extracted from a disk image.
#[derive(Debug)]
pub struct NtdsArtifacts {
    pub ntds_data: Vec<u8>,
    pub system_data: Vec<u8>,
    pub partition_offset: u64,
}

/// A SAM user entry with RID, username, and NT/LM hashes.
#[derive(Debug)]
pub struct SamEntry {
    pub rid: u32,
    pub username: String,
    pub nt_hash: [u8; 16],
    pub lm_hash: [u8; 16],
}

/// Combined extraction result: SAM hashes + LSA secrets + cached credentials.
#[derive(Debug)]
pub struct DiskSecrets {
    pub sam_entries: Vec<SamEntry>,
    pub lsa_secrets: Vec<lsa::LsaSecret>,
    pub cached_credentials: Vec<cache::CachedCredential>,
}

/// Extract DPAPI master key hashes from a disk image.
///
/// Scans user profiles for encrypted master key files and returns
/// Hashcat-compatible hashes (modes 15300/15900).
pub fn extract_dpapi_masterkeys(path: &Path) -> Vec<dpapi_masterkey::DpapiMasterKeyHash> {
    match crate::disk::open_disk(path) {
        Ok(mut disk) => dpapi_masterkey::extract_from_disk(&mut disk),
        Err(e) => {
            log::info!("Cannot open disk for DPAPI scan: {}", e);
            Vec::new()
        }
    }
}

/// Extract NTDS artifacts (NTDS.dit + SYSTEM hive) from a disk image.
///
/// This is the input set required by offline AD secrets extraction workflows.
pub fn extract_ntds_artifacts(path: &Path) -> Result<NtdsArtifacts> {
    let mut disk = crate::disk::open_disk(path)?;
    extract_ntds_artifacts_from_reader(&mut disk)
}

/// Extract both SAM hashes and LSA secrets from a disk image.
pub fn extract_disk_secrets(path: &Path) -> Result<DiskSecrets> {
    let mut disk = crate::disk::open_disk(path)?;
    match extract_secrets_from_reader(&mut disk) {
        Ok(secrets) => return Ok(secrets),
        Err(e) => {
            log::info!("Standard extraction failed: {}", e);
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
    if ext == "vmdk" {
        log::info!("Trying VMDK grain-direct scan for registry hives");
        let mut vmdk = crate::disk::vmdk::VmdkDisk::open(path)?;
        match vmdk_scan::scan_vmdk_grains_for_hives(&mut vmdk) {
            Ok(((sam_data, system_data, security_data), scattered_bootkey)) => {
                return process_hive_data_with_bootkey(
                    sam_data,
                    system_data,
                    security_data,
                    scattered_bootkey,
                );
            }
            Err(e) => {
                log::info!("VMDK grain scan failed: {}", e);
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
    let partitions = find_ntfs_partitions(reader).unwrap_or_default();
    let mut bitlocker_found = false;
    for &partition_offset in &partitions {
        if is_bitlocker_partition(reader, partition_offset) {
            eprintln!("[!] Partition at offset 0x{:x} is BitLocker-encrypted", partition_offset);
            bitlocker_found = true;
            continue;
        }
        log::info!("Trying NTFS partition at offset 0x{:x}", partition_offset);
        match ntfs_reader::read_hive_files(reader, partition_offset) {
            Ok((sam_data, system_data, security_data)) => {
                return process_hive_data(sam_data, system_data, security_data);
            }
            Err(e) => {
                log::info!("Partition at 0x{:x}: {}", partition_offset, e);
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
    let partitions = find_ntfs_partitions(reader).unwrap_or_default();
    let mut bitlocker_found = false;

    for &partition_offset in &partitions {
        if is_bitlocker_partition(reader, partition_offset) {
            eprintln!("[!] Partition at offset 0x{:x} is BitLocker-encrypted", partition_offset);
            bitlocker_found = true;
            continue;
        }
        log::info!("Trying NTFS partition at offset 0x{:x}", partition_offset);
        match ntfs_reader::read_hive_files(reader, partition_offset) {
            Ok((sam_data, system_data, security_data)) => {
                return process_hive_data(sam_data, system_data, security_data);
            }
            Err(e) => {
                log::info!("Partition at 0x{:x}: {}", partition_offset, e);
            }
        }
    }

    // Fallback 1: scan raw disk for "regf" hive signatures (contiguous hives).
    log::info!("NTFS approach failed, trying raw regf scan fallback");
    match disk_fallbacks::scan_for_hives(reader) {
        Ok((sam_data, system_data, security_data)) => {
            return process_hive_data(sam_data, system_data, security_data);
        }
        Err(e) => {
            log::info!("Raw regf scan failed: {}", e);
        }
    }

    // Fallback 2: scan for hbin blocks with offset=0 (first block of each hive).
    // Handles NTFS-fragmented hives where regf header is at one disk location
    // but hbin data starts at a different, non-contiguous location.
    log::info!("Trying hbin-based fallback scan for fragmented hives");
    match disk_fallbacks::scan_for_hbin_roots(reader) {
        Ok((sam_data, system_data, security_data)) => {
            process_hive_data(sam_data, system_data, security_data)
        }
        Err(e) => {
            log::info!("hbin scan failed: {}", e);
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

/// Extract NTDS artifacts from any Read+Seek source.
fn extract_ntds_artifacts_from_reader<R: Read + Seek>(reader: &mut R) -> Result<NtdsArtifacts> {
    let partitions = find_ntfs_partitions(reader).unwrap_or_default();
    let mut bitlocker_found = false;

    for &partition_offset in &partitions {
        if is_bitlocker_partition(reader, partition_offset) {
            eprintln!("[!] Partition at offset 0x{:x} is BitLocker-encrypted", partition_offset);
            bitlocker_found = true;
            continue;
        }
        log::info!(
            "Trying NTDS extraction on NTFS partition at offset 0x{:x}",
            partition_offset
        );
        match ntfs_reader::read_ntds_artifacts(reader, partition_offset) {
            Ok((ntds_data, system_data)) => {
                return Ok(NtdsArtifacts {
                    ntds_data,
                    system_data,
                    partition_offset,
                });
            }
            Err(e) => {
                log::info!("Partition at 0x{:x}: {}", partition_offset, e);
            }
        }
    }

    if bitlocker_found {
        return Err(crate::error::VmkatzError::DecryptionError(
            "Windows partition is BitLocker-encrypted. Provide the recovery key or extract the VMK from memory first.".to_string(),
        ));
    }
    Err(crate::error::VmkatzError::DecryptionError(
        "NTDS.dit not found on readable NTFS partitions".to_string(),
    ))
}

/// Process extracted hive data into DiskSecrets.
fn process_hive_data(
    sam_data: Vec<u8>,
    system_data: Vec<u8>,
    security_data: Option<Vec<u8>>,
) -> Result<DiskSecrets> {
    process_hive_data_with_bootkey(sam_data, system_data, security_data, None)
}

/// Process extracted hive data with an optional pre-extracted bootkey.
fn process_hive_data_with_bootkey(
    sam_data: Vec<u8>,
    system_data: Vec<u8>,
    security_data: Option<Vec<u8>>,
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
        None => bootkey::extract_bootkey(&system_data)?,
    };
    log::info!("Bootkey: {}", hex::encode(boot_key));

    // Extract SAM hashes
    let sam_entries = hashes::extract_hashes(&sam_data, &boot_key)?;

    // Extract LSA secrets from SECURITY hive (optional)
    let (lsa_secrets, cached_credentials) = if let Some(sec_data) = &security_data {
        log::info!("SECURITY hive: {} bytes", sec_data.len());
        let secrets = match lsa::extract_lsa_secrets(sec_data, &boot_key) {
            Ok(secrets) => {
                log::info!("Extracted {} LSA secrets", secrets.len());
                secrets
            }
            Err(e) => {
                log::warn!("LSA secrets extraction failed: {}", e);
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
            log::warn!("DCC2 extraction failed: {}", e);
            Vec::new()
        }
    }
}
