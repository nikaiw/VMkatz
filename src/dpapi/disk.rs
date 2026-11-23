//! NTFS adapter for the independent DPAPI parsers.

use super::masterkey::{DpapiMasterKeyHash, is_guid_filename, parse_masterkey_file};
use std::io::{Read, Seek};
use std::path::Path;

/// Extract DPAPI master key hashes from a disk image.
///
/// Scans user profiles for encrypted master key files and returns
/// Hashcat-compatible hashes (modes 15300/15900).
pub fn extract_dpapi_masterkeys(path: &Path) -> Vec<super::masterkey::DpapiMasterKeyHash> {
    extract_dpapi_masterkeys_scoped(path, None)
}

/// DPAPI master-key scan restricted to one partition when `partition_filter` is `Some`.
///
/// Keeps `--partition` consistent across SAM, NTDS and DPAPI; `None` scans every NTFS
/// partition (the unchanged default used by `extract_dpapi_masterkeys`).
pub fn extract_dpapi_masterkeys_scoped(
    path: &Path,
    partition_filter: Option<u64>,
) -> Vec<super::masterkey::DpapiMasterKeyHash> {
    match crate::disk::open_disk(path) {
        Ok(mut disk) => extract_dpapi_masterkeys_from_reader(&mut disk, partition_filter),
        Err(e) => {
            log::info!("Cannot open disk for DPAPI scan: {e}");
            Vec::new()
        }
    }
}

/// Reader-based DPAPI master key extraction, optionally scoped to one NTFS
/// partition offset. Usable by VMFS mode, which has a reader but no path.
pub fn extract_dpapi_masterkeys_from_reader<R: std::io::Read + std::io::Seek>(
    reader: &mut R,
    partition_filter: Option<u64>,
) -> Vec<super::masterkey::DpapiMasterKeyHash> {
    extract_from_disk_scoped(reader, partition_filter)
}

/// Extract DPAPI master key hashes from all user profiles on an NTFS partition.
///
/// Scans `Users\*\AppData\Roaming\Microsoft\Protect\{SID}\{GUID}` for each user.
pub fn extract_masterkey_hashes_from_partition<R: Read + Seek>(
    reader: &mut R,
    partition_offset: u64,
) -> Vec<DpapiMasterKeyHash> {
    let mut results = Vec::new();

    let mut part_reader = crate::fs::PartitionReader::new(reader, partition_offset);

    let ntfs = match ntfs::Ntfs::new(&mut part_reader) {
        Ok(n) => n,
        Err(e) => {
            log::info!("NTFS parse error for DPAPI scan: {e}");
            return results;
        }
    };

    let root = match ntfs.root_directory(&mut part_reader) {
        Ok(r) => r,
        Err(e) => {
            log::info!("NTFS root dir error for DPAPI scan: {e}");
            return results;
        }
    };

    // Scan SYSTEM profile: Windows\System32\Microsoft\Protect\S-1-5-18\
    scan_protect_dir(
        &ntfs,
        &root,
        &mut part_reader,
        "Windows\\System32\\Microsoft\\Protect",
        "SYSTEM",
        &mut results,
    );

    // Find Users directory
    let Ok(users_dir) = crate::fs::find_entry(&ntfs, &root, &mut part_reader, "Users") else {
        return results;
    };

    // Scan each user profile: Users\{user}\AppData\Roaming\Microsoft\Protect
    let Ok(user_entries) = crate::fs::list_directory(&ntfs, &users_dir, &mut part_reader) else {
        return results;
    };

    for (username, is_dir) in &user_entries {
        if !is_dir {
            continue;
        }
        let lower = username.to_lowercase();
        if lower == "public"
            || lower == "default"
            || lower == "default user"
            || lower == "all users"
        {
            continue;
        }

        let protect_path = format!("{username}\\AppData\\Roaming\\Microsoft\\Protect");
        scan_protect_dir(
            &ntfs,
            &users_dir,
            &mut part_reader,
            &protect_path,
            username,
            &mut results,
        );
    }

    results
}

/// Scan a Protect directory for DPAPI master key files.
fn scan_protect_dir<'n, R: Read + Seek>(
    ntfs: &'n ntfs::Ntfs,
    base_dir: &ntfs::NtfsFile<'n>,
    reader: &mut R,
    protect_path: &str,
    username: &str,
    results: &mut Vec<DpapiMasterKeyHash>,
) {
    let Ok(protect_dir) = crate::fs::navigate_to_dir(ntfs, base_dir, reader, protect_path) else {
        return;
    };

    let Ok(sid_entries) = crate::fs::list_directory(ntfs, &protect_dir, reader) else {
        return;
    };

    for (sid_name, is_sid_dir) in &sid_entries {
        if !is_sid_dir || !sid_name.starts_with("S-1-5-") {
            continue;
        }

        let Ok(sid_dir) = crate::fs::find_entry(ntfs, &protect_dir, reader, sid_name) else {
            continue;
        };

        let Ok(mk_entries) = crate::fs::list_directory(ntfs, &sid_dir, reader) else {
            continue;
        };

        for (mk_name, is_mk_dir) in &mk_entries {
            if *is_mk_dir || !is_guid_filename(mk_name) {
                continue;
            }

            let Ok(mk_file) = crate::fs::find_entry(ntfs, &sid_dir, reader, mk_name) else {
                continue;
            };

            let Ok(mk_data) = crate::fs::read_file_data(&mk_file, reader) else {
                continue;
            };

            // Read NTFS modification time as a proxy for key creation date
            let modified = mk_file
                .info()
                .ok()
                .map_or(0, |info| info.modification_time().nt_timestamp());

            if let Some(hash) = parse_masterkey_file(&mk_data, username, sid_name, modified) {
                log::info!(
                    "DPAPI masterkey: user={} SID={} GUID={} mode={}",
                    username,
                    sid_name,
                    hash.guid,
                    hash.mode
                );
                results.push(hash);
            }
        }
    }
}

/// High-level extraction: scan all NTFS partitions on a disk for DPAPI master key files.
pub fn extract_from_disk<R: Read + Seek>(reader: &mut R) -> Vec<DpapiMasterKeyHash> {
    extract_from_disk_scoped(reader, None)
}

/// Like [`extract_from_disk`], restricted to the NTFS partition at `partition_filter`.
///
/// An offset that matches no NTFS partition yields an empty result (callers that
/// need a hard error validate the offset beforehand).
pub fn extract_from_disk_scoped<R: Read + Seek>(
    reader: &mut R,
    partition_filter: Option<u64>,
) -> Vec<DpapiMasterKeyHash> {
    let partitions = crate::fs::select_partition(
        crate::fs::find_ntfs_partitions(reader).unwrap_or_default(),
        partition_filter,
    )
    .unwrap_or_default();
    let mut results = Vec::new();

    for &offset in &partitions {
        log::info!("Scanning NTFS partition at 0x{offset:x} for DPAPI master keys");
        let mut hashes = extract_masterkey_hashes_from_partition(reader, offset);
        results.append(&mut hashes);
        if !results.is_empty() {
            break; // Found user profiles, stop scanning
        }
    }

    results
}
