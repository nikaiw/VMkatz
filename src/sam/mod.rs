pub mod hive;
pub mod bootkey;
pub mod hashes;
pub mod lsa;

use std::collections::HashMap;
use std::io::{Read, Seek};
use std::path::Path;

use ntfs::NtfsReadSeek;

use crate::error::Result;

/// SAM + SYSTEM + optional SECURITY hive file data.
type HiveFiles = (Vec<u8>, Vec<u8>, Option<Vec<u8>>);

/// A SAM user entry with RID, username, and NT/LM hashes.
#[derive(Debug)]
pub struct SamEntry {
    pub rid: u32,
    pub username: String,
    pub nt_hash: [u8; 16],
    pub lm_hash: [u8; 16],
}

/// Combined extraction result: SAM hashes + LSA secrets.
#[derive(Debug)]
pub struct DiskSecrets {
    pub sam_entries: Vec<SamEntry>,
    pub lsa_secrets: Vec<lsa::LsaSecret>,
}

/// Extract SAM hashes from a disk image (backward-compatible wrapper).
/// Opens the disk, navigates NTFS to find SAM+SYSTEM hives, extracts hashes.
pub fn extract_sam_hashes(path: &Path) -> Result<Vec<SamEntry>> {
    let secrets = extract_disk_secrets(path)?;
    Ok(secrets.sam_entries)
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
        match scan_vmdk_grains_for_hives(&mut vmdk) {
            Ok((sam_data, system_data, security_data)) => {
                return process_hive_data(sam_data, system_data, security_data);
            }
            Err(e) => {
                log::info!("VMDK grain scan failed: {}", e);
                return Err(e);
            }
        }
    }

    Err(crate::error::GovmemError::DecryptionError(
        "All extraction methods failed".to_string(),
    ))
}

/// Extract SAM hashes + LSA secrets from any Read+Seek source.
fn extract_secrets_from_reader<R: Read + Seek>(reader: &mut R) -> Result<DiskSecrets> {
    let partitions = find_ntfs_partitions(reader).unwrap_or_default();

    for &partition_offset in &partitions {
        log::info!("Trying NTFS partition at offset 0x{:x}", partition_offset);
        match read_hive_files(reader, partition_offset) {
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
    match scan_for_hives(reader) {
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
    match scan_for_hbin_roots(reader) {
        Ok((sam_data, system_data, security_data)) => {
            process_hive_data(sam_data, system_data, security_data)
        }
        Err(e) => {
            log::info!("hbin scan failed: {}", e);
            Err(e)
        }
    }
}

/// Process extracted hive data into DiskSecrets.
fn process_hive_data(
    sam_data: Vec<u8>,
    system_data: Vec<u8>,
    security_data: Option<Vec<u8>>,
) -> Result<DiskSecrets> {
    log::info!(
        "SAM hive: {} bytes, SYSTEM hive: {} bytes",
        sam_data.len(),
        system_data.len()
    );

    // Extract bootkey from SYSTEM hive
    let boot_key = bootkey::extract_bootkey(&system_data)?;
    log::info!("Bootkey: {}", hex::encode(boot_key));

    // Extract SAM hashes
    let sam_entries = hashes::extract_hashes(&sam_data, &boot_key)?;

    // Extract LSA secrets from SECURITY hive (optional)
    let lsa_secrets = if let Some(sec_data) = &security_data {
        log::info!("SECURITY hive: {} bytes", sec_data.len());
        match lsa::extract_lsa_secrets(sec_data, &boot_key) {
            Ok(secrets) => {
                log::info!("Extracted {} LSA secrets", secrets.len());
                secrets
            }
            Err(e) => {
                log::warn!("LSA secrets extraction failed: {}", e);
                Vec::new()
            }
        }
    } else {
        log::info!("SECURITY hive not found, skipping LSA secrets");
        Vec::new()
    };

    Ok(DiskSecrets {
        sam_entries,
        lsa_secrets,
    })
}

/// Parse MBR/GPT and find all NTFS partitions, returning their byte offsets.
pub(crate) fn find_ntfs_partitions<R: Read + Seek>(reader: &mut R) -> Result<Vec<u64>> {
    use std::io::SeekFrom;
    reader.seek(SeekFrom::Start(0))?;
    let mut mbr = [0u8; 512];
    reader.read_exact(&mut mbr)?;

    // Check MBR signature
    if mbr[510] != 0x55 || mbr[511] != 0xAA {
        return Err(crate::error::GovmemError::DecryptionError(
            "Invalid MBR signature".to_string(),
        ));
    }

    // Check for GPT protective MBR (partition type 0xEE)
    let first_type = mbr[0x1BE + 4];
    if first_type == 0xEE {
        return find_gpt_ntfs_partitions(reader);
    }

    let mut partitions = Vec::new();

    // Parse MBR partition table entries (4 entries at offsets 0x1BE, 0x1CE, 0x1DE, 0x1EE)
    for i in 0..4 {
        let entry_offset = 0x1BE + i * 16;
        let part_type = mbr[entry_offset + 4];
        let lba_start = u32::from_le_bytes([
            mbr[entry_offset + 8],
            mbr[entry_offset + 9],
            mbr[entry_offset + 10],
            mbr[entry_offset + 11],
        ]);

        log::debug!(
            "MBR Partition {}: type=0x{:02x}, LBA_start={}",
            i, part_type, lba_start
        );

        // NTFS partition type is 0x07
        if part_type == 0x07 && lba_start > 0 {
            partitions.push(lba_start as u64 * 512);
        }
    }

    if partitions.is_empty() {
        return Err(crate::error::GovmemError::DecryptionError(
            "No NTFS partition found in MBR".to_string(),
        ));
    }

    Ok(partitions)
}

/// Parse GPT partition table and find NTFS (Basic Data) partitions.
fn find_gpt_ntfs_partitions<R: Read + Seek>(reader: &mut R) -> Result<Vec<u64>> {
    use std::io::SeekFrom;

    // GPT header at LBA 1 (offset 512)
    reader.seek(SeekFrom::Start(512))?;
    let mut hdr = [0u8; 92];
    reader.read_exact(&mut hdr)?;

    // Verify "EFI PART" signature
    if &hdr[0..8] != b"EFI PART" {
        return Err(crate::error::GovmemError::DecryptionError(
            "Invalid GPT signature".to_string(),
        ));
    }

    let entry_lba = u64::from_le_bytes(hdr[0x48..0x50].try_into().unwrap());
    let num_entries = u32::from_le_bytes(hdr[0x50..0x54].try_into().unwrap());
    let entry_size = u32::from_le_bytes(hdr[0x54..0x58].try_into().unwrap());

    log::debug!(
        "GPT: entry_lba={}, num_entries={}, entry_size={}",
        entry_lba, num_entries, entry_size
    );

    // "Microsoft Basic Data" GUID: EBD0A0A2-B9E5-4433-87C0-68B6B72699C7
    // Mixed-endian byte representation
    const BASIC_DATA_GUID: [u8; 16] = [
        0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44,
        0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7,
    ];

    let mut partitions = Vec::new();
    let entries_offset = entry_lba * 512;

    for i in 0..num_entries {
        let entry_offset = entries_offset + i as u64 * entry_size as u64;
        reader.seek(SeekFrom::Start(entry_offset))?;
        let mut entry = vec![0u8; entry_size as usize];
        reader.read_exact(&mut entry)?;

        let type_guid = &entry[0..16];

        // Skip empty entries
        if type_guid.iter().all(|&b| b == 0) {
            continue;
        }

        let first_lba = u64::from_le_bytes(entry[0x20..0x28].try_into().unwrap());

        if type_guid == BASIC_DATA_GUID {
            log::debug!("GPT partition {}: Basic Data at LBA {}", i, first_lba);
            partitions.push(first_lba * 512);
        }
    }

    if partitions.is_empty() {
        return Err(crate::error::GovmemError::DecryptionError(
            "No NTFS partition found in GPT".to_string(),
        ));
    }

    Ok(partitions)
}

/// Read SAM, SYSTEM, and (optionally) SECURITY hive files from NTFS filesystem.
fn read_hive_files<R: Read + Seek>(
    reader: &mut R,
    partition_offset: u64,
) -> Result<HiveFiles> {
    // Wrap reader with partition offset
    let mut part_reader = PartitionReader::new(reader, partition_offset);

    let ntfs = ntfs::Ntfs::new(&mut part_reader).map_err(|e| {
        crate::error::GovmemError::DecryptionError(format!("NTFS parse error: {}", e))
    })?;

    let root = ntfs.root_directory(&mut part_reader).map_err(|e| {
        crate::error::GovmemError::DecryptionError(format!("NTFS root dir error: {}", e))
    })?;

    // Navigate: Windows/System32/config/
    let windows = find_entry(&ntfs, &root, &mut part_reader, "Windows")?;
    let system32 = find_entry(&ntfs, &windows, &mut part_reader, "System32")?;
    let config = find_entry(&ntfs, &system32, &mut part_reader, "config")?;

    let sam_file = find_entry(&ntfs, &config, &mut part_reader, "SAM")?;
    let system_file = find_entry(&ntfs, &config, &mut part_reader, "SYSTEM")?;

    let sam_data = read_file_data(&sam_file, &mut part_reader)?;
    let system_data = read_file_data(&system_file, &mut part_reader)?;

    // SECURITY hive is optional - not all disk images may have it accessible
    let security_data = find_entry(&ntfs, &config, &mut part_reader, "SECURITY")
        .ok()
        .and_then(|f| read_file_data(&f, &mut part_reader).ok());

    Ok((sam_data, system_data, security_data))
}

/// Find a directory entry by name (case-insensitive).
pub(crate) fn find_entry<'n, R: Read + Seek>(
    ntfs: &'n ntfs::Ntfs,
    dir: &ntfs::NtfsFile<'n>,
    reader: &mut R,
    name: &str,
) -> Result<ntfs::NtfsFile<'n>> {
    let index = dir.directory_index(reader).map_err(|e| {
        crate::error::GovmemError::DecryptionError(format!(
            "Directory index error for '{}': {}",
            name, e
        ))
    })?;
    let mut iter = index.entries();
    while let Some(entry) = iter.next(reader) {
        let entry = entry.map_err(|e| {
            crate::error::GovmemError::DecryptionError(format!("Dir entry error: {}", e))
        })?;
        // key() returns Option<Result<NtfsFileName>>
        let key = match entry.key() {
            Some(Ok(k)) => k,
            Some(Err(e)) => {
                log::warn!("Index key error: {}", e);
                continue;
            }
            None => continue, // Last entry sentinel, no key
        };
        if key.name().to_string_lossy().eq_ignore_ascii_case(name) {
            let file = entry.to_file(ntfs, reader).map_err(|e| {
                crate::error::GovmemError::DecryptionError(format!(
                    "Failed to open '{}': {}",
                    name, e
                ))
            })?;
            return Ok(file);
        }
    }
    Err(crate::error::GovmemError::ProcessNotFound(format!(
        "NTFS entry '{}' not found",
        name
    )))
}

/// Read file data ($DATA attribute) into a Vec<u8>.
pub(crate) fn read_file_data<R: Read + Seek>(
    file: &ntfs::NtfsFile,
    reader: &mut R,
) -> Result<Vec<u8>> {
    let data_item = file
        .data(reader, "")
        .ok_or_else(|| {
            crate::error::GovmemError::DecryptionError("No $DATA attribute".to_string())
        })?
        .map_err(|e| {
            crate::error::GovmemError::DecryptionError(format!("$DATA error: {}", e))
        })?;
    let data_attr = data_item.to_attribute().map_err(|e| {
        crate::error::GovmemError::DecryptionError(format!("to_attribute error: {}", e))
    })?;
    let mut data_value = data_attr.value(reader).map_err(|e| {
        crate::error::GovmemError::DecryptionError(format!("Attribute value error: {}", e))
    })?;
    let len = data_value.len();
    let mut buf = vec![0u8; len as usize];
    data_value.read_exact(reader, &mut buf).map_err(|e| {
        crate::error::GovmemError::DecryptionError(format!("Read file data error: {}", e))
    })?;
    Ok(buf)
}

/// Wraps a Read+Seek with a partition offset.
pub(crate) struct PartitionReader<'a, R: Read + Seek> {
    inner: &'a mut R,
    offset: u64,
}

impl<'a, R: Read + Seek> PartitionReader<'a, R> {
    pub(crate) fn new(inner: &'a mut R, offset: u64) -> Self {
        Self { inner, offset }
    }
}

impl<R: Read + Seek> Read for PartitionReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<R: Read + Seek> Seek for PartitionReader<'_, R> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        match pos {
            std::io::SeekFrom::Start(offset) => {
                let actual = self.inner.seek(std::io::SeekFrom::Start(self.offset + offset))?;
                Ok(actual - self.offset)
            }
            std::io::SeekFrom::Current(delta) => {
                let actual = self.inner.seek(std::io::SeekFrom::Current(delta))?;
                Ok(actual.saturating_sub(self.offset))
            }
            std::io::SeekFrom::End(delta) => {
                let actual = self.inner.seek(std::io::SeekFrom::End(delta))?;
                Ok(actual.saturating_sub(self.offset))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Raw "regf" scan fallback for damaged/incomplete disk images
// ---------------------------------------------------------------------------

/// Maximum hive size we'll try to read (16MB — covers even large SYSTEM hives).
const MAX_HIVE_SIZE: u64 = 16 * 1024 * 1024;
/// Scan chunk size for reading the disk (1MB).
const SCAN_CHUNK: usize = 1024 * 1024;
/// NTFS cluster size (4KB) — regf headers align to cluster boundaries.
const CLUSTER_SIZE: usize = 4096;
/// Minimum valid SYSTEM hive size (real SYSTEM is 8-16MB; reject tiny false matches).
const MIN_SYSTEM_HIVE_SIZE: u64 = 512 * 1024;
/// Minimum valid SAM hive size (real SAM is 40-256KB; reject stubs).
const MIN_SAM_HIVE_SIZE: u64 = 16 * 1024;

/// Scan the raw disk for "regf" registry hive signatures and extract SAM + SYSTEM + SECURITY.
/// Used as fallback when NTFS MFT traversal fails (e.g., incomplete disk images).
fn scan_for_hives<R: Read + Seek>(reader: &mut R) -> Result<HiveFiles> {
    use std::io::SeekFrom;

    let disk_size = reader.seek(SeekFrom::End(0))?;
    reader.seek(SeekFrom::Start(0))?;

    log::info!(
        "Scanning {}MB disk for regf signatures...",
        disk_size / (1024 * 1024)
    );

    let mut sam_data: Option<Vec<u8>> = None;
    let mut system_data: Option<Vec<u8>> = None;
    let mut security_data: Option<Vec<u8>> = None;
    let mut found_count = 0u32;

    let mut offset = 0u64;
    let mut chunk = vec![0u8; SCAN_CHUNK];

    while offset < disk_size {
        reader.seek(SeekFrom::Start(offset))?;
        let n = match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };

        // Scan this chunk at cluster boundaries for "regf" magic
        let mut pos = 0;
        while pos + 4 <= n {
            if &chunk[pos..pos + 4] == b"regf" {
                let hive_offset = offset + pos as u64;
                if let Some((name, data)) = try_read_hive(reader, hive_offset) {
                    log::info!(
                        "Found {} hive at offset 0x{:x} ({} bytes)",
                        name,
                        hive_offset,
                        data.len()
                    );
                    found_count += 1;
                    match name.as_str() {
                        "SAM" => sam_data = Some(data),
                        "SYSTEM" => system_data = Some(data),
                        "SECURITY" => security_data = Some(data),
                        _ => {} // Ignore other hives (SOFTWARE, DEFAULT, etc.)
                    }
                    // Stop once we have SAM + SYSTEM (SECURITY is optional)
                    if sam_data.is_some() && system_data.is_some() {
                        log::info!("Found all required hives ({} total regf)", found_count);
                        #[allow(clippy::unnecessary_unwrap)]
                        return Ok((
                            sam_data.unwrap(),
                            system_data.unwrap(),
                            security_data,
                        ));
                    }
                }
                // Restore read position for continued scanning
                reader.seek(SeekFrom::Start(offset + n as u64))?;
            }
            pos += CLUSTER_SIZE;
        }

        offset += n as u64;
    }

    let has_sam = sam_data.is_some();
    let has_system = system_data.is_some();
    if let (Some(sam), Some(system)) = (sam_data, system_data) {
        Ok((sam, system, security_data))
    } else {
        let mut detail = format!("Raw scan found {} regf hive(s)", found_count);
        if !has_sam {
            detail.push_str(", SAM hive not found");
        }
        if !has_system {
            detail.push_str(", SYSTEM hive not found");
        }
        detail.push_str(". Disk image may be incomplete (missing extents or snapshot delta)");
        Err(crate::error::GovmemError::DecryptionError(detail))
    }
}

/// Try to read and validate a registry hive at the given disk offset.
/// Returns `Some((hive_name, data))` if successful.
fn try_read_hive<R: Read + Seek>(reader: &mut R, offset: u64) -> Option<(String, Vec<u8>)> {
    use std::io::SeekFrom;

    // Read regf header (first 4KB)
    reader.seek(SeekFrom::Start(offset)).ok()?;
    let mut header = [0u8; 4096];
    reader.read_exact(&mut header).ok()?;

    // Validate magic
    if &header[0..4] != b"regf" {
        return None;
    }

    // hive_bins_data_size at offset 0x28
    let bins_size = u32::from_le_bytes(header[0x28..0x2C].try_into().unwrap()) as u64;
    if bins_size == 0 || bins_size > MAX_HIVE_SIZE {
        log::debug!(
            "regf at 0x{:x}: bins_size={} (skipped)",
            offset,
            bins_size
        );
        return None;
    }

    let total_size = 0x1000 + bins_size;

    // Read the complete hive
    reader.seek(SeekFrom::Start(offset)).ok()?;
    let mut data = vec![0u8; total_size as usize];
    reader.read_exact(&mut data).ok()?;

    // Parse to get root key name
    let hive = match hive::Hive::new(&data) {
        Ok(h) => h,
        Err(e) => {
            log::debug!("regf at 0x{:x}: hive parse error: {}", offset, e);
            return None;
        }
    };
    let root = match hive.root_key() {
        Ok(r) => r,
        Err(e) => {
            log::debug!("regf at 0x{:x}: root key error: {}", offset, e);
            return None;
        }
    };
    let name = root.name().to_uppercase();
    log::debug!(
        "regf at 0x{:x}: root='{}', size={}",
        offset,
        name,
        total_size
    );

    // Accept known hive names with minimum size validation to reject
    // false matches (e.g. volatile "System" hive vs real config SYSTEM)
    match name.as_str() {
        "SYSTEM" if total_size >= MIN_SYSTEM_HIVE_SIZE => Some((name, data)),
        "SAM" if total_size >= MIN_SAM_HIVE_SIZE => Some((name, data)),
        "SECURITY" => Some((name, data)),
        "SYSTEM" | "SAM" => {
            log::debug!(
                "regf at 0x{:x}: '{}' too small ({}B), skipping",
                offset,
                name,
                total_size
            );
            None
        }
        _ => {
            log::debug!("regf at 0x{:x}: skipping hive '{}'", offset, name);
            None
        }
    }
}

/// Scan for hbin blocks with hive-offset=0 (first block of each hive).
/// This handles NTFS-fragmented hives where the regf header is at one disk
/// location but the hbin data starts at a different, non-contiguous location.
///
/// When a first-hbin is found with root key SAM/SYSTEM/SECURITY, we read
/// contiguous hbin blocks from that position to reconstruct the hive.
fn scan_for_hbin_roots<R: Read + Seek>(reader: &mut R) -> Result<HiveFiles> {
    use std::io::SeekFrom;

    let disk_size = reader.seek(SeekFrom::End(0))?;
    reader.seek(SeekFrom::Start(0))?;

    log::info!(
        "Scanning {}MB disk for hbin(offset=0) blocks...",
        disk_size / (1024 * 1024)
    );

    let mut sam_data: Option<Vec<u8>> = None;
    let mut system_data: Option<Vec<u8>> = None;
    let mut security_data: Option<Vec<u8>> = None;
    let mut found_count = 0u32;

    let mut offset = 0u64;
    let mut chunk = vec![0u8; SCAN_CHUNK];

    while offset < disk_size {
        reader.seek(SeekFrom::Start(offset))?;
        let n = match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };

        let mut pos = 0;
        while pos + 0x60 <= n {
            if &chunk[pos..pos + 4] == b"hbin" {
                // hbin header: "hbin"(4) + offset_in_hive(4) + size(4) + ...
                let hbin_hive_off =
                    u32::from_le_bytes(chunk[pos + 4..pos + 8].try_into().unwrap());
                let hbin_size =
                    u32::from_le_bytes(chunk[pos + 8..pos + 12].try_into().unwrap());

                // Only interested in first hbin of a hive (offset_in_hive == 0)
                if hbin_hive_off == 0 && hbin_size >= 0x1000 && hbin_size <= 0x100000 {
                    let disk_offset = offset + pos as u64;
                    if let Some((name, data)) = try_read_hbin_hive(reader, disk_offset) {
                        log::info!(
                            "Found {} hive via hbin at offset 0x{:x} ({} bytes)",
                            name,
                            disk_offset,
                            data.len()
                        );
                        found_count += 1;
                        match name.as_str() {
                            "SAM" => sam_data = Some(data),
                            "SYSTEM" => system_data = Some(data),
                            "SECURITY" => security_data = Some(data),
                            _ => {}
                        }
                        if sam_data.is_some() && system_data.is_some() {
                            log::info!("Found all required hives via hbin scan");
                            #[allow(clippy::unnecessary_unwrap)]
                            return Ok((
                                sam_data.unwrap(),
                                system_data.unwrap(),
                                security_data,
                            ));
                        }
                    }
                    reader.seek(SeekFrom::Start(offset + n as u64))?;
                }
            }
            pos += CLUSTER_SIZE;
        }

        offset += n as u64;
    }

    let has_sam = sam_data.is_some();
    let has_system = system_data.is_some();
    if let (Some(sam), Some(system)) = (sam_data, system_data) {
        Ok((sam, system, security_data))
    } else {
        let mut detail = format!(
            "hbin scan found {} candidate(s) but missing",
            found_count
        );
        if !has_sam {
            detail.push_str(" SAM");
        }
        if !has_system {
            if !has_sam {
                detail.push_str(" and");
            }
            detail.push_str(" SYSTEM");
        }
        detail.push_str(". Disk image may be incomplete (missing extents or snapshot delta)");
        Err(crate::error::GovmemError::DecryptionError(detail))
    }
}

/// Try to read a hive starting from its first hbin block at the given offset.
/// The root NK cell within the first hbin tells us the hive name.
/// We then read contiguous hbin blocks to reconstruct the hive data.
fn try_read_hbin_hive<R: Read + Seek>(
    reader: &mut R,
    hbin_offset: u64,
) -> Option<(String, Vec<u8>)> {
    use std::io::SeekFrom;

    // Read the first hbin block
    reader.seek(SeekFrom::Start(hbin_offset)).ok()?;
    let mut first_block = [0u8; 4096];
    reader.read_exact(&mut first_block).ok()?;

    if &first_block[0..4] != b"hbin" {
        return None;
    }

    // Parse root NK cell at offset 0x20 within hbin data area
    let cell_off = 0x20usize;
    if cell_off + 0x60 >= first_block.len() {
        return None;
    }

    let nk_sig = &first_block[cell_off + 4..cell_off + 6];
    if nk_sig != b"nk" {
        return None;
    }

    // Note: we do NOT check KEY_HIVE_ENTRY (0x04) flag here.
    // Some hives (e.g. SAM) only set KEY_COMP_NAME (0x20) on their root key.
    // Since we already filtered for hbin offset_in_hive==0, the NK cell at
    // offset 0x20 IS the root key by definition.

    let name_len =
        u16::from_le_bytes(first_block[cell_off + 0x4C..cell_off + 0x4E].try_into().unwrap())
            as usize;
    if name_len == 0 || cell_off + 0x50 + name_len > first_block.len() {
        return None;
    }

    let name =
        String::from_utf8_lossy(&first_block[cell_off + 0x50..cell_off + 0x50 + name_len])
            .to_uppercase();

    // Only accept target hive names
    if !matches!(name.as_str(), "SAM" | "SYSTEM" | "SECURITY") {
        return None;
    }

    // Read contiguous hbin blocks to reconstruct the hive
    // Build synthetic regf header (4KB) + contiguous hbin data
    let mut hive_data = Vec::new();

    // Create a minimal regf header
    let mut regf_hdr = vec![0u8; 0x1000];
    regf_hdr[0..4].copy_from_slice(b"regf");
    // root_cell_offset at +0x24: 0x20 (standard)
    regf_hdr[0x24..0x28].copy_from_slice(&0x20u32.to_le_bytes());

    // Read contiguous hbin blocks
    let mut hbin_data = Vec::new();
    let mut read_offset = hbin_offset;
    let mut hbin_buf = [0u8; 4096];

    loop {
        if hbin_data.len() as u64 >= MAX_HIVE_SIZE {
            break;
        }

        reader.seek(SeekFrom::Start(read_offset)).ok()?;

        // Read first page of potential hbin block
        if reader.read_exact(&mut hbin_buf).is_err() {
            break;
        }

        if &hbin_buf[0..4] != b"hbin" {
            break;
        }

        let hbin_hive_off =
            u32::from_le_bytes(hbin_buf[4..8].try_into().unwrap()) as usize;
        let block_size =
            u32::from_le_bytes(hbin_buf[8..12].try_into().unwrap()) as usize;
        if block_size < 0x1000 || block_size > 0x100000 {
            break;
        }
        // Validate offset_in_hive matches accumulated data
        if hbin_hive_off != hbin_data.len() {
            break;
        }

        // Read the full hbin block
        let mut block = vec![0u8; block_size];
        reader.seek(SeekFrom::Start(read_offset)).ok()?;
        if reader.read_exact(&mut block).is_err() {
            break;
        }

        hbin_data.extend_from_slice(&block);
        read_offset += block_size as u64;
    }

    if hbin_data.is_empty() {
        return None;
    }

    let bins_size = hbin_data.len() as u32;
    // Set hive_bins_data_size at +0x28
    regf_hdr[0x28..0x2C].copy_from_slice(&bins_size.to_le_bytes());

    hive_data.extend_from_slice(&regf_hdr);
    hive_data.extend_from_slice(&hbin_data);

    let total_size = hive_data.len() as u64;
    // Apply same size validation
    match name.as_str() {
        "SYSTEM" if total_size < MIN_SYSTEM_HIVE_SIZE => {
            log::debug!(
                "hbin hive '{}' too small ({}B), skipping",
                name,
                total_size
            );
            return None;
        }
        "SAM" if total_size < MIN_SAM_HIVE_SIZE => {
            log::debug!(
                "hbin hive '{}' too small ({}B), skipping",
                name,
                total_size
            );
            return None;
        }
        _ => {}
    }

    log::info!(
        "Reconstructed {} hive from hbin blocks: {} bytes ({} hbin data)",
        name,
        hive_data.len(),
        bins_size
    );

    Some((name, hive_data))
}

// ---------------------------------------------------------------------------
// VMDK grain-direct scan: bypasses LBA translation to read only allocated grains
// ---------------------------------------------------------------------------

/// Scan all physically allocated VMDK grains for registry hive signatures.
///
/// Three-phase approach:
/// 1. Fast grain scan to collect candidate positions (regf headers, ALL hbin blocks)
/// 2. Try contiguous reads from regf headers and hbin roots
/// 3. Fragmented assembly: collect scattered hbin blocks by offset_in_hive,
///    chain them to rebuild hives fragmented by NTFS
fn scan_vmdk_grains_for_hives(
    vmdk: &mut crate::disk::vmdk::VmdkDisk,
) -> Result<HiveFiles> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    log::info!("Starting VMDK grain-direct scan for registry hives");

    let mut grains_scanned = 0u64;

    // Phase 1: Collect candidates from grain data
    let mut regf_candidates: Vec<(u64, u64)> = Vec::new(); // (virtual_offset, bins_size)
    let mut hbin_root_candidates: Vec<(u64, String)> = Vec::new(); // (virtual_offset, name)
    // ALL hbin blocks: (virtual_offset, offset_in_hive, block_size)
    let mut all_hbin_blocks: Vec<(u64, u32, u32)> = Vec::new();

    vmdk.scan_all_grains(|virtual_byte, grain_data| {
        grains_scanned += 1;

        let mut pos = 0;
        while pos + CLUSTER_SIZE <= grain_data.len() {
            let chunk = &grain_data[pos..];

            // Check for "regf" signature
            if pos + 0x2C <= grain_data.len() && chunk[0..4] == *b"regf" {
                let bins_size =
                    u32::from_le_bytes(chunk[0x28..0x2C].try_into().unwrap()) as u64;
                if bins_size > 0 && bins_size <= MAX_HIVE_SIZE {
                    regf_candidates.push((virtual_byte + pos as u64, bins_size));
                }
            }

            // Check for "hbin" signature (ANY hbin block, not just offset=0)
            if pos + 0x20 <= grain_data.len() && chunk[0..4] == *b"hbin" {
                let hbin_hive_off =
                    u32::from_le_bytes(chunk[4..8].try_into().unwrap());
                let hbin_size =
                    u32::from_le_bytes(chunk[8..12].try_into().unwrap());
                if (0x1000..=0x100000).contains(&hbin_size)
                    && (hbin_hive_off as u64) < MAX_HIVE_SIZE
                    && hbin_hive_off % 0x1000 == 0
                {
                    all_hbin_blocks.push((
                        virtual_byte + pos as u64,
                        hbin_hive_off,
                        hbin_size,
                    ));

                    // For offset=0 blocks, parse root NK cell to identify hive
                    if hbin_hive_off == 0 {
                        let cell_off = 0x20;
                        if cell_off + 0x60 < chunk.len()
                            && &chunk[cell_off + 4..cell_off + 6] == b"nk"
                        {
                            let name_len = u16::from_le_bytes(
                                chunk[cell_off + 0x4C..cell_off + 0x4E]
                                    .try_into()
                                    .unwrap(),
                            ) as usize;
                            if name_len > 0 && cell_off + 0x50 + name_len <= chunk.len() {
                                let name = String::from_utf8_lossy(
                                    &chunk[cell_off + 0x50..cell_off + 0x50 + name_len],
                                )
                                .to_uppercase();
                                if matches!(name.as_str(), "SAM" | "SYSTEM" | "SECURITY") {
                                    log::info!(
                                        "Grain scan: found {} hbin(0) at virt 0x{:x}+0x{:x}",
                                        name,
                                        virtual_byte,
                                        pos,
                                    );
                                    hbin_root_candidates.push((
                                        virtual_byte + pos as u64,
                                        name,
                                    ));
                                }
                            }
                        }
                    }
                }
            }

            pos += CLUSTER_SIZE;
        }
        true // always scan all grains
    })?;

    log::info!(
        "Grain scan complete: {} grains, {} regf candidates, {} hbin roots, {} total hbin blocks",
        grains_scanned,
        regf_candidates.len(),
        hbin_root_candidates.len(),
        all_hbin_blocks.len(),
    );

    // Phase 2: Try to read full hive data using VmdkDisk seek/read

    let mut sam_data: Option<Vec<u8>> = None;
    let mut system_data: Option<Vec<u8>> = None;
    let mut security_data: Option<Vec<u8>> = None;

    // 2a: Try regf candidates — read total_size bytes contiguously
    for &(virt_off, bins_size) in &regf_candidates {
        let total_size = (0x1000 + bins_size) as usize;
        if vmdk.seek(SeekFrom::Start(virt_off)).is_err() {
            continue;
        }
        let mut data = vec![0u8; total_size];
        if vmdk.read_exact(&mut data).is_err() {
            continue;
        }
        let h = match hive::Hive::new(&data) {
            Ok(h) => h,
            Err(_) => continue,
        };
        let name = match h.root_key() {
            Ok(r) => r.name().to_uppercase(),
            Err(_) => continue,
        };
        let target = match name.as_str() {
            "SAM" if sam_data.is_none() => &mut sam_data,
            "SYSTEM" if system_data.is_none() && total_size as u64 >= MIN_SYSTEM_HIVE_SIZE => {
                &mut system_data
            }
            "SECURITY" if security_data.is_none() => &mut security_data,
            _ => continue,
        };
        log::info!(
            "Grain scan: read {} hive at virt 0x{:x} ({} bytes)",
            name, virt_off, total_size
        );
        *target = Some(data);

        if sam_data.is_some() && system_data.is_some() {
            break;
        }
    }

    if sam_data.is_some() && system_data.is_some() {
        return Ok((sam_data.unwrap(), system_data.unwrap(), security_data));
    }

    // 2b: Try hbin root candidates — read contiguous hbin blocks
    for (hbin_virt, name) in &hbin_root_candidates {
        let target = match name.as_str() {
            "SAM" if sam_data.is_none() => &mut sam_data,
            "SYSTEM" if system_data.is_none() => &mut system_data,
            "SECURITY" if security_data.is_none() => &mut security_data,
            _ => continue,
        };

        let mut hbin_data = Vec::new();
        let mut read_offset = *hbin_virt;
        let mut hbin_buf = [0u8; CLUSTER_SIZE];

        loop {
            if hbin_data.len() as u64 >= MAX_HIVE_SIZE {
                break;
            }
            if vmdk.seek(SeekFrom::Start(read_offset)).is_err() {
                break;
            }
            if vmdk.read_exact(&mut hbin_buf).is_err() {
                break;
            }
            if &hbin_buf[0..4] != b"hbin" {
                break;
            }
            let hbin_hive_off =
                u32::from_le_bytes(hbin_buf[4..8].try_into().unwrap()) as usize;
            let block_size =
                u32::from_le_bytes(hbin_buf[8..12].try_into().unwrap()) as usize;
            if block_size < 0x1000 || block_size > 0x100000 {
                break;
            }
            if hbin_hive_off != hbin_data.len() {
                break;
            }
            let mut block = vec![0u8; block_size];
            if vmdk.seek(SeekFrom::Start(read_offset)).is_err() {
                break;
            }
            if vmdk.read_exact(&mut block).is_err() {
                break;
            }
            hbin_data.extend_from_slice(&block);
            read_offset += block_size as u64;
        }

        if let Some(hive_data) = build_hive_from_hbins(
            vmdk,
            name,
            &hbin_data,
            &regf_candidates,
        ) {
            log::info!(
                "Grain scan: valid {} hive from contiguous hbin at virt 0x{:x} ({} bytes)",
                name, hbin_virt, hive_data.len()
            );
            *target = Some(hive_data);
        }
    }

    if sam_data.is_some() && system_data.is_some() {
        return Ok((sam_data.unwrap(), system_data.unwrap(), security_data));
    }

    // Phase 2c: Fragmented hive assembly
    // Collect all hbin blocks scattered across the disk, group by offset_in_hive,
    // and try to chain them into complete hives.
    if !hbin_root_candidates.is_empty()
        && (sam_data.is_none() || system_data.is_none() || security_data.is_none())
    {
        log::info!(
            "Attempting fragmented hive assembly from {} hbin blocks",
            all_hbin_blocks.len()
        );

        // Build lookup: offset_in_hive → list of (virtual_offset, block_size)
        let mut hbin_by_offset: HashMap<u32, Vec<(u64, u32)>> = HashMap::new();
        for &(virt_off, off_in_hive, blk_size) in &all_hbin_blocks {
            hbin_by_offset
                .entry(off_in_hive)
                .or_default()
                .push((virt_off, blk_size));
        }

        // Find the target bins_size for each hive from regf candidates
        let regf_info = find_regf_for_hives(vmdk, &regf_candidates);

        for (hbin_virt, name) in &hbin_root_candidates {
            let target = match name.as_str() {
                "SAM" if sam_data.is_none() => &mut sam_data,
                "SYSTEM" if system_data.is_none() => &mut system_data,
                "SECURITY" if security_data.is_none() => &mut security_data,
                _ => continue,
            };

            let bins_size = match regf_info.get(name.as_str()) {
                Some(&(_, bs)) => bs as u32,
                None => {
                    // No matching regf header. Use conservative default size.
                    // Greedy assembly will fill gaps with zeros.
                    let default = match name.as_str() {
                        "SYSTEM" => 0x800000u32, // 8MB
                        _ => 0x10000u32,          // 64KB for SAM/SECURITY
                    };
                    log::info!(
                        "Fragmented {}: no matching regf header, using default bins_size=0x{:x}",
                        name, default,
                    );
                    default
                }
            };

            // Read the root hbin block
            let root_blocks = match hbin_by_offset.get(&0) {
                Some(v) => v.clone(),
                None => continue,
            };
            let root_entry = root_blocks.iter().find(|&&(vo, _)| vo == *hbin_virt);
            let root_block_size = match root_entry {
                Some(&(_, sz)) => sz,
                None => 0x1000, // default
            };

            // Assemble: chain hbin blocks by offset_in_hive
            let assembled = assemble_fragmented_hive(
                vmdk,
                &hbin_by_offset,
                name,
                bins_size,
                *hbin_virt,
                root_block_size,
            );

            if let Some(hbin_data) = assembled {
                if let Some(hive_data) = build_hive_from_hbins(
                    vmdk,
                    name,
                    &hbin_data,
                    &regf_candidates,
                ) {
                    log::info!(
                        "Grain scan: valid {} hive assembled from fragmented hbin blocks ({} bytes)",
                        name,
                        hive_data.len()
                    );
                    *target = Some(hive_data);
                }
            }
        }
    }

    let has_sam = sam_data.is_some();
    let has_system = system_data.is_some();
    if let (Some(sam), Some(system)) = (sam_data, system_data) {
        Ok((sam, system, security_data))
    } else {
        let mut detail = "VMDK grain scan:".to_string();
        if !has_sam {
            detail.push_str(" SAM not found");
        }
        if !has_system {
            if !has_sam {
                detail.push_str(",");
            }
            detail.push_str(" SYSTEM not found");
        }
        if !regf_candidates.is_empty() || !hbin_root_candidates.is_empty() {
            detail.push_str(&format!(
                " ({} regf, {} hbin roots, {} total hbins scanned)",
                regf_candidates.len(),
                hbin_root_candidates.len(),
                all_hbin_blocks.len(),
            ));
        }
        Err(crate::error::GovmemError::DecryptionError(detail))
    }
}

/// Find matching regf headers for SAM/SYSTEM/SECURITY by path.
/// Returns name → (virtual_offset, bins_size).
fn find_regf_for_hives(
    vmdk: &mut crate::disk::vmdk::VmdkDisk,
    regf_candidates: &[(u64, u64)],
) -> HashMap<&'static str, (u64, u64)> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    let mut result: HashMap<&'static str, (u64, u64)> = HashMap::new();

    for &(roff, rbins) in regf_candidates {
        if vmdk.seek(SeekFrom::Start(roff + 0x30)).is_err() {
            continue;
        }
        let mut path_buf = [0u8; 128];
        if vmdk.read_exact(&mut path_buf).is_err() {
            continue;
        }
        let path = String::from_utf8_lossy(&path_buf)
            .to_uppercase()
            .replace('\0', "");

        let hive_name: &'static str = if path.contains("CONFIG\\SAM") || path.ends_with("\\SAM") {
            "SAM"
        } else if path.contains("CONFIG\\SYSTEM") || path.ends_with("\\SYSTEM") {
            "SYSTEM"
        } else if path.contains("CONFIG\\SECURITY") || path.ends_with("\\SECURITY") {
            "SECURITY"
        } else {
            continue;
        };

        // Prefer the regf with the largest bins_size (most recent/complete)
        log::info!(
            "Matched regf at 0x{:x} as {} (bins_size=0x{:x}, path={})",
            roff, hive_name, rbins, path.trim()
        );
        if result.get(hive_name).is_none_or(|&(_, prev)| rbins > prev) {
            result.insert(hive_name, (roff, rbins));
        }
    }
    result
}

/// Assemble a fragmented hive by chaining hbin blocks from the global collection.
///
/// For small hives (SAM, SECURITY ≤ 256KB), tries all candidates at each offset
/// with backtracking. For large hives (SYSTEM), uses greedy first-match.
fn assemble_fragmented_hive(
    vmdk: &mut crate::disk::vmdk::VmdkDisk,
    hbin_by_offset: &HashMap<u32, Vec<(u64, u32)>>,
    name: &str,
    bins_size: u32,
    root_virt: u64,
    root_block_size: u32,
) -> Option<Vec<u8>> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    // Read the root hbin block first
    if vmdk.seek(SeekFrom::Start(root_virt)).is_err() {
        return None;
    }
    let mut root_data = vec![0u8; root_block_size as usize];
    if vmdk.read_exact(&mut root_data).is_err() {
        return None;
    }
    if &root_data[0..4] != b"hbin" {
        return None;
    }

    // For small hives, try backtracking search first, fall back to greedy.
    // For large hives, go straight to greedy.
    let max_backtrack_size = 256 * 1024u32; // 256KB
    if bins_size <= max_backtrack_size {
        if let Some(result) =
            assemble_with_backtracking(vmdk, hbin_by_offset, name, bins_size, root_data.clone())
        {
            return Some(result);
        }
        log::info!("Fragmented {}: backtracking failed, trying greedy fallback", name);
    }
    assemble_greedy(vmdk, hbin_by_offset, name, bins_size, root_data)
}

/// Backtracking assembly for small hives (SAM, SECURITY).
///
/// Sorts candidates at each offset by proximity to the root hbin block
/// (NTFS fragments tend to be nearby), then uses depth-first search with
/// incremental validation: after placing each block, checks if the partial
/// hive can parse successfully.
fn assemble_with_backtracking(
    vmdk: &mut crate::disk::vmdk::VmdkDisk,
    hbin_by_offset: &HashMap<u32, Vec<(u64, u32)>>,
    name: &str,
    bins_size: u32,
    root_data: Vec<u8>,
) -> Option<Vec<u8>> {
    let root_virt = {
        // Find root block virtual address from the hbin_by_offset map
        let root_cands = hbin_by_offset.get(&0)?;
        // Use the first candidate at offset 0 (the one matching our root_data)
        root_cands.first()?.0
    };

    // Sort candidates at each offset by proximity to root_virt.
    // Closer blocks are more likely to belong to the same file (NTFS locality).
    let mut sorted_by_offset: HashMap<u32, Vec<(u64, u32)>> = HashMap::new();
    for (&off, cands) in hbin_by_offset {
        if off == 0 || off >= bins_size {
            continue;
        }
        let mut sorted = cands.clone();
        sorted.sort_by_key(|&(virt, _)| {
            if virt >= root_virt {
                virt - root_virt
            } else {
                root_virt - virt
            }
        });
        // Limit to closest candidates to keep search manageable
        sorted.truncate(10);
        sorted_by_offset.insert(off, sorted);
    }

    // Depth-first search with proximity-sorted candidates.
    // choices[i] = (offset_in_hive, candidate_index, block_data)
    let mut choices: Vec<(u32, usize, Vec<u8>)> = Vec::new();
    let mut current_offset = root_data.len() as u32;
    let mut validations = 0u32;
    let max_validations = 2000u32;
    // Track first structurally valid assembly as fallback when strict validation
    // never passes (e.g., delta disks where subkeys are in base disk)
    let mut first_structural: Option<Vec<u8>> = None;

    'outer: loop {
        if validations > max_validations {
            log::info!(
                "Fragmented {}: exceeded {} validations, giving up",
                name,
                max_validations
            );
            break;
        }

        if current_offset >= bins_size {
            // Full chain — assemble and validate
            validations += 1;
            let assembled = assemble_from_choices(&root_data, &choices);
            if validate_hive_content(name, &assembled) {
                log::info!(
                    "Fragmented {}: assembled {} bytes from {} blocks ({} validations)",
                    name,
                    assembled.len(),
                    choices.len() + 1,
                    validations,
                );
                return Some(assembled);
            }
            // Save first structurally valid assembly as fallback
            if first_structural.is_none() && validate_hive_structure(name, &assembled) {
                first_structural = Some(assembled);
            }
            // Backtrack: try next candidate at the deepest level
            if !do_backtrack(vmdk, &mut choices, &mut current_offset, &sorted_by_offset) {
                break;
            }
            continue;
        }

        // Find candidates at current_offset
        let candidates = match sorted_by_offset.get(&current_offset) {
            Some(v) if !v.is_empty() => v,
            _ => {
                if !do_backtrack(vmdk, &mut choices, &mut current_offset, &sorted_by_offset) {
                    log::info!(
                        "Fragmented {}: no candidates at offset 0x{:x}",
                        name,
                        current_offset
                    );
                    break;
                }
                continue;
            }
        };

        // Try candidates starting from index 0 (proximity-sorted, closest first)
        for ci in 0..candidates.len() {
            let (virt_off, blk_size) = candidates[ci];
            if let Some(block) = read_hbin_at(vmdk, virt_off, blk_size, current_offset) {
                choices.push((current_offset, ci, block));
                current_offset += blk_size;
                continue 'outer;
            }
        }

        // All candidates unreadable — backtrack
        if !do_backtrack(vmdk, &mut choices, &mut current_offset, &sorted_by_offset) {
            break;
        }
    }

    // If strict validation never passed, use first structurally valid assembly
    if let Some(data) = first_structural {
        log::info!(
            "Fragmented {}: using structurally valid assembly ({} bytes, subkey check failed)",
            name,
            data.len(),
        );
        return Some(data);
    }

    log::info!(
        "Fragmented {}: search exhausted ({} validations)",
        name,
        validations
    );
    None
}

/// Read and validate an hbin block from virtual disk.
fn read_hbin_at(
    vmdk: &mut crate::disk::vmdk::VmdkDisk,
    virt_off: u64,
    blk_size: u32,
    expected_offset: u32,
) -> Option<Vec<u8>> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    if vmdk.seek(SeekFrom::Start(virt_off)).is_err() {
        return None;
    }
    let mut block = vec![0u8; blk_size as usize];
    if vmdk.read_exact(&mut block).is_err() {
        return None;
    }
    if block.len() < 12 || &block[0..4] != b"hbin" {
        return None;
    }
    let actual_off = u32::from_le_bytes(block[4..8].try_into().unwrap());
    if actual_off != expected_offset {
        return None;
    }
    Some(block)
}

/// Assemble hbin data from root + choices (without disk reads).
fn assemble_from_choices(root_data: &[u8], choices: &[(u32, usize, Vec<u8>)]) -> Vec<u8> {
    let total: usize = root_data.len() + choices.iter().map(|(_, _, d)| d.len()).sum::<usize>();
    let mut assembled = Vec::with_capacity(total);
    assembled.extend_from_slice(root_data);
    for (_, _, block) in choices {
        assembled.extend_from_slice(block);
    }
    assembled
}

/// Backtrack: pop last choice, try next candidates at that offset (reading block data).
/// If all candidates at that offset exhausted, pop further.
fn do_backtrack(
    vmdk: &mut crate::disk::vmdk::VmdkDisk,
    choices: &mut Vec<(u32, usize, Vec<u8>)>,
    current_offset: &mut u32,
    sorted_by_offset: &HashMap<u32, Vec<(u64, u32)>>,
) -> bool {
    while let Some((off, ci, _)) = choices.pop() {
        if let Some(candidates) = sorted_by_offset.get(&off) {
            for next_ci in (ci + 1)..candidates.len() {
                let (virt_off, blk_size) = candidates[next_ci];
                if let Some(block) = read_hbin_at(vmdk, virt_off, blk_size, off) {
                    choices.push((off, next_ci, block));
                    *current_offset = off + blk_size;
                    return true;
                }
            }
        }
        // All candidates exhausted at this offset — backtrack further
    }
    false
}

/// Greedy assembly for large hives (SYSTEM).
/// For each needed offset, reads the first available candidate.
fn assemble_greedy(
    vmdk: &mut crate::disk::vmdk::VmdkDisk,
    hbin_by_offset: &HashMap<u32, Vec<(u64, u32)>>,
    name: &str,
    bins_size: u32,
    root_data: Vec<u8>,
) -> Option<Vec<u8>> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    let mut assembled = root_data;
    let mut next_offset = assembled.len() as u32;
    let mut blocks_found = 1u32;
    let mut blocks_missing = 0u32;

    while next_offset < bins_size {
        let candidates = hbin_by_offset.get(&next_offset);
        let mut found = false;

        if let Some(cands) = candidates {
            for &(virt_off, blk_size) in cands {
                if vmdk.seek(SeekFrom::Start(virt_off)).is_err() {
                    continue;
                }
                let mut block = vec![0u8; blk_size as usize];
                if vmdk.read_exact(&mut block).is_err() {
                    continue;
                }
                if block.len() >= 12 && &block[0..4] == b"hbin" {
                    let actual_off =
                        u32::from_le_bytes(block[4..8].try_into().unwrap());
                    if actual_off == next_offset {
                        assembled.extend_from_slice(&block);
                        next_offset += blk_size;
                        blocks_found += 1;
                        found = true;
                        break;
                    }
                }
            }
        }

        if !found {
            // Fill gap with zeros (this offset's data is in a missing extent)
            // Use 0x1000 as default block size for gaps
            let gap_size = 0x1000u32;
            let zeros = vec![0u8; gap_size as usize];
            assembled.extend_from_slice(&zeros);
            next_offset += gap_size;
            blocks_missing += 1;
        }
    }

    log::info!(
        "Fragmented {}: greedy assembled {} bytes ({} blocks found, {} gaps)",
        name,
        assembled.len(),
        blocks_found,
        blocks_missing
    );

    if blocks_missing as u64 * 0x1000 > bins_size as u64 / 2 {
        log::debug!(
            "Fragmented {}: too many missing blocks ({}), rejecting",
            name,
            blocks_missing
        );
        return None;
    }

    Some(assembled)
}

/// Build a temporary hive (regf + hbin) for validation purposes.
fn build_temp_hive(hbin_data: &[u8]) -> Vec<u8> {
    let mut hive_data = vec![0u8; 0x1000];
    hive_data[0..4].copy_from_slice(b"regf");
    hive_data[0x24..0x28].copy_from_slice(&0x20u32.to_le_bytes());
    let bins_size = hbin_data.len() as u32;
    hive_data[0x28..0x2C].copy_from_slice(&bins_size.to_le_bytes());
    hive_data.extend_from_slice(hbin_data);
    hive_data
}

/// Strict validation: root key name matches AND expected subkey exists.
fn validate_hive_content(name: &str, hbin_data: &[u8]) -> bool {
    let hive_data = build_temp_hive(hbin_data);
    let h = match hive::Hive::new(&hive_data) {
        Ok(h) => h,
        Err(_) => return false,
    };
    let root = match h.root_key() {
        Ok(r) => r,
        Err(_) => return false,
    };
    let rname = root.name().to_uppercase();
    if rname != name.to_uppercase() {
        return false;
    }
    match rname.as_str() {
        "SYSTEM" => root.subkey(&h, "Select").is_ok(),
        "SAM" => root.subkey(&h, "Domains").is_ok(),
        "SECURITY" => root.subkey(&h, "Policy").is_ok(),
        _ => false,
    }
}

/// Relaxed validation: only checks root key name matches the expected hive.
/// Used as fallback when strict validation fails (e.g., delta disks where
/// subkeys exist only in volatile storage or in the base disk).
fn validate_hive_structure(name: &str, hbin_data: &[u8]) -> bool {
    let hive_data = build_temp_hive(hbin_data);
    let h = match hive::Hive::new(&hive_data) {
        Ok(h) => h,
        Err(_) => return false,
    };
    let root = match h.root_key() {
        Ok(r) => r,
        Err(_) => return false,
    };
    root.name().to_uppercase() == name.to_uppercase()
}

/// Build a complete hive (regf header + hbin data) from assembled hbin blocks.
/// Finds the best matching regf header and validates the result.
fn build_hive_from_hbins(
    vmdk: &mut crate::disk::vmdk::VmdkDisk,
    name: &str,
    hbin_data: &[u8],
    regf_candidates: &[(u64, u64)],
) -> Option<Vec<u8>> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    if hbin_data.is_empty() {
        return None;
    }

    // Find matching regf header by path
    let mut best_regf: Option<(u64, u64)> = None;
    for &(roff, rbins) in regf_candidates {
        if vmdk.seek(SeekFrom::Start(roff + 0x30)).is_err() {
            continue;
        }
        let mut path_buf = [0u8; 128];
        if vmdk.read_exact(&mut path_buf).is_err() {
            continue;
        }
        let path = String::from_utf8_lossy(&path_buf)
            .to_uppercase()
            .replace('\0', "");
        let matches = match name {
            "SAM" => path.contains("CONFIG\\SAM") || path.ends_with("\\SAM"),
            "SYSTEM" => path.contains("CONFIG\\SYSTEM") || path.ends_with("\\SYSTEM"),
            "SECURITY" => path.contains("CONFIG\\SECURITY") || path.ends_with("\\SECURITY"),
            _ => false,
        };
        if matches && best_regf.is_none_or(|(_,prev)| rbins > prev) {
            best_regf = Some((roff, rbins));
        }
    }

    let bins_size = if let Some((_, rbins)) = best_regf {
        rbins as u32
    } else {
        hbin_data.len() as u32
    };

    // Build regf header
    let mut regf_hdr = vec![0u8; 0x1000];
    regf_hdr[0..4].copy_from_slice(b"regf");
    regf_hdr[0x24..0x28].copy_from_slice(&0x20u32.to_le_bytes());
    regf_hdr[0x28..0x2C].copy_from_slice(&bins_size.to_le_bytes());
    if let Some((roff, _)) = best_regf {
        if vmdk.seek(SeekFrom::Start(roff)).is_ok() {
            let mut real_hdr = [0u8; 0x30];
            if vmdk.read_exact(&mut real_hdr).is_ok() {
                regf_hdr[0x04..0x30].copy_from_slice(&real_hdr[0x04..0x30]);
            }
        }
    }

    let mut hive_data = regf_hdr;
    let actual_bins = bins_size.min(hbin_data.len() as u32);
    if (actual_bins as usize) < hbin_data.len() {
        hive_data.extend_from_slice(&hbin_data[..actual_bins as usize]);
    } else {
        hive_data.extend_from_slice(hbin_data);
        // Pad if we have less data than bins_size
        if (hbin_data.len() as u32) < bins_size {
            hive_data.resize(0x1000 + bins_size as usize, 0);
        }
    }

    // Validate: try strict first (expected subkeys), fall back to structural (root name only)
    let h = match hive::Hive::new(&hive_data) {
        Ok(h) => h,
        Err(_) => return None,
    };
    let root = match h.root_key() {
        Ok(r) => r,
        Err(_) => return None,
    };
    let rname = root.name().to_uppercase();
    if rname != name.to_uppercase() {
        return None;
    }
    let strict = match rname.as_str() {
        "SYSTEM" => root.subkey(&h, "Select").is_ok(),
        "SAM" => root.subkey(&h, "Domains").is_ok(),
        "SECURITY" => root.subkey(&h, "Policy").is_ok(),
        _ => false,
    };
    if !strict {
        log::debug!(
            "build_hive_from_hbins: {} root key found but expected subkeys missing (delta disk?)",
            name,
        );
    }
    // Accept if root name matches — the extraction pipeline will report
    // specific errors if needed data is missing
    Some(hive_data)
}
