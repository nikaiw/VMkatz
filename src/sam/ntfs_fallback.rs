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

use std::io::{Read, Seek, SeekFrom};

use crate::error::{Result, VmkatzError};
use crate::fs::ntfs::finalize;
use crate::fs::{DirEntry, EntryKind};
use crate::utils::{u16_le_or0, u32_le_or0, u64_le_or0};

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

/// NTFS boot sector parameters.
struct NtfsParams {
    cluster_size: u64,
    record_size: u32,
    mft_position: u64,
    mftmirr_position: u64,
}

/// A single MFT data run (VCN range → LCN cluster mapping).
struct DataRun {
    vcn_start: u64,
    vcn_length: u64,
    lcn_start: u64,
}

/// Parse NTFS boot sector.
fn parse_boot_sector(data: &[u8]) -> Result<NtfsParams> {
    if data.len() < 0x48 {
        return Err(VmkatzError::DecryptionError("Boot sector too small".into()));
    }
    if &data[3..7] != b"NTFS" {
        return Err(VmkatzError::DecryptionError(
            "Not an NTFS boot sector".into(),
        ));
    }

    let bytes_per_sector = u64::from(u16::from_le_bytes([data[0x0B], data[0x0C]]));
    let sectors_per_cluster = u64::from(data[0x0D]);
    let cluster_size = bytes_per_sector * sectors_per_cluster;
    if cluster_size == 0 {
        return Err(VmkatzError::DecryptionError(
            "Invalid NTFS boot sector: cluster_size is 0".into(),
        ));
    }

    let mft_cluster = u64_le_or0(data, 0x30);
    let mftmirr_cluster = u64_le_or0(data, 0x38);

    // Record size: signed byte at 0x40. Positive → clusters, negative → 2^|value|.
    // Guard both arithmetic paths: a hostile boot sector could overflow the
    // shift (>= 64 panics) or the multiply, or declare an absurd size that would
    // drive multi-GB record allocations downstream.
    let raw = data[0x40] as i8;
    let record_size_u64: u64 = if raw > 0 {
        (raw as u64).saturating_mul(cluster_size)
    } else {
        let shift = i32::from(raw).unsigned_abs();
        if shift < 64 { 1u64 << shift } else { 0 }
    };
    // MFT records are 1024 bytes in practice and can't exceed one cluster, so
    // 64 KiB is the real ceiling. The bound matters: the MFT readers allocate
    // 256 records at a time, so the old 1 MiB limit let a bogus boot sector ask
    // for a 256 MiB buffer.
    if record_size_u64 == 0 || record_size_u64 > (1 << 16) {
        return Err(VmkatzError::DecryptionError(format!(
            "Invalid NTFS boot sector: record_size={record_size_u64}"
        )));
    }
    let record_size = record_size_u64 as u32;

    Ok(NtfsParams {
        cluster_size,
        record_size,
        mft_position: mft_cluster * cluster_size,
        mftmirr_position: mftmirr_cluster * cluster_size,
    })
}

/// Parse data run list from non-resident attribute.
fn parse_data_runs(data: &[u8]) -> Vec<DataRun> {
    let mut runs = Vec::new();
    let mut pos = 0;
    let mut vcn = 0u64;
    let mut prev_lcn = 0i64;

    while pos < data.len() {
        let header = data[pos];
        if header == 0 {
            break;
        }
        let length_size = (header & 0x0F) as usize;
        let offset_size = ((header >> 4) & 0x0F) as usize;
        pos += 1;

        if length_size == 0 || pos + length_size + offset_size > data.len() {
            break;
        }

        // Read run length (unsigned)
        let mut length = 0u64;
        for i in 0..length_size {
            length |= u64::from(data[pos + i]) << (i * 8);
        }
        pos += length_size;

        // Read run offset (signed, relative to previous LCN)
        if offset_size > 0 {
            let mut offset = 0i64;
            for i in 0..offset_size {
                offset |= i64::from(data[pos + i]) << (i * 8);
            }
            // Sign-extend
            if offset_size < 8 && (data[pos + offset_size - 1] & 0x80) != 0 {
                for i in offset_size..8 {
                    offset |= 0xFFi64 << (i * 8);
                }
            }
            pos += offset_size;

            prev_lcn += offset;
            if prev_lcn >= 0 {
                runs.push(DataRun {
                    vcn_start: vcn,
                    vcn_length: length,
                    lcn_start: prev_lcn as u64,
                });
            }
        } else {
            // Sparse run (no LCN)
            pos += offset_size;
        }

        vcn += length;
    }

    runs
}

/// Apply NTFS fixup array to a FILE record (in-place).
fn fixup_file_record(data: &mut [u8]) -> bool {
    if data.len() < 0x30 || &data[0..4] != b"FILE" {
        return false;
    }

    let fixup_offset = u16::from_le_bytes([data[4], data[5]]) as usize;
    let fixup_count = u16::from_le_bytes([data[6], data[7]]) as usize;

    if fixup_count < 2 || fixup_offset + fixup_count * 2 > data.len() {
        return false;
    }

    let signature = u16::from_le_bytes([data[fixup_offset], data[fixup_offset + 1]]);

    for i in 1..fixup_count {
        let sector_end = i * 512 - 2;
        if sector_end + 1 >= data.len() {
            break;
        }
        let actual = u16::from_le_bytes([data[sector_end], data[sector_end + 1]]);
        if actual != signature {
            return false;
        }
        let repl_off = fixup_offset + i * 2;
        data[sector_end] = data[repl_off];
        data[sector_end + 1] = data[repl_off + 1];
    }

    true
}

/// Find an attribute by type code in a FILE record. Returns (offset, length).
fn find_attribute(record: &[u8], attr_type: u32) -> Option<(usize, usize)> {
    if record.len() < 0x18 {
        return None;
    }
    let first_attr = u16::from_le_bytes([record[0x14], record[0x15]]) as usize;
    let mut pos = first_attr;

    while pos + 16 <= record.len() {
        let atype = u32_le_or0(record, pos);
        if atype == 0xFFFF_FFFF {
            break;
        }
        let alen = u32_le_or0(record, pos + 4) as usize;
        if alen < 16 || pos + alen > record.len() {
            break;
        }
        if atype == attr_type {
            return Some((pos, alen));
        }
        pos += alen;
    }
    None
}

/// Find ALL attributes of a given type in a FILE record (handles multiple $FILE_NAME etc.).
fn find_all_attributes(record: &[u8], attr_type: u32) -> Vec<(usize, usize)> {
    let mut results = Vec::new();
    if record.len() < 0x18 {
        return results;
    }
    let first_attr = u16::from_le_bytes([record[0x14], record[0x15]]) as usize;
    let mut pos = first_attr;

    while pos + 16 <= record.len() {
        let atype = u32_le_or0(record, pos);
        if atype == 0xFFFF_FFFF {
            break;
        }
        let alen = u32_le_or0(record, pos + 4) as usize;
        if alen < 16 || pos + alen > record.len() {
            break;
        }
        if atype == attr_type {
            results.push((pos, alen));
        }
        pos += alen;
    }
    results
}

/// Extract filename from a $FILE_NAME attribute instance.
fn filename_from_attr(record: &[u8], attr_pos: usize) -> Option<(String, u64)> {
    filename_info_from_attr(record, attr_pos).map(|(name, parent, _)| (name, parent))
}

/// Like `filename_from_attr`, also returning the real data size recorded in
/// the $FILE_NAME attribute (offset 0x30).
fn filename_info_from_attr(record: &[u8], attr_pos: usize) -> Option<(String, u64, u64)> {
    let non_resident = record[attr_pos + 8];
    if non_resident != 0 {
        return None; // $FILE_NAME is always resident
    }
    let value_length = u32_le_or0(record, attr_pos + 0x10) as usize;
    let value_offset = u16_le_or0(record, attr_pos + 0x14) as usize;
    let data_start = attr_pos + value_offset;

    if data_start + value_length > record.len() || value_length < 0x44 {
        return None;
    }
    let fname = &record[data_start..data_start + value_length];

    // Parent directory MFT reference (6 bytes record number + 2 bytes seq)
    let parent_ref = u64_le_or0(fname, 0) & 0x0000_FFFF_FFFF_FFFF;

    let name_len = fname[0x40] as usize;
    let namespace = fname[0x41];
    // Skip DOS-only names (namespace 2)
    if namespace == 2 {
        return None;
    }
    if 0x42 + name_len * 2 > fname.len() {
        return None;
    }
    Some((
        crate::utils::utf16le_decode(&fname[0x42..0x42 + name_len * 2]),
        parent_ref,
        u64_le_or0(fname, 0x30),
    ))
}

/// Extract best filename and parent ref from a FILE record (prefers Win32 over DOS).
fn extract_filename(record: &[u8]) -> Option<(String, u64)> {
    let attrs = find_all_attributes(record, 0x30); // $FILE_NAME = 0x30
    let mut best: Option<(String, u64)> = None;
    for (pos, _len) in attrs {
        if let Some((name, parent)) = filename_from_attr(record, pos) {
            // Take the first non-DOS name, or any name if only DOS available
            if best.is_none() {
                best = Some((name, parent));
            }
        }
    }
    best
}

/// Extract $DATA data runs from a FILE record. Returns (runs, real_size).
fn extract_data_attribute(record: &[u8]) -> Option<(Vec<DataRun>, u64)> {
    let (pos, len) = find_attribute(record, 0x80)?; // $DATA = 0x80
    let non_resident = record[pos + 8];

    if non_resident == 0 {
        // Resident
        let value_length = u64::from(u32_le_or0(record, pos + 0x10));
        return Some((Vec::new(), value_length));
    }

    // Non-resident
    if pos + 0x38 > record.len() {
        return None;
    }
    let real_size = u64_le_or0(record, pos + 0x30);
    let runs_offset = u16::from_le_bytes([record[pos + 0x20], record[pos + 0x21]]) as usize;

    if pos + runs_offset >= pos + len {
        return None;
    }
    let runs = parse_data_runs(&record[pos + runs_offset..pos + len]);
    Some((runs, real_size))
}

/// Read resident $DATA from a FILE record.
fn read_resident_data(record: &[u8]) -> Option<Vec<u8>> {
    let (pos, _len) = find_attribute(record, 0x80)?;
    if record[pos + 8] != 0 {
        return None;
    }
    let value_length = u32_le_or0(record, pos + 0x10) as usize;
    let value_offset = u16_le_or0(record, pos + 0x14) as usize;
    let start = pos + value_offset;
    if start + value_length > record.len() {
        return None;
    }
    Some(record[start..start + value_length].to_vec())
}

/// Read non-resident file data from data runs.
/// Uses block-level resilient I/O: on error, retries once then zero-fills
/// the failing 4KB block and continues. This handles live/in-use block devices
/// where individual sectors may be temporarily locked.
fn read_from_data_runs<R: Read + Seek>(
    reader: &mut R,
    runs: &[DataRun],
    file_size: u64,
    cluster_size: u64,
    partition_offset: u64,
) -> Vec<u8> {
    const BLOCK: u64 = 4096;
    let mut data = Vec::with_capacity(file_size.min(64 * 1024 * 1024) as usize);
    let mut io_errors = 0u32;

    for run in runs {
        let abs_offset = partition_offset + run.lcn_start * cluster_size;
        let run_bytes = run.vcn_length * cluster_size;

        // Read block-by-block for resilience against transient I/O errors
        let mut block_off = 0u64;
        while block_off < run_bytes {
            let block_size = BLOCK.min(run_bytes - block_off) as usize;
            let disk_pos = abs_offset + block_off;

            let ok = reader.seek(SeekFrom::Start(disk_pos)).is_ok() && {
                let start = data.len();
                data.resize(start + block_size, 0);
                if matches!(
                    reader.read_exact(&mut data[start..start + block_size]),
                    Ok(())
                ) {
                    true
                } else {
                    // Zero-fill on error
                    data[start..start + block_size].fill(0);
                    false
                }
            };

            if !ok {
                // Seek failed — zero-fill this block
                if data.len() < (data.len().saturating_sub(block_size) + block_size) {
                    data.resize(data.len() + block_size, 0);
                }
                io_errors += 1;
            }

            block_off += BLOCK;
        }
    }

    if io_errors > 0 {
        log::info!(
            "Data runs: {} blocks had I/O errors (zero-filled), {} bytes total",
            io_errors,
            data.len()
        );
    }

    data.truncate(file_size as usize);
    data
}

/// Read a single MFT record by record number, using the MFT data runs map.
fn read_mft_record<R: Read + Seek>(
    reader: &mut R,
    record_number: u64,
    mft_runs: &[DataRun],
    params: &NtfsParams,
    partition_offset: u64,
) -> Option<Vec<u8>> {
    let byte_offset = record_number * u64::from(params.record_size);
    let cluster_offset = byte_offset / params.cluster_size;
    let offset_in_cluster = byte_offset % params.cluster_size;

    // Find which data run contains this record
    for run in mft_runs {
        let run_vcn_end = run.vcn_start + run.vcn_length;
        if cluster_offset >= run.vcn_start && cluster_offset < run_vcn_end {
            let cluster_in_run = cluster_offset - run.vcn_start;
            let abs_offset = partition_offset
                + (run.lcn_start + cluster_in_run) * params.cluster_size
                + offset_in_cluster;

            if reader.seek(SeekFrom::Start(abs_offset)).is_err() {
                return None;
            }
            let mut record = vec![0u8; params.record_size as usize];
            if reader.read_exact(&mut record).is_err() {
                return None;
            }
            if !fixup_file_record(&mut record) {
                return None;
            }
            return Some(record);
        }
    }
    None
}

/// Parse $ATTRIBUTE_LIST to find extension MFT records containing $DATA.
/// Returns list of MFT record numbers that contain $DATA attributes.
fn parse_attribute_list_from_record<R: Read + Seek>(
    reader: &mut R,
    record: &[u8],
    params: &NtfsParams,
    partition_offset: u64,
) -> Vec<u64> {
    let Some((pos, len)) = find_attribute(record, 0x20) else {
        return Vec::new();
    };

    let non_resident = record[pos + 8];

    let attr_list_data = if non_resident == 0 {
        // Resident $ATTRIBUTE_LIST
        let value_length = u32_le_or0(record, pos + 0x10) as usize;
        let value_offset = u16_le_or0(record, pos + 0x14) as usize;
        let start = pos + value_offset;
        if start + value_length > record.len() {
            return Vec::new();
        }
        record[start..start + value_length].to_vec()
    } else {
        // Non-resident $ATTRIBUTE_LIST — read from data runs
        if pos + 0x38 > record.len() {
            return Vec::new();
        }
        let real_size = u64_le_or0(record, pos + 0x30);
        let runs_offset = u16_le_or0(record, pos + 0x20) as usize;
        if pos + runs_offset >= pos + len || real_size > 256 * 1024 {
            return Vec::new();
        }
        let runs = parse_data_runs(&record[pos + runs_offset..pos + len]);
        if runs.is_empty() {
            return Vec::new();
        }
        read_from_data_runs(
            reader,
            &runs,
            real_size,
            params.cluster_size,
            partition_offset,
        )
    };

    let mut extension_records = Vec::new();
    let mut off = 0;
    while off + 0x1A <= attr_list_data.len() {
        let attr_type = u32_le_or0(&attr_list_data, off);
        let entry_length = u16_le_or0(&attr_list_data, off + 4) as usize;
        if entry_length < 0x1A || off + entry_length > attr_list_data.len() {
            break;
        }
        // $DATA attribute type = 0x80
        if attr_type == 0x80 {
            let mft_ref = u64_le_or0(&attr_list_data, off + 0x10) & 0x0000_FFFF_FFFF_FFFF;
            if !extension_records.contains(&mft_ref) {
                extension_records.push(mft_ref);
            }
        }
        off += entry_length;
    }
    extension_records
}

/// Read file data from an MFT record, with $ATTRIBUTE_LIST support
/// for files whose $DATA spans multiple MFT records.
fn read_file_from_record<R: Read + Seek>(
    reader: &mut R,
    record: &[u8],
    name: &str,
    mft_runs: &[DataRun],
    params: &NtfsParams,
    partition_offset: u64,
) -> Result<Vec<u8>> {
    // Try resident data first
    if let Some(data) = read_resident_data(record) {
        return Ok(data);
    }

    // Try $DATA in base record
    if let Some((runs, file_size)) = extract_data_attribute(record) {
        if !runs.is_empty() {
            log::info!(
                "{}: {} data runs, {} bytes (base record)",
                name,
                runs.len(),
                file_size
            );
            return Ok(read_from_data_runs(
                reader,
                &runs,
                file_size,
                params.cluster_size,
                partition_offset,
            ));
        }
    }

    // $DATA not in base record — check $ATTRIBUTE_LIST for extension records
    let ext_records = parse_attribute_list_from_record(reader, record, params, partition_offset);
    if ext_records.is_empty() {
        return Err(VmkatzError::DecryptionError(format!(
            "{name}: no $DATA attribute"
        )));
    }

    log::info!(
        "{}: $DATA in {} extension record(s), reading via $ATTRIBUTE_LIST",
        name,
        ext_records.len()
    );

    // Collect data runs from all extension records
    let mut all_runs = Vec::new();
    let mut file_size = 0u64;

    for &ext_ref in &ext_records {
        if let Some(ext_record) =
            read_mft_record(reader, ext_ref, mft_runs, params, partition_offset)
        {
            if let Some((runs, size)) = extract_data_attribute(&ext_record) {
                all_runs.extend(runs);
                if size > file_size {
                    file_size = size;
                }
            }
        } else {
            log::debug!("{name}: extension record #{ext_ref} inaccessible");
        }
    }

    if all_runs.is_empty() {
        return Err(VmkatzError::DecryptionError(format!(
            "{name}: no data runs from extension records"
        )));
    }

    log::info!(
        "{}: {} total data runs, {} bytes",
        name,
        all_runs.len(),
        file_size
    );
    Ok(read_from_data_runs(
        reader,
        &all_runs,
        file_size,
        params.cluster_size,
        partition_offset,
    ))
}

/// A file the MFTMirr scan looks for, with its expected parent chain
/// (parent ← grandparent) and a content signature for validation when
/// parent records are inaccessible.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ScanTarget {
    Sam,
    System,
    Security,
    NtdsDit,
}

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
struct ScanRecords {
    records: Vec<(ScanTarget, Vec<u8>)>,
}

impl ScanRecords {
    fn get(&self, target: ScanTarget) -> Option<&Vec<u8>> {
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

/// MFT access bootstrapped via $MFTMirr.
struct MftBootstrap {
    params: NtfsParams,
    mft_runs: Vec<DataRun>,
    /// Accessible MFT segments: (absolute offset, first record, record count)
    accessible_segments: Vec<(u64, u64, u64)>,
}

/// Bootstrap MFT access via $MFTMirr: parse the boot sector, read the mirrored
/// $MFT record, and map which MFT segments are accessible on this disk.
fn mftmirr_bootstrap<R: Read + Seek>(
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
    let mftmirr_abs = partition_offset + params.mftmirr_position;
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
        let abs_offset = partition_offset + run.lcn_start * params.cluster_size;
        let run_bytes = run.vcn_length * params.cluster_size;
        let first_record = run.vcn_start * params.cluster_size / u64::from(params.record_size);
        let num_records = run_bytes / u64::from(params.record_size);

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
        mft_runs,
        accessible_segments,
    })
}

/// Scan accessible MFT segments for records matching the wanted targets.
///
/// With `verify_parents`, a candidate is accepted only if its parent chain
/// matches the target's expected path. Otherwise the file's content signature
/// is validated instead (parent records may be in inaccessible segments).
fn scan_mft_segments<R: Read + Seek>(
    reader: &mut R,
    bootstrap: &MftBootstrap,
    partition_offset: u64,
    wanted: &[ScanTarget],
    records: &mut ScanRecords,
    verify_parents: bool,
) {
    let rs = bootstrap.params.record_size as usize;
    let batch_records = 256usize;

    'segments: for &(abs_offset, first_rec, num_recs) in &bootstrap.accessible_segments {
        let mut rec_idx = 0u64;
        while rec_idx < num_recs {
            let batch = batch_records.min((num_recs - rec_idx) as usize);
            let read_pos = abs_offset + rec_idx * rs as u64;

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
                            // First extent inaccessible — accept the record anyway.
                            // Block-level resilient I/O in read_from_data_runs will
                            // zero-fill only the specific 4KB blocks that fail.
                            // For live VMs, most blocks are readable.
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
}

/// Scan for all wanted targets: first with parent verification, then — if any
/// required target is still missing — without parent verification (candidates
/// are content-signature validated instead).
fn scan_for_targets<R: Read + Seek>(
    reader: &mut R,
    bootstrap: &MftBootstrap,
    partition_offset: u64,
    wanted: &[ScanTarget],
    required: &[ScanTarget],
) -> ScanRecords {
    let mut records = ScanRecords::default();
    scan_mft_segments(
        reader,
        bootstrap,
        partition_offset,
        wanted,
        &mut records,
        true,
    );

    // If parent verification failed for all candidates, retry without parent check
    // (parent MFT records may be in inaccessible segments)
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
        );
    }
    records
}

/// Visit every in-use, parseable MFT record in the accessible segments.
/// The callback receives (record number, fixed-up record) and returns `true`
/// to stop the scan early.
fn for_each_accessible_record<R: Read + Seek>(
    reader: &mut R,
    bootstrap: &MftBootstrap,
    mut visit: impl FnMut(u64, &[u8]) -> bool,
) {
    let rs = bootstrap.params.record_size as usize;
    let batch_records = 256usize;
    for &(abs_offset, first_rec, num_recs) in &bootstrap.accessible_segments {
        let mut rec_idx = 0u64;
        while rec_idx < num_recs {
            let batch = batch_records.min((num_recs - rec_idx) as usize);
            let read_pos = abs_offset + rec_idx * rs as u64;
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
                    return;
                }
            }
            rec_idx += batch as u64;
        }
    }
}

/// Enumerate directory entries by scanning accessible MFT records for
/// `$FILE_NAME` parent references, for when the directory index is unreadable.
///
/// `Ok(None)` means a path component could not be resolved from accessible
/// records; `Err` means the MFT bootstrap itself failed.
pub fn list_path_degraded<R: Read + Seek>(
    reader: &mut R,
    partition_offset: u64,
    path: &str,
) -> Result<Option<Vec<DirEntry>>> {
    let bootstrap = mftmirr_bootstrap(reader, partition_offset)?;

    // Resolve the path to a directory record number (root = record 5).
    let mut current = 5u64;
    for comp in path.split(['\\', '/']).filter(|c| !c.is_empty()) {
        let mut found = None;
        for_each_accessible_record(reader, &bootstrap, |rec_num, record| {
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
        });
        match found {
            Some(n) => current = n,
            None => return Ok(None),
        }
    }

    let mut raw = Vec::new();
    for_each_accessible_record(reader, &bootstrap, |rec_num, record| {
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
        false
    });
    Ok(Some(finalize(raw, true)))
}

/// Try to read registry hives via $MFTMirr bootstrap.
///
/// This is the main entry point for SAM/SYSTEM/SECURITY. Called when
/// `ntfs.root_directory()` fails because the primary MFT start is in an
/// inaccessible disk region.
pub fn try_mftmirr_fallback<R: Read + Seek>(
    reader: &mut R,
    partition_offset: u64,
) -> Result<super::HiveFiles> {
    let bootstrap = mftmirr_bootstrap(reader, partition_offset)?;
    let wanted = [ScanTarget::Sam, ScanTarget::System, ScanTarget::Security];
    // SECURITY is optional — do not rescan the whole MFT for it alone
    let required = [ScanTarget::Sam, ScanTarget::System];
    let records = scan_for_targets(reader, &bootstrap, partition_offset, &wanted, &required);

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
pub fn try_mftmirr_fallback_ntds<R: Read + Seek>(
    reader: &mut R,
    partition_offset: u64,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let bootstrap = mftmirr_bootstrap(reader, partition_offset)?;
    let wanted = [ScanTarget::NtdsDit, ScanTarget::System];
    let records = scan_for_targets(reader, &bootstrap, partition_offset, &wanted, &wanted);

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

/// Try to read the first bytes of a file's data so the caller can validate its
/// content signature ("regf" for registry hives, the ESE magic for ntds.dit).
/// Returns None when the first extent is inaccessible.
fn try_read_file_start<R: Read + Seek>(
    reader: &mut R,
    record: &[u8],
    params: &NtfsParams,
    partition_offset: u64,
) -> Option<Vec<u8>> {
    // Resident data is small and already in the record
    if let Some(data) = read_resident_data(record) {
        return Some(data);
    }

    // Non-resident: read the start of the first data run
    let (runs, _size) = extract_data_attribute(record)?;
    let abs_offset = partition_offset + runs[0].lcn_start * params.cluster_size;
    if reader.seek(SeekFrom::Start(abs_offset)).is_err() {
        return None;
    }
    let mut start = [0u8; 8];
    if reader.read_exact(&mut start).is_err() {
        return None;
    }
    Some(start.to_vec())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const PART_OFF: u64 = 0x1000;
    const CLUSTER: u64 = 512;

    // MFT record numbers
    const REC_MFT: u32 = 0;
    const REC_DECOY_SYSTEM: u32 = 3;
    const REC_DECOY_NTDSDIT: u32 = 4;
    const REC_WINDOWS: u32 = 5;
    const REC_SYSTEM32: u32 = 6;
    const REC_CONFIG: u32 = 7;
    const REC_NTDS: u32 = 8;
    const REC_SYSTEM: u32 = 9;
    const REC_NTDSDIT: u32 = 10;
    const REC_SAM: u32 = 11;
    const REC_SECURITY: u32 = 12;

    // Cluster assignments (all clusters, 512 B each)
    const CL_MFTMIRR: u64 = 2; // 4 records = 8 clusters
    const CL_MFT: u64 = 16; // 16 records = 32 clusters
    const CL_REGF_SYSTEM: u64 = 60;
    const CL_ESE: u64 = 80;
    const CL_REGF_SAM: u64 = 100;
    const CL_REGF_SECURITY: u64 = 120;
    const CL_DECOY: u64 = 140;

    const REC_ROOT_DIR: u32 = 13;
    const REC_ROOT_FILE: u32 = 14;
    const ROOT_FILE_SIZE: u64 = 0x1234_5678;

    const FILE_SIZE: u64 = 0x2000; // every file's $DATA size

    /// Build a resident $FILE_NAME attribute (type 0x30).
    fn file_name_attr(name: &str, parent: u64, size: u64) -> Vec<u8> {
        let name_utf16: Vec<u16> = name.encode_utf16().collect();
        let value_len = 0x42 + name_utf16.len() * 2;
        let value_offset = 0x18usize;
        let mut attr = vec![0u8; value_offset + value_len];
        attr[0..4].copy_from_slice(&0x30u32.to_le_bytes());
        let len = attr.len() as u32;
        attr[4..8].copy_from_slice(&len.to_le_bytes());
        attr[0x0A..0x0C].copy_from_slice(&(value_offset as u16).to_le_bytes());
        attr[0x10..0x14].copy_from_slice(&(value_len as u32).to_le_bytes());
        attr[0x14..0x16].copy_from_slice(&(value_offset as u16).to_le_bytes());
        let value = &mut attr[value_offset..];
        value[0..8].copy_from_slice(&parent.to_le_bytes());
        value[0x30..0x38].copy_from_slice(&size.to_le_bytes());
        value[0x40] = name_utf16.len() as u8;
        value[0x41] = 0; // Win32 namespace
        for (i, ch) in name_utf16.iter().enumerate() {
            value[0x42 + i * 2..0x44 + i * 2].copy_from_slice(&ch.to_le_bytes());
        }
        attr
    }

    /// Build a non-resident $DATA attribute (type 0x80) with one data run.
    fn data_attr(lcn: u64, n_clusters: u64, real_size: u64) -> Vec<u8> {
        let runs_offset = 0x48usize;
        // Run header 0x21: length field 1 byte, offset field 2 bytes
        let mut runs = vec![0x21u8];
        runs.push(n_clusters as u8);
        runs.extend_from_slice(&lcn.to_le_bytes()[..2]);

        let mut attr = vec![0u8; runs_offset + runs.len()];
        attr[0..4].copy_from_slice(&0x80u32.to_le_bytes());
        let len = attr.len() as u32;
        attr[4..8].copy_from_slice(&len.to_le_bytes());
        attr[8] = 1; // non-resident
        attr[0x18..0x20].copy_from_slice(&(n_clusters - 1).to_le_bytes()); // last VCN
        attr[0x20..0x22].copy_from_slice(&(runs_offset as u16).to_le_bytes());
        attr[0x30..0x38].copy_from_slice(&real_size.to_le_bytes());
        attr[runs_offset..].copy_from_slice(&runs);
        attr
    }

    /// Assemble a 1024-byte FILE record with a valid fixup array.
    fn make_record(is_dir: bool, attrs: Vec<Vec<u8>>) -> Vec<u8> {
        let mut rec = vec![0u8; 1024];
        rec[0..4].copy_from_slice(b"FILE");
        rec[4..6].copy_from_slice(&0x30u16.to_le_bytes()); // fixup array offset
        rec[6..8].copy_from_slice(&3u16.to_le_bytes()); // signature + 2 sector ends
        rec[0x14..0x16].copy_from_slice(&0x38u16.to_le_bytes()); // first attribute
        rec[0x16..0x18].copy_from_slice(&(if is_dir { 3u16 } else { 1u16 }).to_le_bytes()); // in-use (+dir)
        rec[0x18..0x1C].copy_from_slice(&1024u32.to_le_bytes()); // used size
        rec[0x1C..0x20].copy_from_slice(&1024u32.to_le_bytes()); // allocated size

        // Fixup array: on-disk sector ends carry the signature, the array holds
        // the replacements (mirroring what fixup_file_record expects).
        rec[0x30..0x32].copy_from_slice(&0x1122u16.to_le_bytes());
        rec[0x32..0x34].copy_from_slice(&0x3344u16.to_le_bytes());
        rec[0x34..0x36].copy_from_slice(&0x5566u16.to_le_bytes());
        rec[510..512].copy_from_slice(&0x1122u16.to_le_bytes());
        rec[1022..1024].copy_from_slice(&0x1122u16.to_le_bytes());

        let mut pos = 0x38;
        for attr in attrs {
            rec[pos..pos + attr.len()].copy_from_slice(&attr);
            pos += attr.len();
        }
        rec[pos..pos + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        rec
    }

    /// Write a "regf" header at a cluster.
    fn put_regf(image: &mut [u8], cluster: u64) {
        let off = (PART_OFF + cluster * CLUSTER) as usize;
        image[off..off + 4].copy_from_slice(b"regf");
    }

    /// Place an MFT record at its number within the MFT extent.
    fn put_mft(image: &mut [u8], rec: u32, r: &[u8]) {
        let off = (PART_OFF + CL_MFT * CLUSTER + u64::from(rec) * 1024) as usize;
        image[off..off + 1024].copy_from_slice(r);
    }

    /// Build a synthetic NTFS volume. `ntds_parent`/`system_parent` set the
    /// parent MFT references of ntds.dit/SYSTEM (use record numbers beyond the
    /// MFT extent to make the parent chain unverifiable).
    pub(crate) fn build_volume(ntds_parent: u64, system_parent: u64, hives: bool, decoys: bool) -> Vec<u8> {
        let mut image = vec![0u8; 0x14000];

        // Boot sector
        let boot = PART_OFF as usize;
        image[boot + 3..boot + 7].copy_from_slice(b"NTFS");
        image[boot + 0x0B..boot + 0x0D].copy_from_slice(&512u16.to_le_bytes());
        image[boot + 0x0D] = 1; // sectors per cluster
        image[boot + 0x30..boot + 0x38].copy_from_slice(&CL_MFT.to_le_bytes());
        image[boot + 0x38..boot + 0x40].copy_from_slice(&CL_MFTMIRR.to_le_bytes());
        image[boot + 0x40] = 0xF6; // -10 → record size 2^10

        // File contents
        put_regf(&mut image, CL_REGF_SYSTEM);
        put_regf(&mut image, CL_REGF_SAM);
        put_regf(&mut image, CL_REGF_SECURITY);
        let off = (PART_OFF + CL_ESE * CLUSTER) as usize;
        image[off + 4..off + 8].copy_from_slice(&[0xEF, 0xCD, 0xAB, 0x89]);

        // Place an MFT record at its number within the MFT extent

        // Record 0 ($MFT): $DATA covering the 16-record MFT extent; mirrored
        // into $MFTMirr, which is how the fallback bootstraps MFT access.
        let mft_record = make_record(false, vec![data_attr(CL_MFT, 32, 16 * 1024)]);
        put_mft(&mut image, REC_MFT, &mft_record);
        let mirr = (PART_OFF + CL_MFTMIRR * CLUSTER) as usize;
        image[mirr..mirr + 1024].copy_from_slice(&mft_record);

        // Directory records (parents)
        put_mft(
            &mut image,
            REC_WINDOWS,
            &make_record(true, vec![file_name_attr("Windows", 5, 0)]),
        );
        put_mft(
            &mut image,
            REC_SYSTEM32,
            &make_record(
                true,
                vec![file_name_attr("System32", u64::from(REC_WINDOWS), 0)],
            ),
        );
        put_mft(
            &mut image,
            REC_CONFIG,
            &make_record(
                true,
                vec![file_name_attr("config", u64::from(REC_SYSTEM32), 0)],
            ),
        );
        put_mft(
            &mut image,
            REC_NTDS,
            &make_record(
                true,
                vec![file_name_attr("NTDS", u64::from(REC_WINDOWS), 0)],
            ),
        );

        // Registry hives and ntds.dit
        put_mft(
            &mut image,
            REC_SYSTEM,
            &make_record(
                false,
                vec![
                    file_name_attr("SYSTEM", system_parent, 0),
                    data_attr(CL_REGF_SYSTEM, FILE_SIZE / CLUSTER, FILE_SIZE),
                ],
            ),
        );
        put_mft(
            &mut image,
            REC_NTDSDIT,
            &make_record(
                false,
                vec![
                    file_name_attr("ntds.dit", ntds_parent, 0),
                    data_attr(CL_ESE, FILE_SIZE / CLUSTER, FILE_SIZE),
                ],
            ),
        );
        if hives {
            put_mft(
                &mut image,
                REC_SAM,
                &make_record(
                    false,
                    vec![
                        file_name_attr("SAM", u64::from(REC_CONFIG), 0),
                        data_attr(CL_REGF_SAM, FILE_SIZE / CLUSTER, FILE_SIZE),
                    ],
                ),
            );
            put_mft(
                &mut image,
                REC_SECURITY,
                &make_record(
                    false,
                    vec![
                        file_name_attr("SECURITY", u64::from(REC_CONFIG), 0),
                        data_attr(CL_REGF_SECURITY, FILE_SIZE / CLUSTER, FILE_SIZE),
                    ],
                ),
            );
        }

        // Root children (parent = record 5): one directory, one file with a known size
        put_mft(
            &mut image,
            REC_ROOT_DIR,
            &make_record(true, vec![file_name_attr("Users", 5, 0)]),
        );
        put_mft(
            &mut image,
            REC_ROOT_FILE,
            &make_record(
                false,
                vec![file_name_attr("pagefile.sys", 5, ROOT_FILE_SIZE)],
            ),
        );

        if decoys {
            // Same names but a wrong parent chain — pass 1 must reject them.
            put_mft(
                &mut image,
                REC_DECOY_SYSTEM,
                &make_record(
                    false,
                    vec![
                        file_name_attr("SYSTEM", u64::from(REC_SYSTEM32), 0),
                        data_attr(CL_REGF_SYSTEM, FILE_SIZE / CLUSTER, FILE_SIZE),
                    ],
                ),
            );
            put_mft(
                &mut image,
                REC_DECOY_NTDSDIT,
                &make_record(
                    false,
                    vec![
                        file_name_attr("ntds.dit", u64::from(REC_CONFIG), 0),
                        data_attr(CL_DECOY, FILE_SIZE / CLUSTER, FILE_SIZE),
                    ],
                ),
            );
        }

        image
    }

    #[test]
    fn mftmirr_fallback_finds_hives_and_ntds_with_verified_parents() {
        let image = build_volume(u64::from(REC_NTDS), u64::from(REC_CONFIG), true, true);
        let mut reader = std::io::Cursor::new(image);

        let (ntds, system) = try_mftmirr_fallback_ntds(&mut reader, PART_OFF).unwrap();
        assert_eq!(ntds.len(), FILE_SIZE as usize);
        assert_eq!(ntds[4..8], [0xEF, 0xCD, 0xAB, 0x89]); // ESE magic
        assert_eq!(&system[0..4], b"regf");

        let (sam, sys, security) = try_mftmirr_fallback(&mut reader, PART_OFF).unwrap();
        assert_eq!(&sam[0..4], b"regf");
        assert_eq!(&sys[0..4], b"regf");
        let security = security.expect("SECURITY hive not found");
        assert_eq!(&security[0..4], b"regf");
    }

    #[test]
    fn mftmirr_fallback_ntds_accepts_content_validated_records_without_parents() {
        // Parent records 998/999 are beyond the MFT extent — pass 1 cannot
        // verify the chain, so pass 2 must validate the content signatures.
        let image = build_volume(999, 998, false, false);
        let mut reader = std::io::Cursor::new(image);

        let (ntds, system) = try_mftmirr_fallback_ntds(&mut reader, PART_OFF).unwrap();
        assert_eq!(ntds[4..8], [0xEF, 0xCD, 0xAB, 0x89]);
        assert_eq!(&system[0..4], b"regf");
    }

    #[test]
    fn mftmirr_fallback_reports_missing_sam() {
        let image = build_volume(u64::from(REC_NTDS), u64::from(REC_CONFIG), false, false);
        let mut reader = std::io::Cursor::new(image);

        let err = try_mftmirr_fallback(&mut reader, PART_OFF).unwrap_err();
        assert!(err.to_string().contains("SAM hive not found"));
    }

    #[test]
    fn degraded_lists_root_children() {
        let image = build_volume(u64::from(REC_NTDS), u64::from(REC_CONFIG), true, false);
        let mut reader = std::io::Cursor::new(image);

        let entries = list_path_degraded(&mut reader, PART_OFF, "")
            .unwrap()
            .expect("root should resolve");
        let find = |n: &str| entries.iter().find(|e| e.name == n).expect(n);
        assert_eq!(find("Users").kind, EntryKind::Dir);
        assert_eq!(
            find("pagefile.sys").kind,
            EntryKind::File {
                size: ROOT_FILE_SIZE
            }
        );
        // Harness record 5 doubles as "Windows", so System32/NTDS also have
        // parent 5; the self-referencing record 5 itself must not be listed.
        assert_eq!(entries.len(), 4);
        assert!(entries.iter().all(|e| e.name != "Windows"));
        assert_eq!(entries[3].name, "pagefile.sys"); // files after dirs
    }

    #[test]
    fn degraded_deep_path_unresolvable() {
        let image = build_volume(u64::from(REC_NTDS), u64::from(REC_CONFIG), true, false);
        let mut reader = std::io::Cursor::new(image);

        let res = list_path_degraded(&mut reader, PART_OFF, "Users\\Missing\\Deeper").unwrap();
        assert!(res.is_none());
        let res = list_path_degraded(&mut reader, PART_OFF, "/NoSuchDir").unwrap();
        assert!(res.is_none());
    }
}
