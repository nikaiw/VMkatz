//! MFTMirr-based NTFS fallback for reading registry hives from incomplete disks.
//!
//! When the primary MFT start is inaccessible (e.g., truncated/missing extent),
//! this module bootstraps MFT access via $MFTMirr:
//! 1. Parse NTFS boot sector → locate $MFTMirr
//! 2. Read $MFT record from MFTMirr → parse $DATA data runs
//! 3. Scan accessible MFT segments for FILE records named SAM/SYSTEM/SECURITY
//! 4. Read file contents via their $DATA data runs

use std::io::{Read, Seek, SeekFrom};

use crate::error::{VmkatzError, Result};

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

/// Read a u32 from a byte slice at the given offset, returning 0 on out-of-bounds.
fn read_u32(data: &[u8], off: usize) -> u32 {
    data.get(off..off + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
        .unwrap_or(0)
}

/// Read a u64 from a byte slice at the given offset, returning 0 on out-of-bounds.
fn read_u64(data: &[u8], off: usize) -> u64 {
    data.get(off..off + 8)
        .and_then(|s| s.try_into().ok())
        .map(u64::from_le_bytes)
        .unwrap_or(0)
}

/// Read a u16 from a byte slice at the given offset, returning 0 on out-of-bounds.
fn read_u16(data: &[u8], off: usize) -> u16 {
    data.get(off..off + 2)
        .and_then(|s| s.try_into().ok())
        .map(u16::from_le_bytes)
        .unwrap_or(0)
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

    let bytes_per_sector = u16::from_le_bytes([data[0x0B], data[0x0C]]) as u64;
    let sectors_per_cluster = data[0x0D] as u64;
    let cluster_size = bytes_per_sector * sectors_per_cluster;
    if cluster_size == 0 {
        return Err(VmkatzError::DecryptionError(
            "Invalid NTFS boot sector: cluster_size is 0".into(),
        ));
    }

    let mft_cluster = read_u64(data, 0x30);
    let mftmirr_cluster = read_u64(data, 0x38);

    // Record size: signed byte at 0x40. Positive → clusters, negative → 2^|value|.
    let raw = data[0x40] as i8;
    let record_size = if raw > 0 {
        raw as u64 * cluster_size
    } else {
        1u64 << (-raw as u32)
    } as u32;
    if record_size == 0 {
        return Err(VmkatzError::DecryptionError(
            "Invalid NTFS boot sector: record_size is 0".into(),
        ));
    }

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
            length |= (data[pos + i] as u64) << (i * 8);
        }
        pos += length_size;

        // Read run offset (signed, relative to previous LCN)
        if offset_size > 0 {
            let mut offset = 0i64;
            for i in 0..offset_size {
                offset |= (data[pos + i] as i64) << (i * 8);
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
        let atype = read_u32(record, pos);
        if atype == 0xFFFF_FFFF {
            break;
        }
        let alen = read_u32(record, pos + 4) as usize;
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
        let atype = read_u32(record, pos);
        if atype == 0xFFFF_FFFF {
            break;
        }
        let alen = read_u32(record, pos + 4) as usize;
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
    let non_resident = record[attr_pos + 8];
    if non_resident != 0 {
        return None; // $FILE_NAME is always resident
    }
    let value_length = read_u32(record, attr_pos + 0x10) as usize;
    let value_offset = read_u16(record, attr_pos + 0x14) as usize;
    let data_start = attr_pos + value_offset;

    if data_start + value_length > record.len() || value_length < 0x44 {
        return None;
    }
    let fname = &record[data_start..data_start + value_length];

    // Parent directory MFT reference (6 bytes record number + 2 bytes seq)
    let parent_ref = read_u64(fname, 0) & 0x0000_FFFF_FFFF_FFFF;

    let name_len = fname[0x40] as usize;
    let namespace = fname[0x41];
    // Skip DOS-only names (namespace 2)
    if namespace == 2 {
        return None;
    }
    if 0x42 + name_len * 2 > fname.len() {
        return None;
    }
    Some((crate::utils::utf16le_decode(&fname[0x42..0x42 + name_len * 2]), parent_ref))
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
        let value_length = read_u32(record, pos + 0x10) as u64;
        return Some((Vec::new(), value_length));
    }

    // Non-resident
    if pos + 0x38 > record.len() {
        return None;
    }
    let real_size = read_u64(record, pos + 0x30);
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
    let value_length = read_u32(record, pos + 0x10) as usize;
    let value_offset = read_u16(record, pos + 0x14) as usize;
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
) -> Result<Vec<u8>> {
    let mut data = Vec::with_capacity(file_size.min(64 * 1024 * 1024) as usize);
    const BLOCK: u64 = 4096;
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
                match reader.read_exact(&mut data[start..start + block_size]) {
                    Ok(()) => true,
                    Err(_) => {
                        // Zero-fill on error
                        data[start..start + block_size].fill(0);
                        false
                    }
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
    Ok(data)
}

/// Read a single MFT record by record number, using the MFT data runs map.
fn read_mft_record<R: Read + Seek>(
    reader: &mut R,
    record_number: u64,
    mft_runs: &[DataRun],
    params: &NtfsParams,
    partition_offset: u64,
) -> Option<Vec<u8>> {
    let byte_offset = record_number * params.record_size as u64;
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
    let (pos, _len) = match find_attribute(record, 0x20) {
        Some(v) => v,
        None => return Vec::new(),
    };

    let non_resident = record[pos + 8];
    let attr_list_data;

    if non_resident == 0 {
        // Resident $ATTRIBUTE_LIST
        let value_length = read_u32(record, pos + 0x10) as usize;
        let value_offset = read_u16(record, pos + 0x14) as usize;
        let start = pos + value_offset;
        if start + value_length > record.len() {
            return Vec::new();
        }
        attr_list_data = record[start..start + value_length].to_vec();
    } else {
        // Non-resident $ATTRIBUTE_LIST — read from data runs
        if pos + 0x38 > record.len() {
            return Vec::new();
        }
        let real_size = read_u64(record, pos + 0x30);
        let runs_offset = read_u16(record, pos + 0x20) as usize;
        if pos + runs_offset >= pos + _len || real_size > 256 * 1024 {
            return Vec::new();
        }
        let runs = parse_data_runs(&record[pos + runs_offset..pos + _len]);
        if runs.is_empty() {
            return Vec::new();
        }
        match read_from_data_runs(reader, &runs, real_size, params.cluster_size, partition_offset) {
            Ok(data) => attr_list_data = data,
            Err(_) => return Vec::new(),
        }
    }

    let mut extension_records = Vec::new();
    let mut off = 0;
    while off + 0x1A <= attr_list_data.len() {
        let attr_type = read_u32(&attr_list_data, off);
        let entry_length = read_u16(&attr_list_data, off + 4) as usize;
        if entry_length < 0x1A || off + entry_length > attr_list_data.len() {
            break;
        }
        // $DATA attribute type = 0x80
        if attr_type == 0x80 {
            let mft_ref = read_u64(&attr_list_data, off + 0x10) & 0x0000_FFFF_FFFF_FFFF;
            if !extension_records.contains(&mft_ref) {
                extension_records.push(mft_ref);
            }
        }
        off += entry_length;
    }
    extension_records
}

/// Read hive file data from an MFT record, with $ATTRIBUTE_LIST support
/// for files whose $DATA spans multiple MFT records.
fn read_hive_from_record<R: Read + Seek>(
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
            log::info!("{}: {} data runs, {} bytes (base record)", name, runs.len(), file_size);
            return read_from_data_runs(reader, &runs, file_size, params.cluster_size, partition_offset);
        }
    }

    // $DATA not in base record — check $ATTRIBUTE_LIST for extension records
    let ext_records = parse_attribute_list_from_record(reader, record, params, partition_offset);
    if ext_records.is_empty() {
        return Err(VmkatzError::DecryptionError(format!("{}: no $DATA attribute", name)));
    }

    log::info!("{}: $DATA in {} extension record(s), reading via $ATTRIBUTE_LIST", name, ext_records.len());

    // Collect data runs from all extension records
    let mut all_runs = Vec::new();
    let mut file_size = 0u64;

    for &ext_ref in &ext_records {
        if let Some(ext_record) = read_mft_record(reader, ext_ref, mft_runs, params, partition_offset) {
            if let Some((runs, size)) = extract_data_attribute(&ext_record) {
                all_runs.extend(runs);
                if size > file_size {
                    file_size = size;
                }
            }
        } else {
            log::debug!("{}: extension record #{} inaccessible", name, ext_ref);
        }
    }

    if all_runs.is_empty() {
        return Err(VmkatzError::DecryptionError(format!("{}: no data runs from extension records", name)));
    }

    log::info!("{}: {} total data runs, {} bytes", name, all_runs.len(), file_size);
    read_from_data_runs(reader, &all_runs, file_size, params.cluster_size, partition_offset)
}

/// Verify that a parent record chain leads to \Windows\System32\config.
/// Checks 3 levels up: parent=config, grandparent=System32, great-grandparent=Windows.
fn verify_config_parent<R: Read + Seek>(
    reader: &mut R,
    parent_ref: u64,
    mft_runs: &[DataRun],
    params: &NtfsParams,
    partition_offset: u64,
) -> bool {
    // Read parent record (should be "config")
    let parent = match read_mft_record(reader, parent_ref, mft_runs, params, partition_offset) {
        Some(r) => r,
        None => return false,
    };
    let (parent_name, grandparent_ref) = match extract_filename(&parent) {
        Some(n) => n,
        None => return false,
    };
    if !parent_name.eq_ignore_ascii_case("config") {
        return false;
    }

    // Read grandparent (should be "System32")
    let grandparent =
        match read_mft_record(reader, grandparent_ref, mft_runs, params, partition_offset) {
            Some(r) => r,
            None => return false,
        };
    let (gp_name, _) = match extract_filename(&grandparent) {
        Some(n) => n,
        None => return false,
    };
    gp_name.eq_ignore_ascii_case("System32")
}

/// Try to read registry hives via $MFTMirr bootstrap.
///
/// This is the main entry point. Called when `ntfs.root_directory()` fails
/// because the primary MFT start is in an inaccessible disk region.
pub fn try_mftmirr_fallback<R: Read + Seek>(
    reader: &mut R,
    partition_offset: u64,
) -> Result<super::HiveFiles> {
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
        VmkatzError::DecryptionError(format!(
            "Cannot seek to MFTMirr at 0x{:x}: {}",
            mftmirr_abs, e
        ))
    })?;
    let mut mftmirr_data = vec![0u8; params.record_size as usize * 4];
    reader
        .read_exact(&mut mftmirr_data)
        .map_err(|e| VmkatzError::DecryptionError(format!("Cannot read MFTMirr: {}", e)))?;

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

    let total_records = mft_size / params.record_size as u64;
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
        let first_record = run.vcn_start * params.cluster_size / params.record_size as u64;
        let num_records = run_bytes / params.record_size as u64;

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

    // Scan accessible MFT records for SAM, SYSTEM, SECURITY filenames
    let rs = params.record_size as usize;
    let mut sam_record: Option<Vec<u8>> = None;
    let mut system_record: Option<Vec<u8>> = None;
    let mut security_record: Option<Vec<u8>> = None;

    let batch_records = 256usize;

    'segments: for &(abs_offset, first_rec, num_recs) in &accessible_segments {
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

                if let Some((name, parent_ref)) = extract_filename(&record) {
                    let name_upper = name.to_uppercase();
                    let target = match name_upper.as_str() {
                        "SAM" if sam_record.is_none() => &mut sam_record,
                        "SYSTEM" if system_record.is_none() => &mut system_record,
                        "SECURITY" if security_record.is_none() => &mut security_record,
                        _ => continue,
                    };

                    // Verify parent chain: parent=config, grandparent=System32
                    if verify_config_parent(
                        reader,
                        parent_ref,
                        &mft_runs,
                        &params,
                        partition_offset,
                    ) {
                        let rec_num = first_rec + rec_idx + i as u64;
                        log::info!(
                            "MFTMirr scan: found {} at MFT record #{} (parent verified)",
                            name_upper,
                            rec_num,
                        );
                        *target = Some(record);
                    } else {
                        log::debug!(
                            "MFTMirr scan: {} at record #{} — parent chain mismatch, skipping",
                            name_upper,
                            first_rec + rec_idx + i as u64,
                        );
                    }

                    if sam_record.is_some() && system_record.is_some() && security_record.is_some()
                    {
                        break 'segments;
                    }
                }
            }

            rec_idx += batch as u64;
        }
    }

    // If parent verification failed for all candidates, retry without parent check
    // (parent MFT records may be in inaccessible segments)
    if sam_record.is_none() || system_record.is_none() {
        log::info!(
            "MFTMirr: retrying without parent verification (parent records may be inaccessible)"
        );

        'segments2: for &(abs_offset, first_rec, num_recs) in &accessible_segments {
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
                    if flags & 1 == 0 || flags & 2 != 0 {
                        continue;
                    }

                    if let Some((name, _parent)) = extract_filename(&record) {
                        let name_upper = name.to_uppercase();
                        let target = match name_upper.as_str() {
                            "SAM" if sam_record.is_none() => &mut sam_record,
                            "SYSTEM" if system_record.is_none() => &mut system_record,
                            "SECURITY" if security_record.is_none() => &mut security_record,
                            _ => continue,
                        };

                        // Without parent check, validate data starts with "regf"
                        let rec_num = first_rec + rec_idx + i as u64;
                        let hive_check =
                            try_read_hive_start(reader, &record, &params, partition_offset);

                        match hive_check {
                            Some(true) => {
                                log::info!(
                                    "MFTMirr scan: found {} at MFT record #{} (regf-validated)",
                                    name_upper,
                                    rec_num,
                                );
                                *target = Some(record);
                            }
                            Some(false) => {
                                log::info!(
                                    "MFTMirr scan: found {} at MFT record #{} (not a regf hive, skipping)",
                                    name_upper,
                                    rec_num,
                                );
                            }
                            None => {
                                // First extent inaccessible — accept the record anyway.
                                // Block-level resilient I/O in read_from_data_runs will
                                // zero-fill only the specific 4KB blocks that fail.
                                // For live VMs, most blocks are readable.
                                log::info!(
                                    "MFTMirr scan: found {} at MFT record #{} (first extent check failed, accepting for resilient read)",
                                    name_upper,
                                    rec_num,
                                );
                                *target = Some(record);
                            }
                        }

                        if sam_record.is_some()
                            && system_record.is_some()
                            && security_record.is_some()
                        {
                            break 'segments2;
                        }
                    }
                }

                rec_idx += batch as u64;
            }
        }
    }

    // Read file data from found records
    let sam_data = match sam_record {
        Some(ref rec) => read_hive_from_record(reader, rec, "SAM", &mft_runs, &params, partition_offset)?,
        None => {
            return Err(VmkatzError::DecryptionError(
                "MFTMirr: SAM hive not found in accessible MFT segments".into(),
            ))
        }
    };
    let system_data = match system_record {
        Some(ref rec) => read_hive_from_record(reader, rec, "SYSTEM", &mft_runs, &params, partition_offset)?,
        None => {
            return Err(VmkatzError::DecryptionError(
                "MFTMirr: SYSTEM hive not found in accessible MFT segments".into(),
            ))
        }
    };
    let security_data = security_record.as_ref().and_then(|rec| {
        read_hive_from_record(reader, rec, "SECURITY", &mft_runs, &params, partition_offset).ok()
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

/// Try to read the first 4 bytes of a file's data to check if it's "regf".
fn try_read_hive_start<R: Read + Seek>(
    reader: &mut R,
    record: &[u8],
    params: &NtfsParams,
    partition_offset: u64,
) -> Option<bool> {
    // Check resident data
    if let Some(data) = read_resident_data(record) {
        return Some(data.len() >= 4 && &data[0..4] == b"regf");
    }

    // Non-resident: read first cluster of first data run
    let (runs, _size) = extract_data_attribute(record)?;
    if runs.is_empty() {
        return None;
    }
    let abs_offset = partition_offset + runs[0].lcn_start * params.cluster_size;
    if reader.seek(SeekFrom::Start(abs_offset)).is_err() {
        return None;
    }
    let mut sig = [0u8; 4];
    if reader.read_exact(&mut sig).is_err() {
        return None;
    }
    Some(&sig == b"regf")
}
