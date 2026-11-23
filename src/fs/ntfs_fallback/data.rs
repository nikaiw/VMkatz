//! Bounded file reads from resident attributes, data runs and extension records.

use std::io::{Read, Seek, SeekFrom};

use crate::error::{Result, VmkatzError};
use crate::fs::recovery::{MAX_CANDIDATES, MAX_FILE_BYTES, ScanBudget};
use crate::utils::{u16_le_or0, u32_le_or0, u64_le_or0};

use super::records::{
    DataRun, NtfsParams, extract_data_attribute, find_attribute, fixup_file_record,
    parse_data_runs, read_resident_data,
};

/// Read non-resident file data from data runs.
/// Uses block-level resilient I/O: on error, zero-fills
/// the failing 4KB block and continues. This handles live/in-use block devices
/// where individual sectors may be temporarily locked.
pub(super) fn read_from_data_runs<R: Read + Seek>(
    reader: &mut R,
    runs: &[DataRun],
    file_size: u64,
    cluster_size: u64,
    partition_offset: u64,
) -> Result<Vec<u8>> {
    if file_size > MAX_FILE_BYTES {
        return Err(VmkatzError::RecoveryLimit("recovered file exceeds 64 MiB"));
    }
    let budget = ScanBudget::new();
    // Logical offsets preserve sparse holes and avoid reading allocated slack
    // (a tiny file can have a huge or corrupt allocated extent).
    let mut data = vec![0; file_size as usize];
    for run in runs {
        budget.check_time()?;
        let start = run
            .vcn_start
            .checked_mul(cluster_size)
            .ok_or_else(|| VmkatzError::DecryptionError("VCN overflow".into()))?;
        if start >= file_size {
            continue;
        }
        let run_bytes = run
            .vcn_length
            .saturating_mul(cluster_size)
            .min(file_size - start);
        let abs = run
            .lcn_start
            .checked_mul(cluster_size)
            .and_then(|off| partition_offset.checked_add(off))
            .ok_or_else(|| VmkatzError::DecryptionError("data run offset overflow".into()))?;
        let end = (start + run_bytes) as usize;
        for (i, block) in data[start as usize..end].chunks_mut(4096).enumerate() {
            budget.check_time()?;
            let pos = abs
                .checked_add(i as u64 * 4096)
                .ok_or_else(|| VmkatzError::DecryptionError("data run offset overflow".into()))?;
            if reader.seek(SeekFrom::Start(pos)).is_err() || reader.read_exact(block).is_err() {
                block.fill(0);
            }
        }
    }
    Ok(data)
}

/// Read a single MFT record by record number, using the MFT data runs map.
pub(super) fn read_mft_record<R: Read + Seek>(
    reader: &mut R,
    record_number: u64,
    mft_runs: &[DataRun],
    params: &NtfsParams,
    partition_offset: u64,
) -> Option<Vec<u8>> {
    let byte_offset = record_number.checked_mul(u64::from(params.record_size))?;
    let cluster_offset = byte_offset / params.cluster_size;
    let offset_in_cluster = byte_offset % params.cluster_size;

    // Find which data run contains this record
    for run in mft_runs {
        let run_vcn_end = run.vcn_start.checked_add(run.vcn_length)?;
        if cluster_offset >= run.vcn_start && cluster_offset < run_vcn_end {
            let cluster_in_run = cluster_offset - run.vcn_start;
            let abs_offset = run
                .lcn_start
                .checked_add(cluster_in_run)?
                .checked_mul(params.cluster_size)?
                .checked_add(partition_offset)?
                .checked_add(offset_in_cluster)?;

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
        .unwrap_or_default()
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
pub(super) fn read_file_from_record<R: Read + Seek>(
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
            return read_from_data_runs(
                reader,
                &runs,
                file_size,
                params.cluster_size,
                partition_offset,
            );
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

    let budget = ScanBudget::new();
    // Collect data runs from all extension records
    let mut all_runs = Vec::new();
    let mut file_size = 0u64;

    for &ext_ref in &ext_records {
        budget.check_time()?;
        if let Some(ext_record) =
            read_mft_record(reader, ext_ref, mft_runs, params, partition_offset)
        {
            if let Some((runs, size)) = extract_data_attribute(&ext_record) {
                if all_runs.len() + runs.len() > MAX_CANDIDATES {
                    return Err(VmkatzError::RecoveryLimit("too many recovered data runs"));
                }
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
    read_from_data_runs(
        reader,
        &all_runs,
        file_size,
        params.cluster_size,
        partition_offset,
    )
}

/// Try to read the first bytes of a file's data so the caller can validate its
/// content signature ("regf" for registry hives, the ESE magic for ntds.dit).
/// Returns None when the first extent is inaccessible.
pub(super) fn try_read_file_start<R: Read + Seek>(
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
    let abs_offset = runs
        .first()?
        .lcn_start
        .checked_mul(params.cluster_size)?
        .checked_add(partition_offset)?;
    if reader.seek(SeekFrom::Start(abs_offset)).is_err() {
        return None;
    }
    let mut start = [0u8; 8];
    if reader.read_exact(&mut start).is_err() {
        return None;
    }
    Some(start.to_vec())
}
