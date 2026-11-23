//! NTFS boot parameters, data runs and FILE record attributes.

use crate::error::{Result, VmkatzError};
use crate::utils::{u16_le_or0, u32_le_or0, u64_le_or0};

/// NTFS boot sector parameters.
pub(super) struct NtfsParams {
    pub(super) cluster_size: u64,
    pub(super) record_size: u32,
    pub(super) mft_position: u64,
    pub(super) mftmirr_position: u64,
}

/// A single MFT data run (VCN range → LCN cluster mapping).
pub(super) struct DataRun {
    pub(super) vcn_start: u64,
    pub(super) vcn_length: u64,
    pub(super) lcn_start: u64,
}

/// Parse NTFS boot sector.
pub(super) fn parse_boot_sector(data: &[u8]) -> Result<NtfsParams> {
    if data.len() < 0x48 {
        return Err(VmkatzError::DecryptionError("Boot sector too small".into()));
    }
    if &data[3..11] != b"NTFS    " {
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

    // Signed record size: positive = clusters, negative = 2^|value|.
    // Guard both arithmetic paths before validating the allocation size.
    let raw = data[0x40] as i8;
    let record_size_u64: u64 = if raw > 0 {
        (raw as u64).saturating_mul(cluster_size)
    } else {
        let shift = i32::from(raw).unsigned_abs();
        if shift < 64 { 1u64 << shift } else { 0 }
    };
    // Cap each record at 64 KiB before allocating MFT buffers.
    if !(512..=1 << 16).contains(&record_size_u64) || !record_size_u64.is_power_of_two() {
        return Err(VmkatzError::DecryptionError(format!(
            "Invalid NTFS boot sector: record_size={record_size_u64}"
        )));
    }
    let record_size = record_size_u64 as u32;

    Ok(NtfsParams {
        cluster_size,
        record_size,
        mft_position: mft_cluster
            .checked_mul(cluster_size)
            .ok_or_else(|| VmkatzError::DecryptionError("MFT offset overflow".into()))?,
        mftmirr_position: mftmirr_cluster
            .checked_mul(cluster_size)
            .ok_or_else(|| VmkatzError::DecryptionError("MFTMirr offset overflow".into()))?,
    })
}

/// Parse data run list from non-resident attribute.
pub(super) fn parse_data_runs(data: &[u8]) -> Vec<DataRun> {
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

        if length_size == 0
            || length_size > 8
            || offset_size > 8
            || pos + length_size + offset_size > data.len()
        {
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

            let Some(next_lcn) = prev_lcn.checked_add(offset) else {
                break;
            };
            prev_lcn = next_lcn;
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

        let Some(next_vcn) = vcn.checked_add(length) else {
            break;
        };
        vcn = next_vcn;
    }

    runs
}

/// Apply NTFS fixup array to a FILE record (in-place).
pub(super) fn fixup_file_record(data: &mut [u8]) -> bool {
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
pub(super) fn find_attribute(record: &[u8], attr_type: u32) -> Option<(usize, usize)> {
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
pub(super) fn find_all_attributes(record: &[u8], attr_type: u32) -> Vec<(usize, usize)> {
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
#[cfg(any(feature = "sam", test))]
fn filename_from_attr(record: &[u8], attr_pos: usize) -> Option<(String, u64)> {
    filename_info_from_attr(record, attr_pos).map(|(name, parent, _)| (name, parent))
}

/// Read the name, parent reference and logical size from a resident $FILE_NAME.
pub(super) fn filename_info_from_attr(
    record: &[u8],
    attr_pos: usize,
) -> Option<(String, u64, u64)> {
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

/// Extract the first non-DOS filename and its parent reference.
#[cfg(any(feature = "sam", test))]
pub(super) fn extract_filename(record: &[u8]) -> Option<(String, u64)> {
    let attrs = find_all_attributes(record, 0x30); // $FILE_NAME = 0x30
    let mut best: Option<(String, u64)> = None;
    for (pos, _len) in attrs {
        if let Some((name, parent)) = filename_from_attr(record, pos) {
            if best.is_none() {
                best = Some((name, parent));
            }
        }
    }
    best
}

/// Extract $DATA data runs from a FILE record. Returns (runs, real_size).
pub(super) fn extract_data_attribute(record: &[u8]) -> Option<(Vec<DataRun>, u64)> {
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
#[cfg(any(feature = "sam", test))]
pub(super) fn read_resident_data(record: &[u8]) -> Option<Vec<u8>> {
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
