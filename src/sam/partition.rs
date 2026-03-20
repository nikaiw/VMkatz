use std::io::{Read, Seek, SeekFrom};

use crate::error::Result;

/// BitLocker OEM ID found at offset +3 in the volume boot record.
const BITLOCKER_OEM_ID: &[u8; 8] = b"-FVE-FS-";

/// Check if a partition at the given byte offset is BitLocker-encrypted.
pub(crate) fn is_bitlocker_partition<R: Read + Seek>(reader: &mut R, offset: u64) -> bool {
    if reader.seek(SeekFrom::Start(offset)).is_err() {
        return false;
    }
    let mut vbr = [0u8; 16];
    if reader.read_exact(&mut vbr).is_err() {
        return false;
    }
    &vbr[3..11] == BITLOCKER_OEM_ID
}

/// Parse MBR/GPT and find all NTFS partitions, returning their byte offsets.
pub(crate) fn find_ntfs_partitions<R: Read + Seek>(reader: &mut R) -> Result<Vec<u64>> {
    if reader.seek(SeekFrom::Start(0)).is_err() {
        return Err(crate::error::VmkatzError::DecryptionError(
            "Cannot seek to MBR (I/O error)".to_string(),
        ));
    }
    let mut mbr = [0u8; 512];
    if reader.read_exact(&mut mbr).is_err() {
        return Err(crate::error::VmkatzError::DecryptionError(
            "Cannot read MBR (I/O error on sector 0)".to_string(),
        ));
    }

    // Check MBR signature
    if mbr[510] != 0x55 || mbr[511] != 0xAA {
        return Err(crate::error::VmkatzError::DecryptionError(
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
            i,
            part_type,
            lba_start
        );

        // NTFS partition type is 0x07
        if part_type == 0x07 && lba_start > 0 {
            partitions.push(lba_start as u64 * 512);
        }
    }

    if partitions.is_empty() {
        return Err(crate::error::VmkatzError::DecryptionError(
            "No NTFS partition found in MBR".to_string(),
        ));
    }

    Ok(partitions)
}

/// Parse GPT partition table and find NTFS (Basic Data) partitions.
fn find_gpt_ntfs_partitions<R: Read + Seek>(reader: &mut R) -> Result<Vec<u64>> {
    // GPT header at LBA 1 (offset 512)
    reader.seek(SeekFrom::Start(512))?;
    let mut hdr = [0u8; 92];
    reader.read_exact(&mut hdr)?;

    // Verify "EFI PART" signature
    if &hdr[0..8] != b"EFI PART" {
        return Err(crate::error::VmkatzError::DecryptionError(
            "Invalid GPT signature".to_string(),
        ));
    }

    let entry_lba = crate::utils::read_u64_le(&hdr, 0x48).unwrap_or(0);
    let num_entries = crate::utils::read_u32_le(&hdr, 0x50).unwrap_or(0);
    let entry_size = crate::utils::read_u32_le(&hdr, 0x54).unwrap_or(0);

    // GPT spec: entry_size is typically 128 bytes; reject invalid values
    if !(128..=4096).contains(&entry_size) {
        return Err(crate::error::VmkatzError::DecryptionError(format!(
            "Invalid GPT entry size: {} (expected 128-4096)",
            entry_size,
        )));
    }

    log::debug!(
        "GPT: entry_lba={}, num_entries={}, entry_size={}",
        entry_lba,
        num_entries,
        entry_size
    );

    // "Microsoft Basic Data" GUID: EBD0A0A2-B9E5-4433-87C0-68B6B72699C7
    // Mixed-endian byte representation
    const BASIC_DATA_GUID: [u8; 16] = [
        0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44, 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26,
        0x99, 0xC7,
    ];

    let mut partitions = Vec::new();
    let entries_offset = entry_lba * 512;

    for i in 0..num_entries {
        let entry_offset = entries_offset + i as u64 * entry_size as u64;
        if reader.seek(SeekFrom::Start(entry_offset)).is_err() {
            continue; // Skip entries we can't seek to
        }
        let mut entry = vec![0u8; entry_size as usize];
        if reader.read_exact(&mut entry).is_err() {
            continue; // Skip entries we can't read (I/O error)
        }

        let type_guid = &entry[0..16];

        // Skip empty entries
        if type_guid.iter().all(|&b| b == 0) {
            continue;
        }

        let first_lba = crate::utils::read_u64_le(&entry, 0x20).unwrap_or(0);

        if type_guid == BASIC_DATA_GUID {
            log::debug!("GPT partition {}: Basic Data at LBA {}", i, first_lba);
            partitions.push(first_lba * 512);
        }
    }

    if partitions.is_empty() {
        return Err(crate::error::VmkatzError::DecryptionError(
            "No NTFS partition found in GPT".to_string(),
        ));
    }

    Ok(partitions)
}
