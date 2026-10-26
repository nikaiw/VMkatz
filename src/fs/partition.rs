use std::io::{Read, Seek, SeekFrom};

use crate::error::{Result, VmkatzError};

/// Restrict a list of partition offsets to a single requested one.
///
/// `None` returns `parts` unchanged. `Some(off)` returns `vec![off]` if present,
/// otherwise a `DiskFormatError` naming the request and the available offsets.
pub fn select_partition(parts: Vec<u64>, wanted: Option<u64>) -> Result<Vec<u64>> {
    let Some(off) = wanted else {
        return Ok(parts);
    };
    if parts.contains(&off) {
        return Ok(vec![off]);
    }
    let avail = if parts.is_empty() {
        "none".to_string()
    } else {
        parts
            .iter()
            .map(|p| format!("0x{p:x}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    Err(VmkatzError::DiskFormatError(format!(
        "partition at offset 0x{off:x} not found; available NTFS partition offsets: {avail}"
    )))
}

/// BitLocker OEM ID found at offset +3 in the volume boot record.
const BITLOCKER_OEM_ID: &[u8; 8] = b"-FVE-FS-";

/// Check if a partition at the given byte offset is BitLocker-encrypted.
pub fn is_bitlocker_partition<R: Read + Seek>(reader: &mut R, offset: u64) -> bool {
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
pub fn find_ntfs_partitions<R: Read + Seek>(reader: &mut R) -> Result<Vec<u64>> {
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

    let mut partitions = Vec::new();
    let mut protective = false;

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

        log::debug!("MBR Partition {i}: type=0x{part_type:02x}, LBA_start={lba_start}");

        if part_type == 0xEE {
            protective = true;
        }
        // NTFS partition type is 0x07
        if part_type == 0x07 && lba_start > 0 {
            partitions.push(u64::from(lba_start) * 512);
        }
    }

    // Protective MBR, or nothing found in the MBR: try GPT.
    if protective || partitions.is_empty() {
        match find_gpt_ntfs_partitions(reader) {
            Ok(gpt) => {
                for off in gpt {
                    if !partitions.contains(&off) {
                        partitions.push(off);
                    }
                }
            }
            Err(e) => log::debug!("GPT scan: {e}"),
        }
    }

    if partitions.is_empty() {
        return Err(crate::error::VmkatzError::DecryptionError(
            "No NTFS partition found in MBR/GPT".to_string(),
        ));
    }

    Ok(partitions)
}

/// Check for an NTFS volume boot record (OEM id "NTFS    " at +3).
fn is_ntfs_vbr<R: Read + Seek>(reader: &mut R, offset: u64) -> bool {
    let mut vbr = [0u8; 512];
    reader.seek(SeekFrom::Start(offset)).is_ok()
        && reader.read_exact(&mut vbr).is_ok()
        && &vbr[3..11] == b"NTFS    "
}

/// Parse GPT partition table and find NTFS partitions (Basic Data GUID or NTFS VBR).
fn find_gpt_ntfs_partitions<R: Read + Seek>(reader: &mut R) -> Result<Vec<u64>> {
    // "Microsoft Basic Data" GUID: EBD0A0A2-B9E5-4433-87C0-68B6B72699C7
    // Mixed-endian byte representation
    const BASIC_DATA_GUID: [u8; 16] = [
        0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44, 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99,
        0xC7,
    ];
    const MAX_ENTRIES: u32 = 256;

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

    // Untrusted header: reject implausible values rather than looping/allocating.
    if !(128..=4096).contains(&entry_size) || num_entries > MAX_ENTRIES {
        return Err(crate::error::VmkatzError::DecryptionError(format!(
            "Implausible GPT header: entries={num_entries}, entry_size={entry_size}",
        )));
    }

    log::debug!("GPT: entry_lba={entry_lba}, num_entries={num_entries}, entry_size={entry_size}");

    let mut partitions = Vec::new();
    let entries_offset = entry_lba.saturating_mul(512);
    let mut entry = vec![0u8; entry_size as usize];

    for i in 0..num_entries {
        let entry_offset = entries_offset.saturating_add(u64::from(i) * u64::from(entry_size));
        if reader.seek(SeekFrom::Start(entry_offset)).is_err()
            || reader.read_exact(&mut entry).is_err()
        {
            continue;
        }

        let type_guid = &entry[0..16];

        // Skip empty entries
        if type_guid.iter().all(|&b| b == 0) {
            continue;
        }

        let first_lba = crate::utils::read_u64_le(&entry, 0x20).unwrap_or(0);
        let Some(offset) = first_lba.checked_mul(512).filter(|_| first_lba > 0) else {
            continue;
        };

        if (type_guid == BASIC_DATA_GUID || is_ntfs_vbr(reader, offset))
            && !partitions.contains(&offset)
        {
            log::debug!("GPT partition {i}: NTFS candidate at LBA {first_lba}");
            partitions.push(offset);
        }
    }

    Ok(partitions)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_partition_passthrough_when_none() {
        let parts = vec![0x100000, 0x6400000];
        assert_eq!(select_partition(parts.clone(), None).unwrap(), parts);
    }

    #[test]
    fn select_partition_keeps_only_match() {
        let parts = vec![0x100000, 0x6400000];
        assert_eq!(
            select_partition(parts.clone(), Some(0x100000)).unwrap(),
            vec![0x100000]
        );
        assert_eq!(
            select_partition(parts, Some(1048576)).unwrap(),
            vec![0x100000]
        );
    }

    #[test]
    fn select_partition_rejects_unknown() {
        let err = select_partition(vec![0x100000, 0x6400000], Some(0xDEAD_BEEF)).unwrap_err();
        let msg = err.to_string().to_lowercase();
        assert!(msg.contains("deadbeef"), "{msg}");
        assert!(msg.contains("100000"), "{msg}");
        assert!(msg.contains("6400000"), "{msg}");
    }

    #[test]
    fn select_partition_rejects_when_no_partitions() {
        let err = select_partition(vec![], Some(0x100000)).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("0x100000") && msg.contains("none"), "{msg}");
    }

    const BASIC: [u8; 16] = [
        0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44, 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99,
        0xC7,
    ];

    /// Build a GPT disk image with one entry (type `guid`, first LBA `lba`).
    fn gpt_disk(guid: [u8; 16], lba: u64, ntfs_vbr: bool) -> Vec<u8> {
        let mut d = vec![0u8; 512 * 64];
        d[0x1BE + 4] = 0xEE;
        d[0x1BE + 8] = 1;
        d[510] = 0x55;
        d[511] = 0xAA;
        d[512..520].copy_from_slice(b"EFI PART");
        d[512 + 0x48..512 + 0x50].copy_from_slice(&2u64.to_le_bytes());
        d[512 + 0x50..512 + 0x54].copy_from_slice(&128u32.to_le_bytes());
        d[512 + 0x54..512 + 0x58].copy_from_slice(&128u32.to_le_bytes());
        let e = 2 * 512;
        d[e..e + 16].copy_from_slice(&guid);
        d[e + 0x20..e + 0x28].copy_from_slice(&lba.to_le_bytes());
        if ntfs_vbr {
            let v = lba as usize * 512;
            d[v..v + 3].copy_from_slice(&[0xEB, 0x52, 0x90]);
            d[v + 3..v + 11].copy_from_slice(b"NTFS    ");
        }
        d
    }

    #[test]
    fn gpt_disk_with_ntfs_basic_data_is_found() {
        let mut c = std::io::Cursor::new(gpt_disk(BASIC, 8, true));
        assert_eq!(find_ntfs_partitions(&mut c).unwrap(), vec![8 * 512]);
    }

    #[test]
    fn gpt_non_basic_guid_with_ntfs_vbr_is_found() {
        let mut c = std::io::Cursor::new(gpt_disk([0x11; 16], 8, true));
        assert_eq!(find_ntfs_partitions(&mut c).unwrap(), vec![8 * 512]);
    }

    #[test]
    fn gpt_basic_data_without_ntfs_vbr_is_rejected() {
        let mut c = std::io::Cursor::new(gpt_disk([0x11; 16], 8, false));
        let r = find_ntfs_partitions(&mut c).unwrap_or_default();
        assert!(!r.contains(&(8 * 512)));
    }

    #[test]
    fn gpt_garbage_entry_count_is_bounded() {
        let mut d = gpt_disk(BASIC, 8, true);
        d[512 + 0x50..512 + 0x54].copy_from_slice(&u32::MAX.to_le_bytes());
        d[512 + 0x54..512 + 0x58].copy_from_slice(&u32::MAX.to_le_bytes());
        let mut c = std::io::Cursor::new(d.clone());
        assert!(find_ntfs_partitions(&mut c).unwrap_or_default().is_empty());
        // absurd count with sane size must also terminate quickly
        d[512 + 0x54..512 + 0x58].copy_from_slice(&128u32.to_le_bytes());
        let mut c = std::io::Cursor::new(d);
        let _ = find_ntfs_partitions(&mut c);
    }

    #[test]
    fn mbr_ntfs_still_detected() {
        let mut d = vec![0u8; 512 * 4];
        d[0x1BE + 4] = 0x07;
        d[0x1BE + 8] = 2;
        d[510] = 0x55;
        d[511] = 0xAA;
        let mut c = std::io::Cursor::new(d);
        assert_eq!(find_ntfs_partitions(&mut c).unwrap(), vec![1024]);
    }
}
