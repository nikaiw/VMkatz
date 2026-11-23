//! GPT and MBR partition-table parsing.

use std::collections::BTreeSet;

use serde::Serialize;

use super::{ByteReader, FsError, FsResult, read_exact_at};

/// Assumed logical sector size. Every Veeam disk image observed uses 512-byte sectors, and
/// GPT/MBR LBA fields are counted in these units.
const SECTOR_SIZE: u64 = 512;
const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";
const GPT_HEADER_LBA: u64 = 1;
const MBR_SIGNATURE_OFFSET: usize = 0x1fe;
const MBR_TABLE_OFFSET: usize = 0x1be;
const MBR_ENTRY_SIZE: usize = 16;
const MBR_ENTRY_COUNT: usize = 4;
const MBR_GPT_PROTECTIVE_TYPE: u8 = 0xee;
/// Container types (CHS extended, LBA extended, Linux extended) whose logical volumes are chained
/// through a list of EBRs rather than described directly in the primary table.
const MBR_EXTENDED_TYPES: [u8; 3] = [0x05, 0x0f, 0x85];
const MAX_PARTITIONS: usize = 256;

/// Broad classification of a partition from its GPT type GUID or MBR type byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartitionKind {
    /// EFI System Partition (FAT).
    EfiSystem,
    /// Microsoft Reserved Partition (no filesystem).
    MicrosoftReserved,
    /// Microsoft Basic Data (usually NTFS, sometimes FAT/exFAT).
    MicrosoftBasicData,
    /// Windows Recovery Environment (NTFS).
    WindowsRecovery,
    /// Linux filesystem data.
    LinuxData,
    /// BIOS boot partition (no filesystem).
    BiosBoot,
    /// A partition whose type is not specifically recognised.
    Unknown,
}

impl PartitionKind {
    const fn label(self) -> &'static str {
        match self {
            Self::EfiSystem => "EFI System",
            Self::MicrosoftReserved => "Microsoft Reserved",
            Self::MicrosoftBasicData => "Basic Data",
            Self::WindowsRecovery => "Windows Recovery",
            Self::LinuxData => "Linux",
            Self::BiosBoot => "BIOS boot",
            Self::Unknown => "partition",
        }
    }
}

/// One partition located in an image's partition table.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Partition {
    /// One-based ordinal for display.
    pub index: usize,
    /// Broad type classification.
    pub kind: PartitionKind,
    /// Absolute byte offset of the partition within the image.
    pub start: u64,
    /// Partition length in bytes.
    pub length: u64,
    /// Display label — the GPT partition name when present, otherwise the kind.
    pub label: String,
}

/// Parse the partition table of `image` (GPT preferred, MBR fallback).
///
/// Returns an empty vector when the image carries no recognisable table.
///
/// # Errors
///
/// Returns an error when a present table is structurally corrupt or a read fails.
pub fn read_partitions<R: ByteReader + ?Sized>(image: &R) -> FsResult<Vec<Partition>> {
    let gpt_header = read_exact_at(image, GPT_HEADER_LBA * SECTOR_SIZE, 92)?;
    if gpt_header.get(0..8) == Some(GPT_SIGNATURE.as_slice()) {
        return read_gpt(image, &gpt_header);
    }
    // A zeroed/damaged primary GPT header is common when only the backup survived; try the
    // alternate header at the last LBA before falling back to MBR.
    if let Some(backup) = read_backup_gpt(image)? {
        return Ok(backup);
    }
    read_mbr(image)
}

/// Try the backup GPT header stored in the image's last LBA.
fn read_backup_gpt<R: ByteReader + ?Sized>(image: &R) -> FsResult<Option<Vec<Partition>>> {
    let size = image.size();
    let Some(last_lba) = (size / SECTOR_SIZE).checked_sub(1) else {
        return Ok(None);
    };
    let Ok(header) = read_exact_at(image, last_lba.saturating_mul(SECTOR_SIZE), 92) else {
        return Ok(None);
    };
    if header.get(0..8) != Some(GPT_SIGNATURE.as_slice()) {
        return Ok(None);
    }
    Ok(Some(read_gpt(image, &header)?))
}

fn read_gpt<R: ByteReader + ?Sized>(image: &R, header: &[u8]) -> FsResult<Vec<Partition>> {
    let entries_lba = read_u64(header, 72)?;
    let entry_count = read_u32(header, 80)?;
    let entry_size = read_u32(header, 84)?;
    if !(128..=4096).contains(&entry_size) {
        return Err(corrupt("GPT header", "implausible partition entry size"));
    }
    let entry_count = usize::try_from(entry_count)
        .unwrap_or(0)
        .min(MAX_PARTITIONS);
    let entry_size_usize = usize::try_from(entry_size).unwrap_or(0);
    let table_offset = entries_lba.saturating_mul(SECTOR_SIZE);
    let table_bytes = entry_count.saturating_mul(entry_size_usize);
    let table = read_exact_at(image, table_offset, table_bytes)?;

    let mut partitions = Vec::new();
    for slot in 0..entry_count {
        let base = slot.saturating_mul(entry_size_usize);
        let Some(entry) = table.get(base..base.saturating_add(entry_size_usize)) else {
            break;
        };
        let type_guid = entry.get(0..16).unwrap_or(&[]);
        if type_guid.iter().all(|byte| *byte == 0) {
            continue; // unused slot
        }
        let first_lba = read_u64(entry, 32)?;
        let last_lba = read_u64(entry, 40)?;
        if last_lba < first_lba {
            continue;
        }
        let start = first_lba.saturating_mul(SECTOR_SIZE);
        let length = last_lba
            .saturating_sub(first_lba)
            .saturating_add(1)
            .saturating_mul(SECTOR_SIZE);
        let kind = gpt_kind(type_guid);
        let name = gpt_name(entry.get(56..128).unwrap_or(&[]));
        let label = if name.is_empty() {
            kind.label().to_owned()
        } else {
            name
        };
        partitions.push(Partition {
            index: partitions.len().saturating_add(1),
            kind,
            start,
            length,
            label,
        });
    }
    Ok(partitions)
}

fn read_mbr<R: ByteReader + ?Sized>(image: &R) -> FsResult<Vec<Partition>> {
    let sector = read_exact_at(image, 0, SECTOR_SIZE_USIZE)?;
    let signature = sector.get(MBR_SIGNATURE_OFFSET..MBR_SIGNATURE_OFFSET.saturating_add(2));
    if signature != Some(&[0x55, 0xaa]) {
        return Ok(Vec::new());
    }
    let mut partitions = Vec::new();
    for slot in 0..MBR_ENTRY_COUNT {
        let base = MBR_TABLE_OFFSET.saturating_add(slot.saturating_mul(MBR_ENTRY_SIZE));
        let Some(entry) = sector.get(base..base.saturating_add(MBR_ENTRY_SIZE)) else {
            break;
        };
        let type_byte = entry.get(4).copied().unwrap_or(0);
        if type_byte == 0 || type_byte == MBR_GPT_PROTECTIVE_TYPE {
            continue;
        }
        let start_lba = u64::from(read_u32(entry, 8)?);
        let sectors = u64::from(read_u32(entry, 12)?);
        if sectors == 0 {
            continue;
        }
        if MBR_EXTENDED_TYPES.contains(&type_byte) {
            // Follow the EBR chain instead of listing the container itself, so the logical volumes
            // inside an extended partition are not silently dropped.
            walk_extended_partitions(image, start_lba, &mut partitions)?;
            continue;
        }
        push_mbr_partition(&mut partitions, type_byte, start_lba, sectors);
    }
    Ok(partitions)
}

/// Push one MBR/EBR partition entry, classifying it by its type byte.
fn push_mbr_partition(
    partitions: &mut Vec<Partition>,
    type_byte: u8,
    start_lba: u64,
    sectors: u64,
) {
    let kind = mbr_kind(type_byte);
    partitions.push(Partition {
        index: partitions.len().saturating_add(1),
        kind,
        start: start_lba.saturating_mul(SECTOR_SIZE),
        length: sectors.saturating_mul(SECTOR_SIZE),
        label: kind.label().to_owned(),
    });
}

/// Walk the linked list of Extended Boot Records, appending each logical volume.
///
/// Entry 0 of each EBR describes a logical volume whose start LBA is relative to that EBR; entry 1
/// links to the next EBR, relative to the extended partition's start. A visited-set bounds cycles.
fn walk_extended_partitions<R: ByteReader + ?Sized>(
    image: &R,
    extended_start_lba: u64,
    partitions: &mut Vec<Partition>,
) -> FsResult<()> {
    let mut ebr_lba = extended_start_lba;
    let mut visited = BTreeSet::new();
    while visited.insert(ebr_lba) && partitions.len() < MAX_PARTITIONS {
        let ebr = read_exact_at(
            image,
            ebr_lba.saturating_mul(SECTOR_SIZE),
            SECTOR_SIZE_USIZE,
        )?;
        if ebr.get(MBR_SIGNATURE_OFFSET..MBR_SIGNATURE_OFFSET.saturating_add(2))
            != Some(&[0x55, 0xaa])
        {
            break;
        }
        if let Some(logical) =
            ebr.get(MBR_TABLE_OFFSET..MBR_TABLE_OFFSET.saturating_add(MBR_ENTRY_SIZE))
        {
            let type_byte = logical.get(4).copied().unwrap_or(0);
            let sectors = u64::from(read_u32(logical, 12)?);
            if type_byte != 0 && sectors != 0 {
                let start = ebr_lba.saturating_add(u64::from(read_u32(logical, 8)?));
                push_mbr_partition(partitions, type_byte, start, sectors);
            }
        }
        let next_start = MBR_TABLE_OFFSET.saturating_add(MBR_ENTRY_SIZE);
        let Some(link) = ebr.get(next_start..next_start.saturating_add(MBR_ENTRY_SIZE)) else {
            break;
        };
        let next_relative = u64::from(read_u32(link, 8)?);
        if next_relative == 0 {
            break;
        }
        ebr_lba = extended_start_lba.saturating_add(next_relative);
    }
    Ok(())
}

const SECTOR_SIZE_USIZE: usize = 512;

/// Known GPT partition type GUIDs, in on-disk byte order (mixed-endian).
const GUID_EFI_SYSTEM: [u8; 16] = [
    0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b,
];
const GUID_MSR: [u8; 16] = [
    0x16, 0xe3, 0xc9, 0xe3, 0x5c, 0x0b, 0xb8, 0x4d, 0x81, 0x7d, 0xf9, 0x2d, 0xf0, 0x02, 0x15, 0xae,
];
const GUID_BASIC_DATA: [u8; 16] = [
    0xa2, 0xa0, 0xd0, 0xeb, 0xe5, 0xb9, 0x33, 0x44, 0x87, 0xc0, 0x68, 0xb6, 0xb7, 0x26, 0x99, 0xc7,
];
const GUID_WINDOWS_RECOVERY: [u8; 16] = [
    0xa4, 0xbb, 0x94, 0xde, 0xd1, 0x06, 0x40, 0x4d, 0xa1, 0x6a, 0xbf, 0xd5, 0x01, 0x79, 0xd6, 0xac,
];
const GUID_LINUX_DATA: [u8; 16] = [
    0xaf, 0x3d, 0xc6, 0x0f, 0x83, 0x84, 0x72, 0x47, 0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4,
];
const GUID_BIOS_BOOT: [u8; 16] = [
    0x48, 0x61, 0x68, 0x21, 0x49, 0x64, 0x6f, 0x6e, 0x74, 0x4e, 0x65, 0x65, 0x64, 0x45, 0x46, 0x49,
];

fn gpt_kind(type_guid: &[u8]) -> PartitionKind {
    match type_guid {
        guid if guid == GUID_EFI_SYSTEM => PartitionKind::EfiSystem,
        guid if guid == GUID_MSR => PartitionKind::MicrosoftReserved,
        guid if guid == GUID_BASIC_DATA => PartitionKind::MicrosoftBasicData,
        guid if guid == GUID_WINDOWS_RECOVERY => PartitionKind::WindowsRecovery,
        guid if guid == GUID_LINUX_DATA => PartitionKind::LinuxData,
        guid if guid == GUID_BIOS_BOOT => PartitionKind::BiosBoot,
        _ => PartitionKind::Unknown,
    }
}

fn mbr_kind(type_byte: u8) -> PartitionKind {
    match type_byte {
        // NTFS / exFAT (0x07) and the FAT variants all carry a Microsoft filesystem.
        0x07 | 0x0b | 0x0c | 0x0e | 0x01 | 0x04 | 0x06 => PartitionKind::MicrosoftBasicData,
        0xef => PartitionKind::EfiSystem,
        0x27 => PartitionKind::WindowsRecovery,
        0x83 => PartitionKind::LinuxData,
        _ => PartitionKind::Unknown,
    }
}

/// Decode a GPT UTF-16LE partition name, trimming trailing NULs.
fn gpt_name(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| {
            u16::from_le_bytes([
                pair.first().copied().unwrap_or(0),
                pair.get(1).copied().unwrap_or(0),
            ])
        })
        .take_while(|unit| *unit != 0)
        .collect();
    String::from_utf16_lossy(&units).trim().to_owned()
}

fn read_u32(bytes: &[u8], offset: usize) -> FsResult<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| corrupt("integer", "offset overflow"))?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| corrupt("integer", "u32 out of range"))?;
    let array = <[u8; 4]>::try_from(slice).map_err(|_ignored| corrupt("integer", "u32 slice"))?;
    Ok(u32::from_le_bytes(array))
}

fn read_u64(bytes: &[u8], offset: usize) -> FsResult<u64> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| corrupt("integer", "offset overflow"))?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| corrupt("integer", "u64 out of range"))?;
    let array = <[u8; 8]>::try_from(slice).map_err(|_ignored| corrupt("integer", "u64 slice"))?;
    Ok(u64::from_le_bytes(array))
}

fn corrupt(structure: &'static str, reason: &str) -> FsError {
    FsError::Corrupt {
        structure,
        reason: reason.to_owned(),
    }
}
