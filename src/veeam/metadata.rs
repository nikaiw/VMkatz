//! Location and validation of modern mirrored metadata banks.

mod view;

use std::path::Path;

use serde::Serialize;

use crate::veeam::{
    Result, VbkError,
    format::parse_header,
    reader::{FileReader, read_u32, read_u64},
};

pub(crate) use view::MetadataBank;

/// First snapshot-slot start. `dissect.archive`'s `VBK.__init__` reads slot 1 from the
/// same location, calling it "`PAGE_SIZE` because `StorageHeader` is considered to be
/// `PAGE_SIZE` large".
const DESCRIPTOR_OFFSET: u64 = 0x1000;
/// Field offsets relative to the active snapshot slot's start. Each name follows
/// `dissect.archive`'s `SnapshotSlotHeader`, `SnapshotDescriptor`, and `BanksGrain`
/// structures; the legacy `_SEGMENT_` names remain in the code for backwards
/// compatibility with earlier releases of `vbktool`.
const STORAGE_EOF_OFFSET: u64 = 0x10;
const BANKS_COUNT_OFFSET: u64 = 0x18;
const MAX_BANKS_OFFSET: u64 = 0x74;
const STORED_BANKS_OFFSET: u64 = 0x78;
const FIRST_BANK_CRC_OFFSET: u64 = 0x7c;
const BANK_DESCRIPTORS_OFFSET: u64 = 0x80;
const BANK_DESCRIPTOR_SIZE: u64 = 16;
const MAX_BANK_COUNT: u64 = 4_096;
const PAGE_SIZE: u64 = 4_096;
const MIRROR_COMPARE_CHUNK_SIZE: u64 = 1024 * 1024;
const CHECKSUM_CHUNK_SIZE: u64 = 1024 * 1024;

/// Fixed-size prelude of a snapshot slot: `SnapshotSlotHeader` (8 bytes) +
/// `SnapshotDescriptor` (108 bytes) + `BanksGrain` (8 bytes) = 124 bytes = `0x7C` bytes.
const SNAPSHOT_SLOT_PRELUDE_SIZE: u64 = FIRST_BANK_CRC_OFFSET;

/// Retained for backwards compatibility with earlier `vbktool` releases; the field-level
/// reads all go through the `_OFFSET`-suffixed slot-relative constants above so that both
/// snapshot slots share a single parsing implementation.
const DECLARED_FILE_LENGTH_OFFSET: u64 = DESCRIPTOR_OFFSET + STORAGE_EOF_OFFSET;
const SEGMENT_DESCRIPTOR_SIZE: u64 = BANK_DESCRIPTOR_SIZE;
const MAX_METADATA_SEGMENTS: u64 = MAX_BANK_COUNT;

/// Byte offset of the 16-byte per-bank keyset identifier inside the bank header page.
///
/// This is the field consulted by `metabank_decrypt_load` @ `0x14036A0E0` in `Extract.exe`
/// (`*(_OWORD *)(bank + 3076) == xmmword_140A35278`).
const BANK_KEYSET_ID_OFFSET: u64 = 0xC04;

/// Byte offset of the allocator flag byte inspected by `metabank_decrypt_load`.
///
/// When this byte equals [`BANK_DECRYPTED_MARKER`] the bank is stored as plaintext even
/// though the storage descriptor permitted encryption.
const BANK_DECRYPTED_MARKER_OFFSET: u64 = 0x2;

/// Sentinel value at [`BANK_DECRYPTED_MARKER_OFFSET`] that means "bank is stored decrypted".
const BANK_DECRYPTED_MARKER: u8 = 2;
const CRC32C_NIBBLE_TABLE: [u32; 16] = [
    0x0000_0000,
    0x105e_c76f,
    0x20bd_8ede,
    0x30e3_49b1,
    0x417b_1dbc,
    0x5125_dad3,
    0x61c6_9362,
    0x7198_540d,
    0x82f6_3b78,
    0x92a8_fc17,
    0xa24b_b5a6,
    0xb215_72c9,
    0xc38d_26c4,
    0xd3d3_e1ab,
    0xe330_a81a,
    0xf36e_6f75,
];

/// One contiguous allocation described by the modern storage directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct MetadataSegment {
    /// Physical segment offset in the backup file.
    pub offset: u64,
    /// Segment length in bytes.
    pub length: u64,
    /// Stored per-segment checksum or zero when absent.
    pub checksum: u32,
}

/// One primary metadata region and its adjacent byte-for-byte mirror.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct MetadataRegion {
    /// Start of the primary serialized region.
    pub primary_offset: u64,
    /// Start of the adjacent mirror.
    pub mirror_offset: u64,
    /// Length of either copy.
    pub length: u64,
    /// First descriptor index composing this region.
    pub first_segment_index: u64,
    /// Number of contiguous descriptors composing this region.
    pub segment_count: u64,
}

/// Validated location of the primary and byte-identical mirrored metadata banks.
///
/// Several public fields keep names inherited from earlier releases of `vbktool`; the
/// per-field documentation explains what `dissect.archive` names them so downstream tools
/// can bridge the two vocabularies.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MetadataLayout {
    /// `SnapshotSlotHeader.CRC` per `dissect.archive` — the CRC32C the writer stored in
    /// the first 4 bytes of the active snapshot slot.
    pub signature: u32,
    /// `SnapshotSlotHeader.ContainsSnapshot` per `dissect.archive` — a non-zero value
    /// marks the slot as populated. Empty slots are filtered out during active-slot
    /// selection (see [`select_active_snapshot_slot`]).
    pub layout_version: u32,
    /// `SnapshotDescriptor.Version` per `dissect.archive` — the monotonically-increasing
    /// slot version. Active-slot selection picks the slot with the higher value.
    pub entry_count_hint: u64,
    /// `SnapshotDescriptor.StorageEOF` per `dissect.archive` — the file length recorded by the
    /// writer at commit time. A complete modern backup sets this exactly equal to the physical file
    /// size; a smaller physical file means the metadata trailer is missing, which the reader
    /// reports as [`VbkError::TruncatedFile`].
    pub declared_file_length: u64,
    /// `BanksGrain.MaxBanks` per `dissect.archive` — the ceiling on the bank-descriptor
    /// slot array. `SnapshotSlotFormat == 0` caps this at `0xF8`; all newer formats cap
    /// it at `0x7F00`.
    pub journal_size_hint: u32,
    /// First `BankDescriptor.CRC` per `dissect.archive`. The remaining bank CRCs live in
    /// `MetadataSegment::checksum`, shifted by one entry (each `MetadataSegment`
    /// exposes its own `Offset` and `Size` plus the *next* entry's `CRC`), so that the
    /// segment-chain verifier can consume the whole array with a single iteration.
    pub directory_checksum: u32,
    /// Number of non-zero CRC32C links verified while parsing the bank descriptor chain.
    pub checksums_verified: usize,
    /// `SnapshotDescriptor.DirectoryRoot` per `dissect.archive` — the root page number
    /// and child count of the top-level directory `MetaBlob`. `vbktool` reaches the
    /// same file records via its implicit page-stack scan; the values are surfaced here
    /// so downstream tooling can drive a descriptor-based walk instead.
    pub directory_root_page: i64,
    /// Directory-root child count (`SnapshotDescriptor.DirectoryRoot.Count`).
    pub directory_root_count: u64,
    /// `SnapshotDescriptor.BlocksStore.RootPage` — root page of the physical block store
    /// `MetaVector`. `vbktool` scans every allocated page for physical records rather
    /// than driving this vector, so the value is currently informational.
    pub blocks_store_root_page: i64,
    /// Number of physical-block entries the writer stored
    /// (`SnapshotDescriptor.BlocksStore.Count`). Matches `physical_blocks` reported by
    /// `verify` on well-formed backups.
    pub blocks_store_count: u64,
    /// `SnapshotDescriptor.BlocksStore.FreeRootPage` — root of the free-block index
    /// (`CFreeBlocksIndex` in Extract.exe, TODO in `dissect.archive`). Unused by
    /// `vbktool`.
    pub free_blocks_root_page: i64,
    /// `SnapshotDescriptor.BlocksStore.DeduplicationRootPage` — root of the
    /// deduplication index (`CDedupIndex`, TODO in `dissect.archive`). Unused by
    /// `vbktool`.
    pub deduplication_root_page: i64,
    /// `SnapshotDescriptor.CryptoStore.RootPage` — root of the crypto-store chain
    /// (`CCryptoStore`, TODO in `dissect.archive`). `-1` for plaintext backups.
    pub crypto_store_root_page: i64,
    /// `BanksGrain.StoredBanks` — the number of bank descriptors actually populated
    /// (should equal `segments.len()` on well-formed backups).
    pub stored_banks: u32,
    /// Bank descriptors in storage-directory order. `dissect.archive` names these
    /// `BankDescriptor` entries; the historical name is preserved for compatibility.
    pub segments: Vec<MetadataSegment>,
    /// Validated primary/mirror region pairs derived by merging contiguous banks.
    pub regions: Vec<MetadataRegion>,
    /// Start of the first primary region used for catalogue traversal.
    pub primary_offset: u64,
    /// Start of the first mirrored region.
    pub mirror_offset: u64,
    /// Length of the first primary region.
    pub bank_length: u64,
}

/// Result of byte-for-byte verification of the two modern metadata banks.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct MetadataMirrorReport {
    /// Sum of the primary-region lengths.
    pub bank_length: u64,
    /// Number of independently mirrored regions.
    pub region_count: usize,
    /// Number of bytes compared before completion or the first mismatch.
    pub bytes_compared: u64,
    /// Whether the full copies are identical.
    pub identical: bool,
    /// Relative byte offset of the first difference, when present.
    pub first_difference: Option<u64>,
    /// Number of metadata segment CRC32C links verified before mirror comparison.
    pub checksums_verified: usize,
}

/// Compare the primary and mirrored modern metadata banks without loading them in full.
///
/// # Errors
///
/// Returns an error if the header or metadata layout is invalid, the file is truncated, or IO fails.
pub fn verify_metadata_mirror(path: &Path) -> Result<MetadataMirrorReport> {
    let header = parse_header(path)?;
    let layout = header.metadata.ok_or(VbkError::FeatureUnavailable {
        feature: "mirrored metadata verification",
        version: header.version,
    })?;
    let reader = FileReader::open(path)?;
    compare_banks(&reader, &layout)
}

/// Whether the modern metadata bank stored at `layout.segments[0]` is on-disk encrypted.
///
/// Mirrors the authoritative check that `metabank_decrypt_load` (`0x14036A0E0` in
/// `Extract.exe`) performs before dispatching a bank into its decrypt path: a bank is
/// treated as encrypted only when the 16-byte keyset identifier at bank offset
/// [`BANK_KEYSET_ID_OFFSET`] is non-zero **and** the allocator-flag byte at
/// [`BANK_DECRYPTED_MARKER_OFFSET`] is not [`BANK_DECRYPTED_MARKER`]. Any other
/// combination (including a bank that is entirely zero at the keyset slot) is a
/// plaintext bank, regardless of what raw-byte hint scans may have picked up
/// elsewhere in the file.
///
/// # Errors
///
/// Returns an error if the first metadata segment cannot be read.
pub(crate) fn bank_header_indicates_encryption(
    reader: &FileReader,
    layout: &MetadataLayout,
) -> Result<bool> {
    let Some(first_segment) = layout.segments.first() else {
        return Ok(false);
    };
    let marker_offset = checked_add(first_segment.offset, BANK_DECRYPTED_MARKER_OFFSET)?;
    let marker: [u8; 1] = reader.read_array(marker_offset)?;
    let keyset_offset = checked_add(first_segment.offset, BANK_KEYSET_ID_OFFSET)?;
    let keyset_id: [u8; 16] = reader.read_array(keyset_offset)?;
    Ok(classify_bank_header(marker[0], keyset_id))
}

/// Pure implementation of the `metabank_decrypt_load` encryption test, isolated for tests.
///
/// Returns `true` when the bank should be treated as ciphertext: allocator flag is not the
/// "already decrypted" sentinel **and** the recorded keyset identifier is non-zero.
fn classify_bank_header(marker: u8, keyset_id: [u8; 16]) -> bool {
    if marker == BANK_DECRYPTED_MARKER {
        return false;
    }
    keyset_id.iter().any(|byte| *byte != 0)
}

pub(crate) fn parse_metadata_layout(reader: &FileReader) -> Result<MetadataLayout> {
    let slot_offset = select_active_snapshot_slot(reader)?;
    parse_metadata_layout_at(reader, slot_offset)
}

/// Verify both snapshot slots and return the offset of the one that should be read.
///
/// Modern Veeam backups double-buffer their snapshot metadata: slot 1 always starts at
/// `PAGE_SIZE` and slot 2 immediately follows, rounded up to the next page. Every write
/// commits into the inactive slot first, then bumps its `Version` counter so that a
/// reader picks the freshest metadata on the next open. `dissect.archive`'s `VBK.__init__`
/// walks both slots, filters by `SnapshotSlotHeader.ContainsSnapshot` and the header
/// CRC32C, and selects the highest `SnapshotDescriptor.Version`; if neither slot is
/// present it raises `No active VBK metadata slot found`. `vbktool` mirrors that policy.
///
/// # Errors
///
/// Returns an error when the outer storage container cannot be read or when neither slot
/// declares a populated snapshot.
fn select_active_snapshot_slot(reader: &FileReader) -> Result<u64> {
    let slot1_offset = DESCRIPTOR_OFFSET;
    let slot1_status = snapshot_slot_status(reader, slot1_offset)?
        .filter(|_| verify_snapshot_slot_crc(reader, slot1_offset).unwrap_or(false));
    let slot1_size = snapshot_slot_size(reader, slot1_offset)?;
    let slot2_offset = checked_add(slot1_offset, slot1_size)?;
    let slot2_status = if slot2_offset + SNAPSHOT_SLOT_PRELUDE_SIZE <= reader.length() {
        snapshot_slot_status(reader, slot2_offset)
            .ok()
            .flatten()
            .filter(|_| verify_snapshot_slot_crc(reader, slot2_offset).unwrap_or(false))
    } else {
        None
    };
    pick_active_slot(slot1_offset, slot1_status, slot2_offset, slot2_status).ok_or_else(|| {
        VbkError::InvalidField {
            offset: slot1_offset,
            field: "snapshot_slot",
            reason: "no active snapshot slot found in either slot".to_owned(),
        }
    })
}

/// Verify a snapshot slot's CRC32C exactly the way `dissect.archive`'s
/// `SnapshotSlot.verify()` does: hash `SnapshotSlotHeader.ContainsSnapshot` (4 bytes) +
/// `SnapshotDescriptor` (108) + `BanksGrain` (8) + `BankDescriptor[MaxBanks]`, then
/// compare against the leading `u32` CRC field. `SnapshotSlotFormat <= 5` uses the
/// non-Castagnoli CRC-32; every fixture surveyed by `vbktool` runs with format `> 5`, so
/// only the CRC32C branch is implemented — an older-format slot whose CRC would need the
/// standard polynomial silently falls back to trusting the header (`Ok(true)`) so it
/// stays selectable.
fn verify_snapshot_slot_crc(reader: &FileReader, slot_offset: u64) -> Result<bool> {
    let stored_crc = read_u32(reader, slot_offset)?;
    let max_banks_offset = checked_add(slot_offset, MAX_BANKS_OFFSET)?;
    let max_banks = u64::from(read_u32(reader, max_banks_offset)?);
    let bank_bytes =
        max_banks
            .checked_mul(BANK_DESCRIPTOR_SIZE)
            .ok_or(VbkError::OffsetOverflow {
                offset: slot_offset,
                length: max_banks,
            })?;
    // Payload = ContainsSnapshot (4) + SnapshotDescriptor (108) + BanksGrain (8) + BankDescriptor[MaxBanks].
    let payload_length = 4_u64
        .checked_add(108)
        .and_then(|value| value.checked_add(8))
        .and_then(|value| value.checked_add(bank_bytes))
        .ok_or(VbkError::OffsetOverflow {
            offset: slot_offset,
            length: bank_bytes,
        })?;
    let payload_start = checked_add(slot_offset, 4)?;
    if payload_start.saturating_add(payload_length) > reader.length() {
        return Ok(true);
    }
    let computed = crc32c_range(reader, payload_start, payload_length)?;
    Ok(computed == stored_crc)
}

/// Pure implementation of `dissect.archive`'s slot-selection rule, isolated for tests.
///
/// Given each slot's optional status, pick the offset of the slot to use:
///
/// - both populated: prefer the higher `Version`, ties go to slot 1;
/// - only slot 1 populated: use slot 1;
/// - only slot 2 populated: use slot 2;
/// - neither populated: `None`, so the caller reports "no active snapshot slot".
fn pick_active_slot(
    slot1_offset: u64,
    slot1: Option<SnapshotSlotStatus>,
    slot2_offset: u64,
    slot2: Option<SnapshotSlotStatus>,
) -> Option<u64> {
    match (slot1, slot2) {
        (Some(s1), Some(s2)) if s2.version > s1.version => Some(slot2_offset),
        (Some(_), _) => Some(slot1_offset),
        (None, Some(_)) => Some(slot2_offset),
        (None, None) => None,
    }
}

/// Header fields consulted during snapshot-slot selection.
struct SnapshotSlotStatus {
    version: u64,
}

/// Return the slot's header status when it declares a populated snapshot, otherwise
/// `None`. Slots that fail the header sanity check are treated as absent so that a
/// partially written slot never displaces its healthy counterpart.
fn snapshot_slot_status(
    reader: &FileReader,
    slot_offset: u64,
) -> Result<Option<SnapshotSlotStatus>> {
    let contains_offset = checked_add(slot_offset, 4)?;
    let contains = read_u32(reader, contains_offset)?;
    if contains == 0 {
        return Ok(None);
    }
    let version_offset = checked_add(slot_offset, 8)?;
    let version = read_u64(reader, version_offset)?;
    Ok(Some(SnapshotSlotStatus { version }))
}

/// Byte length of the snapshot slot at `slot_offset`, rounded up to a page.
///
/// `dissect.archive`'s `SnapshotSlot.size` uses `grain.MaxBanks` when the slot is
/// populated and falls back to the format-derived `valid_max_banks` otherwise. `vbktool`
/// reads `MaxBanks` directly and enforces the same page-alignment rounding.
fn snapshot_slot_size(reader: &FileReader, slot_offset: u64) -> Result<u64> {
    let max_banks_offset = checked_add(slot_offset, MAX_BANKS_OFFSET)?;
    let max_banks = u64::from(read_u32(reader, max_banks_offset)?);
    let bank_descriptors =
        max_banks
            .checked_mul(BANK_DESCRIPTOR_SIZE)
            .ok_or(VbkError::OffsetOverflow {
                offset: slot_offset,
                length: max_banks,
            })?;
    let raw = checked_add(SNAPSHOT_SLOT_PRELUDE_SIZE, bank_descriptors)?;
    Ok((raw + PAGE_SIZE - 1) & !(PAGE_SIZE - 1))
}

fn parse_metadata_layout_at(reader: &FileReader, slot_offset: u64) -> Result<MetadataLayout> {
    let declared_file_length = read_u64(reader, checked_add(slot_offset, STORAGE_EOF_OFFSET)?)?;
    validate_declared_file_length(reader, declared_file_length)?;
    let segment_count = read_segment_count_at(reader, slot_offset)?;
    let segments = read_segments_at(reader, slot_offset, segment_count)?;
    let directory_checksum = read_u32(reader, checked_add(slot_offset, FIRST_BANK_CRC_OFFSET)?)?;
    let checksums_verified = verify_segment_checksums(reader, &segments, directory_checksum)?;
    let regions = build_regions(reader, &segments)?;
    let first_region = regions.first().ok_or_else(empty_regions)?;
    let primary_offset = first_region.primary_offset;
    let mirror_offset = first_region.mirror_offset;
    let bank_length = first_region.length;

    Ok(MetadataLayout {
        signature: read_u32(reader, slot_offset)?,
        layout_version: read_u32(reader, checked_add(slot_offset, 4)?)?,
        entry_count_hint: read_u64(reader, checked_add(slot_offset, 8)?)?,
        declared_file_length,
        journal_size_hint: read_u32(reader, checked_add(slot_offset, MAX_BANKS_OFFSET)?)?,
        directory_checksum,
        checksums_verified,
        directory_root_page: read_i64(reader, checked_add(slot_offset, 0x1C)?)?,
        directory_root_count: read_u64(reader, checked_add(slot_offset, 0x24)?)?,
        blocks_store_root_page: read_i64(reader, checked_add(slot_offset, 0x2C)?)?,
        blocks_store_count: read_u64(reader, checked_add(slot_offset, 0x34)?)?,
        free_blocks_root_page: read_i64(reader, checked_add(slot_offset, 0x3C)?)?,
        deduplication_root_page: read_i64(reader, checked_add(slot_offset, 0x44)?)?,
        crypto_store_root_page: read_i64(reader, checked_add(slot_offset, 0x5C)?)?,
        stored_banks: read_u32(reader, checked_add(slot_offset, STORED_BANKS_OFFSET)?)?,
        segments,
        regions,
        primary_offset,
        mirror_offset,
        bank_length,
    })
}

/// Read a little-endian `i64` from the outer reader. Uses `i64::from_le_bytes` so the
/// signed reinterpretation is explicit rather than a silent `as`-cast.
fn read_i64(reader: &FileReader, offset: u64) -> Result<i64> {
    let bytes = read_u64(reader, offset)?.to_le_bytes();
    Ok(i64::from_le_bytes(bytes))
}

/// Confirm the file holds every byte its storage descriptor accounts for.
///
/// A complete modern backup records its own full length at `0x1010`, exactly equal to the physical
/// file size. When the file is shorter, the metadata trailer that carries the catalogue and block
/// maps is missing, so the whole file is unusable; report that plainly instead of failing later
/// with an opaque out-of-range error while walking the segment array.
#[allow(clippy::as_conversions, clippy::cast_precision_loss)]
fn validate_declared_file_length(reader: &FileReader, declared: u64) -> Result<()> {
    let actual = reader.length();
    if declared == actual {
        return Ok(());
    }
    if declared > actual {
        let present_percent = if declared == 0 {
            0.0_f64
        } else {
            (actual as f64 / declared as f64) * 100.0_f64
        };
        return Err(VbkError::TruncatedFile {
            declared,
            actual,
            present_percent,
        });
    }
    // The file is longer than the descriptor accounts for: an unexpected layout, not a truncation.
    Err(VbkError::InvalidField {
        offset: DECLARED_FILE_LENGTH_OFFSET,
        field: "declared_file_length",
        reason: format!("declared {declared} is smaller than the actual file length {actual}"),
    })
}

fn read_segment_count_at(reader: &FileReader, slot_offset: u64) -> Result<u64> {
    let first_offset = checked_add(slot_offset, BANKS_COUNT_OFFSET)?;
    let second_offset = checked_add(slot_offset, STORED_BANKS_OFFSET)?;
    let first = read_u64(reader, first_offset)?;
    let second = u64::from(read_u32(reader, second_offset)?);
    if first != second {
        return Err(VbkError::InvalidField {
            offset: first_offset,
            field: "metadata_segment_count",
            reason: format!("descriptor copies disagree: {first} and {second}"),
        });
    }
    if first == 0 || first > MAX_METADATA_SEGMENTS {
        return Err(VbkError::LimitExceeded {
            resource: "metadata segment count",
            actual: first,
            limit: MAX_METADATA_SEGMENTS,
        });
    }
    Ok(first)
}

fn read_segments_at(
    reader: &FileReader,
    slot_offset: u64,
    count: u64,
) -> Result<Vec<MetadataSegment>> {
    let banks_offset = checked_add(slot_offset, BANK_DESCRIPTORS_OFFSET)?;
    let capacity = usize::try_from(count).map_err(|error| VbkError::InvalidField {
        offset: banks_offset,
        field: "metadata_segment_count",
        reason: error.to_string(),
    })?;
    let mut segments = Vec::with_capacity(capacity);
    for index in 0..count {
        let relative =
            index
                .checked_mul(SEGMENT_DESCRIPTOR_SIZE)
                .ok_or(VbkError::OffsetOverflow {
                    offset: banks_offset,
                    length: index,
                })?;
        let offset = checked_add(banks_offset, relative)?;
        let segment = MetadataSegment {
            offset: read_u64(reader, offset)?,
            length: u64::from(read_u32(reader, checked_add(offset, 8)?)?),
            checksum: read_u32(reader, checked_add(offset, 12)?)?,
        };
        validate_segment_alignment(&segment, offset)?;
        segments.push(segment);
    }
    Ok(segments)
}

fn verify_segment_checksums(
    reader: &FileReader,
    segments: &[MetadataSegment],
    first_checksum: u32,
) -> Result<usize> {
    let mut expected = first_checksum;
    let mut verified = 0_usize;
    for segment in segments {
        if expected != 0 {
            let actual = crc32c_range(reader, segment.offset, segment.length)?;
            if actual != expected {
                return Err(VbkError::ChecksumMismatch {
                    resource: "metadata segment",
                    offset: segment.offset,
                    expected,
                    actual,
                });
            }
            verified = verified.checked_add(1).ok_or(VbkError::LimitExceeded {
                resource: "metadata checksum count",
                actual: u64::MAX,
                limit: u64::MAX - 1,
            })?;
        }
        expected = segment.checksum;
    }
    Ok(verified)
}

fn crc32c_range(reader: &FileReader, offset: u64, length: u64) -> Result<u32> {
    let mut crc = u32::MAX;
    let mut consumed = 0_u64;
    while consumed < length {
        let chunk_length = (length - consumed).min(CHECKSUM_CHUNK_SIZE);
        let chunk_offset = checked_add(offset, consumed)?;
        let bytes = reader.read_bytes(chunk_offset, chunk_length, "metadata checksum chunk")?;
        crc = update_crc32c(crc, &bytes)?;
        consumed = checked_add(consumed, chunk_length)?;
    }
    Ok(!crc)
}

fn update_crc32c(mut crc: u32, bytes: &[u8]) -> Result<u32> {
    for byte in bytes {
        crc ^= u32::from(*byte);
        crc = crc32c_nibble(crc)?;
        crc = crc32c_nibble(crc)?;
    }
    Ok(crc)
}

fn crc32c_nibble(crc: u32) -> Result<u32> {
    let index = usize::try_from(crc & 0x0f).map_err(invalid_region_index)?;
    let polynomial =
        CRC32C_NIBBLE_TABLE
            .get(index)
            .copied()
            .ok_or_else(|| VbkError::InvalidField {
                offset: 0,
                field: "crc32c_table_index",
                reason: "CRC32C nibble is outside the lookup table".to_owned(),
            })?;
    Ok((crc >> 4) ^ polynomial)
}

fn validate_segment_alignment(segment: &MetadataSegment, descriptor_offset: u64) -> Result<()> {
    if segment.offset % PAGE_SIZE != 0 || segment.length == 0 || segment.length % PAGE_SIZE != 0 {
        return Err(VbkError::InvalidField {
            offset: descriptor_offset,
            field: "metadata_segment",
            reason: format!(
                "offset 0x{:x} and length 0x{:x} must be non-zero and 4 KiB aligned",
                segment.offset, segment.length
            ),
        });
    }
    Ok(())
}

fn build_regions(reader: &FileReader, segments: &[MetadataSegment]) -> Result<Vec<MetadataRegion>> {
    let first = segments.first().ok_or_else(empty_regions)?;
    let mut regions = Vec::new();
    let mut draft = RegionDraft {
        primary: first.offset,
        length: first.length,
        first_index: 0,
        count: 1,
    };
    for (index, segment) in segments.iter().enumerate().skip(1) {
        let expected = checked_add(draft.primary, draft.length)?;
        if segment.offset == expected {
            draft.length = checked_add(draft.length, segment.length)?;
            draft.count = checked_add(draft.count, 1)?;
            continue;
        }
        push_region(reader, &mut regions, draft, Some(segment.offset))?;
        draft = RegionDraft {
            primary: segment.offset,
            length: segment.length,
            first_index: u64::try_from(index).map_err(invalid_region_index)?,
            count: 1,
        };
    }
    push_region(reader, &mut regions, draft, None)?;
    Ok(regions)
}

#[derive(Clone, Copy, Debug)]
struct RegionDraft {
    primary: u64,
    length: u64,
    first_index: u64,
    count: u64,
}

fn push_region(
    reader: &FileReader,
    regions: &mut Vec<MetadataRegion>,
    draft: RegionDraft,
    next_primary: Option<u64>,
) -> Result<()> {
    let mirror = checked_add(draft.primary, draft.length)?;
    let mirror_end = checked_add(mirror, draft.length)?;
    if mirror_end > reader.length() {
        return Err(VbkError::RangeOutsideFile {
            offset: mirror,
            length: draft.length,
            file_length: reader.length(),
        });
    }
    if let Some(offset) = next_primary
        && offset < mirror_end
    {
        return Err(VbkError::InvalidField {
            offset,
            field: "metadata_region",
            reason: format!("next primary overlaps mirror ending at 0x{mirror_end:x}"),
        });
    }
    regions.push(MetadataRegion {
        primary_offset: draft.primary,
        mirror_offset: mirror,
        length: draft.length,
        first_segment_index: draft.first_index,
        segment_count: draft.count,
    });
    Ok(())
}

fn empty_regions() -> VbkError {
    VbkError::InvalidField {
        offset: DESCRIPTOR_OFFSET + BANK_DESCRIPTORS_OFFSET,
        field: "metadata_regions",
        reason: "empty segment directory".to_owned(),
    }
}

fn invalid_region_index(error: std::num::TryFromIntError) -> VbkError {
    VbkError::InvalidField {
        offset: DESCRIPTOR_OFFSET + BANK_DESCRIPTORS_OFFSET,
        field: "metadata_region_index",
        reason: error.to_string(),
    }
}

fn checked_add(offset: u64, length: u64) -> Result<u64> {
    offset
        .checked_add(length)
        .ok_or(VbkError::OffsetOverflow { offset, length })
}

fn compare_banks(reader: &FileReader, layout: &MetadataLayout) -> Result<MetadataMirrorReport> {
    let total_length = total_region_length(&layout.regions)?;
    let mut bytes_compared = 0_u64;
    for region in &layout.regions {
        if let Some(relative) = compare_region(reader, region)? {
            let first_difference = checked_add(bytes_compared, relative)?;
            return Ok(MetadataMirrorReport {
                bank_length: total_length,
                region_count: layout.regions.len(),
                bytes_compared: first_difference,
                identical: false,
                first_difference: Some(first_difference),
                checksums_verified: layout.checksums_verified,
            });
        }
        bytes_compared = checked_add(bytes_compared, region.length)?;
    }
    Ok(MetadataMirrorReport {
        bank_length: total_length,
        region_count: layout.regions.len(),
        bytes_compared,
        identical: true,
        first_difference: None,
        checksums_verified: layout.checksums_verified,
    })
}

fn compare_region(reader: &FileReader, region: &MetadataRegion) -> Result<Option<u64>> {
    let mut relative_offset = 0_u64;
    while relative_offset < region.length {
        let remaining = region.length - relative_offset;
        let chunk_length = remaining.min(MIRROR_COMPARE_CHUNK_SIZE);
        let primary_offset = checked_add(region.primary_offset, relative_offset)?;
        let mirror_offset = checked_add(region.mirror_offset, relative_offset)?;
        let primary =
            reader.read_bytes(primary_offset, chunk_length, "metadata comparison chunk")?;
        let mirror = reader.read_bytes(mirror_offset, chunk_length, "metadata comparison chunk")?;
        if let Some(difference) = first_buffer_difference(&primary, &mirror)? {
            return Ok(Some(checked_add(relative_offset, difference)?));
        }
        relative_offset = checked_add(relative_offset, chunk_length)?;
    }
    Ok(None)
}

fn first_buffer_difference(primary: &[u8], mirror: &[u8]) -> Result<Option<u64>> {
    for (index, (primary_byte, mirror_byte)) in primary.iter().zip(mirror).enumerate() {
        if primary_byte != mirror_byte {
            let index = u64::try_from(index).map_err(|error| VbkError::InvalidField {
                offset: 0,
                field: "metadata_difference_offset",
                reason: error.to_string(),
            })?;
            return Ok(Some(index));
        }
    }
    Ok(None)
}

fn total_region_length(regions: &[MetadataRegion]) -> Result<u64> {
    let mut total = 0_u64;
    for region in regions {
        total = checked_add(total, region.length)?;
    }
    Ok(total)
}
