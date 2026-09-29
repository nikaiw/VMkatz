//! Physical block records and logical per-file block maps.

use std::{collections::BTreeSet, path::Path};

use serde::Serialize;

mod types;

pub use types::{BlockFlags, BlockReference, Compression, Digest};

use crate::veeam::{
    Result, StoredItem, StoredItemKind, VbkError, format::parse_header, metadata::MetadataBank,
    reader::FileReader,
};

const PHYSICAL_RECORD_SIZE: usize = 60;
const PLAINTEXT_LOGICAL_RECORD_SIZE: usize = 46;
const ENCRYPTED_LOGICAL_RECORD_SIZE: usize = 46;
/// Byte-0 tag identifying a physical block record. Byte-1 carries flag bits observed to
/// range over at least `0x01`, `0x02`, and `0x3F`; bytes 2-3 are always zero.
///
/// The mask zeroes byte 1 (`0xFF00`) so any `flags` value passes, while requiring bytes 2 and 3
/// to be zero and byte 0 to be `0x04`.
const PHYSICAL_RECORD_TAG_MASK: u32 = 0xFFFF_00FF;
const PHYSICAL_RECORD_TAG_VALUE: u32 = 0x0000_0004;
const MAX_LOGICAL_RECORDS_PER_PAGE: u64 = 89;
const SPARSE_TABLE_RECORDS: u64 = 1_088;
const SPARSE_TABLE_DESCRIPTOR_SIZE: usize = 24;
const MAX_SPARSE_TABLES_PER_DIRECTORY: u64 = 170;
const PAGE_STACK_FIRST_DATA_LOCATION: usize = 16;
const PAGE_LOCATION_SIZE: usize = 8;
const INVALID_PAGE_LOCATION: u64 = u64::MAX;
const LOGICAL_BLOCK_UNIT_SIZE: u64 = 1024 * 1024;
const SECTOR_SIZE: u64 = 256;

/// One physically stored and possibly compressed content block.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct PhysicalBlock {
    /// Whether this table slot contains active stored data rather than a discarded placeholder.
    pub active: bool,
    /// Absolute offset of the stored bytes.
    pub offset: u64,
    /// Allocated sector count after masking format flags.
    pub allocated_sectors: u32,
    /// Stored byte count, including a compression header when present.
    pub stored_size: u32,
    /// Expected decompressed byte count.
    pub raw_size: u64,
    /// Keyset identifier for encrypted content, or `None` for plaintext blocks.
    pub keyset_id: Option<[u8; 16]>,
    /// Compression applied to the stored bytes.
    pub compression: Compression,
    /// Digest of reconstructed bytes.
    pub digest: Digest,
}

/// One logical file range, either sparse or backed by a physical record.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct LogicalBlock {
    /// Reconstructed length.
    pub raw_size: u32,
    /// Digest recorded for the logical content.
    pub digest: Digest,
    /// Source of this logical range.
    pub reference: BlockReference,
}

/// A catalogue file associated with its validated logical block map.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FileBlockMap {
    /// Catalogue record.
    pub item: StoredItem,
    /// Absolute offset of the logical map page.
    pub map_offset: u64,
    /// Physical metadata pages consumed by this map, including page-stack roots and data pages.
    pub metadata_pages: Vec<u64>,
    /// Logical ranges in file order.
    pub blocks: Vec<LogicalBlock>,
}

/// Discover physical records and associate every modern catalogue file with a logical map.
///
/// # Errors
///
/// Returns an error when metadata is ambiguous, a logical map is malformed, references an invalid
/// physical block, or fails structural validation.
pub fn build_file_maps(
    path: &Path,
    items: &[StoredItem],
) -> Result<(Vec<PhysicalBlock>, Vec<FileBlockMap>)> {
    build_file_maps_with_password(path, items, None)
}

/// Discover physical records and logical file maps, decrypting metadata when required.
///
/// # Errors
///
/// Returns an error for invalid metadata, absent or incorrect passwords, ambiguous maps, invalid
/// physical references, or unsupported layouts.
pub fn build_file_maps_with_password(
    path: &Path,
    items: &[StoredItem],
    password: Option<&str>,
) -> Result<(Vec<PhysicalBlock>, Vec<FileBlockMap>)> {
    let header = parse_header(path)?;
    validate_descriptor_profile(&header)?;
    if header.external_storage_id.is_some() {
        return Err(VbkError::UnsupportedBlockReference {
            kind: "external storage",
            offset: 0x130,
        });
    }
    let layout = header.metadata.ok_or(VbkError::FeatureUnavailable {
        feature: "modern block maps",
        version: header.version,
    })?;
    let reader = FileReader::open(path)?;
    let bank = MetadataBank::open_all_primary(&reader, &layout, &header.encryption, password)?;
    let logical_record_size = if header.encryption.encrypted {
        ENCRYPTED_LOGICAL_RECORD_SIZE
    } else {
        PLAINTEXT_LOGICAL_RECORD_SIZE
    };
    let physical = scan_physical_blocks(&bank, reader.length())?;
    let mut used_pages = BTreeSet::new();
    let mut files = Vec::new();
    for item in items {
        if item.kind == StoredItemKind::File {
            // Incremental (DirItemType 4 Patch / 5 Increment) records use a position-keyed block
            // vector (see build_increment_recovery_with_password), and their unchanged regions live
            // in the parent chain, not in this file. This whole-file map builder cannot represent
            // that, so it refuses them; callers wanting the changed blocks use the partial path.
            if item.is_patch {
                return Err(VbkError::IncrementalRecordUnsupported {
                    record_offset: item.record_offset,
                });
            }
            let file_map = find_file_map(
                &bank,
                item,
                &physical,
                &used_pages,
                LogicalMapProfile {
                    record_size: logical_record_size,
                    version: header.version,
                },
            )?;
            for page in &file_map.metadata_pages {
                let inserted = used_pages.insert(*page);
                if !inserted {
                    return Err(invalid_map(*page, "logical map metadata page was reused"));
                }
            }
            files.push(file_map);
        }
    }
    Ok((physical, files))
}

const INCREMENT_RECORD_SIZE: usize = 53;
const INCREMENT_RECORDS_PER_PAGE: usize = 77; // 4096 / 53
const INCREMENT_TABLE_HEADER_SLOTS: usize = 2; // next-page + self-root i64 slots
const MAX_INCREMENT_BLOCKS: u64 = 64 * 1024 * 1024; // bound the dense map (64 Ti at 1 MiB blocks)
const INCREMENT_ROOT_PAGE_OFFSET: usize = 0x98;
const INCREMENT_COUNT_OFFSET: usize = 0xa0;
const INCREMENT_FIB_SIZE_OFFSET: usize = 0xa8;

/// Reconstruction plan and recovery statistics for one incremental (`Patch`/`Increment`) record.
///
/// The dense `map` spans the whole file: positions the increment stores appear as local or
/// zero blocks, while positions it does not store are filled with zero blocks — those are the
/// unchanged regions that belong to the parent chain and cannot be recovered from this file.
#[derive(Clone, Debug)]
pub struct IncrementRecovery {
    /// Physical block table of this file.
    pub physical: Vec<PhysicalBlock>,
    /// Dense block map covering the full file size.
    pub map: FileBlockMap,
    /// Total 1 MiB positions in the reconstructed file.
    pub total_blocks: u64,
    /// Positions recovered from this file's own data (`Normal` records).
    pub local_blocks: u64,
    /// Positions this backup point stored as explicit zeros (`Sparse` records).
    pub sparse_blocks: u64,
    /// Positions with no record: unchanged, deferred to the (absent) parent chain.
    pub parent_blocks: u64,
}

/// Decode the position-keyed block vector of an incremental record (see the format spec §13.1)
/// into a dense, whole-file reconstruction plan.
///
/// # Errors
///
/// Returns an error if the record is not incremental, the vector is malformed or chains beyond one
/// table page, a record references a missing physical block, or the file is implausibly large.
pub fn build_increment_recovery_with_password(
    path: &Path,
    item: &StoredItem,
    password: Option<&str>,
) -> Result<IncrementRecovery> {
    if !item.is_patch {
        return Err(invalid_map(
            item.record_offset,
            "record is not an incremental Patch/Increment",
        ));
    }
    let header = parse_header(path)?;
    validate_descriptor_profile(&header)?;
    let layout = header.metadata.ok_or(VbkError::FeatureUnavailable {
        feature: "incremental block maps",
        version: header.version,
    })?;
    let reader = FileReader::open(path)?;
    let bank = MetadataBank::open_all_primary(&reader, &layout, &header.encryption, password)?;
    let physical = scan_physical_blocks(&bank, reader.length())?;

    let (root, count, file_size) = read_increment_header(&bank, item.record_offset)?;
    let total_blocks = increment_total_blocks(file_size)?;
    // The stored-block count can never exceed the number of positions the file holds. Reject a
    // larger value before it drives an eager `Vec::with_capacity`, bounding memory on hostile input.
    if count > total_blocks {
        return Err(invalid_map(
            item.record_offset,
            "incremental record stores more blocks than the file has positions",
        ));
    }
    let present = read_increment_vector(&bank, root, count, &physical)?;
    let (blocks, local_blocks, sparse_blocks) =
        assemble_increment_map(&present, total_blocks, file_size)?;
    let parent_blocks = total_blocks
        .checked_sub(local_blocks)
        .and_then(|value| value.checked_sub(sparse_blocks))
        .ok_or_else(|| {
            invalid_map(
                item.record_offset,
                "increment stores more blocks than the file holds",
            )
        })?;

    let map = FileBlockMap {
        item: item.clone(),
        map_offset: root,
        metadata_pages: Vec::new(),
        blocks,
    };
    Ok(IncrementRecovery {
        physical,
        map,
        total_blocks,
        local_blocks,
        sparse_blocks,
        parent_blocks,
    })
}

/// Read `RootPage`, `Count`, and `FibSize` from an incremental record's union payload.
fn read_increment_header(bank: &MetadataBank, record_offset: u64) -> Result<(u64, u64, u64)> {
    let page_offset = record_offset & !0xFFF;
    let relative = usize::try_from(record_offset - page_offset)
        .map_err(|error| invalid_map(record_offset, &error.to_string()))?;
    let page = bank.page_at_offset(page_offset).ok_or_else(|| {
        invalid_map(
            record_offset,
            "incremental record page is not in the metadata bank",
        )
    })?;
    let root = read_u64(
        &page.bytes,
        checked_usize_add(relative, INCREMENT_ROOT_PAGE_OFFSET)?,
    )?;
    let count = read_u64(
        &page.bytes,
        checked_usize_add(relative, INCREMENT_COUNT_OFFSET)?,
    )?;
    let file_size = read_u64(
        &page.bytes,
        checked_usize_add(relative, INCREMENT_FIB_SIZE_OFFSET)?,
    )?;
    Ok((root, count, file_size))
}

fn increment_total_blocks(file_size: u64) -> Result<u64> {
    let total = file_size.div_ceil(LOGICAL_BLOCK_UNIT_SIZE);
    if total == 0 {
        return Err(invalid_map(0, "incremental file size is zero"));
    }
    if total > MAX_INCREMENT_BLOCKS {
        return Err(VbkError::LimitExceeded {
            resource: "incremental block count",
            actual: total,
            limit: MAX_INCREMENT_BLOCKS,
        });
    }
    Ok(total)
}

/// Walk the `MetaVector2` table (single page) and parse each 53-byte record into a
/// `(file_block_index, LogicalBlock)` pair, validated to be strictly ascending by index.
fn read_increment_vector(
    bank: &MetadataBank,
    root: u64,
    count: u64,
    physical: &[PhysicalBlock],
) -> Result<Vec<(u64, LogicalBlock)>> {
    let table = bank
        .page_at(root)
        .ok_or_else(|| invalid_map(root, "incremental vector root page missing"))?;
    if read_u64(&table.bytes, 0)? != INVALID_PAGE_LOCATION {
        return Err(invalid_map(
            root,
            "chained incremental vector tables are not supported",
        ));
    }
    let count = usize::try_from(count).map_err(|error| invalid_map(root, &error.to_string()))?;
    let leaf_pages = count.div_ceil(INCREMENT_RECORDS_PER_PAGE);
    let mut present = Vec::with_capacity(count);
    let mut previous: Option<u64> = None;
    for leaf_index in 0..leaf_pages {
        let slot = checked_usize_add(INCREMENT_TABLE_HEADER_SLOTS, leaf_index)?;
        let slot_offset = slot
            .checked_mul(8)
            .ok_or_else(|| invalid_map(root, "table slot overflow"))?;
        let location = read_u64(&table.bytes, slot_offset)?;
        let leaf = bank
            .page_at(location)
            .ok_or_else(|| invalid_map(location, "incremental vector leaf page missing"))?;
        let records_here =
            (count - leaf_index * INCREMENT_RECORDS_PER_PAGE).min(INCREMENT_RECORDS_PER_PAGE);
        for record in 0..records_here {
            let base = record
                .checked_mul(INCREMENT_RECORD_SIZE)
                .ok_or_else(|| invalid_map(location, "record offset overflow"))?;
            let (index, logical) = parse_increment_record(&leaf.bytes, base, physical)?;
            if previous.is_some_and(|prev| index <= prev) {
                return Err(invalid_map(
                    location,
                    "incremental records are not strictly ascending by position",
                ));
            }
            previous = Some(index);
            present.push((index, logical));
        }
    }
    Ok(present)
}

/// Parse one 53-byte incremental block descriptor.
fn parse_increment_record(
    bytes: &[u8],
    base: usize,
    physical: &[PhysicalBlock],
) -> Result<(u64, LogicalBlock)> {
    let raw_size = read_optional_u32(bytes, base)
        .ok_or_else(|| invalid_map(0, "truncated incremental record"))?;
    let kind = read_u8(bytes, checked_usize_add(base, 4)?)?;
    let block_id = read_u64(bytes, checked_usize_add(base, 0x15)?)?;
    let block_index = read_u64(bytes, checked_usize_add(base, 0x1d)?)?;
    match kind {
        0 => Ok((
            block_index,
            increment_local_block(bytes, base, raw_size, block_id, physical)?,
        )),
        1 => Ok((
            block_index,
            LogicalBlock {
                raw_size,
                digest: Digest::None,
                reference: BlockReference::Zero,
            },
        )),
        other => Err(VbkError::UnsupportedBlockReference {
            kind: increment_kind_name(other),
            offset: block_index,
        }),
    }
}

/// Build a local (`Normal`) logical block from an incremental record, validating it against the
/// referenced physical block's size and digest so a tampered or mis-sized record is rejected.
fn increment_local_block(
    bytes: &[u8],
    base: usize,
    raw_size: u32,
    block_id: u64,
    physical: &[PhysicalBlock],
) -> Result<LogicalBlock> {
    let index = usize::try_from(block_id).map_err(|error| invalid_map(0, &error.to_string()))?;
    let stored = physical.get(index).ok_or_else(|| {
        invalid_map(
            block_id,
            "incremental record references a missing physical block",
        )
    })?;
    if !stored.active {
        return Err(invalid_map(
            block_id,
            "incremental record references an inactive physical block",
        ));
    }
    // The physical block's decoded length must match the record's declared block size, or the
    // reconstructed geometry would silently shift when a wrongly-sized block is written.
    if stored.raw_size != u64::from(raw_size) {
        return Err(invalid_map(
            block_id,
            "incremental record block size differs from the referenced physical block",
        ));
    }
    // Cross-check the record's own digest against the referenced physical block's digest, so a
    // tampered record pointing at a different block cannot pass verification (the core logical map
    // enforces the same record→physical digest equality).
    let record_digest = read_array::<16>(bytes, checked_usize_add(base, 5)?)?;
    if let Some(stored_digest) = stored.digest.short_bytes()
        && record_digest != stored_digest
    {
        return Err(invalid_map(
            block_id,
            "incremental record digest differs from the referenced physical block",
        ));
    }
    Ok(LogicalBlock {
        raw_size,
        digest: stored.digest,
        reference: BlockReference::Local(block_id),
    })
}

const fn increment_kind_name(kind: u8) -> &'static str {
    match kind {
        2 => "increment reserved",
        3 => "increment archived",
        4 => "increment block-in-blob",
        5 => "increment block-in-blob reserved",
        _ => "increment unknown",
    }
}

/// Build the dense whole-file block list, filling unstored positions with zero blocks.
fn assemble_increment_map(
    present: &[(u64, LogicalBlock)],
    total_blocks: u64,
    file_size: u64,
) -> Result<(Vec<LogicalBlock>, u64, u64)> {
    let total =
        usize::try_from(total_blocks).map_err(|error| invalid_map(0, &error.to_string()))?;
    let block_size = u32::try_from(LOGICAL_BLOCK_UNIT_SIZE)
        .map_err(|error| invalid_map(0, &error.to_string()))?;
    let last_bytes = file_size - (total_blocks - 1) * LOGICAL_BLOCK_UNIT_SIZE;
    let last_size =
        u32::try_from(last_bytes).map_err(|error| invalid_map(0, &error.to_string()))?;
    let mut blocks = Vec::with_capacity(total);
    for index in 0..total {
        let raw_size = if index + 1 == total {
            last_size
        } else {
            block_size
        };
        blocks.push(LogicalBlock {
            raw_size,
            digest: Digest::None,
            reference: BlockReference::Zero,
        });
    }
    let mut local_blocks = 0_u64;
    let mut sparse_blocks = 0_u64;
    for (index, logical) in present {
        let slot_index =
            usize::try_from(*index).map_err(|error| invalid_map(*index, &error.to_string()))?;
        let slot = blocks.get_mut(slot_index).ok_or_else(|| {
            invalid_map(*index, "incremental block position is beyond the file size")
        })?;
        // The record's block size must match the file geometry at this position, so a full-size
        // block placed on a short final position (or vice versa) is rejected rather than silently
        // shifting the output.
        if logical.raw_size != slot.raw_size {
            return Err(invalid_map(
                *index,
                "incremental record block size does not match the file position it maps to",
            ));
        }
        match logical.reference {
            BlockReference::Local(_) => local_blocks += 1,
            BlockReference::Zero => sparse_blocks += 1,
            BlockReference::Parent(_)
            | BlockReference::Deduplicated(_)
            | BlockReference::External(_) => {}
        }
        *slot = LogicalBlock {
            raw_size: slot.raw_size,
            digest: logical.digest,
            reference: logical.reference,
        };
    }
    Ok((blocks, local_blocks, sparse_blocks))
}

fn validate_descriptor_profile(header: &crate::veeam::BackupHeader) -> Result<()> {
    match header.version {
        7 => {
            return Err(VbkError::FeatureUnavailable {
                feature: "V7 block descriptors",
                version: header.version,
            });
        }
        0x10008 => {
            return Err(VbkError::FeatureUnavailable {
                feature: "0x10008 block descriptors",
                version: header.version,
            });
        }
        9..=14 => {}
        0 | 1 => {
            return Err(VbkError::FeatureUnavailable {
                feature: "legacy block maps",
                version: header.version,
            });
        }
        unsupported => {
            return Err(VbkError::UnsupportedVersion {
                version: unsupported,
            });
        }
    }
    if header.format_flag != Some(9) {
        let actual = header
            .format_flag
            .map_or_else(|| "missing".to_owned(), |value| value.to_string());
        return Err(VbkError::InvalidField {
            offset: 0x107,
            field: "format_flag",
            reason: format!("modern block descriptors require flag 9, found {actual}"),
        });
    }
    // The header `DigestType` names the storage's nominal digest engine, but per-block
    // digests choose their engine independently and flag it in-band (compression high byte
    // for physical records, state high nibble for logical records): `0` = MD5,
    // `1` = BLAKE3-128. Every server-managed Windows Agent full observed keeps this string
    // at `md5` while its blocks are BLAKE3-128, so the string is not the dispatch signal.
    // Accept both engines the block layer can actually verify; reject only SHA-256 (a
    // 32-byte digest that does not fit the 16-byte in-band scheme) and unrecognised names.
    match header.digest_engine.as_deref() {
        Some("md5" | "MD5" | "blake3_128" | "BLAKE3-128") => Ok(()),
        Some("sha256" | "SHA256") => Err(VbkError::UnsupportedDigest {
            algorithm: "sha256 descriptor",
            offset: 4,
        }),
        Some(..) | None => Err(VbkError::UnsupportedDigest {
            algorithm: "unknown descriptor",
            offset: 4,
        }),
    }
}

/// The effective per-block digest engine a backup's physical block records actually use.
///
/// The header's `DigestType` string is not a reliable indicator: server-managed Windows
/// Agent fulls keep it at `md5` while every block carries a BLAKE3-128 digest, dispatched
/// through the in-band engine hint (see [`Digest::from_engine`]). This summary is derived
/// from the block records themselves, so it reflects reality rather than the header.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockDigestEngine {
    /// No physical block carries a digest (every digest field is all-zero).
    None,
    /// Every digest-bearing block uses MD5.
    Md5,
    /// Every digest-bearing block uses BLAKE3-128.
    Blake3_128,
    /// Every digest-bearing block uses SHA-256.
    Sha256,
    /// More than one engine appears across the physical block records.
    Mixed,
}

/// Detect the effective per-block digest engine ([`BlockDigestEngine`]) of a modern backup.
///
/// Opens the metadata bank (decrypting with `password` when the backup is encrypted),
/// scans the physical block records, and folds their digest tags into a single verdict.
/// This is what `info` reports instead of the header's nominal `DigestType` string.
///
/// # Errors
///
/// Returns an error for legacy/transitional/marker layouts, external-storage backups, a
/// missing or incorrect password, or IO failures — the same gating that block extraction
/// applies, because the summary is meaningless when the descriptors cannot be decoded.
pub fn inspect_block_digest_engine(
    path: &Path,
    password: Option<&str>,
) -> Result<BlockDigestEngine> {
    let header = parse_header(path)?;
    validate_descriptor_profile(&header)?;
    if header.external_storage_id.is_some() {
        return Err(VbkError::UnsupportedBlockReference {
            kind: "external storage",
            offset: 0x130,
        });
    }
    let layout = header.metadata.ok_or(VbkError::FeatureUnavailable {
        feature: "modern block maps",
        version: header.version,
    })?;
    let reader = FileReader::open(path)?;
    let bank = MetadataBank::open_all_primary(&reader, &layout, &header.encryption, password)?;
    let physical = scan_physical_blocks(&bank, reader.length())?;
    Ok(summarize_block_digest_engine(&physical))
}

fn summarize_block_digest_engine(physical: &[PhysicalBlock]) -> BlockDigestEngine {
    let mut seen: Option<BlockDigestEngine> = None;
    for block in physical {
        let engine = match block.digest {
            Digest::None => continue,
            Digest::Md5(_) => BlockDigestEngine::Md5,
            Digest::Sha256(_) => BlockDigestEngine::Sha256,
            Digest::Blake3_128(_) => BlockDigestEngine::Blake3_128,
        };
        match seen {
            None => seen = Some(engine),
            Some(existing) if existing == engine => {}
            Some(_) => return BlockDigestEngine::Mixed,
        }
    }
    seen.unwrap_or(BlockDigestEngine::None)
}

fn scan_physical_blocks(bank: &MetadataBank, file_length: u64) -> Result<Vec<PhysicalBlock>> {
    let mut blocks = Vec::new();
    for page in bank.pages() {
        if page.location.is_none() {
            continue;
        }
        // Both base = 0 and base = 8 are needed: modern format-flag-9 pages start
        // records at offset 0, but the v9 fixture stashes them at offset 8 behind an
        // 8-byte header word that our tag scan otherwise skips over.
        for base in [0_usize, 8_usize] {
            scan_physical_page(&page.bytes, base, file_length, &mut blocks)?;
        }
    }
    Ok(blocks)
}

fn scan_physical_page(
    page: &[u8],
    base: usize,
    file_length: u64,
    blocks: &mut Vec<PhysicalBlock>,
) -> Result<()> {
    let mut relative = base;
    while has_physical_record_tag(page, relative) {
        let Some(record) = parse_physical_record(page, relative, file_length)? else {
            break;
        };
        blocks.push(record);
        let Some(next) = relative.checked_add(PHYSICAL_RECORD_SIZE) else {
            break;
        };
        relative = next;
    }
    Ok(())
}

/// Detect a physical-block record header at `relative`.
///
/// The header is a 32-bit little-endian tag whose byte layout is `[0x04, flags, 0x00, 0x00]`.
/// `flags` varies across writers (`0x01`, `0x02`, `0x3F`, and other values have been observed
/// in Windows Agent server-managed fulls). The scan accepts any `flags` byte because the
/// downstream record fields provide sufficient validation on their own.
fn has_physical_record_tag(page: &[u8], relative: usize) -> bool {
    let Some(value) = read_optional_u32(page, relative) else {
        return false;
    };
    value & PHYSICAL_RECORD_TAG_MASK == PHYSICAL_RECORD_TAG_VALUE
}

fn parse_physical_record(
    page: &[u8],
    relative: usize,
    file_length: u64,
) -> Result<Option<PhysicalBlock>> {
    let Some(fields) = read_physical_fields(page, relative)? else {
        return Ok(None);
    };
    let compression = Compression::from_modern(fields.compression);
    let allocated_sectors = fields.allocation_raw & 0x00FF_FFFF;
    if !physical_range_is_valid(
        fields.offset,
        fields.stored_size,
        allocated_sectors,
        file_length,
    ) {
        return Ok(None);
    }
    let digest_type = physical_digest_type(fields.compression);
    Ok(Some(PhysicalBlock {
        active: true,
        offset: fields.offset,
        allocated_sectors,
        stored_size: fields.stored_size,
        raw_size: fields.raw_size,
        keyset_id: optional_identifier(fields.keyset_id),
        compression,
        digest: Digest::from_engine(fields.digest, digest_type),
    }))
}

/// Extract the digest-engine hint from a physical record's compression identifier.
///
/// Server-managed writers place the engine ID in the high byte of the `u16` alongside the
/// algorithm selector in the low byte. Plain-modern writers leave the high byte at zero,
/// which resolves to MD5.
const fn physical_digest_type(compression: u16) -> u8 {
    compression.to_le_bytes()[1]
}

/// The physical record's `allocation` field carries a sector count in its low 24 bits and
/// a flag byte in the top 8.
///
/// The Windows Agent "SERVER MANAGED" writer stores `0x01` when a codec is engaged and
/// `0x00` when the payload is uncompressed, but the older test13/test9 fixtures always
/// leave the byte at zero regardless of the codec. Because the semantics differ across
/// writers, `vbktool` masks the top byte off during parsing and does not treat any value
/// as diagnostic; the record's own `compression` `u16` and stored/raw sizes are the
/// authoritative signal.
struct PhysicalRecordFields {
    offset: u64,
    allocation_raw: u32,
    stored_size: u32,
    raw_size: u64,
    compression: u16,
    digest: [u8; 16],
    keyset_id: [u8; 16],
}

fn read_physical_fields(page: &[u8], relative: usize) -> Result<Option<PhysicalRecordFields>> {
    let Some(offset) = physical_record_offset(page, relative)? else {
        return Ok(None);
    };
    let allocation_raw = read_u32(page, checked_usize_add(relative, 14)?)?;
    Ok(Some(PhysicalRecordFields {
        offset,
        allocation_raw,
        stored_size: read_u32(page, checked_usize_add(relative, 36)?)?,
        raw_size: u64::from(read_u32(page, checked_usize_add(relative, 40)?)?),
        compression: read_u16(page, checked_usize_add(relative, 34)?)?,
        digest: read_array::<16>(page, checked_usize_add(relative, 18)?)?,
        keyset_id: read_array::<16>(page, checked_usize_add(relative, 44)?)?,
    }))
}

fn physical_record_offset(page: &[u8], relative: usize) -> Result<Option<u64>> {
    let Some(end) = relative.checked_add(PHYSICAL_RECORD_SIZE) else {
        return Ok(None);
    };
    if end > page.len() {
        return Ok(None);
    }
    let sector = read_u64(page, checked_usize_add(relative, 6)?)?;
    Ok(sector.checked_mul(SECTOR_SIZE))
}

fn physical_range_is_valid(offset: u64, stored_size: u32, sectors: u32, file_length: u64) -> bool {
    let stored = u64::from(stored_size);
    let Some(allocated) = u64::from(sectors).checked_mul(SECTOR_SIZE) else {
        return false;
    };
    let Some(end) = offset.checked_add(stored) else {
        return false;
    };
    stored != 0 && stored <= allocated && end <= file_length
}

fn optional_identifier(identifier: [u8; 16]) -> Option<[u8; 16]> {
    identifier
        .iter()
        .any(|byte| *byte != 0)
        .then_some(identifier)
}

fn find_file_map(
    bank: &MetadataBank,
    item: &StoredItem,
    physical: &[PhysicalBlock],
    used_pages: &BTreeSet<u64>,
    profile: LogicalMapProfile,
) -> Result<FileBlockMap> {
    let block_count = required_file_field(item.block_count, item.record_offset, "block_count")?;
    let file_size = required_file_field(item.size, item.record_offset, "file_size")?;
    let expected = LogicalMapExpectation {
        block_count,
        file_size,
        record_size: profile.record_size,
        version: profile.version,
    };
    if block_count == 0 {
        return Err(VbkError::LimitExceeded {
            resource: "logical block count",
            actual: block_count,
            limit: u64::MAX,
        });
    }
    if expected.version == 9
        && let Some(map) = find_v9_inline_file_map(bank, item, physical, used_pages, expected)?
    {
        return Ok(map);
    }
    let mut candidate = None;
    let (table_pages, _page_stack_referenced) = bank.table_pages()?;
    for page in table_pages {
        if used_pages.contains(&page.offset) {
            continue;
        }
        for base in [0_usize, 8_usize] {
            if let Some(blocks) = parse_logical_candidate(&page.bytes, base, expected, physical)? {
                if candidate.is_some() {
                    return Err(invalid_map(
                        page.offset,
                        "multiple logical maps match one file",
                    ));
                }
                candidate = Some(FileBlockMap {
                    item: item.clone(),
                    map_offset: checked_add_usize(page.offset, base)?,
                    metadata_pages: vec![page.offset],
                    blocks,
                });
            }
        }
    }
    match candidate {
        Some(map) => Ok(map),
        None if block_count > MAX_LOGICAL_RECORDS_PER_PAGE => {
            find_sparse_file_map(bank, item, physical, used_pages, expected)
        }
        None => Err(invalid_map(
            item.record_offset,
            "no logical map matches file record",
        )),
    }
}

fn find_v9_inline_file_map(
    bank: &MetadataBank,
    item: &StoredItem,
    physical: &[PhysicalBlock],
    used_pages: &BTreeSet<u64>,
    expected: LogicalMapExpectation,
) -> Result<Option<FileBlockMap>> {
    let mut candidate = None;
    let (pages, _page_stack_referenced) = bank.table_pages()?;
    for root in pages {
        if used_pages.contains(&root.offset) || !v9_inline_descriptor_matches(&root.bytes, expected)
        {
            continue;
        }
        let data_offset = root
            .offset
            .checked_add(4_096)
            .ok_or(VbkError::OffsetOverflow {
                offset: root.offset,
                length: 4_096,
            })?;
        let Some(data) = bank.page_at_offset(data_offset) else {
            continue;
        };
        if used_pages.contains(&data.offset) {
            continue;
        }
        let Some(blocks) = parse_logical_candidate(&data.bytes, 8, expected, physical)? else {
            continue;
        };
        if candidate.is_some() {
            return Err(invalid_map(
                root.offset,
                "multiple V9 inline logical maps match one file",
            ));
        }
        candidate = Some(FileBlockMap {
            item: item.clone(),
            map_offset: root.offset,
            metadata_pages: vec![root.offset, data.offset],
            blocks,
        });
    }
    Ok(candidate)
}

fn v9_inline_descriptor_matches(bytes: &[u8], expected: LogicalMapExpectation) -> bool {
    read_optional_u64(bytes, 0) == Some(INVALID_PAGE_LOCATION)
        && read_optional_u64(bytes, 16) == Some(expected.file_size.min(LOGICAL_BLOCK_UNIT_SIZE))
        && read_optional_u64(bytes, 24) == Some(expected.block_count)
}

fn find_sparse_file_map(
    bank: &MetadataBank,
    item: &StoredItem,
    physical: &[PhysicalBlock],
    used_pages: &BTreeSet<u64>,
    expected: LogicalMapExpectation,
) -> Result<FileBlockMap> {
    let table_count = expected.block_count.div_ceil(SPARSE_TABLE_RECORDS);
    if table_count > MAX_SPARSE_TABLES_PER_DIRECTORY {
        return Err(VbkError::LimitExceeded {
            resource: "sparse logical-map table count",
            actual: table_count,
            limit: MAX_SPARSE_TABLES_PER_DIRECTORY,
        });
    }
    let mut candidate = None;
    let (table_pages, _page_stack_referenced) = bank.table_pages()?;
    for page in table_pages {
        if used_pages.contains(&page.offset) {
            continue;
        }
        for base in [0_usize, 8_usize] {
            let Some(mut parsed) =
                parse_sparse_candidate(bank, &page.bytes, base, expected, physical)?
            else {
                continue;
            };
            if candidate.is_some() {
                return Err(invalid_map(
                    page.offset,
                    "multiple sparse logical maps match one file",
                ));
            }
            parsed.metadata_pages.push(page.offset);
            parsed.metadata_pages.sort_unstable();
            parsed.metadata_pages.dedup();
            candidate = Some(FileBlockMap {
                item: item.clone(),
                map_offset: checked_add_usize(page.offset, base)?,
                metadata_pages: parsed.metadata_pages,
                blocks: parsed.blocks,
            });
        }
    }
    candidate.ok_or_else(|| {
        invalid_map(
            item.record_offset,
            "no sparse logical map matches file record",
        )
    })
}

fn parse_sparse_candidate(
    bank: &MetadataBank,
    directory: &[u8],
    base: usize,
    expected: LogicalMapExpectation,
    physical: &[PhysicalBlock],
) -> Result<Option<ParsedSparseMap>> {
    let table_count = expected.block_count.div_ceil(SPARSE_TABLE_RECORDS);
    let capacity = usize::try_from(expected.block_count)
        .map_err(|error| invalid_map(0, &error.to_string()))?;
    let mut blocks = Vec::with_capacity(capacity);
    let mut used_locations = BTreeSet::new();
    let mut metadata_pages = Vec::new();
    let page_context = SparsePageContext {
        bank,
        record_size: expected.record_size,
        physical,
    };
    for table_index in 0..table_count {
        let descriptor_offset = sparse_descriptor_offset(base, table_index)?;
        let Some(descriptor) = parse_sparse_descriptor(directory, descriptor_offset)? else {
            return Ok(None);
        };
        let first_record =
            table_index
                .checked_mul(SPARSE_TABLE_RECORDS)
                .ok_or(VbkError::OffsetOverflow {
                    offset: table_index,
                    length: SPARSE_TABLE_RECORDS,
                })?;
        let record_count = (expected.block_count - first_record).min(SPARSE_TABLE_RECORDS);
        if descriptor.root == INVALID_PAGE_LOCATION {
            if descriptor.record_count != 0 {
                return Ok(None);
            }
            append_sparse_blocks(&mut blocks, record_count, expected.file_size)?;
            continue;
        }
        if descriptor.record_count != record_count {
            return Ok(None);
        }
        let Some(table_blocks) = parse_page_stack(
            page_context,
            descriptor.root,
            record_count,
            &mut used_locations,
            &mut metadata_pages,
        )?
        else {
            return Ok(None);
        };
        blocks.extend(table_blocks);
    }
    validate_sparse_candidate(blocks, metadata_pages, expected)
}

#[derive(Debug)]
struct ParsedSparseMap {
    blocks: Vec<LogicalBlock>,
    metadata_pages: Vec<u64>,
}

#[derive(Clone, Copy, Debug)]
struct SparseTableDescriptor {
    root: u64,
    record_count: u64,
}

#[derive(Clone, Copy, Debug)]
struct SparsePageContext<'a> {
    bank: &'a MetadataBank,
    record_size: usize,
    physical: &'a [PhysicalBlock],
}

fn parse_sparse_descriptor(bytes: &[u8], offset: usize) -> Result<Option<SparseTableDescriptor>> {
    let Some(root) = read_optional_u64(bytes, offset) else {
        return Ok(None);
    };
    let block_size_offset = checked_usize_add(offset, 8)?;
    let Some(block_size) = read_optional_u64(bytes, block_size_offset) else {
        return Ok(None);
    };
    if block_size != LOGICAL_BLOCK_UNIT_SIZE {
        return Ok(None);
    }
    let record_count_offset = checked_usize_add(offset, 16)?;
    let Some(record_count) = read_optional_u64(bytes, record_count_offset) else {
        return Ok(None);
    };
    Ok(Some(SparseTableDescriptor { root, record_count }))
}

fn sparse_descriptor_offset(base: usize, table_index: u64) -> Result<usize> {
    let table_index =
        usize::try_from(table_index).map_err(|error| invalid_map(0, &error.to_string()))?;
    table_index
        .checked_mul(SPARSE_TABLE_DESCRIPTOR_SIZE)
        .and_then(|relative| base.checked_add(relative))
        .ok_or_else(|| invalid_map(0, "sparse table descriptor offset overflow"))
}

fn parse_page_stack(
    context: SparsePageContext<'_>,
    root: u64,
    record_count: u64,
    used_locations: &mut BTreeSet<u64>,
    metadata_pages: &mut Vec<u64>,
) -> Result<Option<Vec<LogicalBlock>>> {
    let Some(root_page) = context.bank.page_at(root) else {
        return Ok(None);
    };
    if !used_locations.insert(root) || read_optional_u64(&root_page.bytes, 8) != Some(root) {
        return Ok(None);
    }
    metadata_pages.push(root_page.offset);
    let page_count = record_count.div_ceil(MAX_LOGICAL_RECORDS_PER_PAGE);
    let capacity =
        usize::try_from(record_count).map_err(|error| invalid_map(0, &error.to_string()))?;
    let mut blocks = Vec::with_capacity(capacity);
    for page_index in 0..page_count {
        let location_offset = page_stack_location_offset(page_index)?;
        let Some(location) = read_optional_u64(&root_page.bytes, location_offset) else {
            return Ok(None);
        };
        if location == INVALID_PAGE_LOCATION || !used_locations.insert(location) {
            return Ok(None);
        }
        let Some(data_page) = context.bank.page_at(location) else {
            return Ok(None);
        };
        metadata_pages.push(data_page.offset);
        let remaining = record_count - u64::try_from(blocks.len()).map_err(invalid_count)?;
        let count = remaining.min(MAX_LOGICAL_RECORDS_PER_PAGE);
        if !append_logical_page(
            &mut blocks,
            &data_page.bytes,
            count,
            context.record_size,
            context.physical,
        )? {
            return Ok(None);
        }
    }
    Ok(Some(blocks))
}

fn page_stack_location_offset(page_index: u64) -> Result<usize> {
    let page_index =
        usize::try_from(page_index).map_err(|error| invalid_map(0, &error.to_string()))?;
    page_index
        .checked_mul(PAGE_LOCATION_SIZE)
        .and_then(|relative| PAGE_STACK_FIRST_DATA_LOCATION.checked_add(relative))
        .ok_or_else(|| invalid_map(0, "page-stack location offset overflow"))
}

fn append_logical_page(
    blocks: &mut Vec<LogicalBlock>,
    page: &[u8],
    count: u64,
    record_size: usize,
    physical: &[PhysicalBlock],
) -> Result<bool> {
    for index in 0..count {
        let index = usize::try_from(index).map_err(|error| invalid_map(0, &error.to_string()))?;
        let Some(relative) = index.checked_mul(record_size) else {
            return Ok(false);
        };
        let Some(block) = parse_logical_record(page, relative)? else {
            return Ok(false);
        };
        if !validate_logical_reference(&block, physical)? {
            return Ok(false);
        }
        blocks.push(block);
    }
    Ok(true)
}

fn append_sparse_blocks(blocks: &mut Vec<LogicalBlock>, count: u64, file_size: u64) -> Result<()> {
    let mut written = logical_size(blocks)?;
    for _index in 0..count {
        let remaining = file_size
            .checked_sub(written)
            .ok_or_else(|| invalid_map(0, "sparse logical map exceeds file size"))?;
        let raw_size = remaining.min(LOGICAL_BLOCK_UNIT_SIZE);
        if raw_size == 0 {
            return Err(invalid_map(
                0,
                "sparse logical map contains a zero-length block",
            ));
        }
        let raw_size =
            u32::try_from(raw_size).map_err(|error| invalid_map(0, &error.to_string()))?;
        blocks.push(LogicalBlock {
            raw_size,
            digest: Digest::None,
            reference: BlockReference::Zero,
        });
        written =
            written
                .checked_add(u64::from(raw_size))
                .ok_or_else(|| VbkError::OffsetOverflow {
                    offset: written,
                    length: u64::from(raw_size),
                })?;
    }
    Ok(())
}

fn validate_sparse_candidate(
    blocks: Vec<LogicalBlock>,
    metadata_pages: Vec<u64>,
    expected: LogicalMapExpectation,
) -> Result<Option<ParsedSparseMap>> {
    let size = logical_size(&blocks)?;
    let count = u64::try_from(blocks.len()).map_err(invalid_count)?;
    if size == expected.file_size && count == expected.block_count {
        return Ok(Some(ParsedSparseMap {
            blocks,
            metadata_pages,
        }));
    }
    Ok(None)
}

fn logical_size(blocks: &[LogicalBlock]) -> Result<u64> {
    let mut size = 0_u64;
    for block in blocks {
        size = size.checked_add(u64::from(block.raw_size)).ok_or_else(|| {
            VbkError::OffsetOverflow {
                offset: size,
                length: u64::from(block.raw_size),
            }
        })?;
    }
    Ok(size)
}

fn invalid_count(error: std::num::TryFromIntError) -> VbkError {
    invalid_map(0, &error.to_string())
}

#[derive(Clone, Copy, Debug)]
struct LogicalMapExpectation {
    block_count: u64,
    file_size: u64,
    record_size: usize,
    version: u32,
}

#[derive(Clone, Copy, Debug)]
struct LogicalMapProfile {
    record_size: usize,
    version: u32,
}

fn parse_logical_candidate(
    page: &[u8],
    base: usize,
    expected: LogicalMapExpectation,
    physical: &[PhysicalBlock],
) -> Result<Option<Vec<LogicalBlock>>> {
    let record_limit = expected.block_count.min(MAX_LOGICAL_RECORDS_PER_PAGE);
    let capacity =
        usize::try_from(record_limit).map_err(|error| invalid_map(0, &error.to_string()))?;
    let mut blocks = Vec::with_capacity(capacity);
    let mut total_size = 0_u64;
    let mut total_units = 0_u64;
    for index in 0..record_limit {
        let index_usize =
            usize::try_from(index).map_err(|error| invalid_map(0, &error.to_string()))?;
        let Some(relative) = index_usize
            .checked_mul(expected.record_size)
            .and_then(|value| base.checked_add(value))
        else {
            return Ok(None);
        };
        let Some(block) = parse_logical_record(page, relative)? else {
            return Ok(None);
        };
        if !validate_logical_reference(&block, physical)? {
            return Ok(None);
        }
        total_size = total_size
            .checked_add(u64::from(block.raw_size))
            .ok_or_else(|| VbkError::OffsetOverflow {
                offset: total_size,
                length: u64::from(block.raw_size),
            })?;
        let units = u64::from(block.raw_size).div_ceil(LOGICAL_BLOCK_UNIT_SIZE);
        total_units = total_units
            .checked_add(units)
            .ok_or(VbkError::OffsetOverflow {
                offset: total_units,
                length: units,
            })?;
        blocks.push(block);
        if total_size == expected.file_size && total_units == expected.block_count {
            return Ok(Some(blocks));
        }
        if total_size >= expected.file_size || total_units >= expected.block_count {
            return Ok(None);
        }
    }
    Ok(None)
}

fn parse_logical_record(page: &[u8], relative: usize) -> Result<Option<LogicalBlock>> {
    let Some(raw_size) = read_optional_u32(page, relative) else {
        return Ok(None);
    };
    if raw_size == 0 {
        return Ok(None);
    }
    let state = read_u8(page, checked_usize_add(relative, 4)?)?;
    let Some(reference_kind) = logical_reference_kind(state) else {
        return Ok(None);
    };
    let index = read_u64(page, checked_usize_add(relative, 21)?)?;
    let digest_bytes = read_array::<16>(page, checked_usize_add(relative, 5)?)?;
    Ok(Some(LogicalBlock {
        raw_size,
        digest: Digest::from_engine(digest_bytes, state >> 4),
        reference: if reference_kind == 0 {
            BlockReference::Local(index)
        } else {
            BlockReference::Zero
        },
    }))
}

/// Extract the reference kind embedded in a logical-map record's state byte.
///
/// Older format-flag-9 fixtures store the reference kind directly in bits 0-3 with the
/// upper nibble zeroed (`state == 0` local, `state == 1` zero). Windows Agent
/// "SERVER MANAGED" fulls widen the byte to `(engine << 4) | reference_kind` where the
/// engine nibble is the in-band per-block digest hint (`0x0` = MD5, `0x1` = BLAKE3-128,
/// matching [`Digest::from_engine`]). This is *not* the storage-header `DigestType`
/// string — server-managed fulls keep that at `md5` while their blocks are BLAKE3-128, so
/// the engine nibble is the authoritative signal. Every other combination is left as "not
/// a logical record" so the linear scan bails cleanly.
fn logical_reference_kind(state: u8) -> Option<u8> {
    let reference_kind: u8 = state & 0x0F;
    let engine: u8 = state >> 4;
    if reference_kind > 1_u8 || engine > 0x03_u8 {
        return None;
    }
    Some(reference_kind)
}

fn validate_logical_reference(block: &LogicalBlock, physical: &[PhysicalBlock]) -> Result<bool> {
    let index = match block.reference {
        BlockReference::Zero => return Ok(true),
        BlockReference::Local(index) => index,
        BlockReference::Parent(_)
        | BlockReference::Deduplicated(_)
        | BlockReference::External(_) => return Ok(false),
    };
    let index = usize::try_from(index).map_err(|error| invalid_map(0, &error.to_string()))?;
    let Some(stored) = physical.get(index) else {
        return Ok(false);
    };
    Ok(stored.active
        && stored.raw_size == u64::from(block.raw_size)
        && stored.digest == block.digest)
}

fn read_optional_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let slice = bytes.get(offset..end)?;
    let array = <[u8; 4]>::try_from(slice).ok()?;
    Some(u32::from_le_bytes(array))
}

fn read_optional_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    let slice = bytes.get(offset..end)?;
    let array = <[u8; 8]>::try_from(slice).ok()?;
    Some(u64::from_le_bytes(array))
}

fn read_u8(bytes: &[u8], offset: usize) -> Result<u8> {
    bytes
        .get(offset)
        .copied()
        .ok_or_else(|| invalid_map(0, "truncated u8"))
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(read_array::<2>(bytes, offset)?))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(read_array::<4>(bytes, offset)?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(read_array::<8>(bytes, offset)?))
}

fn read_array<const SIZE: usize>(bytes: &[u8], offset: usize) -> Result<[u8; SIZE]> {
    let end = offset
        .checked_add(SIZE)
        .ok_or_else(|| invalid_map(0, "slice offset overflow"))?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| invalid_map(0, "truncated metadata record"))?;
    <[u8; SIZE]>::try_from(slice).map_err(|error| invalid_map(0, &error.to_string()))
}

fn checked_add_usize(offset: u64, value: usize) -> Result<u64> {
    let value = u64::try_from(value).map_err(|error| invalid_map(offset, &error.to_string()))?;
    offset.checked_add(value).ok_or(VbkError::OffsetOverflow {
        offset,
        length: value,
    })
}

fn checked_usize_add(offset: usize, value: usize) -> Result<usize> {
    offset
        .checked_add(value)
        .ok_or_else(|| invalid_map(0, "record offset overflow"))
}

fn required_file_field(value: Option<u64>, offset: u64, field: &'static str) -> Result<u64> {
    value.ok_or_else(|| invalid_map(offset, field))
}

fn invalid_map(offset: u64, reason: &str) -> VbkError {
    VbkError::InvalidField {
        offset,
        field: "block_map",
        reason: reason.to_owned(),
    }
}
