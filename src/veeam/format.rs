//! Version-aware parsing of the outer VBK storage header.

use std::{fmt, path::Path};

use serde::Serialize;

use crate::veeam::{
    EncryptionInfo, Result, VbkError,
    encryption::inspect_reader,
    metadata::{MetadataLayout, bank_header_indicates_encryption, parse_metadata_layout},
    reader::{FileReader, read_u8, read_u32, read_u64},
};

const MODERN_HEADER_SIZE: u64 = 0x1000;
/// The `Initialized` flag at storage-header offset `0x4` (`u32`). Extract.exe and
/// `dissect.archive` agree that this is a lifecycle flag, not the digest engine ID; the
/// public `BackupHeader::digest_type` alias is retained for backwards compatibility.
const MODERN_INITIALIZED_OFFSET: u64 = 0x004;
const MODERN_DIGEST_NAME_LENGTH_OFFSET: u64 = 0x008;
const MODERN_DIGEST_NAME_OFFSET: u64 = 0x00c;
/// `SnapshotSlotFormat` per `dissect.archive`'s `StorageHeader`. Only the low byte is used
/// as a modern block-descriptor selector; higher bytes have not been observed non-zero.
const MODERN_FORMAT_FLAG_OFFSET: u64 = 0x107;
const MODERN_BLOCK_SIZE_OFFSET: u64 = 0x10b;
/// `ClusterAlign` per `dissect.archive`. Named `misc_flag` here for backwards compatibility.
const MODERN_MISC_FLAG_OFFSET: u64 = 0x10f;
/// External-storage identifier at header offset `0x130` per `dissect.archive`'s
/// `StorageHeader` (bytes `0x120..0x130` are an unknown 16-byte field). Older `vbktool`
/// releases read this field from `0x120`, which was a copy of the intervening unknown
/// bytes and reported spurious identifiers on backups that populated the padding.
const MODERN_EXTERNAL_STORAGE_ID_OFFSET: u64 = 0x130;
const MAX_DIGEST_NAME_LENGTH: u64 = 0xfb;
const MAX_FIB_COUNT: u64 = 1_000_000;
const PREVIEW_LENGTH: u64 = 24;
const MAX_FIB_NAME_LENGTH: u64 = 64 * 1024;

/// A supported family of outer storage layouts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FormatFamily {
    /// Versions 0 and 1, with inline FIB entries.
    Legacy,
    /// Transitional version 7.
    Transitional,
    /// Versions 9 through 14.
    Modern,
    /// Special marker version `0x10008`.
    Marker,
}

impl fmt::Display for FormatFamily {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Legacy => formatter.write_str("legacy"),
            Self::Transitional => formatter.write_str("transitional"),
            Self::Modern => formatter.write_str("modern"),
            Self::Marker => formatter.write_str("marker"),
        }
    }
}

/// The strongest capability verified for a format version.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportLevel {
    /// The header layout is recognized from reverse engineering but lacks a supplied fixture.
    HeaderRecognized,
    /// Header parsing is covered by a supplied fixture.
    HeaderTested,
    /// Header and mirrored metadata-bank location are covered by a supplied fixture.
    MetadataLocatedTested,
    /// Experimental FIB catalogue scanning is covered by a supplied fixture.
    CatalogScannedTested,
    /// Catalogue, logical maps, LZ4 decoding, sparse blocks, and extraction are fixture-tested.
    ExtractionTested,
}

impl fmt::Display for SupportLevel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeaderRecognized => formatter.write_str("header_recognized"),
            Self::HeaderTested => formatter.write_str("header_tested"),
            Self::MetadataLocatedTested => formatter.write_str("metadata_located_tested"),
            Self::CatalogScannedTested => formatter.write_str("catalog_scanned_tested"),
            Self::ExtractionTested => formatter.write_str("extraction_tested"),
        }
    }
}

/// A File-In-Backup entry embedded in legacy storage directories.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FibEntry {
    /// Physical offset of this FIB directory record.
    pub record_offset: u64,
    /// Whether this FIB redirects data to an incremental patch.
    pub is_patch: bool,
    /// Physical start of the FIB data extent.
    pub data_extent_start: u64,
    /// FIB identifier or sub-version field.
    pub identifier: u32,
    /// Physical extent length.
    pub data_extent_length: u64,
    /// Number of blocks described by the FIB.
    pub block_count: u32,
    /// Stored FIB name.
    pub name: String,
}

/// Parsed fields from the outer storage header.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BackupHeader {
    /// Complete input file length.
    pub file_length: u64,
    /// Veeam storage version at file offset zero.
    pub version: u32,
    /// Selected layout family.
    pub family: FormatFamily,
    /// Strongest verified capability for this version.
    pub support: SupportLevel,
    /// Digest engine identifier when present.
    pub digest_engine: Option<String>,
    /// Digest type or size field.
    pub digest_type: Option<u32>,
    /// Storage format flag used by modern layouts.
    pub format_flag: Option<u32>,
    /// Logical block size used by modern layouts.
    pub block_size: Option<u32>,
    /// Additional modern storage flag with unknown semantics.
    pub misc_flag: Option<u8>,
    /// External storage identifier; all zeroes means no external backing.
    pub external_storage_id: Option<[u8; 16]>,
    /// Inline legacy FIB entries. Modern FIBs live in the metadata bank.
    pub fibs: Vec<FibEntry>,
    /// Located modern metadata bank and its mirrored copy.
    pub metadata: Option<MetadataLayout>,
    /// Password-independent encryption status and wrapped-keyset inventory.
    pub encryption: EncryptionInfo,
}

/// Parse the outer header of a VBK, VIB, or VRB file.
///
/// # Errors
///
/// Returns an error for IO failures, truncated data, unsupported versions, or invalid bounded fields.
pub fn parse_header(path: &Path) -> Result<BackupHeader> {
    let reader = FileReader::open(path)?;
    let version = read_u32(&reader, 0)?;
    match version {
        0 | 1 => parse_legacy(&reader, version),
        7 | 9..=14 | 0x10008 => parse_modern(&reader, version),
        unsupported => Err(classify_unsupported(&reader, unsupported)),
    }
}

/// Turn an unrecognized version word into the most specific diagnostic available.
///
/// A `.vbm` metadata sidecar is XML that begins with `<BackupMeta …`, so its first byte is `<`
/// (`0x3c`). Recognizing that avoids reporting a meaningless "storage version" built from ASCII.
fn classify_unsupported(reader: &FileReader, version: u32) -> VbkError {
    if version.to_le_bytes()[0] == b'<' {
        if let Some(preview) = printable_preview(reader) {
            return VbkError::NotAStorageContainer { preview };
        }
    }
    VbkError::UnsupportedVersion { version }
}

/// Read a short, printable snapshot of the file's opening bytes for diagnostics.
fn printable_preview(reader: &FileReader) -> Option<String> {
    let want = reader.length().min(PREVIEW_LENGTH);
    let bytes = reader.read_bytes(0, want, "file preview").ok()?;
    Some(
        bytes
            .iter()
            .map(|&byte| {
                if byte.is_ascii_graphic() || byte == b' ' {
                    char::from(byte)
                } else {
                    '.'
                }
            })
            .collect(),
    )
}

fn parse_modern(reader: &FileReader, version: u32) -> Result<BackupHeader> {
    validate_modern_header(reader)?;
    let digest_type = read_u32(reader, MODERN_INITIALIZED_OFFSET)?;
    let digest_engine = read_modern_digest_name(reader)?;
    let external_storage_id = reader.read_array::<16>(MODERN_EXTERNAL_STORAGE_ID_OFFSET)?;
    let metadata = parse_metadata_layout(reader)?;
    let encryption = reconcile_encryption(reader, &metadata, inspect_reader(reader)?)?;

    Ok(BackupHeader {
        file_length: reader.length(),
        version,
        family: modern_family(version)?,
        support: support_level(version),
        digest_engine: Some(digest_engine),
        digest_type: Some(digest_type),
        format_flag: Some(read_u32(reader, MODERN_FORMAT_FLAG_OFFSET)?),
        block_size: Some(read_u32(reader, MODERN_BLOCK_SIZE_OFFSET)?),
        misc_flag: Some(read_u8(reader, MODERN_MISC_FLAG_OFFSET)?),
        external_storage_id: nonzero_identifier(external_storage_id),
        fibs: Vec::new(),
        metadata: Some(metadata),
        encryption,
    })
}

/// Overlay `inspect_reader`'s raw-byte findings with the authoritative bank-header check.
///
/// `inspect_reader` walks the first 16 MiB of the file looking for password hints, storage
/// descriptors, and wrapped keyset records. Its per-hint heuristic (`identifier + 4 zeros +
/// printable ASCII`) can trip inside compressed LZ4/UTF-16 payloads far past the actual
/// metadata bank, which historically caused unencrypted "SERVER MANAGED" agent backups to
/// be misreported as encrypted (see `metabank_decrypt_load` @ `0x14036A0E0`). The bank
/// header keyset field is the same source of truth that `Extract.exe` consults, so it wins
/// against any raw-byte finding.
fn reconcile_encryption(
    reader: &FileReader,
    metadata: &MetadataLayout,
    scanned: EncryptionInfo,
) -> Result<EncryptionInfo> {
    if bank_header_indicates_encryption(reader, metadata)? {
        return Ok(scanned);
    }
    Ok(EncryptionInfo::default())
}

fn validate_modern_header(reader: &FileReader) -> Result<()> {
    if reader.length() < MODERN_HEADER_SIZE {
        return Err(VbkError::RangeOutsideFile {
            offset: 0,
            length: MODERN_HEADER_SIZE,
            file_length: reader.length(),
        });
    }
    Ok(())
}

fn read_modern_digest_name(reader: &FileReader) -> Result<String> {
    let length = u64::from(read_u32(reader, MODERN_DIGEST_NAME_LENGTH_OFFSET)?);
    if length > MAX_DIGEST_NAME_LENGTH {
        return Err(VbkError::LimitExceeded {
            resource: "digest engine name",
            actual: length,
            limit: MAX_DIGEST_NAME_LENGTH,
        });
    }
    let bytes = reader.read_bytes(MODERN_DIGEST_NAME_OFFSET, length, "digest engine name")?;
    String::from_utf8(bytes).map_err(|error| VbkError::InvalidField {
        offset: MODERN_DIGEST_NAME_OFFSET,
        field: "digest_engine",
        reason: error.to_string(),
    })
}

fn parse_legacy(reader: &FileReader, version: u32) -> Result<BackupHeader> {
    let fib_count = u64::from(read_u32(reader, 4)?);
    if fib_count > MAX_FIB_COUNT {
        return Err(VbkError::LimitExceeded {
            resource: "FIB count",
            actual: fib_count,
            limit: MAX_FIB_COUNT,
        });
    }

    let mut cursor = LegacyCursor::new(reader, 8);
    let capacity = usize::try_from(fib_count).map_err(|error| VbkError::InvalidField {
        offset: 4,
        field: "fib_count",
        reason: error.to_string(),
    })?;
    let mut fibs = Vec::with_capacity(capacity);
    for _index in 0..fib_count {
        let fib = cursor.read_fib()?;
        validate_fib_extent(reader, &fib)?;
        fibs.push(fib);
    }
    let digest_engine = cursor.read_string("digest_engine")?;
    let digest_type = cursor.read_u32()?;

    Ok(BackupHeader {
        file_length: reader.length(),
        version,
        family: FormatFamily::Legacy,
        support: SupportLevel::HeaderRecognized,
        digest_engine: Some(digest_engine),
        digest_type: Some(digest_type),
        format_flag: None,
        block_size: None,
        misc_flag: None,
        external_storage_id: None,
        fibs,
        metadata: None,
        encryption: inspect_reader(reader)?,
    })
}

#[derive(Debug)]
struct LegacyCursor<'reader> {
    reader: &'reader FileReader,
    offset: u64,
}

impl<'reader> LegacyCursor<'reader> {
    const fn new(reader: &'reader FileReader, offset: u64) -> Self {
        Self { reader, offset }
    }

    fn read_fib(&mut self) -> Result<FibEntry> {
        let record_offset = self.offset;
        let is_patch = self.read_u8()? != 0;
        let data_extent_start = self.read_u64()?;
        let identifier = self.read_u32()?;
        let data_extent_length = self.read_u64()?;
        let block_count = self.read_u32()?;
        let name = self.read_string("FIB name")?;
        Ok(FibEntry {
            record_offset,
            is_patch,
            data_extent_start,
            identifier,
            data_extent_length,
            block_count,
            name,
        })
    }

    fn read_string(&mut self, field: &'static str) -> Result<String> {
        let length_offset = self.offset;
        let length = u64::from(self.read_u32()?);
        if length > MAX_FIB_NAME_LENGTH {
            return Err(VbkError::LimitExceeded {
                resource: field,
                actual: length,
                limit: MAX_FIB_NAME_LENGTH,
            });
        }
        let bytes = self.reader.read_bytes(self.offset, length, field)?;
        self.advance(length)?;
        String::from_utf8(bytes).map_err(|error| VbkError::InvalidField {
            offset: length_offset,
            field,
            reason: error.to_string(),
        })
    }

    fn read_u8(&mut self) -> Result<u8> {
        let value = read_u8(self.reader, self.offset)?;
        self.advance(1)?;
        Ok(value)
    }

    fn read_u32(&mut self) -> Result<u32> {
        let value = read_u32(self.reader, self.offset)?;
        self.advance(4)?;
        Ok(value)
    }

    fn read_u64(&mut self) -> Result<u64> {
        let value = read_u64(self.reader, self.offset)?;
        self.advance(8)?;
        Ok(value)
    }

    fn advance(&mut self, length: u64) -> Result<()> {
        self.offset = self
            .offset
            .checked_add(length)
            .ok_or(VbkError::OffsetOverflow {
                offset: self.offset,
                length,
            })?;
        Ok(())
    }
}

fn validate_fib_extent(reader: &FileReader, fib: &FibEntry) -> Result<()> {
    let end = fib
        .data_extent_start
        .checked_add(fib.data_extent_length)
        .ok_or(VbkError::OffsetOverflow {
            offset: fib.data_extent_start,
            length: fib.data_extent_length,
        })?;
    if fib.data_extent_length == 0 || end > reader.length() {
        return Err(VbkError::RangeOutsideFile {
            offset: fib.data_extent_start,
            length: fib.data_extent_length,
            file_length: reader.length(),
        });
    }
    Ok(())
}

fn modern_family(version: u32) -> Result<FormatFamily> {
    match version {
        7 => Ok(FormatFamily::Transitional),
        9..=14 => Ok(FormatFamily::Modern),
        0x10008 => Ok(FormatFamily::Marker),
        unsupported => Err(VbkError::UnsupportedVersion {
            version: unsupported,
        }),
    }
}

const fn support_level(version: u32) -> SupportLevel {
    if version == 9 || version == 13 {
        SupportLevel::ExtractionTested
    } else {
        SupportLevel::HeaderRecognized
    }
}

fn nonzero_identifier(identifier: [u8; 16]) -> Option<[u8; 16]> {
    if identifier.iter().all(|byte| *byte == 0) {
        None
    } else {
        Some(identifier)
    }
}
