//! Experimental decoding of typed FIB catalogue records in modern metadata pages.

use std::{fmt, path::Path};

use serde::Serialize;

use crate::veeam::{
    FormatFamily, Result, VbkError,
    format::{BackupHeader, parse_header},
    metadata::MetadataBank,
    reader::FileReader,
};

const MAX_CATALOG_PAGES: u64 = 0x80_000;
/// Size of the `DirItemRecord.Name` buffer per `dissect.archive` (`Name[128]`, bytes
/// `0x08..0x88`). A valid `NameLength` cannot exceed it, and capping here guarantees the
/// name read never spills into `PropsRootPage` at `0x88`.
const MAX_ITEM_NAME_LENGTH: u32 = 128;
const FILE_RECORD_STRIDE: usize = 0xc0;

/// Type stored at the beginning of a recognized catalogue record.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StoredItemKind {
    /// Internal VM or host directory.
    Directory,
    /// File stored below an internal directory.
    File,
}

impl fmt::Display for StoredItemKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Directory => formatter.write_str("directory"),
            Self::File => formatter.write_str("file"),
        }
    }
}

/// Confidence associated with catalogue discovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogConfidence {
    /// FIB entries came directly from a bounded legacy storage directory.
    LegacyStorageDirectory,
    /// Typed records were validated on data pages referenced by checked page stacks.
    PageStackReferencedRecordScan,
    /// Allocated version-specific pages were scanned with bounded, typed record validation.
    GuardedAllocatedPageScan,
}

impl fmt::Display for CatalogConfidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LegacyStorageDirectory => formatter.write_str("legacy_storage_directory"),
            Self::PageStackReferencedRecordScan => {
                formatter.write_str("page_stack_referenced_record_scan")
            }
            Self::GuardedAllocatedPageScan => formatter.write_str("guarded_allocated_page_scan"),
        }
    }
}

/// One named object found in the modern FIB catalogue.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StoredItem {
    /// Record kind.
    pub kind: StoredItemKind,
    /// Stored name.
    pub name: String,
    /// Stable catalogue path formed from the enclosing directory and stored name.
    pub path: String,
    /// Absolute file offset of the record.
    pub record_offset: u64,
    /// Whether the item redirects data to an incremental patch.
    pub is_patch: bool,
    /// Logical block count for file records.
    pub block_count: Option<u64>,
    /// Reconstructed file size for file records.
    pub size: Option<u64>,
    /// `DirItemRecord.PropsRootPage` per `dissect.archive` — page location of the
    /// `PropertiesDictionary` `MetaBlob` attached to this record, or `None` when the writer
    /// stored the null sentinel (`-1`). Directory records always carry `None`.
    pub props_root_page: Option<u64>,
}

/// Flat catalogue discovered in the primary modern metadata bank.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Catalog {
    /// Parser confidence, kept explicit until the complete metadata B-tree is decoded.
    pub confidence: CatalogConfidence,
    /// Named records in physical catalogue order.
    pub items: Vec<StoredItem>,
}

/// List typed FIB catalogue records from a modern VBK metadata bank.
///
/// # Errors
///
/// Returns an error for invalid headers, unavailable legacy metadata, excessive page counts, or IO failures.
pub fn list_items(path: &Path) -> Result<Catalog> {
    list_items_with_password(path, None)
}

/// List typed catalogue records, decrypting metadata with `password` when required.
///
/// # Errors
///
/// Returns an error for invalid headers, unavailable metadata, an absent or incorrect password,
/// excessive page counts, malformed encrypted segments, or IO failures.
pub fn list_items_with_password(path: &Path, password: Option<&str>) -> Result<Catalog> {
    let header = parse_header(path)?;
    match header.family {
        FormatFamily::Legacy => return Ok(legacy_catalog(&header)),
        FormatFamily::Transitional | FormatFamily::Modern | FormatFamily::Marker => {}
    }
    modern_catalog(path, &header, password)
}

fn legacy_catalog(header: &BackupHeader) -> Catalog {
    let mut items = Vec::with_capacity(header.fibs.len());
    for fib in &header.fibs {
        items.push(StoredItem {
            kind: StoredItemKind::File,
            name: fib.name.clone(),
            path: fib.name.clone(),
            record_offset: fib.record_offset,
            is_patch: fib.is_patch,
            block_count: Some(u64::from(fib.block_count)),
            size: None,
            props_root_page: None,
        });
    }
    Catalog {
        confidence: CatalogConfidence::LegacyStorageDirectory,
        items,
    }
}

fn modern_catalog(path: &Path, header: &BackupHeader, password: Option<&str>) -> Result<Catalog> {
    let layout = header
        .metadata
        .as_ref()
        .ok_or(VbkError::FeatureUnavailable {
            feature: "modern FIB catalogue",
            version: header.version,
        })?;
    let reader = FileReader::open(path)?;
    let bank = MetadataBank::open_primary(&reader, layout, &header.encryption, password)?;
    let page_count = u64::try_from(bank.pages().len()).map_err(invalid_page_count)?;
    if page_count > MAX_CATALOG_PAGES {
        return Err(VbkError::LimitExceeded {
            resource: "catalogue page count",
            actual: page_count,
            limit: MAX_CATALOG_PAGES,
        });
    }

    let mut items = Vec::new();
    let (table_pages, page_stack_referenced) = bank.table_pages()?;
    for page in table_pages {
        scan_page(&page.bytes, page.offset, &mut items)?;
    }
    assign_paths(&mut items);
    Ok(Catalog {
        confidence: if page_stack_referenced {
            CatalogConfidence::PageStackReferencedRecordScan
        } else {
            CatalogConfidence::GuardedAllocatedPageScan
        },
        items,
    })
}

fn invalid_page_count(error: std::num::TryFromIntError) -> VbkError {
    VbkError::InvalidField {
        offset: 0,
        field: "catalogue_page_count",
        reason: error.to_string(),
    }
}

fn scan_page(page: &[u8], page_offset: u64, items: &mut Vec<StoredItem>) -> Result<()> {
    for base in [0_usize, 8_usize] {
        let Some(first) = parse_candidate(page, base, page_offset)? else {
            continue;
        };
        match first.kind {
            StoredItemKind::Directory => items.push(first),
            StoredItemKind::File => scan_file_records(page, base, page_offset, first, items)?,
        }
    }
    Ok(())
}

fn scan_file_records(
    page: &[u8],
    base: usize,
    page_offset: u64,
    first: StoredItem,
    items: &mut Vec<StoredItem>,
) -> Result<()> {
    items.push(first);
    let mut record_offset =
        base.checked_add(FILE_RECORD_STRIDE)
            .ok_or(VbkError::OffsetOverflow {
                offset: page_offset,
                length: u64::try_from(FILE_RECORD_STRIDE).map_err(invalid_stride)?,
            })?;
    while let Some(item) = parse_candidate(page, record_offset, page_offset)? {
        if item.kind != StoredItemKind::File {
            break;
        }
        items.push(item);
        record_offset =
            record_offset
                .checked_add(FILE_RECORD_STRIDE)
                .ok_or(VbkError::OffsetOverflow {
                    offset: page_offset,
                    length: u64::try_from(FILE_RECORD_STRIDE).map_err(invalid_stride)?,
                })?;
    }
    Ok(())
}

fn parse_candidate(page: &[u8], relative: usize, page_offset: u64) -> Result<Option<StoredItem>> {
    let Some((kind, is_patch)) = read_kind(page, relative, page_offset)? else {
        return Ok(None);
    };
    let length_offset = relative.checked_add(4).ok_or(VbkError::OffsetOverflow {
        offset: page_offset,
        length: 4,
    })?;
    let name_length = read_slice_u32(page, length_offset, page_offset)?;
    if name_length == 0 || name_length > MAX_ITEM_NAME_LENGTH {
        return Ok(None);
    }
    let name_offset = relative.checked_add(8).ok_or(VbkError::OffsetOverflow {
        offset: page_offset,
        length: 8,
    })?;
    let name = read_name(page, name_offset, name_length)?;
    let Some(name) = name else {
        return Ok(None);
    };
    let relative_u64 = u64::try_from(relative).map_err(|error| VbkError::InvalidField {
        offset: page_offset,
        field: "catalogue_record_offset",
        reason: error.to_string(),
    })?;
    Ok(Some(StoredItem {
        kind,
        path: name.clone(),
        name,
        record_offset: checked_add(page_offset, relative_u64)?,
        is_patch,
        block_count: read_file_field(page, relative, kind, 0xa0, page_offset)?,
        size: read_file_field(page, relative, kind, 0xa8, page_offset)?,
        props_root_page: read_props_root_page(page, relative, kind, page_offset)?,
    }))
}

fn read_props_root_page(
    page: &[u8],
    record_offset: usize,
    kind: StoredItemKind,
    page_offset: u64,
) -> Result<Option<u64>> {
    if kind == StoredItemKind::Directory {
        return Ok(None);
    }
    let relative = record_offset
        .checked_add(0x88)
        .ok_or(VbkError::OffsetOverflow {
            offset: page_offset,
            length: 0x88,
        })?;
    let end = relative.checked_add(8).ok_or(VbkError::OffsetOverflow {
        offset: page_offset,
        length: 8,
    })?;
    let bytes = page
        .get(relative..end)
        .ok_or_else(|| VbkError::InvalidField {
            offset: page_offset,
            field: "catalogue_props_root_page",
            reason: "file record extends beyond its metadata page".to_owned(),
        })?;
    let array = <[u8; 8]>::try_from(bytes).map_err(|error| VbkError::InvalidField {
        offset: page_offset,
        field: "catalogue_props_root_page",
        reason: error.to_string(),
    })?;
    let raw = i64::from_le_bytes(array);
    Ok((raw != -1).then(|| u64::from_le_bytes(array)))
}

fn assign_paths(items: &mut [StoredItem]) {
    let mut directory = None;
    for item in items {
        match item.kind {
            StoredItemKind::Directory => {
                item.path.clone_from(&item.name);
                directory = Some(item.name.clone());
            }
            StoredItemKind::File => {
                item.path = directory.as_ref().map_or_else(
                    || item.name.clone(),
                    |parent| format!("{parent}/{}", item.name),
                );
            }
        }
    }
}

fn read_file_field(
    page: &[u8],
    record_offset: usize,
    kind: StoredItemKind,
    field_offset: usize,
    page_offset: u64,
) -> Result<Option<u64>> {
    if kind == StoredItemKind::Directory {
        return Ok(None);
    }
    let relative = record_offset
        .checked_add(field_offset)
        .ok_or(VbkError::OffsetOverflow {
            offset: page_offset,
            length: u64::try_from(field_offset).map_err(invalid_stride)?,
        })?;
    let end = relative.checked_add(8).ok_or(VbkError::OffsetOverflow {
        offset: page_offset,
        length: 8,
    })?;
    let bytes = page
        .get(relative..end)
        .ok_or_else(|| VbkError::InvalidField {
            offset: page_offset,
            field: "catalogue_file_field",
            reason: "file record extends beyond its metadata page".to_owned(),
        })?;
    let array = <[u8; 8]>::try_from(bytes).map_err(|error| VbkError::InvalidField {
        offset: page_offset,
        field: "catalogue_file_field",
        reason: error.to_string(),
    })?;
    Ok(Some(u64::from_le_bytes(array)))
}

fn read_kind(
    page: &[u8],
    relative: usize,
    page_offset: u64,
) -> Result<Option<(StoredItemKind, bool)>> {
    // `DirItemType` per `dissect.archive`: `1` = SubFolder (directory), `2` = ExtFib,
    // `3` = IntFib, `4` = Patch, `5` = Increment. All four file types share an identical
    // on-disk header (name, block count at `+0xa0`, size at `+0xa8`) and each names a stored
    // file, so they are decoded the same way. This matters for incremental (`.vib`/`.vrb`)
    // backups: a VM's disk extents are stored as `Increment` records (`-flat.vmdk`), so
    // stopping the record run at the first `4`/`5` used to drop every disk — and every
    // record that followed it on the page — from the listing. `4`/`5` name data that is an
    // incremental patch on the parent chain, so they are surfaced with `is_patch = true`.
    match read_slice_u32(page, relative, page_offset)? {
        1 => Ok(Some((StoredItemKind::Directory, false))),
        2 | 3 => Ok(Some((StoredItemKind::File, false))),
        4 | 5 => Ok(Some((StoredItemKind::File, true))),
        _ => Ok(None),
    }
}

fn read_slice_u32(page: &[u8], relative: usize, page_offset: u64) -> Result<u32> {
    let end = relative.checked_add(4).ok_or(VbkError::OffsetOverflow {
        offset: page_offset,
        length: 4,
    })?;
    let Some(bytes) = page.get(relative..end) else {
        return Ok(0);
    };
    let array = <[u8; 4]>::try_from(bytes).map_err(|error| VbkError::InvalidField {
        offset: page_offset,
        field: "catalogue_u32",
        reason: error.to_string(),
    })?;
    Ok(u32::from_le_bytes(array))
}

fn read_name(page: &[u8], relative: usize, length: u32) -> Result<Option<String>> {
    let length = usize::try_from(length).map_err(|error| VbkError::InvalidField {
        offset: 0,
        field: "catalogue_name_length",
        reason: error.to_string(),
    })?;
    let Some(end) = relative.checked_add(length) else {
        return Ok(None);
    };
    let Some(bytes) = page.get(relative..end) else {
        return Ok(None);
    };
    let Ok(name) = std::str::from_utf8(bytes) else {
        return Ok(None);
    };
    if name.chars().any(char::is_control) {
        return Ok(None);
    }
    Ok(Some(name.to_owned()))
}

fn checked_add(offset: u64, length: u64) -> Result<u64> {
    offset
        .checked_add(length)
        .ok_or(VbkError::OffsetOverflow { offset, length })
}

fn invalid_stride(error: std::num::TryFromIntError) -> VbkError {
    VbkError::InvalidField {
        offset: 0,
        field: "catalogue_record_stride",
        reason: error.to_string(),
    }
}
