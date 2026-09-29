//! Validated reconstruction of catalogue files from logical and physical blocks.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
};

use md5::{Digest as DigestEngine, Md5};
use serde::Serialize;
use sha2::Sha256;

use crate::veeam::{
    BlockReference, Compression, Digest, FileBlockMap, LogicalBlock, PhysicalBlock, Result,
    StoredItemKind, VbkError,
    block::{build_file_maps_with_password, build_increment_recovery_with_password},
    catalog::list_items_with_password,
    encryption::{RecoveredKeysets, recover_reader_keysets},
    format::parse_header,
    reader::FileReader,
};

const VEEAM_LZ4_HEADER_SIZE: usize = 12;
const COMPRESSED_HEADER_SIZE: usize = 16;
const RLE_SIZE_HEADER: usize = 4;
const VEEAM_LZ4_MAGIC: u32 = 0xf800_000f;
const MAX_RECONSTRUCTED_BLOCK: u64 = 64 * 1024 * 1024;
const ZERO_CHUNK_SIZE: usize = 64 * 1024;
const ZERO_CHUNK_SIZE_U64: u64 = 64 * 1024;

/// Summary of a successfully reconstructed catalogue file.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExtractionReport {
    /// Exact catalogue name.
    pub name: String,
    /// Bytes written to the destination.
    pub bytes_written: u64,
    /// Logical block count.
    pub block_count: usize,
    /// Number of implicit zero blocks.
    pub sparse_blocks: usize,
    /// Number of physically compressed blocks.
    pub compressed_blocks: usize,
}

/// Summary of recursively extracting every catalogue file.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct BatchExtractionReport {
    /// Number of files created.
    pub files_written: usize,
    /// Sum of reconstructed logical file sizes.
    pub bytes_written: u64,
}

/// Position-independent reader for one reconstructed catalogue file.
#[derive(Debug)]
pub struct LogicalFileReader {
    reader: FileReader,
    physical: Vec<PhysicalBlock>,
    map: FileBlockMap,
    keysets: Option<RecoveredKeysets>,
    length: u64,
}

impl LogicalFileReader {
    /// Open one file by exact name or stable catalogue path.
    ///
    /// # Errors
    ///
    /// Returns an error for an unavailable item, malformed maps, unsupported references, or an
    /// absent or incorrect password.
    pub fn open(path: &Path, name: &str, password: Option<&str>) -> Result<Self> {
        let prepared = prepare_item(path, name, password)?;
        let reader = FileReader::open(path)?;
        let header = parse_header(path)?;
        let keysets = if header.encryption.encrypted {
            let password = password.ok_or_else(|| password_required(&header.encryption))?;
            Some(recover_reader_keysets(
                &reader,
                &header.encryption,
                password,
            )?)
        } else {
            None
        };
        let length = prepared.map.item.size.ok_or_else(|| {
            invalid_block(
                prepared.map.item.record_offset,
                "catalogue file size is missing",
            )
        })?;
        Ok(Self {
            reader,
            physical: prepared.physical,
            map: prepared.map,
            keysets,
            length,
        })
    }

    /// Return the reconstructed byte length.
    pub const fn len(&self) -> u64 {
        self.length
    }

    /// Whether the reconstructed file is empty.
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Read reconstructed bytes at `offset` without materializing the complete file.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid block data, decompression or decryption failures, unsupported
    /// references, digest mismatches, or offset arithmetic overflow.
    pub fn read_at(&self, output: &mut [u8], offset: u64) -> Result<usize> {
        if output.is_empty() || offset >= self.length {
            return Ok(0);
        }
        let requested = u64::try_from(output.len())
            .map_err(|error| invalid_block(offset, &error.to_string()))?;
        let request_end = offset.saturating_add(requested).min(self.length);
        let source = ReconstructionSource {
            reader: &self.reader,
            physical: &self.physical,
            keysets: self.keysets.as_ref(),
        };
        read_logical_range(&source, &self.map, output, offset, request_end)
    }
}

/// A [`crate::veeam::diskfs::ByteReader`] view of a reconstructed catalogue file.
///
/// Wraps a [`LogicalFileReader`] so a stored disk image can be walked (partition table,
/// FAT/NTFS) without copying it out first. Kept a distinct type rather than implementing the
/// trait on `LogicalFileReader` directly so its inherent `read_at` and the trait method do
/// not share a name.
#[derive(Debug)]
pub struct LogicalImageReader<'a>(&'a LogicalFileReader);

impl<'a> LogicalImageReader<'a> {
    /// View `reader` as a disk-image byte source.
    #[must_use]
    pub const fn new(reader: &'a LogicalFileReader) -> Self {
        Self(reader)
    }
}

impl crate::veeam::diskfs::ByteReader for LogicalImageReader<'_> {
    fn read_at(&self, buffer: &mut [u8], offset: u64) -> crate::veeam::diskfs::FsResult<usize> {
        self.0
            .read_at(buffer, offset)
            .map_err(|error| crate::veeam::diskfs::FsError::Io {
                message: error.to_string(),
            })
    }

    fn size(&self) -> u64 {
        self.0.len()
    }
}

fn read_logical_range(
    source: &ReconstructionSource<'_>,
    map: &FileBlockMap,
    output: &mut [u8],
    request_start: u64,
    request_end: u64,
) -> Result<usize> {
    let mut logical_start = 0_u64;
    let mut written = 0_usize;
    let mut counters = ReconstructionCounters::default();
    for logical in &map.blocks {
        let logical_end = logical_start
            .checked_add(u64::from(logical.raw_size))
            .ok_or_else(|| VbkError::OffsetOverflow {
                offset: logical_start,
                length: u64::from(logical.raw_size),
            })?;
        if logical_end > request_start && logical_start < request_end {
            written = read_logical_overlap(
                source,
                logical,
                output,
                LogicalOverlap {
                    logical_start,
                    logical_end,
                    request_start,
                    request_end,
                },
                &mut counters,
            )?;
        }
        logical_start = logical_end;
        if logical_start >= request_end {
            break;
        }
    }
    Ok(written)
}

#[derive(Clone, Copy, Debug)]
struct LogicalOverlap {
    logical_start: u64,
    logical_end: u64,
    request_start: u64,
    request_end: u64,
}

fn read_logical_overlap(
    source: &ReconstructionSource<'_>,
    logical: &LogicalBlock,
    output: &mut [u8],
    overlap: LogicalOverlap,
    counters: &mut ReconstructionCounters,
) -> Result<usize> {
    let start = overlap.logical_start.max(overlap.request_start);
    let end = overlap.logical_end.min(overlap.request_end);
    let output_start = usize::try_from(start - overlap.request_start)
        .map_err(|error| invalid_block(start, &error.to_string()))?;
    let output_end = usize::try_from(end - overlap.request_start)
        .map_err(|error| invalid_block(end, &error.to_string()))?;
    let target = output
        .get_mut(output_start..output_end)
        .ok_or_else(|| invalid_block(start, "logical read output range is invalid"))?;
    match logical.reference {
        BlockReference::Zero => {
            verify_sparse_digest(logical, counters)?;
            target.fill(0);
        }
        BlockReference::Local(_) => {
            read_stored_overlap(source, logical, target, start - overlap.logical_start)?
        }
        BlockReference::Parent(_) => return Err(unsupported_reference("parent", start)),
        BlockReference::Deduplicated(_) => {
            return Err(unsupported_reference("deduplicated", start));
        }
        BlockReference::External(_) => return Err(unsupported_reference("external", start)),
    }
    Ok(output_end)
}

fn read_stored_overlap(
    source: &ReconstructionSource<'_>,
    logical: &LogicalBlock,
    target: &mut [u8],
    source_start: u64,
) -> Result<()> {
    let stored = physical_block(logical, source.physical)?;
    let decoded = decode_physical_block(source.reader, stored, source.keysets)?;
    verify_digest(&decoded, logical.digest, stored.offset, "logical block")?;
    let source_start = usize::try_from(source_start)
        .map_err(|error| invalid_block(stored.offset, &error.to_string()))?;
    let source_end = source_start
        .checked_add(target.len())
        .ok_or_else(|| invalid_block(stored.offset, "logical read source range overflow"))?;
    let source_bytes = decoded
        .get(source_start..source_end)
        .ok_or_else(|| invalid_block(stored.offset, "logical read source range is invalid"))?;
    target.copy_from_slice(source_bytes);
    Ok(())
}

const fn unsupported_reference(kind: &'static str, offset: u64) -> VbkError {
    VbkError::UnsupportedBlockReference { kind, offset }
}

/// Reconstruct one catalogue file, selected by exact name, into a writer.
///
/// Every physically stored block is decompressed independently and verified against its MD5
/// digest before it is written. Sparse blocks are streamed as zeroes and verified as well.
///
/// # Errors
///
/// Returns an error for a missing or ambiguous name, invalid block metadata, unsupported
/// compression, decompression failure, digest mismatch, or destination IO failure.
pub fn extract_item<W: Write>(path: &Path, name: &str, output: &mut W) -> Result<ExtractionReport> {
    extract_item_with_password(path, name, output, None)
}

/// Reconstruct one catalogue file, decrypting metadata with `password` when required.
///
/// # Errors
///
/// Returns an error for absent or incorrect passwords, malformed metadata, missing or ambiguous
/// names, invalid block data, digest mismatches, or destination IO failures.
pub fn extract_item_with_password<W: Write>(
    path: &Path,
    name: &str,
    output: &mut W,
    password: Option<&str>,
) -> Result<ExtractionReport> {
    let prepared = prepare_item(path, name, password)?;
    reconstruct_map(path, &prepared.map, &prepared.physical, output, password)
}

/// Reconstruct one catalogue file into a newly created destination.
///
/// Existing destinations are never overwritten. A partial destination created by this call is
/// removed when reconstruction or flushing fails.
///
/// # Errors
///
/// Returns an extraction or IO error, including when the destination already exists.
pub fn extract_item_to_path(
    path: &Path,
    name: &str,
    destination: &Path,
) -> Result<ExtractionReport> {
    extract_item_to_path_with_password(path, name, destination, None)
}

/// Reconstruct one catalogue file into a new destination, decrypting metadata when required.
///
/// Existing destinations are never overwritten and a partial destination is removed on failure.
///
/// # Errors
///
/// Returns password, parsing, extraction, verification, or destination IO errors.
pub fn extract_item_to_path_with_password(
    path: &Path,
    name: &str,
    destination: &Path,
    password: Option<&str>,
) -> Result<ExtractionReport> {
    let prepared = prepare_item(path, name, password)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    let result =
        reconstruct_map_to_file(path, &prepared.map, &prepared.physical, &mut file, password)
            .and_then(|report| {
                file.flush()?;
                Ok(report)
            });
    if result.is_err() {
        drop(file);
        fs::remove_file(destination)?;
    }
    result
}

/// Summary of a best-effort partial reconstruction of an incremental (`Patch`/`Increment`) file.
///
/// The output spans the whole file; positions the increment did not store are written as zeros
/// because their unchanged data lives in the parent chain, which this file does not contain.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PartialExtractionReport {
    /// Exact catalogue name.
    pub name: String,
    /// Bytes written to the destination (the full file size).
    pub bytes_written: u64,
    /// Total 1 MiB positions in the file.
    pub total_blocks: u64,
    /// Positions recovered from this file's own data.
    pub local_blocks: u64,
    /// Positions this backup point stored as explicit zeros.
    pub explicit_sparse_blocks: u64,
    /// Positions left zero because they are unchanged and only exist in the parent chain.
    pub parent_absent_blocks: u64,
}

/// Result of an extraction that may target either a self-contained file or an incremental one.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtractionOutcome {
    /// A fully reconstructed self-contained file.
    Full(ExtractionReport),
    /// A best-effort partial reconstruction of an incremental file.
    Partial(PartialExtractionReport),
}

/// Reconstruct one file, allowing a best-effort partial result for incremental records.
///
/// For a self-contained file this behaves like [`extract_item_to_path_with_password`]. For an
/// incremental (`Patch`/`Increment`) record it reconstructs only when `allow_partial` is set,
/// zero-filling the unchanged regions that belong to the absent parent chain and reporting how much
/// was recovered locally; without `allow_partial` it returns [`VbkError::IncrementalRecordUnsupported`].
///
/// # Errors
///
/// Returns password, parsing, extraction, verification, or destination IO errors, or the
/// incremental-record error when a `.vib`/`.vrb` disk is targeted without `allow_partial`.
pub fn extract_item_to_path_with_options(
    path: &Path,
    name: &str,
    destination: &Path,
    password: Option<&str>,
    allow_partial: bool,
) -> Result<ExtractionOutcome> {
    let catalog = list_items_with_password(path, password)?;
    let item = unique_file(&catalog.items, name)?;
    if !item.is_patch {
        let report = extract_item_to_path_with_password(path, name, destination, password)?;
        return Ok(ExtractionOutcome::Full(report));
    }
    if !allow_partial {
        return Err(VbkError::IncrementalRecordUnsupported {
            record_offset: item.record_offset,
        });
    }
    let recovery = build_increment_recovery_with_password(path, item, password)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    let result =
        reconstruct_map_to_file(path, &recovery.map, &recovery.physical, &mut file, password)
            .and_then(|report| {
                file.flush()?;
                Ok(report)
            });
    if result.is_err() {
        drop(file);
        fs::remove_file(destination)?;
    }
    let report = result?;
    Ok(ExtractionOutcome::Partial(PartialExtractionReport {
        name: item.name.clone(),
        bytes_written: report.bytes_written,
        total_blocks: recovery.total_blocks,
        local_blocks: recovery.local_blocks,
        explicit_sparse_blocks: recovery.sparse_blocks,
        parent_absent_blocks: recovery.parent_blocks,
    }))
}

/// Extract every modern catalogue file below a newly created directory.
///
/// All catalogue paths and block capabilities are validated before the destination directory is
/// created. Existing destinations and files are never overwritten. If a later file fails, files
/// already completed in the new directory are retained for inspection.
///
/// # Errors
///
/// Returns an error for unsafe or duplicate catalogue paths, unsupported storage features,
/// malformed blocks, invalid passwords, existing destinations, or destination IO failures.
pub fn extract_all_to_directory(
    path: &Path,
    destination: &Path,
    password: Option<&str>,
) -> Result<BatchExtractionReport> {
    let prepared = prepare_backup(path, password)?;
    let relative_paths = validated_output_paths(&prepared.maps)?;
    fs::create_dir(destination)?;
    let mut report = BatchExtractionReport {
        files_written: 0,
        bytes_written: 0,
    };
    for (map, relative) in prepared.maps.iter().zip(relative_paths) {
        let output_path = destination.join(relative);
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let extraction =
            extract_prepared_map(path, map, &prepared.physical, &output_path, password)?;
        report.files_written = checked_count(report.files_written, "batch extraction file count")?;
        report.bytes_written = report
            .bytes_written
            .checked_add(extraction.bytes_written)
            .ok_or(VbkError::OffsetOverflow {
                offset: report.bytes_written,
                length: extraction.bytes_written,
            })?;
    }
    Ok(report)
}

fn validated_output_paths(maps: &[FileBlockMap]) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::with_capacity(maps.len());
    let mut unique = BTreeSet::new();
    for map in maps {
        let relative = safe_catalog_path(&map.item.path, map.item.record_offset)?;
        if !unique.insert(relative.clone()) {
            return Err(invalid_block(
                map.item.record_offset,
                "duplicate catalogue output path",
            ));
        }
        paths.push(relative);
    }
    if let Some(index) = parent_file_conflict(&paths) {
        let offset = maps.get(index).map_or(0, |map| map.item.record_offset);
        return Err(invalid_block(
            offset,
            "catalogue file path is the parent of another file path",
        ));
    }
    Ok(paths)
}

fn parent_file_conflict(paths: &[PathBuf]) -> Option<usize> {
    paths.iter().enumerate().find_map(|(index, path)| {
        paths
            .iter()
            .enumerate()
            .any(|(other_index, other)| index != other_index && other.starts_with(path))
            .then_some(index)
    })
}

fn safe_catalog_path(path: &str, offset: u64) -> Result<PathBuf> {
    let mut safe = PathBuf::new();
    for component in Path::new(path).components() {
        match component {
            Component::Normal(name) => safe.push(name),
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => {
                return Err(invalid_block(
                    offset,
                    "catalogue path is not a safe relative path",
                ));
            }
        }
    }
    if safe.as_os_str().is_empty() {
        return Err(invalid_block(offset, "catalogue path is empty"));
    }
    Ok(safe)
}

fn extract_prepared_map(
    path: &Path,
    map: &FileBlockMap,
    physical: &[PhysicalBlock],
    destination: &Path,
    password: Option<&str>,
) -> Result<ExtractionReport> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    let result =
        reconstruct_map_to_file(path, map, physical, &mut file, password).and_then(|report| {
            file.flush()?;
            Ok(report)
        });
    if result.is_err() {
        drop(file);
        fs::remove_file(destination)?;
    }
    result
}

#[derive(Debug)]
struct PreparedItem {
    physical: Vec<PhysicalBlock>,
    map: FileBlockMap,
}

#[derive(Debug)]
pub(crate) struct PreparedBackup {
    pub(crate) physical: Vec<PhysicalBlock>,
    pub(crate) maps: Vec<FileBlockMap>,
}

fn prepare_item(path: &Path, name: &str, password: Option<&str>) -> Result<PreparedItem> {
    let catalog = list_items_with_password(path, password)?;
    let item = unique_file(&catalog.items, name)?;
    let (physical, maps) =
        build_file_maps_with_password(path, std::slice::from_ref(item), password)?;
    let map = maps
        .into_iter()
        .find(|candidate| candidate.item.record_offset == item.record_offset)
        .ok_or_else(|| VbkError::ItemNotFound {
            name: name.to_owned(),
        })?;
    preflight_map(&map, &physical)?;
    Ok(PreparedItem { physical, map })
}

pub(crate) fn prepare_backup(path: &Path, password: Option<&str>) -> Result<PreparedBackup> {
    let catalog = list_items_with_password(path, password)?;
    let files = catalog
        .items
        .iter()
        .filter(|item| item.kind == StoredItemKind::File)
        .cloned()
        .collect::<Vec<_>>();
    let (physical, maps) = build_file_maps_with_password(path, &files, password)?;
    for map in &maps {
        preflight_map(map, &physical)?;
    }
    Ok(PreparedBackup { physical, maps })
}

pub(crate) fn verify_prepared_content(
    path: &Path,
    prepared: &PreparedBackup,
    password: Option<&str>,
) -> Result<usize> {
    let reader = FileReader::open(path)?;
    let header = parse_header(path)?;
    let keysets = if header.encryption.encrypted {
        let password = password.ok_or_else(|| password_required(&header.encryption))?;
        Some(recover_reader_keysets(
            &reader,
            &header.encryption,
            password,
        )?)
    } else {
        None
    };
    let source = ReconstructionSource {
        reader: &reader,
        physical: &prepared.physical,
        keysets: keysets.as_ref(),
    };
    let mut verified = 0_usize;
    let mut counters = ReconstructionCounters::default();
    for map in &prepared.maps {
        for logical in &map.blocks {
            verify_logical_content(&source, logical, &mut counters)?;
            verified = checked_count(verified, "verified content block count")?;
        }
    }
    Ok(verified)
}

fn verify_logical_content(
    source: &ReconstructionSource<'_>,
    logical: &LogicalBlock,
    counters: &mut ReconstructionCounters,
) -> Result<()> {
    match logical.reference {
        BlockReference::Zero => verify_sparse_digest(logical, counters),
        BlockReference::Local(_) => {
            let stored = physical_block(logical, source.physical)?;
            let decoded = decode_physical_block(source.reader, stored, source.keysets)?;
            verify_digest(&decoded, logical.digest, stored.offset, "logical block")
        }
        BlockReference::Parent(_) => Err(VbkError::UnsupportedBlockReference {
            kind: "parent",
            offset: 0,
        }),
        BlockReference::Deduplicated(_) => Err(VbkError::UnsupportedBlockReference {
            kind: "deduplicated",
            offset: 0,
        }),
        BlockReference::External(_) => Err(VbkError::UnsupportedBlockReference {
            kind: "external",
            offset: 0,
        }),
    }
}

fn unique_file<'a>(
    items: &'a [crate::veeam::StoredItem],
    name: &str,
) -> Result<&'a crate::veeam::StoredItem> {
    let matching = matching_file_count(items, name);
    if matching == 0 {
        return Err(VbkError::ItemNotFound {
            name: name.to_owned(),
        });
    }
    if matching > 1 {
        return Err(VbkError::AmbiguousItem {
            name: name.to_owned(),
            matches: matching,
        });
    }
    items
        .iter()
        .find(|item| item.kind == StoredItemKind::File && (item.name == name || item.path == name))
        .ok_or_else(|| VbkError::ItemNotFound {
            name: name.to_owned(),
        })
}

fn matching_file_count(items: &[crate::veeam::StoredItem], name: &str) -> usize {
    items
        .iter()
        .filter(|item| {
            item.kind == StoredItemKind::File && (item.name == name || item.path == name)
        })
        .count()
}

fn reconstruct_map<W: Write>(
    path: &Path,
    map: &FileBlockMap,
    physical: &[PhysicalBlock],
    output: &mut W,
    password: Option<&str>,
) -> Result<ExtractionReport> {
    let reader = FileReader::open(path)?;
    let header = parse_header(path)?;
    let keysets = if header.encryption.encrypted {
        let password = password.ok_or_else(|| password_required(&header.encryption))?;
        Some(recover_reader_keysets(
            &reader,
            &header.encryption,
            password,
        )?)
    } else {
        None
    };
    let mut counters = ReconstructionCounters::default();
    let source = ReconstructionSource {
        reader: &reader,
        physical,
        keysets: keysets.as_ref(),
    };
    for block in &map.blocks {
        write_logical_block(&source, block, output, &mut counters)?;
    }
    validate_file_size(map, counters.bytes_written)?;
    Ok(extraction_report(map, &counters))
}

fn reconstruct_map_to_file(
    path: &Path,
    map: &FileBlockMap,
    physical: &[PhysicalBlock],
    output: &mut File,
    password: Option<&str>,
) -> Result<ExtractionReport> {
    let reader = FileReader::open(path)?;
    let header = parse_header(path)?;
    let keysets = if header.encryption.encrypted {
        let password = password.ok_or_else(|| password_required(&header.encryption))?;
        Some(recover_reader_keysets(
            &reader,
            &header.encryption,
            password,
        )?)
    } else {
        None
    };
    let source = ReconstructionSource {
        reader: &reader,
        physical,
        keysets: keysets.as_ref(),
    };
    let mut counters = ReconstructionCounters::default();
    for block in &map.blocks {
        if block.reference == BlockReference::Zero {
            seek_sparse_block(block, output, &mut counters)?;
        } else {
            write_logical_block(&source, block, output, &mut counters)?;
        }
    }
    validate_file_size(map, counters.bytes_written)?;
    output.set_len(counters.bytes_written)?;
    Ok(extraction_report(map, &counters))
}

fn extraction_report(map: &FileBlockMap, counters: &ReconstructionCounters) -> ExtractionReport {
    ExtractionReport {
        name: map.item.name.clone(),
        bytes_written: counters.bytes_written,
        block_count: map.blocks.len(),
        sparse_blocks: counters.sparse_blocks,
        compressed_blocks: counters.compressed_blocks,
    }
}

#[derive(Debug, Default)]
struct ReconstructionCounters {
    bytes_written: u64,
    sparse_blocks: usize,
    compressed_blocks: usize,
    zero_digests: BTreeMap<(u32, u8), Digest>,
}

#[derive(Debug)]
struct ReconstructionSource<'source> {
    reader: &'source FileReader,
    physical: &'source [PhysicalBlock],
    keysets: Option<&'source RecoveredKeysets>,
}

fn write_logical_block<W: Write>(
    source: &ReconstructionSource<'_>,
    logical: &LogicalBlock,
    output: &mut W,
    counters: &mut ReconstructionCounters,
) -> Result<()> {
    if logical.reference == BlockReference::Zero {
        verify_sparse_digest(logical, counters)?;
        write_sparse_block(logical, output)?;
        counters.sparse_blocks = checked_count(counters.sparse_blocks, "sparse block count")?;
    } else {
        let stored = physical_block(logical, source.physical)?;
        let decoded = decode_physical_block(source.reader, stored, source.keysets)?;
        verify_digest(&decoded, logical.digest, stored.offset, "logical block")?;
        output.write_all(&decoded)?;
        if stored.compression.is_compressed() {
            counters.compressed_blocks =
                checked_count(counters.compressed_blocks, "compressed block count")?;
        }
    }
    count_logical_block(logical, counters)?;
    Ok(())
}

fn seek_sparse_block(
    logical: &LogicalBlock,
    output: &mut File,
    counters: &mut ReconstructionCounters,
) -> Result<()> {
    verify_sparse_digest(logical, counters)?;
    let distance = i64::from(logical.raw_size);
    let _position = output.seek(SeekFrom::Current(distance))?;
    counters.sparse_blocks = checked_count(counters.sparse_blocks, "sparse block count")?;
    count_logical_block(logical, counters)
}

fn count_logical_block(
    logical: &LogicalBlock,
    counters: &mut ReconstructionCounters,
) -> Result<()> {
    counters.bytes_written = counters
        .bytes_written
        .checked_add(u64::from(logical.raw_size))
        .ok_or_else(|| VbkError::OffsetOverflow {
            offset: counters.bytes_written,
            length: u64::from(logical.raw_size),
        })?;
    Ok(())
}

fn physical_block<'a>(
    logical: &LogicalBlock,
    physical: &'a [PhysicalBlock],
) -> Result<&'a PhysicalBlock> {
    let index = match logical.reference {
        BlockReference::Local(index) => index,
        BlockReference::Zero => return Err(invalid_block(0, "zero block has no physical index")),
        BlockReference::Parent(_) => {
            return Err(VbkError::UnsupportedBlockReference {
                kind: "parent",
                offset: 0,
            });
        }
        BlockReference::Deduplicated(_) => {
            return Err(VbkError::UnsupportedBlockReference {
                kind: "deduplicated",
                offset: 0,
            });
        }
        BlockReference::External(_) => {
            return Err(VbkError::UnsupportedBlockReference {
                kind: "external",
                offset: 0,
            });
        }
    };
    let index = usize::try_from(index).map_err(|error| invalid_block(0, &error.to_string()))?;
    physical
        .get(index)
        .ok_or_else(|| invalid_block(0, "physical block index is outside the table"))
}

fn preflight_map(map: &FileBlockMap, physical: &[PhysicalBlock]) -> Result<()> {
    for logical in &map.blocks {
        match logical.reference {
            BlockReference::Zero => {}
            BlockReference::Local(_) => {
                let stored = physical_block(logical, physical)?;
                preflight_compression(stored.compression, stored.offset)?;
            }
            BlockReference::Parent(_) => {
                return Err(VbkError::UnsupportedBlockReference {
                    kind: "parent",
                    offset: map.item.record_offset,
                });
            }
            BlockReference::Deduplicated(_) => {
                return Err(VbkError::UnsupportedBlockReference {
                    kind: "deduplicated",
                    offset: map.item.record_offset,
                });
            }
            BlockReference::External(_) => {
                return Err(VbkError::UnsupportedBlockReference {
                    kind: "external",
                    offset: map.item.record_offset,
                });
            }
        }
    }
    Ok(())
}

fn preflight_compression(compression: Compression, offset: u64) -> Result<()> {
    match compression {
        Compression::None
        | Compression::Rle
        | Compression::Zlib
        | Compression::Lz4
        | Compression::Zstd
        | Compression::VeeamLz4 => Ok(()),
        Compression::Unsupported(compression) => Err(VbkError::UnsupportedCompression {
            compression,
            offset,
        }),
    }
}

fn decode_physical_block(
    reader: &FileReader,
    block: &PhysicalBlock,
    keysets: Option<&RecoveredKeysets>,
) -> Result<Vec<u8>> {
    validate_raw_size(block)?;
    let stored = reader.read_bytes(block.offset, u64::from(block.stored_size), "stored block")?;
    let stored = decrypt_stored_block(stored, block, keysets)?;
    decode_stored_block(stored, block)
}

fn decode_stored_block(stored: Vec<u8>, block: &PhysicalBlock) -> Result<Vec<u8>> {
    let decoded = match block.compression {
        Compression::VeeamLz4 => decode_veeam_lz4(&stored, block)?,
        Compression::None => decode_uncompressed(stored, block)?,
        Compression::Rle => decode_rle(&stored, block)?,
        Compression::Zlib => decode_zlib(&stored, block)?,
        Compression::Lz4 => decode_lz4(&stored, block)?,
        Compression::Zstd => decode_zstd(&stored, block)?,
        Compression::Unsupported(compression) => {
            return Err(VbkError::UnsupportedCompression {
                compression,
                offset: block.offset,
            });
        }
    };
    verify_digest(&decoded, block.digest, block.offset, "physical block")?;
    Ok(decoded)
}

fn decrypt_stored_block(
    stored: Vec<u8>,
    block: &PhysicalBlock,
    keysets: Option<&RecoveredKeysets>,
) -> Result<Vec<u8>> {
    let Some(identifier) = block.keyset_id else {
        return Ok(stored);
    };
    let keysets = keysets
        .ok_or_else(|| invalid_block(block.offset, "encrypted block has no recovered keysets"))?;
    let keyset = keysets
        .get(identifier)
        .ok_or_else(|| invalid_block(block.offset, "encrypted block keyset was not recovered"))?;
    keyset.decrypt_padded(&stored, block.offset)
}

fn password_required(encryption: &crate::veeam::EncryptionInfo) -> VbkError {
    let keyset_suffix = encryption
        .keyset_ids
        .first()
        .map_or_else(String::new, |identifier| format!(" (keyset {identifier})"));
    VbkError::PasswordRequired { keyset_suffix }
}

fn validate_raw_size(block: &PhysicalBlock) -> Result<()> {
    if block.raw_size > MAX_RECONSTRUCTED_BLOCK {
        return Err(VbkError::LimitExceeded {
            resource: "reconstructed block size",
            actual: block.raw_size,
            limit: MAX_RECONSTRUCTED_BLOCK,
        });
    }
    Ok(())
}

fn decode_veeam_lz4(stored: &[u8], block: &PhysicalBlock) -> Result<Vec<u8>> {
    let header = stored
        .get(..VEEAM_LZ4_HEADER_SIZE)
        .ok_or_else(|| invalid_block(block.offset, "truncated Veeam LZ4 header"))?;
    let magic = read_header_u32(header, 0, block.offset)?;
    // Bytes 4..8 hold a writer-side checksum. `dissect.archive` names it `CRC` (CRC32C),
    // but neither the plain nor the reflected Castagnoli polynomial matches the field on
    // real backups, and dissect itself never verifies it. Extract.exe's authoritative
    // check happens at the higher digest layer (section 8.2), so `vbktool` intentionally
    // skips this field and relies on the per-block BLAKE3-128 or MD5 digest instead.
    let declared_size = u64::from(read_header_u32(header, 8, block.offset)?);
    if magic != VEEAM_LZ4_MAGIC || declared_size != block.raw_size {
        return Err(invalid_block(
            block.offset,
            "invalid Veeam LZ4 magic or raw size",
        ));
    }
    let payload = stored
        .get(VEEAM_LZ4_HEADER_SIZE..)
        .ok_or_else(|| invalid_block(block.offset, "missing Veeam LZ4 payload"))?;
    let raw_size = usize::try_from(block.raw_size)
        .map_err(|error| invalid_block(block.offset, &error.to_string()))?;
    let decoded = lz4_flex::block::decompress(payload, raw_size)
        .map_err(|error| invalid_block(block.offset, &format!("LZ4 decode failed: {error}")))?;
    checked_decoded_length(decoded, block, "Veeam LZ4")
}

fn decode_uncompressed(stored: Vec<u8>, block: &PhysicalBlock) -> Result<Vec<u8>> {
    let stored_size = u64::try_from(stored.len())
        .map_err(|error| invalid_block(block.offset, &error.to_string()))?;
    if stored_size != block.raw_size {
        return Err(invalid_block(
            block.offset,
            "uncompressed stored and raw sizes differ",
        ));
    }
    Ok(stored)
}

/// Enforce the decoded-length invariant for decoders (LZ4, Veeam-LZ4, Zstandard) whose library
/// treats `raw_size` as a capacity hint and can return fewer bytes without erroring. A short buffer
/// would otherwise be silently zero-padded to the file size on a digest-less block.
fn checked_decoded_length(
    decoded: Vec<u8>,
    block: &PhysicalBlock,
    algorithm: &str,
) -> Result<Vec<u8>> {
    let actual = u64::try_from(decoded.len())
        .map_err(|error| invalid_block(block.offset, &error.to_string()))?;
    if actual != block.raw_size {
        return Err(invalid_block(
            block.offset,
            &format!(
                "{algorithm} decoded {actual} bytes but the descriptor declares {}",
                block.raw_size
            ),
        ));
    }
    Ok(decoded)
}

fn decode_zlib(stored: &[u8], block: &PhysicalBlock) -> Result<Vec<u8>> {
    let payload = compressed_payload(stored, block)?;
    let decoder = flate2::read::ZlibDecoder::new(payload);
    decode_reader(decoder, block.raw_size, block.offset, "zlib")
}

fn decode_rle(stored: &[u8], block: &PhysicalBlock) -> Result<Vec<u8>> {
    let payload = compressed_payload(stored, block)?;
    let header = payload
        .get(..RLE_SIZE_HEADER)
        .ok_or_else(|| invalid_block(block.offset, "truncated RLE size header"))?;
    let declared = u64::from(read_header_u32(header, 0, block.offset)?);
    if declared != block.raw_size {
        return Err(invalid_block(
            block.offset,
            "RLE size does not match its descriptor",
        ));
    }
    let encoded = payload
        .get(RLE_SIZE_HEADER..)
        .ok_or_else(|| invalid_block(block.offset, "missing RLE payload"))?;
    decode_rle_bytes(encoded, block.raw_size, block.offset)
}

fn decode_rle_bytes(encoded: &[u8], raw_size: u64, offset: u64) -> Result<Vec<u8>> {
    let capacity =
        usize::try_from(raw_size).map_err(|error| invalid_block(offset, &error.to_string()))?;
    let mut output = Vec::with_capacity(capacity);
    let mut cursor = 0_usize;
    while cursor < encoded.len() {
        let value = encoded
            .get(cursor)
            .copied()
            .ok_or_else(|| invalid_block(offset, "RLE cursor is outside the payload"))?;
        cursor = cursor
            .checked_add(1)
            .ok_or_else(|| invalid_block(offset, "RLE cursor overflow"))?;
        let count = rle_run_length(encoded, &mut cursor, value, offset)?;
        let new_length = output
            .len()
            .checked_add(count)
            .ok_or_else(|| invalid_block(offset, "RLE output length overflow"))?;
        if new_length > capacity {
            return Err(invalid_block(
                offset,
                "RLE output exceeds its declared size",
            ));
        }
        output.resize(new_length, value);
    }
    if output.len() != capacity {
        return Err(invalid_block(
            offset,
            "RLE output size differs from its declaration",
        ));
    }
    Ok(output)
}

fn rle_run_length(encoded: &[u8], cursor: &mut usize, value: u8, offset: u64) -> Result<usize> {
    if encoded.get(*cursor).copied() != Some(value) {
        return Ok(1);
    }
    let count_offset = cursor
        .checked_add(1)
        .ok_or_else(|| invalid_block(offset, "RLE run offset overflow"))?;
    let count = encoded
        .get(count_offset)
        .copied()
        .ok_or_else(|| invalid_block(offset, "truncated RLE run"))?;
    if count < 2 {
        return Err(invalid_block(offset, "RLE run length is smaller than two"));
    }
    *cursor = count_offset
        .checked_add(1)
        .ok_or_else(|| invalid_block(offset, "RLE cursor overflow"))?;
    Ok(usize::from(count))
}

fn decode_lz4(stored: &[u8], block: &PhysicalBlock) -> Result<Vec<u8>> {
    let payload = compressed_payload(stored, block)?;
    let raw_size = usize::try_from(block.raw_size)
        .map_err(|error| invalid_block(block.offset, &error.to_string()))?;
    let decoded = lz4_flex::block::decompress(payload, raw_size)
        .map_err(|error| invalid_block(block.offset, &format!("LZ4 decode failed: {error}")))?;
    checked_decoded_length(decoded, block, "LZ4")
}

fn decode_zstd(stored: &[u8], block: &PhysicalBlock) -> Result<Vec<u8>> {
    let payload = compressed_payload(stored, block)?;
    let raw_size = usize::try_from(block.raw_size)
        .map_err(|error| invalid_block(block.offset, &error.to_string()))?;
    let decoded = zstd::bulk::decompress(payload, raw_size).map_err(|error| {
        invalid_block(block.offset, &format!("Zstandard decode failed: {error}"))
    })?;
    checked_decoded_length(decoded, block, "Zstandard")
}

fn compressed_payload<'stored>(
    stored: &'stored [u8],
    block: &PhysicalBlock,
) -> Result<&'stored [u8]> {
    let header = stored
        .get(..COMPRESSED_HEADER_SIZE)
        .ok_or_else(|| invalid_block(block.offset, "truncated compressed-block header"))?;
    let raw_size = read_header_u64(header, 0, block.offset)?;
    let compressed_size = read_header_u64(header, 8, block.offset)?;
    let payload = stored
        .get(COMPRESSED_HEADER_SIZE..)
        .ok_or_else(|| invalid_block(block.offset, "missing compressed-block payload"))?;
    let actual_size = u64::try_from(payload.len())
        .map_err(|error| invalid_block(block.offset, &error.to_string()))?;
    if raw_size != block.raw_size || compressed_size != actual_size {
        return Err(invalid_block(
            block.offset,
            "compressed-block header sizes do not match its descriptor or payload",
        ));
    }
    Ok(payload)
}

fn decode_reader<R: Read>(
    decoder: R,
    raw_size: u64,
    offset: u64,
    algorithm: &str,
) -> Result<Vec<u8>> {
    let capacity =
        usize::try_from(raw_size).map_err(|error| invalid_block(offset, &error.to_string()))?;
    let limit = raw_size.checked_add(1).ok_or(VbkError::OffsetOverflow {
        offset,
        length: raw_size,
    })?;
    let mut output = Vec::with_capacity(capacity);
    let _decoded_size = decoder
        .take(limit)
        .read_to_end(&mut output)
        .map_err(|error| invalid_block(offset, &format!("{algorithm} decode failed: {error}")))?;
    let actual =
        u64::try_from(output.len()).map_err(|error| invalid_block(offset, &error.to_string()))?;
    if actual != raw_size {
        return Err(invalid_block(
            offset,
            "decompressed size differs from its declaration",
        ));
    }
    Ok(output)
}

fn write_sparse_block<W: Write>(logical: &LogicalBlock, output: &mut W) -> Result<()> {
    let zeros = vec![0_u8; ZERO_CHUNK_SIZE];
    let mut remaining = u64::from(logical.raw_size);
    while remaining > 0 {
        let length = usize::try_from(remaining.min(ZERO_CHUNK_SIZE_U64))
            .map_err(|error| invalid_block(0, &error.to_string()))?;
        let chunk = zeros
            .get(..length)
            .ok_or_else(|| invalid_block(0, "zero chunk length is out of bounds"))?;
        output.write_all(chunk)?;
        remaining -= u64::try_from(length).map_err(|error| invalid_block(0, &error.to_string()))?;
    }
    Ok(())
}

fn verify_sparse_digest(
    logical: &LogicalBlock,
    counters: &mut ReconstructionCounters,
) -> Result<()> {
    if logical.digest == Digest::None {
        return Ok(());
    }
    let key = (logical.raw_size, digest_identifier(logical.digest));
    let calculated = if let Some(digest) = counters.zero_digests.get(&key) {
        *digest
    } else {
        let digest = zero_digest(logical.raw_size, logical.digest)?;
        let _previous = counters.zero_digests.insert(key, digest);
        digest
    };
    if calculated != logical.digest {
        return Err(VbkError::DigestMismatch {
            resource: "sparse logical block",
            offset: 0,
        });
    }
    Ok(())
}

fn zero_digest(raw_size: u32, algorithm: Digest) -> Result<Digest> {
    let zeros = vec![0_u8; ZERO_CHUNK_SIZE];
    let mut remaining = u64::from(raw_size);
    match algorithm {
        Digest::None => Ok(Digest::None),
        Digest::Md5(_) => {
            let mut engine = Md5::new();
            update_zero_digest(&mut engine, &zeros, &mut remaining)?;
            Ok(Digest::Md5(engine.finalize().into()))
        }
        Digest::Sha256(_) => {
            let mut engine = Sha256::new();
            update_zero_digest(&mut engine, &zeros, &mut remaining)?;
            Ok(Digest::Sha256(engine.finalize().into()))
        }
        Digest::Blake3_128(_) => {
            let mut engine = blake3::Hasher::new();
            update_blake3_zeros(&mut engine, &zeros, &mut remaining)?;
            let mut truncated = [0_u8; 16];
            let bytes = engine.finalize();
            truncated.copy_from_slice(bytes.as_bytes().get(..16).ok_or_else(|| {
                invalid_block(
                    0,
                    "BLAKE3 output is shorter than its 128-bit representation",
                )
            })?);
            Ok(Digest::Blake3_128(truncated))
        }
    }
}

fn verify_digest(
    bytes: &[u8],
    expected: Digest,
    offset: u64,
    resource: &'static str,
) -> Result<()> {
    if calculate_digest(bytes, expected)? != expected {
        return Err(VbkError::DigestMismatch { resource, offset });
    }
    Ok(())
}

fn calculate_digest(bytes: &[u8], algorithm: Digest) -> Result<Digest> {
    match algorithm {
        Digest::None => Ok(Digest::None),
        Digest::Md5(_) => Ok(Digest::Md5(Md5::digest(bytes).into())),
        Digest::Sha256(_) => Ok(Digest::Sha256(Sha256::digest(bytes).into())),
        Digest::Blake3_128(_) => {
            let mut truncated = [0_u8; 16];
            let digest = blake3::hash(bytes);
            truncated.copy_from_slice(digest.as_bytes().get(..16).ok_or_else(|| {
                invalid_block(
                    0,
                    "BLAKE3 output is shorter than its 128-bit representation",
                )
            })?);
            Ok(Digest::Blake3_128(truncated))
        }
    }
}

fn update_zero_digest<D: DigestEngine>(
    engine: &mut D,
    zeros: &[u8],
    remaining: &mut u64,
) -> Result<()> {
    while *remaining > 0 {
        let chunk = zero_chunk(zeros, *remaining)?;
        engine.update(chunk);
        *remaining -=
            u64::try_from(chunk.len()).map_err(|error| invalid_block(0, &error.to_string()))?;
    }
    Ok(())
}

fn update_blake3_zeros(
    engine: &mut blake3::Hasher,
    zeros: &[u8],
    remaining: &mut u64,
) -> Result<()> {
    while *remaining > 0 {
        let chunk = zero_chunk(zeros, *remaining)?;
        let _engine = engine.update(chunk);
        *remaining -=
            u64::try_from(chunk.len()).map_err(|error| invalid_block(0, &error.to_string()))?;
    }
    Ok(())
}

fn zero_chunk(zeros: &[u8], remaining: u64) -> Result<&[u8]> {
    let length = usize::try_from(remaining.min(ZERO_CHUNK_SIZE_U64))
        .map_err(|error| invalid_block(0, &error.to_string()))?;
    zeros
        .get(..length)
        .ok_or_else(|| invalid_block(0, "zero chunk length is out of bounds"))
}

const fn digest_identifier(digest: Digest) -> u8 {
    match digest {
        Digest::None => 0,
        Digest::Md5(_) => 1,
        Digest::Sha256(_) => 2,
        Digest::Blake3_128(_) => 3,
    }
}

fn validate_file_size(map: &FileBlockMap, actual: u64) -> Result<()> {
    let expected = map
        .item
        .size
        .ok_or_else(|| invalid_block(map.item.record_offset, "catalogue file size is missing"))?;
    if actual != expected {
        return Err(invalid_block(
            map.item.record_offset,
            "reconstructed file size differs",
        ));
    }
    Ok(())
}

fn read_header_u32(header: &[u8], offset: usize, block_offset: u64) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| invalid_block(block_offset, "compression header offset overflow"))?;
    let bytes = header
        .get(offset..end)
        .ok_or_else(|| invalid_block(block_offset, "truncated compression header field"))?;
    let array = <[u8; 4]>::try_from(bytes)
        .map_err(|error| invalid_block(block_offset, &error.to_string()))?;
    Ok(u32::from_le_bytes(array))
}

fn read_header_u64(header: &[u8], offset: usize, block_offset: u64) -> Result<u64> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| invalid_block(block_offset, "compression header offset overflow"))?;
    let bytes = header
        .get(offset..end)
        .ok_or_else(|| invalid_block(block_offset, "truncated compression header field"))?;
    let array = <[u8; 8]>::try_from(bytes)
        .map_err(|error| invalid_block(block_offset, &error.to_string()))?;
    Ok(u64::from_le_bytes(array))
}

fn invalid_block(offset: u64, reason: &str) -> VbkError {
    VbkError::InvalidField {
        offset,
        field: "content_block",
        reason: reason.to_owned(),
    }
}

fn checked_count(count: usize, resource: &'static str) -> Result<usize> {
    count.checked_add(1).ok_or(VbkError::LimitExceeded {
        resource,
        actual: u64::MAX,
        limit: u64::MAX - 1,
    })
}
