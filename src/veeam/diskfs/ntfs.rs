//! Read-only NTFS walker (boot sector, MFT, directory indexes, `$DATA`).

use std::collections::BTreeMap;

use super::{ByteReader, FileSystem, FsEntry, FsError, FsResult, MAX_FS_FILE_SIZE, read_exact_at};

const NTFS_OEM: &[u8; 8] = b"NTFS    ";
const FILE_SIGNATURE: &[u8; 4] = b"FILE";
const INDX_SIGNATURE: &[u8; 4] = b"INDX";
const ROOT_RECORD: u64 = 5;
const ATTR_DATA: u32 = 0x80;
const ATTR_INDEX_ROOT: u32 = 0x90;
const ATTR_INDEX_ALLOCATION: u32 = 0xa0;
const ATTR_END: u32 = 0xffff_ffff;
const MAX_RUN_CLUSTERS: u64 = 1 << 34;
const MAX_INDEX_ENTRIES: usize = 1 << 20;

/// A mounted NTFS filesystem over a partition-sized [`ByteReader`].
#[derive(Debug)]
pub struct NtfsFileSystem<'a, R: ByteReader + ?Sized> {
    reader: &'a R,
    bytes_per_sector: u64,
    bytes_per_cluster: u64,
    mft_offset: u64,
    record_size: u64,
    index_record_size: u64,
}

/// Whether `reader` opens with an NTFS boot sector.
///
/// # Errors
///
/// Returns an error only when the boot sector cannot be read.
pub(crate) fn is_ntfs<R: ByteReader + ?Sized>(reader: &R) -> FsResult<bool> {
    let sector = read_exact_at(reader, 0, 512)?;
    Ok(sector.get(3..11) == Some(NTFS_OEM.as_slice()))
}

impl<'a, R: ByteReader + ?Sized> NtfsFileSystem<'a, R> {
    /// Parse the boot sector and locate the MFT.
    ///
    /// # Errors
    ///
    /// Returns an error for an out-of-range boot-sector field or an IO failure.
    pub fn open(reader: &'a R) -> FsResult<Self> {
        let boot = read_exact_at(reader, 0, 512)?;
        let bytes_per_sector = u64::from(read_u16(&boot, 0x0b)?);
        let sectors_per_cluster = u64::from(read_u8(&boot, 0x0d)?);
        if !(bytes_per_sector.is_power_of_two() && (512..=4096).contains(&bytes_per_sector)) {
            return Err(corrupt("NTFS boot", "implausible bytes-per-sector"));
        }
        if sectors_per_cluster == 0 || !sectors_per_cluster.is_power_of_two() {
            return Err(corrupt("NTFS boot", "implausible sectors-per-cluster"));
        }
        let bytes_per_cluster = bytes_per_sector.saturating_mul(sectors_per_cluster);
        let mft_cluster = read_u64(&boot, 0x30)?;
        let record_size = clusters_or_bytes(read_i8(&boot, 0x40)?, bytes_per_cluster);
        if record_size == 0 || record_size > 64 * 1024 {
            return Err(corrupt("NTFS boot", "implausible MFT record size"));
        }
        // Bytes per index record (BPB +0x44) uses the same clusters-or-bytes encoding as the MFT
        // record size. It is the stride between INDX blocks, which is NOT the cluster size on
        // volumes with clusters larger than the index record.
        let index_record_size = clusters_or_bytes(read_i8(&boot, 0x44)?, bytes_per_cluster);
        if index_record_size == 0 || index_record_size > 64 * 1024 {
            return Err(corrupt("NTFS boot", "implausible index record size"));
        }
        Ok(Self {
            reader,
            bytes_per_sector,
            bytes_per_cluster,
            mft_offset: mft_cluster.saturating_mul(bytes_per_cluster),
            record_size,
            index_record_size,
        })
    }

    /// Read and fix up one MFT record by number.
    fn read_record(&self, number: u64) -> FsResult<Vec<u8>> {
        let offset = self
            .mft_offset
            .saturating_add(number.saturating_mul(self.record_size));
        let length = usize::try_from(self.record_size).unwrap_or(0);
        let mut record = read_exact_at(self.reader, offset, length)?;
        if record.get(0..4) != Some(FILE_SIGNATURE.as_slice()) {
            return Err(corrupt("MFT record", "missing FILE signature"));
        }
        apply_fixups(&mut record, self.bytes_per_sector)?;
        Ok(record)
    }

    /// Iterate a record's attributes, invoking `visit` with (type, record slice, header offset).
    fn each_attribute(
        record: &[u8],
        mut visit: impl FnMut(u32, usize) -> FsResult<bool>,
    ) -> FsResult<()> {
        let first = usize::from(read_u16(record, 0x14)?);
        let mut cursor = first;
        let mut guard = 0_u32;
        while let Ok(kind) = read_u32(record, cursor) {
            guard = guard.saturating_add(1);
            if kind == ATTR_END || guard > 4096 {
                break;
            }
            let length = read_u32(record, cursor.saturating_add(4))?;
            if length == 0 {
                break;
            }
            if !visit(kind, cursor)? {
                break;
            }
            cursor = cursor.saturating_add(usize::try_from(length).unwrap_or(0));
        }
        Ok(())
    }

    /// Collect a non-resident attribute's data runs, including sparse holes.
    fn data_runs(&self, record: &[u8], header: usize) -> FsResult<Vec<DataRun>> {
        let run_offset =
            header.saturating_add(usize::from(read_u16(record, header.saturating_add(0x20))?));
        let runs = record.get(run_offset..).unwrap_or(&[]);
        Ok(decode_runs(runs, self.bytes_per_cluster))
    }

    /// Read a `$DATA`-like attribute's full content (resident or non-resident) up to `limit`.
    fn read_attribute_data(&self, record: &[u8], header: usize, limit: u64) -> FsResult<Vec<u8>> {
        let non_resident = read_u8(record, header.saturating_add(8))?;
        if non_resident == 0 {
            let length =
                usize::try_from(read_u32(record, header.saturating_add(0x10))?).unwrap_or(0);
            let value_offset =
                header.saturating_add(usize::from(read_u16(record, header.saturating_add(0x14))?));
            let end = value_offset.saturating_add(length);
            let slice = record
                .get(value_offset..end)
                .ok_or_else(|| corrupt("resident data", "range"))?;
            return Ok(slice.to_vec());
        }
        // Compressed (LZNT1) or encrypted attributes cannot be decoded here; refuse rather than
        // emit their raw/partial bytes as if they were the file content.
        let flags = read_u16(record, header.saturating_add(0x0c))?;
        if flags & 0x0001 != 0 {
            return Err(corrupt(
                "non-resident data",
                "NTFS-compressed attribute is not supported",
            ));
        }
        if flags & 0x4000 != 0 {
            return Err(corrupt(
                "non-resident data",
                "NTFS-encrypted attribute is not supported",
            ));
        }
        let real_size = read_u64(record, header.saturating_add(0x30))?;
        let capped = real_size.min(limit);
        let mut data = Vec::new();
        for run in self.data_runs(record, header)? {
            let remaining = capped.saturating_sub(u64::try_from(data.len()).unwrap_or(u64::MAX));
            if remaining == 0 {
                break;
            }
            let want = usize::try_from(run.length.min(remaining)).unwrap_or(0);
            match run.offset {
                // Sparse hole: no backing bytes on disk — the region reads as zeros. Synthesising
                // the hole keeps every later run at its correct file offset.
                None => data.resize(data.len().saturating_add(want), 0),
                Some(offset) => data.extend_from_slice(&read_exact_at(self.reader, offset, want)?),
            }
        }
        data.truncate(usize::try_from(capped).unwrap_or(0));
        Ok(data)
    }

    /// Gather every index entry of a directory record into a name-keyed entry map.
    fn directory_entries(&self, record: &[u8]) -> FsResult<Vec<FsEntry>> {
        let mut blocks: Vec<Vec<u8>> = Vec::new();
        let mut index_root: Option<usize> = None;
        let mut alloc_header: Option<usize> = None;
        Self::each_attribute(record, |kind, header| {
            match kind {
                ATTR_INDEX_ROOT => index_root = Some(header),
                ATTR_INDEX_ALLOCATION => alloc_header = Some(header),
                _ => {}
            }
            Ok(true)
        })?;

        let mut entries: BTreeMap<String, FsEntry> = BTreeMap::new();
        if let Some(header) = index_root {
            let value_offset =
                header.saturating_add(usize::from(read_u16(record, header.saturating_add(0x14))?));
            // INDEX_ROOT: index header sits 16 bytes into the attribute value.
            let node = value_offset.saturating_add(16);
            let first = node
                .saturating_add(usize::try_from(read_u32(record, node).unwrap_or(0)).unwrap_or(0));
            let end = node.saturating_add(
                usize::try_from(read_u32(record, node.saturating_add(4)).unwrap_or(0)).unwrap_or(0),
            );
            collect_index_entries(record.get(first..end).unwrap_or(&[]), &mut entries);
        }
        if let Some(header) = alloc_header {
            let data = self.read_attribute_data(record, header, u64::from(u32::MAX))?;
            blocks.push(data);
        }
        for block in &blocks {
            self.walk_index_allocation(block, &mut entries);
        }
        Ok(entries.into_values().collect())
    }

    fn walk_index_allocation(&self, data: &[u8], entries: &mut BTreeMap<String, FsEntry>) {
        // Step by the index-record size, not the cluster size: when clusters are larger than the
        // index record (e.g. 8 KiB clusters, 4 KiB index records), striding by the cluster size
        // would skip the INDX blocks that sit inside a cluster and drop their directory entries.
        let step = usize::try_from(self.index_record_size.max(self.bytes_per_sector))
            .unwrap_or(4096)
            .max(512);
        let mut position = 0_usize;
        while let Some(chunk) = data.get(position..position.saturating_add(step)) {
            if chunk.get(0..4) == Some(INDX_SIGNATURE.as_slice()) {
                let mut record = chunk.to_vec();
                if apply_fixups(&mut record, self.bytes_per_sector).is_ok() {
                    // The index-node header begins at offset 0x18 in an INDX block.
                    let node = 0x18_usize;
                    let first = node.saturating_add(
                        usize::try_from(read_u32(&record, node).unwrap_or(0)).unwrap_or(0),
                    );
                    let end = node.saturating_add(
                        usize::try_from(read_u32(&record, node.saturating_add(4)).unwrap_or(0))
                            .unwrap_or(0),
                    );
                    collect_index_entries(record.get(first..end).unwrap_or(&[]), entries);
                }
            }
            position = position.saturating_add(step);
        }
    }

    /// Read a file record's unnamed `$DATA` into `output`, capped at [`MAX_FS_FILE_SIZE`].
    fn read_data(&self, record: &[u8], output: &mut Vec<u8>) -> FsResult<()> {
        let mut data_header: Option<usize> = None;
        Self::each_attribute(record, |kind, header| {
            if kind == ATTR_DATA && data_header.is_none() {
                // Only the unnamed data stream (name length 0 at header+9).
                if read_u8(record, header.saturating_add(9)).unwrap_or(0) == 0 {
                    data_header = Some(header);
                }
            }
            Ok(true)
        })?;
        let header = data_header.ok_or_else(|| corrupt("file", "no $DATA attribute"))?;
        let data = self.read_attribute_data(record, header, MAX_FS_FILE_SIZE)?;
        output.clear();
        output.extend_from_slice(&data);
        Ok(())
    }
}

impl<R: ByteReader + ?Sized> FileSystem for NtfsFileSystem<'_, R> {
    fn kind(&self) -> &'static str {
        "NTFS"
    }

    fn root(&self) -> u64 {
        ROOT_RECORD
    }

    fn read_dir(&self, locator: u64) -> FsResult<Vec<FsEntry>> {
        let record = self.read_record(locator)?;
        self.directory_entries(&record)
    }

    fn read_file(&self, locator: u64, output: &mut Vec<u8>) -> FsResult<()> {
        let record = self.read_record(locator)?;
        self.read_data(&record, output)
    }
}

/// Interpret NTFS's "clusters, or a negative log2-bytes" size encoding (records, indexes).
fn clusters_or_bytes(raw: i8, bytes_per_cluster: u64) -> u64 {
    if raw >= 0 {
        u64::try_from(raw)
            .unwrap_or(0)
            .saturating_mul(bytes_per_cluster)
    } else {
        let shift = u32::try_from(-i32::from(raw)).unwrap_or(0);
        1_u64.checked_shl(shift).unwrap_or(0)
    }
}

/// Apply the update-sequence-array fixups an NTFS FILE/INDX record carries.
fn apply_fixups(record: &mut [u8], bytes_per_sector: u64) -> FsResult<()> {
    let usa_offset = usize::from(read_u16(record, 4)?);
    let usa_count = usize::from(read_u16(record, 6)?);
    if usa_count == 0 {
        return Ok(());
    }
    let sector = usize::try_from(bytes_per_sector).unwrap_or(512).max(1);
    for index in 1..usa_count {
        let usa_at = usa_offset.saturating_add(index.saturating_mul(2));
        let Some(value) = read_u16(record, usa_at).ok() else {
            break;
        };
        let sector_end = index.saturating_mul(sector);
        let Some(tail) = sector_end.checked_sub(2) else {
            break;
        };
        let Some(slot) = record.get_mut(tail..sector_end) else {
            break;
        };
        slot.copy_from_slice(&value.to_le_bytes());
    }
    Ok(())
}

/// One decoded NTFS data run: a byte length, and either a backing byte offset or a sparse hole.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DataRun {
    length: u64,
    offset: Option<u64>,
}

/// Decode an NTFS data-run list into byte-length runs, preserving sparse holes (`offset: None`) so
/// a reader can synthesise them and keep every backed run at its correct file offset.
fn decode_runs(runs: &[u8], bytes_per_cluster: u64) -> Vec<DataRun> {
    let mut result = Vec::new();
    let mut cursor = 0_usize;
    let mut previous_lcn = 0_i64;
    loop {
        let header = runs.get(cursor).copied().unwrap_or(0);
        if header == 0 {
            break;
        }
        let length_size = usize::from(header & 0x0f);
        let offset_size = usize::from(header >> 4_u32);
        cursor = cursor.saturating_add(1);
        let length = read_le_uint(runs, cursor, length_size);
        cursor = cursor.saturating_add(length_size);
        let delta = read_le_sint(runs, cursor, offset_size);
        cursor = cursor.saturating_add(offset_size);
        if length == 0 || length > MAX_RUN_CLUSTERS {
            break;
        }
        let byte_length = length.saturating_mul(bytes_per_cluster);
        if offset_size == 0 {
            // Sparse run: no backing bytes on disk, but its length still advances the file offset.
            result.push(DataRun {
                length: byte_length,
                offset: None,
            });
            continue;
        }
        previous_lcn = previous_lcn.saturating_add(delta);
        if previous_lcn < 0 {
            break;
        }
        let byte_offset = u64::try_from(previous_lcn)
            .unwrap_or(0)
            .saturating_mul(bytes_per_cluster);
        result.push(DataRun {
            length: byte_length,
            offset: Some(byte_offset),
        });
    }
    result
}

/// Parse the entries of one index node into `entries`, keyed by name to dedupe root vs alloc.
fn collect_index_entries(node: &[u8], entries: &mut BTreeMap<String, FsEntry>) {
    let mut cursor = 0_usize;
    let mut guard = 0_usize;
    while let Some(entry) = node.get(cursor..cursor.saturating_add(16)) {
        guard = guard.saturating_add(1);
        if guard > MAX_INDEX_ENTRIES {
            break;
        }
        let entry_length = usize::from(read_u16(entry, 8).unwrap_or(0));
        let flags = read_u16(entry, 12).unwrap_or(0);
        if flags & 0x02 != 0 || entry_length < 16 {
            break; // last entry in this node
        }
        let file_reference = read_u64(entry, 0).unwrap_or(0) & 0x0000_ffff_ffff_ffff;
        // The $FILE_NAME stream sits at entry offset 16.
        if let Some(fname) = node.get(cursor.saturating_add(16)..cursor.saturating_add(entry_length))
            && let Some((name, is_directory, size, namespace)) = parse_file_name(fname)
            // Skip pure-DOS 8.3 aliases (namespace 2); every such file also carries a
            // Win32 name entry. Skip metadata files ($MFT, $Bitmap, …) and the self entry.
            && namespace != 2
            && name != "."
            && !name.is_empty()
            && !name.starts_with('$')
        {
            let _previous = entries.insert(
                name.clone(),
                FsEntry {
                    name,
                    is_directory,
                    size: if is_directory { 0 } else { size },
                    locator: file_reference,
                },
            );
        }
        cursor = cursor.saturating_add(entry_length);
    }
}

/// Decode a `$FILE_NAME` stream into its name, directory flag, real size, and namespace.
fn parse_file_name(stream: &[u8]) -> Option<(String, bool, u64, u8)> {
    let flags = read_u32(stream, 56).ok()?;
    let real_size = read_u64(stream, 48).ok()?;
    let name_length = usize::from(read_u8(stream, 64).ok()?);
    let namespace = read_u8(stream, 65).ok()?;
    let mut units = Vec::with_capacity(name_length);
    for index in 0..name_length {
        let at = 66_usize.saturating_add(index.saturating_mul(2));
        units.push(read_u16(stream, at).ok()?);
    }
    let is_directory = flags & 0x1000_0000 != 0;
    Some((
        String::from_utf16_lossy(&units),
        is_directory,
        real_size,
        namespace,
    ))
}

fn read_le_uint(bytes: &[u8], offset: usize, size: usize) -> u64 {
    let mut value = 0_u64;
    for index in 0..size {
        let byte = bytes
            .get(offset.saturating_add(index))
            .copied()
            .unwrap_or(0);
        value |= u64::from(byte) << (index.min(7).saturating_mul(8));
    }
    value
}

fn read_le_sint(bytes: &[u8], offset: usize, size: usize) -> i64 {
    if size == 0 {
        return 0;
    }
    let raw = read_le_uint(bytes, offset, size);
    let sign_bit_index = size.saturating_mul(8).saturating_sub(1);
    if raw & (1_u64 << sign_bit_index.min(63)) != 0 {
        let mask = if size >= 8 {
            u64::MAX
        } else {
            (1_u64 << (size.saturating_mul(8))).saturating_sub(1)
        };
        let magnitude = (!raw & mask).saturating_add(1);
        -i64::try_from(magnitude).unwrap_or(i64::MAX)
    } else {
        i64::try_from(raw).unwrap_or(i64::MAX)
    }
}

fn read_u8(bytes: &[u8], offset: usize) -> FsResult<u8> {
    bytes
        .get(offset)
        .copied()
        .ok_or_else(|| corrupt("NTFS", "u8 out of range"))
}

fn read_i8(bytes: &[u8], offset: usize) -> FsResult<i8> {
    let value = read_u8(bytes, offset)?;
    Ok(i8::from_le_bytes([value]))
}

fn read_u16(bytes: &[u8], offset: usize) -> FsResult<u16> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| corrupt("NTFS", "offset overflow"))?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| corrupt("NTFS", "u16 out of range"))?;
    let array = <[u8; 2]>::try_from(slice).map_err(|_ignored| corrupt("NTFS", "u16 slice"))?;
    Ok(u16::from_le_bytes(array))
}

fn read_u32(bytes: &[u8], offset: usize) -> FsResult<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| corrupt("NTFS", "offset overflow"))?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| corrupt("NTFS", "u32 out of range"))?;
    let array = <[u8; 4]>::try_from(slice).map_err(|_ignored| corrupt("NTFS", "u32 slice"))?;
    Ok(u32::from_le_bytes(array))
}

fn read_u64(bytes: &[u8], offset: usize) -> FsResult<u64> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| corrupt("NTFS", "offset overflow"))?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| corrupt("NTFS", "u64 out of range"))?;
    let array = <[u8; 8]>::try_from(slice).map_err(|_ignored| corrupt("NTFS", "u64 slice"))?;
    Ok(u64::from_le_bytes(array))
}

fn corrupt(structure: &'static str, reason: &str) -> FsError {
    FsError::Corrupt {
        structure,
        reason: reason.to_owned(),
    }
}
