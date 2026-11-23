//! Minimal read-only FAT12/16/32 walker.

use super::{ByteReader, FileSystem, FsEntry, FsError, FsResult, MAX_FS_FILE_SIZE, read_exact_at};

const DIRECTORY_ENTRY_SIZE: usize = 32;
const ATTR_LONG_NAME: u8 = 0x0f;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_VOLUME_ID: u8 = 0x08;
const MAX_CLUSTER_CHAIN: u32 = 1 << 26;
const MAX_DIRECTORY_ENTRIES: usize = 1 << 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FatKind {
    Fat12,
    Fat16,
    Fat32,
}

/// A mounted FAT filesystem over a partition-sized [`ByteReader`].
#[derive(Debug)]
pub struct FatFileSystem<'a, R: ByteReader + ?Sized> {
    reader: &'a R,
    bytes_per_sector: u64,
    sectors_per_cluster: u64,
    fat_start: u64,
    data_start: u64,
    root_dir_sectors: u64,
    root_cluster: u32,
    root_entry_count: u64,
    fat_kind: FatKind,
}

/// Whether `reader` opens with a FAT boot sector.
///
/// # Errors
///
/// Returns an error only when the boot sector cannot be read.
pub(crate) fn is_fat<R: ByteReader + ?Sized>(reader: &R) -> FsResult<bool> {
    let sector = read_exact_at(reader, 0, 512)?;
    if sector.get(510..512) != Some(&[0x55, 0xaa]) {
        return Ok(false);
    }
    let fat16_tag = sector.get(0x36..0x3b);
    let fat32_tag = sector.get(0x52..0x57);
    Ok(fat16_tag == Some(b"FAT12")
        || fat16_tag == Some(b"FAT16")
        || fat16_tag == Some(b"FAT  ")
        || fat32_tag == Some(b"FAT32"))
}

impl<'a, R: ByteReader + ?Sized> FatFileSystem<'a, R> {
    /// Parse the BPB and mount the filesystem.
    ///
    /// # Errors
    ///
    /// Returns an error for an out-of-range boot-sector field or an IO failure.
    pub fn open(reader: &'a R) -> FsResult<Self> {
        let boot = read_exact_at(reader, 0, 512)?;
        let bytes_per_sector = u64::from(read_u16(&boot, 0x0b)?);
        let sectors_per_cluster = u64::from(read_u8(&boot, 0x0d)?);
        let num_fats = u64::from(read_u8(&boot, 0x10)?);
        if !(bytes_per_sector.is_power_of_two() && (512..=4096).contains(&bytes_per_sector)) {
            return Err(corrupt("FAT BPB", "implausible bytes-per-sector"));
        }
        if sectors_per_cluster == 0 || !sectors_per_cluster.is_power_of_two() {
            return Err(corrupt("FAT BPB", "implausible sectors-per-cluster"));
        }
        if num_fats == 0 {
            return Err(corrupt("FAT BPB", "zero FAT copies"));
        }
        Self::mount(
            reader,
            &boot,
            bytes_per_sector,
            sectors_per_cluster,
            num_fats,
        )
    }

    fn mount(
        reader: &'a R,
        boot: &[u8],
        bytes_per_sector: u64,
        sectors_per_cluster: u64,
        num_fats: u64,
    ) -> FsResult<Self> {
        let reserved_sectors = u64::from(read_u16(boot, 0x0e)?);
        let root_entry_count = u64::from(read_u16(boot, 0x11)?);
        let fat_size = match u64::from(read_u16(boot, 0x16)?) {
            0 => u64::from(read_u32(boot, 0x24)?),
            small => small,
        };
        let total_sectors = match u64::from(read_u16(boot, 0x13)?) {
            0 => u64::from(read_u32(boot, 0x20)?),
            small => small,
        };
        let root_cluster = read_u32(boot, 0x2c)?;
        let root_dir_sectors = root_entry_count
            .saturating_mul(32)
            .saturating_add(bytes_per_sector.saturating_sub(1))
            .checked_div(bytes_per_sector)
            .unwrap_or(0);
        let data_start = reserved_sectors
            .saturating_add(num_fats.saturating_mul(fat_size))
            .saturating_add(root_dir_sectors);
        let cluster_count = total_sectors
            .saturating_sub(data_start)
            .checked_div(sectors_per_cluster)
            .unwrap_or(0);
        let fat_kind = if cluster_count < 4085 {
            FatKind::Fat12
        } else if cluster_count < 65525 {
            FatKind::Fat16
        } else {
            FatKind::Fat32
        };
        Ok(Self {
            reader,
            bytes_per_sector,
            sectors_per_cluster,
            fat_start: reserved_sectors,
            data_start,
            root_dir_sectors,
            root_cluster,
            root_entry_count,
            fat_kind,
        })
    }

    fn cluster_bytes(&self) -> u64 {
        self.bytes_per_sector
            .saturating_mul(self.sectors_per_cluster)
    }

    fn cluster_offset(&self, cluster: u32) -> u64 {
        let index = u64::from(cluster).saturating_sub(2);
        self.data_start
            .saturating_add(index.saturating_mul(self.sectors_per_cluster))
            .saturating_mul(self.bytes_per_sector)
    }

    fn next_cluster(&self, cluster: u32) -> FsResult<Option<u32>> {
        let fat_base = self.fat_start.saturating_mul(self.bytes_per_sector);
        let (raw, eoc_floor) = match self.fat_kind {
            FatKind::Fat32 => {
                let offset = fat_base.saturating_add(u64::from(cluster).saturating_mul(4));
                let bytes = read_exact_at(self.reader, offset, 4)?;
                (read_u32(&bytes, 0)? & 0x0fff_ffff, 0x0fff_fff8)
            }
            FatKind::Fat16 => {
                let offset = fat_base.saturating_add(u64::from(cluster).saturating_mul(2));
                let bytes = read_exact_at(self.reader, offset, 2)?;
                (u32::from(read_u16(&bytes, 0)?), 0xfff8)
            }
            FatKind::Fat12 => {
                let offset = fat_base.saturating_add(
                    u64::from(cluster)
                        .saturating_mul(3)
                        .checked_div(2)
                        .unwrap_or(0),
                );
                let bytes = read_exact_at(self.reader, offset, 2)?;
                let raw16 = read_u16(&bytes, 0)?;
                let value = if cluster & 1 == 1 {
                    raw16 >> 4_u32
                } else {
                    raw16 & 0x0fff
                };
                (u32::from(value), 0xff8)
            }
        };
        if raw >= eoc_floor || raw < 2 {
            Ok(None)
        } else {
            Ok(Some(raw))
        }
    }

    /// Read the raw bytes of a whole cluster chain starting at `cluster`, capped at `limit`.
    fn read_chain(&self, cluster: u32, limit: u64) -> FsResult<Vec<u8>> {
        let mut data = Vec::new();
        let mut current = cluster;
        let mut steps = 0_u32;
        let chunk = self.cluster_bytes();
        while steps < MAX_CLUSTER_CHAIN && u64::try_from(data.len()).unwrap_or(u64::MAX) < limit {
            if current < 2 {
                break;
            }
            let want = usize::try_from(chunk).unwrap_or(0);
            let block = read_exact_at(self.reader, self.cluster_offset(current), want)?;
            data.extend_from_slice(&block);
            match self.next_cluster(current)? {
                Some(next) => current = next,
                None => break,
            }
            steps = steps.saturating_add(1);
        }
        Ok(data)
    }

    /// Read the bytes making up a directory (cluster chain, or the FAT12/16 fixed root).
    fn read_directory_bytes(&self, cluster: u32) -> FsResult<Vec<u8>> {
        if cluster == 0 && self.fat_kind != FatKind::Fat32 {
            // The fixed root directory sits directly after the FAT copies.
            let root_offset = self
                .data_start
                .saturating_sub(self.root_dir_sectors)
                .saturating_mul(self.bytes_per_sector);
            let length = usize::try_from(self.root_entry_count.saturating_mul(32)).unwrap_or(0);
            return read_exact_at(self.reader, root_offset, length);
        }
        let start = if cluster < 2 {
            self.root_cluster
        } else {
            cluster
        };
        self.read_chain(start, u64::from(u32::MAX))
    }
}

/// Pack a file's first cluster and size into a single locator.
fn pack_file(cluster: u32, size: u32) -> u64 {
    (u64::from(size) << 32) | u64::from(cluster)
}

fn unpack_file(locator: u64) -> (u32, u64) {
    let cluster = u32::try_from(locator & 0xffff_ffff).unwrap_or(0);
    let size = locator >> 32_u32;
    (cluster, size)
}

impl<R: ByteReader + ?Sized> FileSystem for FatFileSystem<'_, R> {
    fn kind(&self) -> &'static str {
        match self.fat_kind {
            FatKind::Fat12 => "FAT12",
            FatKind::Fat16 => "FAT16",
            FatKind::Fat32 => "FAT32",
        }
    }

    fn root(&self) -> u64 {
        if self.fat_kind == FatKind::Fat32 {
            u64::from(self.root_cluster)
        } else {
            0
        }
    }

    fn read_dir(&self, locator: u64) -> FsResult<Vec<FsEntry>> {
        let cluster = u32::try_from(locator & 0xffff_ffff).unwrap_or(0);
        let bytes = self.read_directory_bytes(cluster)?;
        Ok(parse_directory(&bytes))
    }

    fn read_file(&self, locator: u64, output: &mut Vec<u8>) -> FsResult<()> {
        let (cluster, size) = unpack_file(locator);
        if size > MAX_FS_FILE_SIZE {
            return Err(FsError::Unsupported {
                feature: "file larger than the browser cap",
            });
        }
        let mut data = self.read_chain(cluster, size)?;
        data.truncate(usize::try_from(size).unwrap_or(0));
        output.clear();
        output.append(&mut data);
        Ok(())
    }
}

/// Decode a directory's raw bytes into entries, reassembling long file names.
fn parse_directory(bytes: &[u8]) -> Vec<FsEntry> {
    let mut entries = Vec::new();
    let mut lfn: Vec<u16> = Vec::new();
    let mut count = 0_usize;
    for chunk in bytes.chunks_exact(DIRECTORY_ENTRY_SIZE) {
        count = count.saturating_add(1);
        if count > MAX_DIRECTORY_ENTRIES {
            break;
        }
        let first = chunk.first().copied().unwrap_or(0);
        if first == 0x00 {
            break; // end of directory
        }
        if first == 0xe5 {
            lfn.clear();
            continue; // deleted
        }
        let attributes = chunk.get(0x0b).copied().unwrap_or(0);
        if attributes == ATTR_LONG_NAME {
            prepend_lfn(&mut lfn, chunk);
            continue;
        }
        if attributes & ATTR_VOLUME_ID != 0 {
            lfn.clear();
            continue;
        }
        let long_name = take_lfn(&mut lfn);
        let name = long_name.unwrap_or_else(|| short_name(chunk));
        if name == "." || name == ".." || name.is_empty() {
            continue;
        }
        let high = u32::from(read_u16(chunk, 0x14).unwrap_or(0));
        let low = u32::from(read_u16(chunk, 0x1a).unwrap_or(0));
        let cluster = (high << 16_u32) | low;
        let size = read_u32(chunk, 0x1c).unwrap_or(0);
        let is_directory = attributes & ATTR_DIRECTORY != 0;
        entries.push(FsEntry {
            name,
            is_directory,
            size: if is_directory { 0 } else { u64::from(size) },
            locator: if is_directory {
                u64::from(cluster)
            } else {
                pack_file(cluster, size)
            },
        });
    }
    entries
}

fn prepend_lfn(lfn: &mut Vec<u16>, chunk: &[u8]) {
    // A long-name entry carries 13 UTF-16 units at offsets 1, 14, and 28.
    let mut units = Vec::with_capacity(13);
    for &offset in &[1_usize, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30] {
        let unit = read_u16(chunk, offset).unwrap_or(0);
        if unit == 0 || unit == 0xffff {
            break;
        }
        units.push(unit);
    }
    // Entries appear in reverse order on disk; prepend to rebuild forward order.
    let mut combined = units;
    combined.append(lfn);
    *lfn = combined;
}

fn take_lfn(lfn: &mut Vec<u16>) -> Option<String> {
    if lfn.is_empty() {
        return None;
    }
    let name = String::from_utf16_lossy(lfn);
    lfn.clear();
    Some(name.trim_end_matches(['\u{0}', ' ']).to_owned())
}

fn short_name(chunk: &[u8]) -> String {
    let base = chunk.get(0..8).unwrap_or(&[]);
    let ext = chunk.get(8..11).unwrap_or(&[]);
    let base = ascii_trim(base);
    let ext = ascii_trim(ext);
    if ext.is_empty() {
        base
    } else {
        format!("{base}.{ext}")
    }
}

fn ascii_trim(bytes: &[u8]) -> String {
    let text: String = bytes
        .iter()
        .map(|byte| char::from(*byte))
        .collect::<String>()
        .trim_end()
        .to_owned();
    text
}

fn read_u8(bytes: &[u8], offset: usize) -> FsResult<u8> {
    bytes
        .get(offset)
        .copied()
        .ok_or_else(|| corrupt("FAT", "u8 out of range"))
}

fn read_u16(bytes: &[u8], offset: usize) -> FsResult<u16> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| corrupt("FAT", "offset overflow"))?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| corrupt("FAT", "u16 out of range"))?;
    let array = <[u8; 2]>::try_from(slice).map_err(|_ignored| corrupt("FAT", "u16 slice"))?;
    Ok(u16::from_le_bytes(array))
}

fn read_u32(bytes: &[u8], offset: usize) -> FsResult<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| corrupt("FAT", "offset overflow"))?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| corrupt("FAT", "u32 out of range"))?;
    let array = <[u8; 4]>::try_from(slice).map_err(|_ignored| corrupt("FAT", "u32 slice"))?;
    Ok(u32::from_le_bytes(array))
}

fn corrupt(structure: &'static str, reason: &str) -> FsError {
    FsError::Corrupt {
        structure,
        reason: reason.to_owned(),
    }
}
