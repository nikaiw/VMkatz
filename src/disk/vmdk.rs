use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::error::{VmkatzError, Result};

const VMDK_MAGIC: u32 = 0x564D444B; // "KDMV" LE
const SECTOR_SIZE: u64 = 512;

/// VMware twoGbMaxExtentSparse VMDK reader with snapshot chain support.
pub struct VmdkDisk {
    extents: Vec<VmdkExtent>,
    disk_size: u64,
    cursor: u64,
    parent: Option<Box<VmdkDisk>>,
}

struct VmdkExtent {
    file: File,
    start_sector: u64,
    capacity: u64,
    grain_size: u64,
    num_gtes_per_gt: u32,
    gd: Vec<u32>,
}

/// Parsed descriptor metadata.
struct Descriptor {
    parent_hint: Option<String>,
    extent_files: Vec<(u64, String)>, // (sector_count, filename)
}

impl VmdkDisk {
    pub fn open(path: &Path) -> Result<Self> {
        // Detect whether this is a text descriptor or a binary extent file
        if is_binary_extent(path) {
            return Self::open_from_directory(path);
        }

        let base_dir = path.parent().unwrap_or(Path::new("."));
        let desc_text = std::fs::read_to_string(path).map_err(VmkatzError::Io)?;
        let desc = parse_descriptor(&desc_text)?;

        let mut extents = Vec::new();
        let mut start_sector = 0u64;

        for (sector_count, filename) in &desc.extent_files {
            let extent_path = base_dir.join(filename);
            let ext = open_extent(&extent_path, start_sector, *sector_count)?;
            start_sector += ext.capacity;
            extents.push(ext);
        }

        let disk_size = start_sector * SECTOR_SIZE;

        // Recursively open parent if snapshot
        let parent = if let Some(ref hint) = desc.parent_hint {
            let parent_path = resolve_parent_path(base_dir, hint);
            Some(Box::new(VmdkDisk::open(&parent_path)?))
        } else {
            None
        };

        Ok(VmdkDisk {
            extents,
            disk_size,
            cursor: 0,
            parent,
        })
    }

    /// Open a VMDK from a binary extent file by discovering all sibling extents
    /// in the same directory. Used when no text descriptor is available.
    ///
    /// In twoGbMaxExtentSparse format, each `-sNNN.vmdk` extent covers a
    /// sequential portion of the virtual disk. The extent number N means it
    /// covers sectors `(N-1)*capacity` through `N*capacity-1`. Missing extents
    /// (gaps in numbering) return zeros for their sector range.
    fn open_from_directory(extent_path: &Path) -> Result<Self> {
        let dir = extent_path.parent().unwrap_or(Path::new("."));
        let numbered_extents = collect_extent_files(dir)?;

        if numbered_extents.is_empty() {
            return Err(VmkatzError::DiskFormatError(
                "No VMDK extent files found in directory".into(),
            ));
        }

        // Determine total disk size from highest extent number
        let max_num = numbered_extents.iter().map(|(n, _)| *n).max().unwrap();

        log::info!(
            "Found {} VMDK extent files (no descriptor), max extent number: s{:03}",
            numbered_extents.len(),
            max_num
        );

        let mut extents = Vec::new();
        let mut capacity_per_extent = 0u64;

        for (num, path) in &numbered_extents {
            // Each extent's start_sector = (num - 1) * capacity
            let mut ext = open_extent(path, 0, 0)?;
            capacity_per_extent = ext.capacity;
            ext.start_sector = (*num as u64 - 1) * ext.capacity;
            log::info!(
                "  Extent s{:03}: {} (start_sector={}, capacity={}MB)",
                num,
                path.file_name().unwrap_or_default().to_string_lossy(),
                ext.start_sector,
                ext.capacity * SECTOR_SIZE / (1024 * 1024)
            );
            extents.push(ext);
        }

        let disk_size = max_num as u64 * capacity_per_extent * SECTOR_SIZE;
        log::info!(
            "Total virtual disk: {}MB ({} of {} extents present, {:.0}% coverage)",
            disk_size / (1024 * 1024),
            numbered_extents.len(),
            max_num,
            numbered_extents.len() as f64 / max_num as f64 * 100.0
        );

        Ok(VmdkDisk {
            extents,
            disk_size,
            cursor: 0,
            parent: None,
        })
    }

    /// Read sectors from the virtual disk at a given virtual sector offset.
    /// Returns the number of bytes read. Zeros are returned for unallocated grains
    /// if there is no parent; otherwise the parent chain is consulted.
    fn read_virtual(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if offset >= self.disk_size {
            return Ok(0);
        }

        let avail = (self.disk_size - offset) as usize;
        let to_read = buf.len().min(avail);
        if to_read == 0 {
            return Ok(0);
        }

        let mut filled = 0usize;
        while filled < to_read {
            let pos = offset + filled as u64;
            let virtual_sector = pos / SECTOR_SIZE;
            let sector_off = pos % SECTOR_SIZE;

            // Find which extent this sector belongs to using binary search.
            // Extents are sorted by start_sector, so partition_point gives us
            // the first extent whose start_sector > virtual_sector; the candidate
            // is the one just before that (if any).
            let candidate_idx = self
                .extents
                .partition_point(|e| e.start_sector <= virtual_sector);
            let ext = if candidate_idx > 0 {
                let e = &mut self.extents[candidate_idx - 1];
                if virtual_sector < e.start_sector + e.capacity {
                    e
                } else {
                    // Sector falls in a gap after this extent — zero-fill up to
                    // the next extent's start or the end of the request.
                    let gap_end_byte = if candidate_idx < self.extents.len() {
                        self.extents[candidate_idx].start_sector * SECTOR_SIZE
                    } else {
                        self.disk_size
                    };
                    let gap_remain = (gap_end_byte - pos) as usize;
                    let chunk = gap_remain.min(to_read - filled);
                    buf[filled..filled + chunk].fill(0);
                    filled += chunk;
                    continue;
                }
            } else {
                // Before all extents — zero-fill up to first extent
                let gap_end_byte = if self.extents.is_empty() {
                    self.disk_size
                } else {
                    self.extents[0].start_sector * SECTOR_SIZE
                };
                let gap_remain = (gap_end_byte - pos) as usize;
                let chunk = gap_remain.min(to_read - filled);
                buf[filled..filled + chunk].fill(0);
                filled += chunk;
                continue;
            };

            let local_sector = virtual_sector - ext.start_sector;
            let grain_index = local_sector / ext.grain_size;
            let gt_index = (grain_index / ext.num_gtes_per_gt as u64) as usize;
            let gte_index = (grain_index % ext.num_gtes_per_gt as u64) as usize;

            // How many bytes remain in this grain from current offset
            let grain_offset = (local_sector % ext.grain_size) * SECTOR_SIZE + sector_off;
            let grain_bytes = ext.grain_size * SECTOR_SIZE;
            let remain_in_grain = (grain_bytes - grain_offset) as usize;
            let chunk = remain_in_grain.min(to_read - filled);

            let grain_sector = if gt_index < ext.gd.len() {
                let gt_sector = ext.gd[gt_index];
                if gt_sector == 0 {
                    0u32
                } else {
                    // Read GTE from grain table
                    let gt_byte_off = gt_sector as u64 * SECTOR_SIZE + gte_index as u64 * 4;
                    let mut gte_buf = [0u8; 4];
                    let ok = ext.file.seek(SeekFrom::Start(gt_byte_off)).is_ok()
                        && ext.file.read_exact(&mut gte_buf).is_ok();
                    if ok {
                        u32::from_le_bytes(gte_buf)
                    } else {
                        0u32 // Truncated file: treat as unallocated
                    }
                }
            } else {
                0u32
            };

            if grain_sector != 0 {
                // Grain is allocated in this layer
                let data_off = grain_sector as u64 * SECTOR_SIZE + grain_offset;
                // Handle truncated extent files: if data is beyond file, treat as zeros
                let read_ok = ext.file.seek(SeekFrom::Start(data_off)).is_ok()
                    && ext
                        .file
                        .read_exact(&mut buf[filled..filled + chunk])
                        .is_ok();
                if !read_ok {
                    buf[filled..filled + chunk].fill(0);
                }
            } else if let Some(ref mut parent) = self.parent {
                // Delegate to parent chain
                parent.cursor = pos;
                let n = parent.read_virtual(pos, &mut buf[filled..filled + chunk])?;
                if n < chunk {
                    // Parent didn't have it either; zero-fill remainder
                    buf[filled + n..filled + chunk].fill(0);
                }
            } else {
                // No parent, unallocated = zeros
                buf[filled..filled + chunk].fill(0);
            }

            filled += chunk;
        }

        Ok(filled)
    }
}

impl VmdkDisk {
    /// Iterate over all physically allocated grains across all extent files.
    ///
    /// This bypasses normal LBA-to-grain translation and directly reads every
    /// non-zero grain table entry from each extent. Much faster than linear
    /// scanning for incomplete disk images with missing extents, since it only
    /// touches data that actually exists on disk.
    ///
    /// Calls `callback` for each allocated grain. The callback receives the
    /// grain's virtual byte offset and a slice of the grain data. Return `true`
    /// from the callback to continue scanning, `false` to stop early.
    pub fn scan_all_grains<F>(&mut self, mut callback: F) -> Result<()>
    where
        F: FnMut(u64, &[u8]) -> bool,
    {
        for ext_idx in 0..self.extents.len() {
            let grain_bytes = self.extents[ext_idx].grain_size * SECTOR_SIZE;
            let num_gtes = self.extents[ext_idx].num_gtes_per_gt;
            let gd_len = self.extents[ext_idx].gd.len();
            let start_sector = self.extents[ext_idx].start_sector;

            for gd_idx in 0..gd_len {
                let gt_sector = self.extents[ext_idx].gd[gd_idx];
                if gt_sector == 0 {
                    continue;
                }

                // Read the grain table
                let gt_offset = gt_sector as u64 * SECTOR_SIZE;
                let gt_size = num_gtes as usize * 4;
                let mut gt_buf = vec![0u8; gt_size];
                let ok = self.extents[ext_idx]
                    .file
                    .seek(SeekFrom::Start(gt_offset))
                    .is_ok()
                    && self.extents[ext_idx].file.read_exact(&mut gt_buf).is_ok();
                if !ok {
                    continue;
                }

                for gte_idx in 0..num_gtes as usize {
                    let grain_sector = u32::from_le_bytes(
                        gt_buf[gte_idx * 4..(gte_idx + 1) * 4].try_into().unwrap(),
                    );
                    if grain_sector == 0 {
                        continue;
                    }

                    let data_offset = grain_sector as u64 * SECTOR_SIZE;
                    let mut grain_data = vec![0u8; grain_bytes as usize];
                    let read_ok = self.extents[ext_idx]
                        .file
                        .seek(SeekFrom::Start(data_offset))
                        .is_ok()
                        && self.extents[ext_idx]
                            .file
                            .read_exact(&mut grain_data)
                            .is_ok();
                    if !read_ok {
                        // Grain beyond file (truncated extent), skip
                        continue;
                    }

                    // Virtual byte offset = (start_sector + local_grain_index * grain_size) * SECTOR_SIZE
                    let local_grain = gd_idx as u64 * num_gtes as u64 + gte_idx as u64;
                    let virtual_byte = (start_sector
                        + local_grain * self.extents[ext_idx].grain_size)
                        * SECTOR_SIZE;

                    if !callback(virtual_byte, &grain_data) {
                        return Ok(());
                    }
                }
            }
        }
        Ok(())
    }
}

impl Read for VmdkDisk {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let offset = self.cursor;
        let n = self
            .read_virtual(offset, buf)
            .map_err(std::io::Error::other)?;
        self.cursor += n as u64;
        Ok(n)
    }
}

impl Seek for VmdkDisk {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(p) => p as i64,
            SeekFrom::Current(p) => self.cursor as i64 + p,
            SeekFrom::End(p) => self.disk_size as i64 + p,
        };
        if new_pos < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek to negative position",
            ));
        }
        self.cursor = new_pos as u64;
        Ok(self.cursor)
    }
}

impl super::DiskImage for VmdkDisk {
    fn disk_size(&self) -> u64 {
        self.disk_size
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn parse_descriptor(text: &str) -> Result<Descriptor> {
    let mut parent_hint = None;
    let mut extent_files = Vec::new();

    for line in text.lines() {
        let line = line.trim();

        if let Some(rest) = line.strip_prefix("parentFileNameHint=") {
            parent_hint = Some(rest.trim_matches('"').to_string());
        }

        // RW <sectors> SPARSE "<filename>"
        if line.starts_with("RW ") {
            let parts: Vec<&str> = line.splitn(4, ' ').collect();
            if parts.len() == 4 {
                let sectors: u64 = parts[1]
                    .parse()
                    .map_err(|_| VmkatzError::DiskFormatError("bad VMDK extent sectors".into()))?;
                let filename = parts[3].trim_matches('"').to_string();
                extent_files.push((sectors, filename));
            }
        }
    }

    if extent_files.is_empty() {
        return Err(VmkatzError::DiskFormatError(
            "no extents in VMDK descriptor".into(),
        ));
    }

    Ok(Descriptor {
        parent_hint,
        extent_files,
    })
}

fn open_extent(path: &Path, start_sector: u64, _declared_capacity: u64) -> Result<VmdkExtent> {
    let mut file = File::open(path).map_err(VmkatzError::Io)?;

    let mut hdr = [0u8; 0x48];
    file.read_exact(&mut hdr)?;

    let magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
    if magic != VMDK_MAGIC {
        return Err(VmkatzError::InvalidMagic(magic));
    }

    // SparseExtentHeader fields (VMDK format spec):
    let capacity = u64::from_le_bytes(hdr[0x0C..0x14].try_into().unwrap());        // capacity (sectors)
    let grain_size = u64::from_le_bytes(hdr[0x14..0x1C].try_into().unwrap());      // grainSize (sectors)
    let num_gtes_per_gt = u32::from_le_bytes(hdr[0x2C..0x30].try_into().unwrap()); // numGTEsPerGT
    let gd_offset_sectors = u64::from_le_bytes(hdr[0x38..0x40].try_into().unwrap()); // gdOffset (sectors)

    // Number of grain directory entries = ceil(capacity / grain_size / num_gtes_per_gt)
    if grain_size == 0 || num_gtes_per_gt == 0 {
        return Err(VmkatzError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid VMDK header: grain_size={}, numGTEsPerGT={}", grain_size, num_gtes_per_gt),
        )));
    }
    let total_grains = capacity.div_ceil(grain_size);
    let gd_entries = total_grains.div_ceil(num_gtes_per_gt as u64) as usize;

    // Read the entire grain directory
    let gd_byte_off = gd_offset_sectors * SECTOR_SIZE;
    file.seek(SeekFrom::Start(gd_byte_off))?;
    let mut gd_raw = vec![0u8; gd_entries * 4];
    file.read_exact(&mut gd_raw)?;

    let gd: Vec<u32> = gd_raw
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
        .collect();

    Ok(VmdkExtent {
        file,
        start_sector,
        capacity,
        grain_size,
        num_gtes_per_gt,
        gd,
    })
}

fn resolve_parent_path(base_dir: &Path, hint: &str) -> PathBuf {
    let hint_path = Path::new(hint);
    if hint_path.is_absolute() {
        hint_path.to_path_buf()
    } else {
        base_dir.join(hint)
    }
}

/// Check if a file is a binary VMDK extent (KDMV magic) rather than a text descriptor.
fn is_binary_extent(path: &Path) -> bool {
    if let Ok(mut f) = File::open(path) {
        let mut magic = [0u8; 4];
        if f.read_exact(&mut magic).is_ok() {
            return u32::from_le_bytes(magic) == VMDK_MAGIC;
        }
    }
    false
}

/// Collect all `-sNNN.vmdk` extent files from a directory, sorted by number.
/// Returns `(extent_number, path)` pairs so callers can use the number for positioning.
fn collect_extent_files(dir: &Path) -> Result<Vec<(u32, PathBuf)>> {
    let mut extents: Vec<(u32, PathBuf)> = Vec::new();

    let entries = std::fs::read_dir(dir).map_err(VmkatzError::Io)?;
    for entry in entries.flatten() {
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !ext.eq_ignore_ascii_case("vmdk") {
            continue;
        }
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        if let Some(num) = parse_extent_number(stem) {
            if is_binary_extent(&path) {
                extents.push((num, path));
            }
        }
    }

    extents.sort_by_key(|(num, _)| *num);
    Ok(extents)
}

/// Extract the extent number from a stem like `Name-s014`.
fn parse_extent_number(stem: &str) -> Option<u32> {
    let pos = stem.rfind("-s")?;
    let suffix = &stem[pos + 2..];
    if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) {
        let num: u32 = suffix.parse().ok()?;
        // Extent numbers are 1-based (s001, s002, ...); reject 0 to prevent underflow
        if num == 0 { return None; }
        Some(num)
    } else {
        None
    }
}
