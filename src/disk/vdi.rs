use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::error::{GovmemError, Result};

const VDI_MAGIC: u32 = 0xBEDA_107F;
const BAT_UNALLOCATED: u32 = 0xFFFF_FFFF;
const VDI_IMAGE_DIFF: u32 = 4;

/// VDI disk image reader supporting dynamic and differencing images.
pub struct VdiDisk {
    file: File,
    disk_size: u64,
    block_size: u32,
    bat: Vec<u32>,
    offset_data: u64,
    cursor: u64,
    parent: Option<Box<VdiDisk>>,
}

/// Raw VDI UUID stored as 16 bytes (Microsoft LE format).
#[derive(Clone, Copy, PartialEq, Eq)]
struct VdiUuid([u8; 16]);

impl VdiUuid {
    fn is_zero(&self) -> bool {
        self.0 == [0u8; 16]
    }
}

impl std::fmt::Display for VdiUuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let b = &self.0;
        // Microsoft LE: first 3 groups little-endian, last 2 big-endian
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6],
            b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
        )
    }
}

struct VdiHeader {
    image_type: u32,
    offset_blocks: u64,
    offset_data: u64,
    disk_size: u64,
    block_size: u32,
    blocks_total: u32,
    image_uuid: VdiUuid,
    parent_uuid: VdiUuid,
}

fn read_u16_le(f: &mut File) -> std::io::Result<u16> {
    let mut buf = [0u8; 2];
    f.read_exact(&mut buf)?;
    Ok(u16::from_le_bytes(buf))
}

fn read_u32_le(f: &mut File) -> std::io::Result<u32> {
    let mut buf = [0u8; 4];
    f.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_u64_le(f: &mut File) -> std::io::Result<u64> {
    let mut buf = [0u8; 8];
    f.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

fn parse_header(file: &mut File) -> Result<VdiHeader> {
    // Magic at 0x40
    file.seek(SeekFrom::Start(0x40))?;
    let magic = read_u32_le(file)?;
    if magic != VDI_MAGIC {
        return Err(GovmemError::InvalidMagic(magic));
    }

    // Version at 0x44: minor u16, major u16
    let _ver_minor = read_u16_le(file)?;
    let _ver_major = read_u16_le(file)?;

    // Header size at 0x48
    let _header_size = read_u32_le(file)?;

    // Image type at 0x4C
    let image_type = read_u32_le(file)?;

    // BAT offset at 0x154, data offset at 0x158
    file.seek(SeekFrom::Start(0x154))?;
    let offset_blocks = read_u32_le(file)? as u64;
    let offset_data = read_u32_le(file)? as u64;

    // Disk size (u64) at 0x170
    file.seek(SeekFrom::Start(0x170))?;
    let disk_size = read_u64_le(file)?;

    // Block size at 0x178
    let block_size = read_u32_le(file)?;

    // Skip 0x17C (unused), blocks_total at 0x180
    file.seek(SeekFrom::Start(0x180))?;
    let blocks_total = read_u32_le(file)?;

    // Image UUID at 0x188
    file.seek(SeekFrom::Start(0x188))?;
    let mut image_uuid = [0u8; 16];
    file.read_exact(&mut image_uuid)?;

    // Parent UUID at 0x1A8
    file.seek(SeekFrom::Start(0x1A8))?;
    let mut parent_uuid = [0u8; 16];
    file.read_exact(&mut parent_uuid)?;

    Ok(VdiHeader {
        image_type,
        offset_blocks,
        offset_data,
        disk_size,
        block_size,
        blocks_total,
        image_uuid: VdiUuid(image_uuid),
        parent_uuid: VdiUuid(parent_uuid),
    })
}

/// Find the parent VDI by scanning .vbox XML and sibling directories.
fn find_parent_vdi(child_path: &Path, parent_uuid: &VdiUuid) -> Result<PathBuf> {
    // Strategy 1: parse .vbox XML in ancestor directories for disk hierarchy
    if let Some(found) = find_parent_via_vbox(child_path, parent_uuid) {
        return Ok(found);
    }

    // Strategy 2: scan sibling .vdi files for matching UUID
    if let Some(found) = find_parent_by_uuid_scan(child_path, parent_uuid) {
        return Ok(found);
    }

    Err(GovmemError::ProcessNotFound(format!(
        "Parent VDI with UUID {} not found",
        parent_uuid
    )))
}

/// Parse .vbox XML files to find disk paths matching the parent UUID.
fn find_parent_via_vbox(child_path: &Path, parent_uuid: &VdiUuid) -> Option<PathBuf> {
    let parent_uuid_str = parent_uuid.to_string();
    // Search up from child directory for .vbox files
    let mut search_dir = child_path.parent()?;
    for _ in 0..4 {
        if let Ok(entries) = std::fs::read_dir(search_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("vbox") {
                    if let Some(found) = parse_vbox_for_disk(&path, &parent_uuid_str, search_dir) {
                        return Some(found);
                    }
                }
            }
        }
        search_dir = search_dir.parent()?;
    }
    None
}

/// Simple XML parser: find HardDisk uuid matching parent_uuid, return its location.
fn parse_vbox_for_disk(
    vbox_path: &Path,
    parent_uuid_str: &str,
    base_dir: &Path,
) -> Option<PathBuf> {
    let content = std::fs::read_to_string(vbox_path).ok()?;
    // Look for HardDisk entries with matching UUID
    // Format: <HardDisk uuid="{UUID}" location="path" ...>
    let needle = format!("uuid=\"{{{}}}", parent_uuid_str);
    let idx = content.find(&needle)?;
    // Find location attribute near this uuid
    let region = &content[idx.saturating_sub(200)..content.len().min(idx + 500)];
    let loc_marker = "location=\"";
    let loc_start = region.find(loc_marker)? + loc_marker.len();
    let loc_end = region[loc_start..].find('"')? + loc_start;
    let location = &region[loc_start..loc_end];

    let loc_path = Path::new(location);
    let full_path = if loc_path.is_absolute() {
        loc_path.to_path_buf()
    } else {
        base_dir.join(loc_path)
    };

    if full_path.exists() {
        Some(full_path)
    } else {
        None
    }
}

/// Scan directories for .vdi files with matching image UUID.
fn find_parent_by_uuid_scan(child_path: &Path, parent_uuid: &VdiUuid) -> Option<PathBuf> {
    let mut search_dir = child_path.parent()?;
    for _ in 0..3 {
        if let Some(found) = scan_dir_for_uuid(search_dir, parent_uuid, child_path, 0) {
            return Some(found);
        }
        search_dir = search_dir.parent()?;
    }
    scan_dir_for_uuid(search_dir, parent_uuid, child_path, 0)
}

fn scan_dir_for_uuid(
    dir: &Path,
    target_uuid: &VdiUuid,
    exclude: &Path,
    depth: u32,
) -> Option<PathBuf> {
    if depth > 2 {
        return None;
    }
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() && depth < 2 {
            if let Some(found) = scan_dir_for_uuid(&path, target_uuid, exclude, depth + 1) {
                return Some(found);
            }
        } else if path.extension().and_then(|e| e.to_str()) == Some("vdi") {
            if let Ok(canonical) = path.canonicalize() {
                if let Ok(excl_canonical) = exclude.canonicalize() {
                    if canonical == excl_canonical {
                        continue;
                    }
                }
            }
            // Quick check: read image UUID
            if let Ok(mut f) = File::open(&path) {
                if let Ok(hdr) = parse_header(&mut f) {
                    if hdr.image_uuid == *target_uuid {
                        return Some(path);
                    }
                }
            }
        }
    }
    None
}

impl VdiDisk {
    /// Open a VDI disk image, recursively opening parent images for differencing disks.
    pub fn open(path: &Path) -> Result<Self> {
        let mut file = File::open(path)?;
        let header = parse_header(&mut file)?;

        log::debug!(
            "VDI: type={} disk_size={} block_size={} blocks_total={} uuid={}",
            header.image_type,
            header.disk_size,
            header.block_size,
            header.blocks_total,
            header.image_uuid
        );

        // Read BAT
        file.seek(SeekFrom::Start(header.offset_blocks))?;
        let mut bat = Vec::with_capacity(header.blocks_total as usize);
        for _ in 0..header.blocks_total {
            bat.push(read_u32_le(&mut file)?);
        }

        // Open parent for differencing images
        let parent = if header.image_type == VDI_IMAGE_DIFF && !header.parent_uuid.is_zero() {
            log::debug!("VDI: diff image, parent UUID = {}", header.parent_uuid);
            let parent_path = find_parent_vdi(path, &header.parent_uuid)?;
            log::debug!("VDI: found parent at {:?}", parent_path);
            Some(Box::new(VdiDisk::open(&parent_path)?))
        } else {
            None
        };

        Ok(VdiDisk {
            file,
            disk_size: header.disk_size,
            block_size: header.block_size,
            bat,
            offset_data: header.offset_data,
            cursor: 0,
            parent,
        })
    }

    /// Read from a specific block, returning bytes read.
    fn read_block(
        &mut self,
        block_idx: usize,
        offset_in_block: u32,
        buf: &mut [u8],
    ) -> std::io::Result<usize> {
        let bat_entry = self.bat.get(block_idx).copied().unwrap_or(BAT_UNALLOCATED);

        if bat_entry == BAT_UNALLOCATED {
            if let Some(ref mut parent) = self.parent {
                // Delegate to parent for differencing images
                let virtual_offset =
                    block_idx as u64 * self.block_size as u64 + offset_in_block as u64;
                parent.seek(SeekFrom::Start(virtual_offset))?;
                return parent.read(buf);
            }
            // Dynamic image: unallocated = zeros
            buf.iter_mut().for_each(|b| *b = 0);
            return Ok(buf.len());
        }

        // data_offset = offset_data + bat_entry * block_size + offset_in_block
        let data_offset =
            self.offset_data + bat_entry as u64 * self.block_size as u64 + offset_in_block as u64;
        self.file.seek(SeekFrom::Start(data_offset))?;
        self.file.read(buf)
    }
}

impl Read for VdiDisk {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.cursor >= self.disk_size {
            return Ok(0);
        }

        let remaining = (self.disk_size - self.cursor) as usize;
        let to_read = buf.len().min(remaining);
        if to_read == 0 {
            return Ok(0);
        }

        let mut total = 0;
        while total < to_read {
            let pos = self.cursor;
            let block_idx = (pos / self.block_size as u64) as usize;
            let offset_in_block = (pos % self.block_size as u64) as u32;
            let avail_in_block = self.block_size - offset_in_block;
            let chunk = (to_read - total).min(avail_in_block as usize);

            let n = self.read_block(block_idx, offset_in_block, &mut buf[total..total + chunk])?;
            if n == 0 {
                break;
            }
            total += n;
            self.cursor += n as u64;
        }

        Ok(total)
    }
}

impl Seek for VdiDisk {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(offset) => offset as i64,
            SeekFrom::End(offset) => self.disk_size as i64 + offset,
            SeekFrom::Current(offset) => self.cursor as i64 + offset,
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

impl crate::disk::DiskImage for VdiDisk {
    fn disk_size(&self) -> u64 {
        self.disk_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disk::DiskImage;

    #[test]
    fn test_open_base_vdi() {
        let path = Path::new("/home/user/vm/windows10-clean/windows10-clean.vdi");
        if !path.exists() {
            return;
        }
        let mut disk = VdiDisk::open(path).expect("failed to open base VDI");
        assert_eq!(disk.disk_size(), 85899345920); // 80 GB

        // Read MBR and check signature
        let mut mbr = [0u8; 512];
        disk.read_exact(&mut mbr).expect("failed to read MBR");
        assert_eq!(mbr[510], 0x55);
        assert_eq!(mbr[511], 0xAA);

        // Check NTFS signature at LBA 2048 (byte offset 0x100000)
        disk.seek(SeekFrom::Start(2048 * 512)).unwrap();
        let mut ntfs_hdr = [0u8; 8];
        disk.read_exact(&mut ntfs_hdr).unwrap();
        assert_eq!(&ntfs_hdr[3..8], b"NTFS ");
    }

    #[test]
    fn test_open_diff_vdi() {
        let path = Path::new(
            "/home/user/vm/windows10-clean/Snapshots/{29fc354e-2d14-424f-95be-d4f79d10e922}.vdi",
        );
        if !path.exists() {
            return;
        }
        let mut disk = VdiDisk::open(path).expect("failed to open diff VDI");
        assert_eq!(disk.disk_size(), 85899345920);

        // MBR should be readable (from parent via fallthrough)
        let mut mbr = [0u8; 512];
        disk.read_exact(&mut mbr).expect("failed to read MBR");
        assert_eq!(mbr[510], 0x55);
        assert_eq!(mbr[511], 0xAA);
    }
}
