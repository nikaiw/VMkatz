use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::error::{VmkatzError, Result};
use super::{read_u16_be_file, read_u32_be_file, read_u64_be_file};

/// VHD footer cookie: "conectix" (8 bytes).
const VHD_COOKIE: [u8; 8] = *b"conectix";
/// Dynamic disk header cookie: "cxsparse" (8 bytes).
const CXSPARSE_COOKIE: [u8; 8] = *b"cxsparse";
/// Unallocated BAT entry.
const BAT_UNUSED: u32 = 0xFFFF_FFFF;
/// Disk type: fixed.
const DISK_TYPE_FIXED: u32 = 2;
/// Disk type: dynamic.
const DISK_TYPE_DYNAMIC: u32 = 3;
/// Disk type: differencing.
const DISK_TYPE_DIFFERENCING: u32 = 4;

/// VHD (Virtual Hard Disk v1) disk image reader with differencing chain support.
///
/// Supports fixed, dynamic, and differencing VHD images. All multi-byte
/// values in VHD are big-endian.
pub struct VhdDisk {
    file: File,
    disk_size: u64,
    disk_type: u32,
    /// For fixed disks: data starts at offset 0.
    /// BAT and block layout only used for dynamic/differencing.
    bat: Vec<u32>,
    block_size: u32,
    /// Sector bitmap size per block (rounded up to 512-byte sector boundary).
    bitmap_sectors: u32,
    cursor: u64,
    parent: Option<Box<VhdDisk>>,
}

struct VhdFooter {
    data_offset: u64,
    current_size: u64,
    disk_type: u32,
    #[allow(dead_code)]
    unique_id: [u8; 16],
}

struct VhdDynamicHeader {
    table_offset: u64,
    max_table_entries: u32,
    block_size: u32,
    parent_unique_id: [u8; 16],
    parent_locators: Vec<ParentLocator>,
}

struct ParentLocator {
    platform_code: u32,
    platform_data_length: u32,
    platform_data_offset: u64,
}

fn parse_footer(file: &mut File) -> Result<VhdFooter> {
    // Footer is the last 512 bytes of the file
    let file_size = file.seek(SeekFrom::End(0))?;
    if file_size < 512 {
        return Err(VmkatzError::DiskFormatError(
            "File too small for VHD".to_string(),
        ));
    }
    file.seek(SeekFrom::Start(file_size - 512))?;

    let mut cookie = [0u8; 8];
    file.read_exact(&mut cookie)?;
    if cookie != VHD_COOKIE {
        return Err(VmkatzError::InvalidMagic(u32::from_be_bytes([
            cookie[0], cookie[1], cookie[2], cookie[3],
        ])));
    }

    let _features = read_u32_be_file(file)?;
    let _format_version = read_u32_be_file(file)?;
    let data_offset = read_u64_be_file(file)?;
    let _timestamp = read_u32_be_file(file)?;
    let _creator_app = read_u32_be_file(file)?;
    let _creator_version = read_u32_be_file(file)?;
    let _creator_host_os = read_u32_be_file(file)?;
    let _original_size = read_u64_be_file(file)?;
    let current_size = read_u64_be_file(file)?;
    let _cylinders = read_u16_be_file(file)?;
    let _heads = {
        let mut b = [0u8; 1];
        file.read_exact(&mut b)?;
        b[0]
    };
    let _sectors_per_track = {
        let mut b = [0u8; 1];
        file.read_exact(&mut b)?;
        b[0]
    };
    let disk_type = read_u32_be_file(file)?;
    let _checksum = read_u32_be_file(file)?;
    let mut unique_id = [0u8; 16];
    file.read_exact(&mut unique_id)?;

    Ok(VhdFooter {
        data_offset,
        current_size,
        disk_type,
        unique_id,
    })
}

fn parse_dynamic_header(file: &mut File, data_offset: u64) -> Result<VhdDynamicHeader> {
    file.seek(SeekFrom::Start(data_offset))?;

    let mut cookie = [0u8; 8];
    file.read_exact(&mut cookie)?;
    if cookie != CXSPARSE_COOKIE {
        return Err(VmkatzError::DiskFormatError(format!(
            "Invalid dynamic header cookie: {:?}",
            &cookie
        )));
    }

    let _data_offset2 = read_u64_be_file(file)?; // reserved
    let table_offset = read_u64_be_file(file)?;
    let _header_version = read_u32_be_file(file)?;
    let max_table_entries = read_u32_be_file(file)?;
    let block_size = read_u32_be_file(file)?;
    let _checksum = read_u32_be_file(file)?;

    let mut parent_unique_id = [0u8; 16];
    file.read_exact(&mut parent_unique_id)?;

    let _parent_timestamp = read_u32_be_file(file)?;
    let _reserved = read_u32_be_file(file)?;

    // Skip parent unicode name (512 bytes)
    file.seek(SeekFrom::Current(512))?;

    // Read 8 parent locator entries (24 bytes each)
    let mut parent_locators = Vec::new();
    for _ in 0..8 {
        let platform_code = read_u32_be_file(file)?;
        let _platform_data_space = read_u32_be_file(file)?;
        let platform_data_length = read_u32_be_file(file)?;
        let _reserved = read_u32_be_file(file)?;
        let platform_data_offset = read_u64_be_file(file)?;

        if platform_code != 0 && platform_data_length > 0 {
            parent_locators.push(ParentLocator {
                platform_code,
                platform_data_length,
                platform_data_offset,
            });
        }
    }

    Ok(VhdDynamicHeader {
        table_offset,
        max_table_entries,
        block_size,
        parent_unique_id,
        parent_locators,
    })
}

/// Read a parent locator path from the file.
fn read_parent_path(file: &mut File, locator: &ParentLocator) -> std::io::Result<String> {
    file.seek(SeekFrom::Start(locator.platform_data_offset))?;
    let mut data = vec![0u8; locator.platform_data_length as usize];
    file.read_exact(&mut data)?;

    // Wi2k/Wi2r/W2ku/W2ru are UTF-16LE encoded
    let code = locator.platform_code;
    if code == 0x5769326B   // Wi2k
        || code == 0x57693272 // Wi2r
        || code == 0x57326B75 // W2ku
        || code == 0x57327275
    // W2ru
    {
        Ok(crate::utils::utf16le_decode(&data))
    } else if code == 0x4D616358 {
        // MacX: UTF-8 file URL
        Ok(String::from_utf8_lossy(&data)
            .trim_end_matches('\0')
            .to_string())
    } else {
        Ok(String::from_utf8_lossy(&data)
            .trim_end_matches('\0')
            .to_string())
    }
}

/// Resolve a parent VHD path relative to the child.
fn resolve_parent_path(child_path: &Path, parent_ref: &str) -> PathBuf {
    let normalized = parent_ref.replace('\\', "/");
    let parent_path = Path::new(&normalized);

    if parent_path.is_absolute() {
        if parent_path.exists() {
            return parent_path.to_path_buf();
        }
        // On Linux: try just the filename in the same directory
        let child_dir = child_path.parent().unwrap_or(Path::new("."));
        if let Some(name) = parent_path.file_name() {
            let sibling = child_dir.join(name);
            if sibling.exists() {
                return sibling;
            }
        }
        parent_path.to_path_buf()
    } else {
        let child_dir = child_path.parent().unwrap_or(Path::new("."));
        child_dir.join(parent_path)
    }
}

impl VhdDisk {
    /// Open a VHD disk image, recursively opening parent for differencing disks.
    pub fn open(path: &Path) -> Result<Self> {
        let mut file = File::open(path)?;
        let footer = parse_footer(&mut file)?;

        log::info!(
            "VHD: disk_size={}MB type={}",
            footer.current_size / (1024 * 1024),
            match footer.disk_type {
                DISK_TYPE_FIXED => "fixed",
                DISK_TYPE_DYNAMIC => "dynamic",
                DISK_TYPE_DIFFERENCING => "differencing",
                _ => "unknown",
            },
        );

        if footer.disk_type == DISK_TYPE_FIXED {
            // Fixed disk: raw data at offset 0, footer at end
            return Ok(VhdDisk {
                file,
                disk_size: footer.current_size,
                disk_type: DISK_TYPE_FIXED,
                bat: Vec::new(),
                block_size: 0,
                bitmap_sectors: 0,
                cursor: 0,
                parent: None,
            });
        }

        // Dynamic or differencing
        let dyn_header = parse_dynamic_header(&mut file, footer.data_offset)?;

        let block_size = dyn_header.block_size;
        if block_size == 0 {
            return Err(VmkatzError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid VHD dynamic header: block_size=0",
            )));
        }
        // Bitmap: 1 bit per sector (512 bytes), rounded up to sector boundary
        let sectors_per_block = block_size / 512;
        let bitmap_bytes = sectors_per_block.div_ceil(8);
        let bitmap_sectors = bitmap_bytes.div_ceil(512);

        log::debug!(
            "VHD: block_size={}KB bat_entries={} bitmap_sectors={}",
            block_size / 1024,
            dyn_header.max_table_entries,
            bitmap_sectors,
        );

        // Read BAT (big-endian u32 entries)
        file.seek(SeekFrom::Start(dyn_header.table_offset))?;
        let mut bat = Vec::with_capacity(dyn_header.max_table_entries as usize);
        for _ in 0..dyn_header.max_table_entries {
            bat.push(read_u32_be_file(&mut file)?);
        }

        // Open parent for differencing disks
        let parent = if footer.disk_type == DISK_TYPE_DIFFERENCING {
            let parent_id = dyn_header.parent_unique_id;
            if parent_id == [0u8; 16] {
                log::warn!("VHD differencing disk has zero parent UUID");
                None
            } else {
                // Try each parent locator
                let mut found_parent = None;
                for loc in &dyn_header.parent_locators {
                    if let Ok(parent_ref) = read_parent_path(&mut file, loc) {
                        if parent_ref.is_empty() {
                            continue;
                        }
                        let parent_path = resolve_parent_path(path, &parent_ref);
                        log::info!("VHD: differencing disk, parent: {:?}", parent_path);
                        if parent_path.exists() {
                            match VhdDisk::open(&parent_path) {
                                Ok(p) => {
                                    found_parent = Some(Box::new(p));
                                    break;
                                }
                                Err(e) => {
                                    log::warn!(
                                        "VHD: failed to open parent {:?}: {}",
                                        parent_path,
                                        e
                                    );
                                }
                            }
                        }
                    }
                }
                if found_parent.is_none() {
                    log::warn!("VHD: no accessible parent found for differencing disk");
                }
                found_parent
            }
        } else {
            None
        };

        Ok(VhdDisk {
            file,
            disk_size: footer.current_size,
            disk_type: footer.disk_type,
            bat,
            block_size,
            bitmap_sectors,
            cursor: 0,
            parent,
        })
    }

    /// Read from a virtual offset within a single block boundary.
    fn read_block(
        &mut self,
        block_index: usize,
        offset_in_block: u32,
        buf: &mut [u8],
    ) -> std::io::Result<usize> {
        if self.disk_type == DISK_TYPE_FIXED {
            // Fixed disk: direct read
            let file_offset = block_index as u64 * self.block_size as u64 + offset_in_block as u64;
            self.file.seek(SeekFrom::Start(file_offset))?;
            return self.file.read(buf);
        }

        let bat_entry = self.bat.get(block_index).copied().unwrap_or(BAT_UNUSED);

        if bat_entry == BAT_UNUSED {
            if let Some(ref mut parent) = self.parent {
                let virtual_offset =
                    block_index as u64 * self.block_size as u64 + offset_in_block as u64;
                parent.seek(SeekFrom::Start(virtual_offset))?;
                return parent.read(buf);
            }
            buf.fill(0);
            return Ok(buf.len());
        }

        // Block starts at bat_entry * 512 (sector offset)
        let block_start = bat_entry as u64 * 512;
        let data_start = block_start + self.bitmap_sectors as u64 * 512;

        if self.disk_type == DISK_TYPE_DIFFERENCING {
            // Check sector bitmap for differencing disks
            self.read_diff_block(block_index, offset_in_block, block_start, data_start, buf)
        } else {
            // Dynamic disk: read directly from data area
            let read_offset = data_start + offset_in_block as u64;
            self.file.seek(SeekFrom::Start(read_offset))?;
            self.file.read(buf)
        }
    }

    /// Read from a differencing disk block, checking the sector bitmap.
    fn read_diff_block(
        &mut self,
        block_index: usize,
        offset_in_block: u32,
        block_start: u64,
        data_start: u64,
        buf: &mut [u8],
    ) -> std::io::Result<usize> {
        let mut filled = 0usize;
        let mut pos = offset_in_block;

        while filled < buf.len() && (pos as u64) < self.block_size as u64 {
            let sector_in_block = pos / 512;
            let bitmap_byte_idx = sector_in_block / 8;
            let bitmap_bit = 7 - (sector_in_block % 8); // MSB first

            // Read bitmap byte
            self.file
                .seek(SeekFrom::Start(block_start + bitmap_byte_idx as u64))?;
            let mut bm = [0u8; 1];
            self.file.read_exact(&mut bm)?;

            let in_child = (bm[0] >> bitmap_bit) & 1 == 1;
            let offset_in_sector = pos % 512;
            let avail = (512 - offset_in_sector) as usize;
            let chunk = avail.min(buf.len() - filled);

            if in_child {
                let read_off = data_start + pos as u64;
                self.file.seek(SeekFrom::Start(read_off))?;
                self.file.read_exact(&mut buf[filled..filled + chunk])?;
            } else if let Some(ref mut parent) = self.parent {
                let virtual_offset = block_index as u64 * self.block_size as u64 + pos as u64;
                parent.seek(SeekFrom::Start(virtual_offset))?;
                parent.read_exact(&mut buf[filled..filled + chunk])?;
            } else {
                buf[filled..filled + chunk].fill(0);
            }

            filled += chunk;
            pos += chunk as u32;
        }

        Ok(filled)
    }
}

impl Read for VhdDisk {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.cursor >= self.disk_size {
            return Ok(0);
        }

        let remaining = (self.disk_size - self.cursor) as usize;
        let to_read = buf.len().min(remaining);
        if to_read == 0 {
            return Ok(0);
        }

        if self.disk_type == DISK_TYPE_FIXED {
            // Fixed disk: direct sequential read
            self.file.seek(SeekFrom::Start(self.cursor))?;
            let n = self.file.read(&mut buf[..to_read])?;
            self.cursor += n as u64;
            return Ok(n);
        }

        let block_size = self.block_size as u64;
        let mut total = 0;
        while total < to_read {
            let pos = self.cursor;
            let block_index = (pos / block_size) as usize;
            let offset_in_block = (pos % block_size) as u32;
            let avail_in_block = (block_size - offset_in_block as u64) as usize;
            let chunk = (to_read - total).min(avail_in_block);

            let n =
                self.read_block(block_index, offset_in_block, &mut buf[total..total + chunk])?;
            if n == 0 {
                break;
            }
            total += n;
            self.cursor += n as u64;
        }

        Ok(total)
    }
}

impl Seek for VhdDisk {
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

impl super::DiskImage for VhdDisk {
    fn disk_size(&self) -> u64 {
        self.disk_size
    }
}

