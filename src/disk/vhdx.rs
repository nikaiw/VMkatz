use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::error::{VmkatzError, Result};
use super::{read_u32_le_file, read_u64_le_file};

/// VHDX file identifier signature: "vhdxfile" (8 bytes at offset 0).
const VHDX_FILE_SIGNATURE: u64 = 0x656C_6966_7864_6876; // "vhdxfile" LE
/// Header signature: "head" (4 bytes).
const VHDX_HEADER_SIGNATURE: u32 = 0x6461_6568; // "head" LE
/// Region table signature: "regi" (4 bytes).
const VHDX_REGION_SIGNATURE: u32 = 0x6967_6572; // "regi" LE
/// Metadata table signature: "metadata" (8 bytes).
const VHDX_METADATA_SIGNATURE: u64 = 0x6174_6164_6174_656D; // "metadata" LE

/// BAT region GUID: {2DC27766-F623-4200-9D64-115E9BFD4A08}
const BAT_REGION_GUID: [u8; 16] = [
    0x66, 0x77, 0xC2, 0x2D, 0x23, 0xF6, 0x00, 0x42, 0x9D, 0x64, 0x11, 0x5E, 0x9B, 0xFD, 0x4A, 0x08,
];

/// Metadata region GUID: {8B7CA206-4790-4B9A-B8FE-575F050F886E}
const METADATA_REGION_GUID: [u8; 16] = [
    0x06, 0xA2, 0x7C, 0x8B, 0x90, 0x47, 0x9A, 0x4B, 0xB8, 0xFE, 0x57, 0x5F, 0x05, 0x0F, 0x88, 0x6E,
];

/// File Parameters metadata GUID: {CAA16737-FA36-4D43-B3B6-33F0AA44E76B}
const META_FILE_PARAMETERS: [u8; 16] = [
    0x37, 0x67, 0xA1, 0xCA, 0x36, 0xFA, 0x43, 0x4D, 0xB3, 0xB6, 0x33, 0xF0, 0xAA, 0x44, 0xE7, 0x6B,
];

/// Virtual Disk Size metadata GUID: {2FA54224-CD1B-4876-B211-5DBED83BF4B8}
const META_VIRTUAL_DISK_SIZE: [u8; 16] = [
    0x24, 0x42, 0xA5, 0x2F, 0x1B, 0xCD, 0x76, 0x48, 0xB2, 0x11, 0x5D, 0xBE, 0xD8, 0x3B, 0xF4, 0xB8,
];

/// Logical Sector Size metadata GUID: {8141BF1D-A96F-4709-BA47-F233A8FAAB5F}
const META_LOGICAL_SECTOR_SIZE: [u8; 16] = [
    0x1D, 0xBF, 0x41, 0x81, 0x6F, 0xA9, 0x09, 0x47, 0xBA, 0x47, 0xF2, 0x33, 0xA8, 0xFA, 0xAB, 0x5F,
];

/// Parent Locator metadata GUID: {A8D35F2D-B30B-454D-ABF7-D3D84834AB0C}
const META_PARENT_LOCATOR: [u8; 16] = [
    0x2D, 0x5F, 0xD3, 0xA8, 0x0B, 0xB3, 0x4D, 0x45, 0xAB, 0xF7, 0xD3, 0xD8, 0x48, 0x34, 0xAB, 0x0C,
];

/// BAT payload block states.
const PAYLOAD_BLOCK_NOT_PRESENT: u8 = 0;
const PAYLOAD_BLOCK_UNDEFINED: u8 = 1;
const PAYLOAD_BLOCK_ZERO: u8 = 2;
const PAYLOAD_BLOCK_UNMAPPED: u8 = 3;
const PAYLOAD_BLOCK_FULLY_PRESENT: u8 = 6;
const PAYLOAD_BLOCK_PARTIALLY_PRESENT: u8 = 7;

/// VHDX (Virtual Hard Disk v2) disk image reader with differencing chain support.
pub struct VhdxDisk {
    file: File,
    disk_size: u64,
    block_size: u32,
    logical_sector_size: u32,
    chunk_ratio: u64,
    bat: Vec<u64>,
    cursor: u64,
    parent: Option<Box<VhdxDisk>>,
}

fn read_guid(f: &mut File) -> std::io::Result<[u8; 16]> {
    let mut buf = [0u8; 16];
    f.read_exact(&mut buf)?;
    Ok(buf)
}

/// Check if a GUID is all zeros.
fn guid_is_zero(guid: &[u8; 16]) -> bool {
    guid.iter().all(|&b| b == 0)
}

/// Parsed VHDX header (the valid one with highest sequence number).
struct VhdxHeader {
    #[allow(dead_code)]
    sequence_number: u64,
    log_guid: [u8; 16],
}

/// Region table entries we care about.
struct VhdxRegions {
    bat_offset: u64,
    bat_length: u32,
    metadata_offset: u64,
    #[allow(dead_code)]
    metadata_length: u32,
}

/// Parsed metadata.
struct VhdxMetadata {
    block_size: u32,
    virtual_disk_size: u64,
    logical_sector_size: u32,
    has_parent: bool,
}

/// Parse the VHDX file identifier at offset 0.
fn validate_file_identifier(file: &mut File) -> Result<()> {
    file.seek(SeekFrom::Start(0))?;
    let sig = read_u64_le_file(file)?;
    if sig != VHDX_FILE_SIGNATURE {
        return Err(VmkatzError::InvalidMagic(sig as u32));
    }
    Ok(())
}

/// Parse both headers, return the valid one with the highest sequence number.
fn parse_headers(file: &mut File) -> Result<VhdxHeader> {
    let mut best: Option<VhdxHeader> = None;

    for &offset in &[0x10000u64, 0x20000u64] {
        file.seek(SeekFrom::Start(offset))?;
        let sig = read_u32_le_file(file)?;
        if sig != VHDX_HEADER_SIGNATURE {
            continue;
        }
        // Skip checksum (4 bytes) — we don't verify CRC-32C for read-only
        let _checksum = read_u32_le_file(file)?;
        let sequence_number = read_u64_le_file(file)?;
        // FileWriteGuid (16B) + DataWriteGuid (16B)
        let _file_write_guid = read_guid(file)?;
        let _data_write_guid = read_guid(file)?;
        let log_guid = read_guid(file)?;

        match &best {
            Some(b) if sequence_number <= b.sequence_number => {}
            _ => {
                best = Some(VhdxHeader {
                    sequence_number,
                    log_guid,
                });
            }
        }
    }

    best.ok_or_else(|| VmkatzError::DiskFormatError("No valid VHDX header found".to_string()))
}

/// Parse region table at the given offset, extract BAT and metadata region info.
fn parse_region_table(file: &mut File, offset: u64) -> Result<VhdxRegions> {
    file.seek(SeekFrom::Start(offset))?;
    let sig = read_u32_le_file(file)?;
    if sig != VHDX_REGION_SIGNATURE {
        return Err(VmkatzError::DiskFormatError(format!(
            "Invalid region table signature at 0x{:x}: 0x{:08x}",
            offset, sig
        )));
    }
    let _checksum = read_u32_le_file(file)?;
    let entry_count = read_u32_le_file(file)?;
    let _reserved = read_u32_le_file(file)?;

    if entry_count > 2047 {
        return Err(VmkatzError::DiskFormatError(format!(
            "Region table entry count too large: {}",
            entry_count
        )));
    }

    let mut bat_offset = 0u64;
    let mut bat_length = 0u32;
    let mut metadata_offset = 0u64;
    let mut metadata_length = 0u32;

    for _ in 0..entry_count {
        let guid = read_guid(file)?;
        let file_offset = read_u64_le_file(file)?;
        let length = read_u32_le_file(file)?;
        let _required = read_u32_le_file(file)?;

        if guid == BAT_REGION_GUID {
            bat_offset = file_offset;
            bat_length = length;
        } else if guid == METADATA_REGION_GUID {
            metadata_offset = file_offset;
            metadata_length = length;
        }
    }

    if bat_offset == 0 || metadata_offset == 0 {
        return Err(VmkatzError::DiskFormatError(
            "VHDX region table missing BAT or metadata region".to_string(),
        ));
    }

    Ok(VhdxRegions {
        bat_offset,
        bat_length,
        metadata_offset,
        metadata_length,
    })
}

/// Parse the metadata region to extract disk parameters.
fn parse_metadata(file: &mut File, metadata_offset: u64) -> Result<VhdxMetadata> {
    file.seek(SeekFrom::Start(metadata_offset))?;
    let sig = read_u64_le_file(file)?;
    if sig != VHDX_METADATA_SIGNATURE {
        return Err(VmkatzError::DiskFormatError(format!(
            "Invalid metadata signature: 0x{:016x}",
            sig
        )));
    }
    // Skip reserved (2B) + entry_count (2B) + reserved (20B) = 24B
    // Actually: reserved(2) + entry_count(2) + reserved(20) = 24 bytes after sig(8)
    let mut hdr_rest = [0u8; 2];
    file.read_exact(&mut hdr_rest)?; // reserved
    let mut count_buf = [0u8; 2];
    file.read_exact(&mut count_buf)?;
    let entry_count = u16::from_le_bytes(count_buf);
    let mut reserved = [0u8; 20];
    file.read_exact(&mut reserved)?;

    if entry_count > 2047 {
        return Err(VmkatzError::DiskFormatError(format!(
            "Metadata entry count too large: {}",
            entry_count
        )));
    }

    // Collect metadata entries: (guid, offset_from_metadata_start, length)
    let mut entries: Vec<([u8; 16], u32, u32)> = Vec::new();
    for _ in 0..entry_count {
        let item_id = read_guid(file)?;
        let item_offset = read_u32_le_file(file)?;
        let item_length = read_u32_le_file(file)?;
        let _flags = read_u32_le_file(file)?;
        let _reserved2 = read_u32_le_file(file)?;
        entries.push((item_id, item_offset, item_length));
    }

    let mut block_size: Option<u32> = None;
    let mut virtual_disk_size: Option<u64> = None;
    let mut logical_sector_size: Option<u32> = None;
    let mut has_parent = false;

    for (guid, item_offset, item_length) in &entries {
        let abs_offset = metadata_offset + *item_offset as u64;

        if *guid == META_FILE_PARAMETERS && *item_length >= 8 {
            file.seek(SeekFrom::Start(abs_offset))?;
            let bs = read_u32_le_file(file)?;
            let flags = read_u32_le_file(file)?;
            block_size = Some(bs);
            has_parent = (flags & 2) != 0; // bit 1 = HasParent
        } else if *guid == META_VIRTUAL_DISK_SIZE && *item_length >= 8 {
            file.seek(SeekFrom::Start(abs_offset))?;
            virtual_disk_size = Some(read_u64_le_file(file)?);
        } else if *guid == META_LOGICAL_SECTOR_SIZE && *item_length >= 4 {
            file.seek(SeekFrom::Start(abs_offset))?;
            logical_sector_size = Some(read_u32_le_file(file)?);
        }
    }

    let block_size = block_size.ok_or_else(|| {
        VmkatzError::DiskFormatError("VHDX metadata missing File Parameters".to_string())
    })?;
    let virtual_disk_size = virtual_disk_size.ok_or_else(|| {
        VmkatzError::DiskFormatError("VHDX metadata missing Virtual Disk Size".to_string())
    })?;
    let logical_sector_size = logical_sector_size.unwrap_or(512);

    Ok(VhdxMetadata {
        block_size,
        virtual_disk_size,
        logical_sector_size,
        has_parent,
    })
}

/// Parse parent locator from metadata to find the parent VHDX path.
fn parse_parent_locator(file: &mut File, metadata_offset: u64) -> Result<Option<String>> {
    // Re-read metadata entries to find parent locator
    file.seek(SeekFrom::Start(metadata_offset + 8))?; // skip signature
    let mut hdr_rest = [0u8; 2];
    file.read_exact(&mut hdr_rest)?;
    let mut count_buf = [0u8; 2];
    file.read_exact(&mut count_buf)?;
    let entry_count = u16::from_le_bytes(count_buf);
    let mut reserved = [0u8; 20];
    file.read_exact(&mut reserved)?;

    let mut parent_offset = 0u32;
    let mut parent_length = 0u32;

    for _ in 0..entry_count {
        let item_id = read_guid(file)?;
        let item_off = read_u32_le_file(file)?;
        let item_len = read_u32_le_file(file)?;
        let _flags = read_u32_le_file(file)?;
        let _reserved2 = read_u32_le_file(file)?;

        if item_id == META_PARENT_LOCATOR {
            parent_offset = item_off;
            parent_length = item_len;
        }
    }

    if parent_offset == 0 || parent_length < 20 {
        return Ok(None);
    }

    let abs_offset = metadata_offset + parent_offset as u64;
    file.seek(SeekFrom::Start(abs_offset))?;

    // Parent locator header: LocatorType (16B) + Reserved (2B) + KeyValueCount (2B)
    let _locator_type = read_guid(file)?;
    let mut tmp2 = [0u8; 2];
    file.read_exact(&mut tmp2)?; // reserved
    file.read_exact(&mut tmp2)?;
    let kv_count = u16::from_le_bytes(tmp2);

    // Key-value entries: 12 bytes each (key_offset: u32, value_offset: u32, key_length: u16, value_length: u16)
    struct KvEntry {
        key_offset: u32,
        value_offset: u32,
        key_length: u16,
        value_length: u16,
    }

    let mut kv_entries = Vec::new();
    for _ in 0..kv_count {
        let key_offset = read_u32_le_file(file)?;
        let value_offset = read_u32_le_file(file)?;
        let mut lens = [0u8; 2];
        file.read_exact(&mut lens)?;
        let key_length = u16::from_le_bytes(lens);
        file.read_exact(&mut lens)?;
        let value_length = u16::from_le_bytes(lens);
        kv_entries.push(KvEntry {
            key_offset,
            value_offset,
            key_length,
            value_length,
        });
    }

    // Read key-value pairs, looking for "relative_path" or "absolute_win32_path"
    let mut relative_path: Option<String> = None;
    let mut absolute_path: Option<String> = None;

    for kv in &kv_entries {
        // Read key (UTF-16LE)
        let key_abs = abs_offset + kv.key_offset as u64;
        file.seek(SeekFrom::Start(key_abs))?;
        let mut key_buf = vec![0u8; kv.key_length as usize];
        file.read_exact(&mut key_buf)?;
        let key = utf16le_to_string(&key_buf);

        // Read value (UTF-16LE)
        let val_abs = abs_offset + kv.value_offset as u64;
        file.seek(SeekFrom::Start(val_abs))?;
        let mut val_buf = vec![0u8; kv.value_length as usize];
        file.read_exact(&mut val_buf)?;
        let value = utf16le_to_string(&val_buf);

        match key.as_str() {
            "relative_path" => relative_path = Some(value),
            "absolute_win32_path" => absolute_path = Some(value),
            _ => {}
        }
    }

    // Prefer relative path for portability
    Ok(relative_path.or(absolute_path))
}

/// Convert UTF-16LE bytes to a String, stripping null terminator.
fn utf16le_to_string(data: &[u8]) -> String {
    crate::utils::utf16le_decode(data)
}

/// Resolve a parent path (possibly Windows-style) relative to the child VHDX.
fn resolve_parent_path(child_path: &Path, parent_ref: &str) -> PathBuf {
    // Convert Windows backslashes to forward slashes
    let normalized = parent_ref.replace('\\', "/");
    let parent_path = Path::new(&normalized);

    if parent_path.is_absolute() {
        // Try as-is first (works if running on Windows or path is valid)
        if parent_path.exists() {
            return parent_path.to_path_buf();
        }
        // On Linux: strip drive letter (e.g., "C:/foo" → "/foo") and try relative
        if normalized.len() > 2 && normalized.as_bytes()[1] == b':' {
            let stripped = &normalized[2..];
            let child_dir = child_path.parent().unwrap_or(Path::new("."));
            let relative = child_dir.join(Path::new(stripped).file_name().unwrap_or_default());
            if relative.exists() {
                return relative;
            }
        }
        parent_path.to_path_buf()
    } else {
        let child_dir = child_path.parent().unwrap_or(Path::new("."));
        child_dir.join(parent_path)
    }
}

impl VhdxDisk {
    /// Open a VHDX disk image, recursively opening parent for differencing disks.
    pub fn open(path: &Path) -> Result<Self> {
        let mut file = File::open(path)?;

        // 1. Validate file identifier
        validate_file_identifier(&mut file)?;

        // 2. Parse headers (pick valid one with highest sequence number)
        let header = parse_headers(&mut file)?;
        if !guid_is_zero(&header.log_guid) {
            log::warn!("VHDX has non-empty log GUID — log replay not implemented, data may be inconsistent");
        }

        // 3. Parse region table (try at 0x30000, fallback to 0x40000)
        let regions = parse_region_table(&mut file, 0x30000)
            .or_else(|_| parse_region_table(&mut file, 0x40000))?;

        // 4. Parse metadata
        let metadata = parse_metadata(&mut file, regions.metadata_offset)?;

        log::info!(
            "VHDX: disk_size={}MB block_size={}MB sector_size={} has_parent={}",
            metadata.virtual_disk_size / (1024 * 1024),
            metadata.block_size / (1024 * 1024),
            metadata.logical_sector_size,
            metadata.has_parent,
        );

        // 5. Compute BAT layout
        let block_size = metadata.block_size as u64;
        let logical_sector_size = metadata.logical_sector_size as u64;
        if block_size == 0 || logical_sector_size == 0 {
            return Err(VmkatzError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid VHDX metadata: block_size={}, logical_sector_size={}", block_size, logical_sector_size),
            )));
        }
        // chunk_ratio = (2^23 * logical_sector_size) / block_size
        // 8_388_608 = 2^23 (VHDX spec §3.5.1: number of payload blocks covered
        // by one sector bitmap block, derived from sector bitmap granularity).
        let chunk_ratio = (8_388_608 * logical_sector_size) / block_size;
        let data_blocks_count = metadata.virtual_disk_size.div_ceil(block_size);

        // Total BAT entries include interleaved sector bitmap entries
        let total_bat_entries = if metadata.has_parent {
            let sb_count = data_blocks_count.div_ceil(chunk_ratio);
            sb_count * (chunk_ratio + 1)
        } else if data_blocks_count > 0 {
            data_blocks_count + (data_blocks_count - 1) / chunk_ratio
        } else {
            0
        };

        // Clamp to what's actually in the region
        let max_entries_in_region = regions.bat_length as u64 / 8;
        let bat_entries_to_read = total_bat_entries.min(max_entries_in_region);

        // 6. Read BAT
        file.seek(SeekFrom::Start(regions.bat_offset))?;
        let mut bat = Vec::with_capacity(bat_entries_to_read as usize);
        for _ in 0..bat_entries_to_read {
            bat.push(read_u64_le_file(&mut file)?);
        }

        log::debug!(
            "VHDX: {} data blocks, chunk_ratio={}, {} BAT entries loaded",
            data_blocks_count,
            chunk_ratio,
            bat.len(),
        );

        // 7. Open parent for differencing disks
        let parent = if metadata.has_parent {
            match parse_parent_locator(&mut file, regions.metadata_offset) {
                Ok(Some(parent_ref)) => {
                    let parent_path = resolve_parent_path(path, &parent_ref);
                    log::info!("VHDX: differencing disk, parent: {:?}", parent_path);
                    if parent_path.exists() {
                        Some(Box::new(VhdxDisk::open(&parent_path)?))
                    } else {
                        log::warn!("VHDX parent not found: {:?}", parent_path);
                        None
                    }
                }
                Ok(None) => {
                    log::warn!("VHDX has_parent=true but no parent locator found");
                    None
                }
                Err(e) => {
                    log::warn!("VHDX parent locator parse error: {}", e);
                    None
                }
            }
        } else {
            None
        };

        Ok(VhdxDisk {
            file,
            disk_size: metadata.virtual_disk_size,
            block_size: metadata.block_size,
            logical_sector_size: metadata.logical_sector_size,
            chunk_ratio,
            bat,
            cursor: 0,
            parent,
        })
    }

    /// Read from a specific virtual block, returning bytes read.
    fn read_block(
        &mut self,
        block_index: u64,
        offset_in_block: u64,
        buf: &mut [u8],
    ) -> std::io::Result<usize> {
        // Compute BAT index (payload entries are interleaved with sector bitmap entries)
        let bat_index = block_index + (block_index / self.chunk_ratio);
        let entry = if (bat_index as usize) < self.bat.len() {
            self.bat[bat_index as usize]
        } else {
            0 // treat out-of-range as NOT_PRESENT
        };

        let state = (entry & 0x7) as u8;
        let file_offset = entry & 0xFFFF_FFFF_FFF0_0000;

        match state {
            PAYLOAD_BLOCK_FULLY_PRESENT => {
                let read_offset = file_offset + offset_in_block;
                self.file.seek(SeekFrom::Start(read_offset))?;
                self.file.read(buf)
            }
            PAYLOAD_BLOCK_PARTIALLY_PRESENT => {
                // For differencing disks: need sector bitmap
                self.read_partial_block(block_index, offset_in_block, file_offset, buf)
            }
            PAYLOAD_BLOCK_NOT_PRESENT => {
                // Dynamic: zeros. Differencing: parent.
                if let Some(ref mut parent) = self.parent {
                    let virtual_offset = block_index * self.block_size as u64 + offset_in_block;
                    parent.seek(SeekFrom::Start(virtual_offset))?;
                    parent.read(buf)
                } else {
                    buf.fill(0);
                    Ok(buf.len())
                }
            }
            PAYLOAD_BLOCK_UNDEFINED | PAYLOAD_BLOCK_ZERO | PAYLOAD_BLOCK_UNMAPPED => {
                buf.fill(0);
                Ok(buf.len())
            }
            _ => {
                // Unknown state — treat as zeros
                buf.fill(0);
                Ok(buf.len())
            }
        }
    }

    /// Handle PARTIALLY_PRESENT blocks (differencing disks with sector bitmap).
    fn read_partial_block(
        &mut self,
        block_index: u64,
        offset_in_block: u64,
        payload_file_offset: u64,
        buf: &mut [u8],
    ) -> std::io::Result<usize> {
        // Find the sector bitmap BAT entry for this chunk
        let chunk_index = block_index / self.chunk_ratio;
        let sb_bat_index = chunk_index * (self.chunk_ratio + 1) + self.chunk_ratio;

        let sb_entry = if (sb_bat_index as usize) < self.bat.len() {
            self.bat[sb_bat_index as usize]
        } else {
            0
        };

        let sb_state = (sb_entry & 0x7) as u8;
        let sb_file_offset = sb_entry & 0xFFFF_FFFF_FFF0_0000;

        if sb_state != 6 || sb_file_offset == 0 {
            // Sector bitmap not present — fall through to parent
            if let Some(ref mut parent) = self.parent {
                let virtual_offset = block_index * self.block_size as u64 + offset_in_block;
                parent.seek(SeekFrom::Start(virtual_offset))?;
                return parent.read(buf);
            }
            buf.fill(0);
            return Ok(buf.len());
        }

        // Read sector-by-sector using the bitmap
        let sector_size = self.logical_sector_size as u64;
        let block_size = self.block_size as u64;
        let mut filled = 0usize;
        let mut pos_in_block = offset_in_block;

        while filled < buf.len() && pos_in_block < block_size {
            let sector_index = pos_in_block / sector_size;
            let bitmap_byte_off = sb_file_offset + sector_index / 8;
            let bitmap_bit = (sector_index % 8) as u8;

            // Read bitmap byte
            self.file.seek(SeekFrom::Start(bitmap_byte_off))?;
            let mut bm = [0u8; 1];
            self.file.read_exact(&mut bm)?;

            let in_child = (bm[0] >> bitmap_bit) & 1 == 1;
            let offset_in_sector = pos_in_block % sector_size;
            let avail = (sector_size - offset_in_sector) as usize;
            let chunk = avail.min(buf.len() - filled);

            if in_child {
                // Read from this file
                let read_off = payload_file_offset + pos_in_block;
                self.file.seek(SeekFrom::Start(read_off))?;
                self.file.read_exact(&mut buf[filled..filled + chunk])?;
            } else if let Some(ref mut parent) = self.parent {
                // Read from parent
                let virtual_offset = block_index * block_size + pos_in_block;
                parent.seek(SeekFrom::Start(virtual_offset))?;
                parent.read_exact(&mut buf[filled..filled + chunk])?;
            } else {
                buf[filled..filled + chunk].fill(0);
            }

            filled += chunk;
            pos_in_block += chunk as u64;
        }

        Ok(filled)
    }
}

impl Read for VhdxDisk {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.cursor >= self.disk_size {
            return Ok(0);
        }

        let remaining = (self.disk_size - self.cursor) as usize;
        let to_read = buf.len().min(remaining);
        if to_read == 0 {
            return Ok(0);
        }

        let block_size = self.block_size as u64;
        let mut total = 0;
        while total < to_read {
            let pos = self.cursor;
            let block_index = pos / block_size;
            let offset_in_block = pos % block_size;
            let avail_in_block = (block_size - offset_in_block) as usize;
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

impl Seek for VhdxDisk {
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

impl super::DiskImage for VhdxDisk {
    fn disk_size(&self) -> u64 {
        self.disk_size
    }
}

