//! Logical-volume extent mapping for VMFS devices.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use crate::error::{Result, VmkatzError};
use crate::utils::{u32_le, u64_le};

pub(super) const LVM_HEADER_OFFSET: u64 = 0x0010_0000;
pub(super) const LVM_MAGIC: u32 = 0xC001_D00D;

// LVM PE table constants
const LVM_PES_PER_BITMAP: u32 = 8192;
const LVM_PE_ENTRY_SIZE: u32 = 128; // Allocated slot size; the descriptor uses 37 bytes.

/// Physical extent mapping: logical volume offset → physical device offset.
#[derive(Debug, Clone)]
struct PhysicalExtent {
    logical_offset: u64,
    physical_offset: u64,
    length: u64,
}

/// LVM volume map — translates logical volume offsets to physical device offsets.
#[derive(Debug)]
pub(super) struct LvmLayer {
    extents: Vec<PhysicalExtent>, // sorted by logical_offset
}

impl LvmLayer {
    pub(super) fn parse(file: &mut File) -> Result<Self> {
        file.seek(SeekFrom::Start(LVM_HEADER_OFFSET))
            .map_err(VmkatzError::Io)?;
        let mut hdr = [0u8; 0xD6];
        file.read_exact(&mut hdr).map_err(VmkatzError::Io)?;

        let magic = u32_le(&hdr, 0x00);
        if magic != LVM_MAGIC {
            return Err(VmkatzError::DiskFormatError(format!(
                "Invalid LVM magic 0x{magic:08x} at 0x{LVM_HEADER_OFFSET:x}"
            )));
        }

        let major_version = u32_le(&hdr, 0x04);
        let num_pes = u32_le(&hdr, 0x6A);
        let data_offset = u64_le(&hdr, 0x7A);
        let num_pe_maps = u32_le(&hdr, 0xBE);
        let md_alignment = u32_le(&hdr, 0xCA);
        let num_pes6 = u32_le(&hdr, 0xCE);
        let _num_volumes = u32_le(&hdr, 0x66);

        let is_lvm6 = major_version >= 6;
        let actual_num_pes = if is_lvm6 { num_pes6 } else { num_pes };

        log::debug!(
            "LVM v{major_version}: {actual_num_pes} PEs, data_offset=0x{data_offset:x}, mdAlignment={md_alignment}, numPEMaps={num_pe_maps}"
        );

        // Calculate offsets to PE bitmap and table
        let (device_metadata_size, max_volumes, pe_bitmap_size) = if is_lvm6 {
            (
                u64::from(md_alignment),
                1u32,
                u64::from(std::cmp::max(md_alignment, 1024)),
            )
        } else {
            (512u64, 512u32, 1024u64)
        };

        let unused_md_sectors = 1024u64 - u64::from(max_volumes);
        let unused_md_size = unused_md_sectors * 512;
        let reserved_size = unused_md_size - (256 * 32); // LVM_SIZEOF_SDTENTRY * FS_PLIST_DEF_MAX_PARTITIONS

        let offset_to_volume_table = device_metadata_size;
        let offset_to_sd_table =
            offset_to_volume_table + (u64::from(max_volumes) * 512) + reserved_size;
        let offset_to_pe_bitmap = offset_to_sd_table + (256 * 32);

        // Read volume descriptor to get logical volume size
        let vol_table_offset = LVM_HEADER_OFFSET + device_metadata_size;
        file.seek(SeekFrom::Start(vol_table_offset))
            .map_err(VmkatzError::Io)?;
        let mut vol_desc = [0u8; 0x200];
        file.read_exact(&mut vol_desc).map_err(VmkatzError::Io)?;
        let volume_size = u64_le(&vol_desc, 0x00);
        let volume_id = u32_le(&vol_desc, 0x70);

        log::debug!(
            "LVM volume: size=0x{:x} ({}GB), id={}",
            volume_size,
            volume_size / (1024 * 1024 * 1024),
            volume_id
        );

        // Read PE table entries
        let pe_bitmap_offset = LVM_HEADER_OFFSET + offset_to_pe_bitmap;
        let pe_table_size = u64::from(LVM_PES_PER_BITMAP) * u64::from(LVM_PE_ENTRY_SIZE);
        let num_maps = std::cmp::max(1, num_pe_maps);

        let mut extents = Vec::new();

        for map_idx in 0..num_maps {
            let map_offset =
                pe_bitmap_offset + (u64::from(map_idx) * (pe_bitmap_size + pe_table_size));
            let table_offset = map_offset + pe_bitmap_size;

            let pes_this_map = std::cmp::min(
                actual_num_pes - (map_idx * LVM_PES_PER_BITMAP),
                LVM_PES_PER_BITMAP,
            );

            // Each 128-byte slot contains a used flag and a 36-byte PE descriptor.
            for pe_idx in 0..pes_this_map {
                let entry_offset = table_offset + u64::from(pe_idx) * 128; // LVM_SIZEOF_PTENTRY = 128
                file.seek(SeekFrom::Start(entry_offset))
                    .map_err(VmkatzError::Io)?;
                let mut entry = [0u8; 0x25];
                file.read_exact(&mut entry).map_err(VmkatzError::Io)?;

                let used = entry[0];
                if used == 0 {
                    continue;
                }

                // PE descriptor starts at offset 1
                let pe_volume_id = u32_le(&entry, 0x05);
                let p_offset = u64_le(&entry, 0x09);
                let l_offset = u64_le(&entry, 0x11);
                let length = u64_le(&entry, 0x19);

                if pe_volume_id != volume_id {
                    continue;
                }

                log::debug!(
                    "PE[{pe_idx}]: phys=0x{p_offset:x} log=0x{l_offset:x} len=0x{length:x}"
                );

                extents.push(PhysicalExtent {
                    logical_offset: l_offset,
                    physical_offset: p_offset,
                    length,
                });
            }

            if (map_idx + 1) * LVM_PES_PER_BITMAP >= actual_num_pes {
                break;
            }
        }

        // Sort by logical offset
        extents.sort_by_key(|e| e.logical_offset);

        // Merge contiguous extents
        let mut merged = Vec::new();
        for ext in extents {
            if let Some(last) = merged.last_mut() {
                let last: &mut PhysicalExtent = last;
                if last.logical_offset + last.length == ext.logical_offset
                    && last.physical_offset + last.length == ext.physical_offset
                {
                    last.length += ext.length;
                    continue;
                }
            }
            merged.push(ext);
        }

        log::info!(
            "LVM: {} extents, volume_size=0x{:x}",
            merged.len(),
            volume_size
        );

        Ok(Self { extents: merged })
    }

    /// Translate logical volume offset to physical device offset.
    pub(super) fn logical_to_physical(&self, logical: u64) -> Option<u64> {
        // Binary search for the containing extent
        let idx = match self
            .extents
            .binary_search_by_key(&logical, |e| e.logical_offset)
        {
            Ok(i) => i,
            Err(0) => return None,
            Err(i) => i - 1,
        };

        let ext = &self.extents[idx];
        let offset_in_ext = logical - ext.logical_offset;
        if offset_in_ext < ext.length {
            Some(ext.physical_offset + offset_in_ext)
        } else {
            None
        }
    }
}
