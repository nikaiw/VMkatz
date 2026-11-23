//! VMFS superblock, resource metadata and file descriptors.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use crate::error::{Result, VmkatzError};
use crate::utils::{u16_le, u32_le, u64_le};

use super::lvm::LvmLayer;

pub(super) const VMFS_MAGIC: u32 = 0x2FAB_F15E;
pub(super) const VMFSL_MAGIC: u32 = 0x2FAB_F15F;
pub(super) const FS3_FS_HEADER_OFFSET: u64 = 0x0020_0000;
const RFMD_SIGNATURE: u32 = 0x7266_6D64; // "rfmd"

/// Parsed FS3_Descriptor (VMFS-5/6 superblock).
#[derive(Debug)]
pub(super) struct VmfsSuperblock {
    pub(super) _magic: u32,
    pub(super) _major_version: u32,
    pub(super) is_vmfs6: bool,
    pub(super) dense_sub_blocks: bool,
    pub(super) file_block_size: u64,
    pub(super) sub_block_size: u32,
    pub(super) fdc_cluster_group_offset: u32,
    pub(super) fdc_clusters_per_group: u32,
    pub(super) md_alignment: u32,
    pub(super) sfb_to_lfb_shift: u16,
    pub(super) _ptr_block_shift: u16,
    pub(super) _sfb_addr_bits: u16,
    pub(super) _label: String,
}

impl VmfsSuperblock {
    pub(super) fn parse(file: &mut File, lvm: &LvmLayer) -> Result<Self> {
        let vol_offset = FS3_FS_HEADER_OFFSET;
        let phys = lvm.logical_to_physical(vol_offset).ok_or_else(|| {
            VmkatzError::DiskFormatError("Cannot map superblock offset to physical".into())
        })?;

        file.seek(SeekFrom::Start(phys)).map_err(VmkatzError::Io)?;
        let mut buf = [0u8; 0x170];
        file.read_exact(&mut buf).map_err(VmkatzError::Io)?;

        let magic = u32_le(&buf, 0x00);
        if magic != VMFS_MAGIC && magic != VMFSL_MAGIC {
            return Err(VmkatzError::DiskFormatError(format!(
                "Invalid VMFS magic 0x{magic:08x} at vol offset 0x{vol_offset:x}"
            )));
        }

        let major_version = u32_le(&buf, 0x04);
        let is_vmfs6 = major_version >= 24;
        let dense_sub_blocks = u32_le(&buf, 0x19) & 0x04 != 0;

        let label_bytes = &buf[0x1D..0x9D];
        let label = String::from_utf8_lossy(
            &label_bytes[..label_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(label_bytes.len())],
        )
        .to_string();

        let file_block_size = u64_le(&buf, 0xA1);
        let fdc_cluster_group_offset = u32_le(&buf, 0xD1);
        let fdc_clusters_per_group = u32_le(&buf, 0xD5);
        let sub_block_size = u32_le(&buf, 0xD9);
        let md_alignment = u32_le(&buf, 0x134);
        let sfb_to_lfb_shift = u16_le(&buf, 0x138);
        let ptr_block_shift = u16_le(&buf, 0x13E);
        let sfb_addr_bits = u16_le(&buf, 0x140);

        // These sizing fields drive metadata allocations (fd_size, sub-block
        // reads). Reject absurd values (real ones are a few KB) so a crafted
        // superblock can't force a multi-GB allocation. Cap: 16 MiB.
        if md_alignment > 16 * 1024 * 1024 || sub_block_size > 16 * 1024 * 1024 {
            return Err(VmkatzError::DiskFormatError(format!(
                "VMFS superblock metadata size out of range: mdAlign=0x{md_alignment:x} subBlock=0x{sub_block_size:x}"
            )));
        }

        log::info!(
            "{} '{}': blockSize=0x{:x}, mdAlign=0x{:x}, subBlockSize=0x{:x}",
            if is_vmfs6 { "VMFS-6" } else { "VMFS-5" },
            label,
            file_block_size,
            md_alignment,
            sub_block_size
        );

        Ok(Self {
            _magic: magic,
            _major_version: major_version,
            is_vmfs6,
            dense_sub_blocks,
            file_block_size,
            sub_block_size,
            fdc_cluster_group_offset,
            fdc_clusters_per_group,
            md_alignment,
            sfb_to_lfb_shift,
            _ptr_block_shift: ptr_block_shift,
            _sfb_addr_bits: sfb_addr_bits,
            _label: label,
        })
    }

    pub(super) const fn fd_size(&self) -> u64 {
        if self.is_vmfs6 {
            2 * self.md_alignment as u64
        } else {
            2048
        }
    }

    pub(super) const fn fd_meta_offset(&self) -> u64 {
        if self.is_vmfs6 {
            self.md_alignment as u64
        } else {
            512
        }
    }

    pub(super) const fn fd_data_addrs_size(&self) -> usize {
        if !self.is_vmfs6 {
            return 1024;
        } // 256 * 4 bytes
        if self.md_alignment <= 0x1000 {
            2560
        } else {
            self.md_alignment as usize >> 1
        }
    }

    pub(super) const fn fd_max_data_addrs(&self) -> usize {
        if !self.is_vmfs6 {
            return 256;
        }
        if self.md_alignment <= 0x1000 {
            320
        } else {
            self.md_alignment as usize >> 4
        }
    }

    pub(super) const fn fd_data_addrs_offset(&self) -> usize {
        // saturating: a crafted small md_alignment can make fd_data_addrs_size
        // exceed fd_size (underflow → panic in debug). The block-pointer loop is
        // separately bounded by `off + N > buf.len()`, so 0 is a safe floor.
        (self.fd_size() as usize).saturating_sub(self.fd_data_addrs_size())
    }

    pub(super) const fn file_block_size_shift(&self) -> u32 {
        self.file_block_size.trailing_zeros()
    }

    pub(super) const fn ptr_block_num_ptrs(&self) -> usize {
        if !self.is_vmfs6 {
            return 1024;
        } // 4096/4
        if self.md_alignment < 0x10000 {
            8192
        } else {
            self.md_alignment as usize >> 3
        }
    }

    pub(super) const fn ptr_block_page_size(&self) -> usize {
        if self.is_vmfs6 { 0x10000 } else { 0x1000 }
    }

    /// SFB resources per cluster — needed for SFB→volume offset calculation.
    pub(super) fn sfb_size(&self) -> u64 {
        if self.file_block_size == 0 {
            return 0x2000;
        }
        std::cmp::min(0x2000, 0x2000_0000u64 / self.file_block_size)
    }
}

/// Parsed FS3_ResFileMetadata (88 bytes, "rfmd" signature).
#[derive(Debug, Clone)]
pub(super) struct ResFileMeta {
    pub(super) resources_per_cluster: u32,
    pub(super) clusters_per_group: u32,
    pub(super) cluster_group_offset: u32,
    pub(super) resource_size: u32,
    pub(super) cluster_group_size: u32,
    pub(super) child_meta_offset: u32,
    pub(super) flags: u32,
    pub(super) parent_resources_per_cluster: u32,
    pub(super) parent_clusters_per_group: u32,
    pub(super) parent_cluster_group_size: u32,
}

impl ResFileMeta {
    pub(super) fn parse(data: &[u8], is_vmfs6: bool) -> Option<Self> {
        if data.len() < 0x14 {
            return None;
        }

        // VMFS-6 has an rfmd signature at offset 0x20; VMFS-5 does not
        if is_vmfs6 {
            if data.len() < 0x58 {
                return None;
            }
            let signature = u32_le(data, 0x20);
            if signature != RFMD_SIGNATURE {
                log::warn!("Invalid rfmd signature: 0x{signature:08x}");
                return None;
            }
        }

        let resources_per_cluster = u32_le(data, 0x00);
        let clusters_per_group = u32_le(data, 0x04);
        let cluster_group_offset = u32_le(data, 0x08);
        let resource_size = u32_le(data, 0x0C);
        let cluster_group_size = u32_le(data, 0x10);

        // Extended fields only in VMFS-6
        let (
            flags,
            child_meta_offset,
            parent_resources_per_cluster,
            parent_clusters_per_group,
            parent_cluster_group_size,
        ) = if is_vmfs6 && data.len() >= 0x44 {
            (
                u32_le(data, 0x28),
                u32_le(data, 0x34),
                u32_le(data, 0x38),
                u32_le(data, 0x3C),
                u32_le(data, 0x40),
            )
        } else {
            (0, 0, 0, 0, 0)
        };

        Some(Self {
            resources_per_cluster,
            clusters_per_group,
            cluster_group_offset,
            resource_size,
            cluster_group_size,
            child_meta_offset,
            flags,
            parent_resources_per_cluster,
            parent_clusters_per_group,
            parent_cluster_group_size,
        })
    }
}

/// Parsed FS3_FileMetadata from a file descriptor.
#[derive(Debug, Clone)]
pub(super) struct FileDescriptor {
    pub(super) address: u32,
    pub(super) desc_type: u32,
    pub(super) file_length: u64,
    pub(super) num_blocks: u64,
    pub(super) zla: u32,
    pub(super) block_offset_shift: u8,
    /// Block pointer array (up to 320 u64 entries)
    pub(super) blocks: Vec<u64>,
}
