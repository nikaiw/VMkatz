//! VMFS-6 self-contained raw parser — reads flat VMDK files directly from ESXi SCSI devices,
//! bypassing VMFS file locks on running VMs.
//!
//! Resolution chain: LVM → Superblock → SFD bootstrap → FDC resource → FD → Directory → File data.
//!
//! No mounted filesystem, no vmkfstools, no .sbc.sf file access needed.
//! Everything is read from the raw SCSI partition device.

use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::error::{Result, VmkatzError};

// ── Constants ────────────────────────────────────────────────────────

const LVM_HEADER_OFFSET: u64 = 0x0010_0000;
const LVM_MAGIC: u32 = 0xC001_D00D;
const VMFS_MAGIC: u32 = 0x2FAB_F15E;
const VMFSL_MAGIC: u32 = 0x2FAB_F15F;
const FS3_FS_HEADER_OFFSET: u64 = 0x0020_0000;
const RFMD_SIGNATURE: u32 = 0x7266_6D64; // "rfmd"

// System file descriptor addresses (32-bit FD addresses)
const ROOT_DIR_ADDR: u32 = 0x0000_0004;
const FBB_DESC_ADDR: u32 = 0x0040_0004;
const FDC_DESC_ADDR: u32 = 0x0080_0004;
const PBC_DESC_ADDR: u32 = 0x00C0_0004;
const SBC_DESC_ADDR: u32 = 0x0100_0004;
const PB2_DESC_ADDR: u32 = 0x0180_0004;

// Address type tags (lower 3 bits)
const ADDR_SFB: u8 = 1; // Small File Block
const ADDR_SB: u8 = 2;  // Sub-Block
const ADDR_PB: u8 = 3;  // Pointer Block
const _ADDR_FD: u8 = 4; // File Descriptor
const ADDR_PB2: u8 = 5; // Pointer Block v2
const ADDR_LFB: u8 = 7; // Large File Block

// ZLA (Zero Level Address) types
const ZLA_FILE_BLOCK: u32 = 1;
const ZLA_SUB_BLOCK: u32 = 2;
const ZLA_POINTER_BLOCK: u32 = 3;
const ZLA_POINTER2_BLOCK: u32 = 5;
const ZLA_DOUBLE_INDIRECT: u32 = 0x10D0;
const ZLA_RESIDENT: u32 = 0x10D1;

// Directory constants
const FS6_DIR_HEADER_VERSION: u32 = 0x00F5_0001;
const FS6_DIR_HEADER_DEBUG_VERSION: u32 = 0x00FD_C001;
const FS6_DIR_HEADER_BLOCK_SIZE: u64 = 0x10000;
const FS6_DIR_ENTRY_SIZE: usize = 0x120; // 288 bytes
const FS6_DIR_BLOCK_HEADER_SIZE: usize = 0x40; // 64 bytes

// LVM PE table constants
const LVM_PES_PER_BITMAP: u32 = 8192;
const LVM_PE_ENTRY_SIZE: u32 = 128; // 0x80 according to sizeof but cstruct says 0x25 (37)... use 0x80

// ── LVM Layer ────────────────────────────────────────────────────────

/// Physical extent mapping: logical volume offset → physical device offset.
#[derive(Debug, Clone)]
struct PhysicalExtent {
    logical_offset: u64,
    physical_offset: u64,
    length: u64,
}

/// LVM volume map — translates logical volume offsets to physical device offsets.
#[derive(Debug)]
struct LvmLayer {
    extents: Vec<PhysicalExtent>, // sorted by logical_offset
}

impl LvmLayer {
    fn parse(file: &mut File) -> Result<Self> {
        file.seek(SeekFrom::Start(LVM_HEADER_OFFSET))
            .map_err(VmkatzError::Io)?;
        let mut hdr = [0u8; 0xD6];
        file.read_exact(&mut hdr).map_err(VmkatzError::Io)?;

        let magic = u32::from_le_bytes(hdr[0x00..0x04].try_into().unwrap());
        if magic != LVM_MAGIC {
            return Err(VmkatzError::DiskFormatError(format!(
                "Invalid LVM magic 0x{:08x} at 0x{:x}",
                magic, LVM_HEADER_OFFSET
            )));
        }

        let major_version = u32::from_le_bytes(hdr[0x04..0x08].try_into().unwrap());
        let num_pes = u32::from_le_bytes(hdr[0x6A..0x6E].try_into().unwrap());
        let data_offset = u64::from_le_bytes(hdr[0x7A..0x82].try_into().unwrap());
        let num_pe_maps = u32::from_le_bytes(hdr[0xBE..0xC2].try_into().unwrap());
        let md_alignment = u32::from_le_bytes(hdr[0xCA..0xCE].try_into().unwrap());
        let num_pes6 = u32::from_le_bytes(hdr[0xCE..0xD2].try_into().unwrap());
        let _num_volumes = u32::from_le_bytes(hdr[0x66..0x6A].try_into().unwrap());

        let is_lvm6 = major_version >= 6;
        let actual_num_pes = if is_lvm6 { num_pes6 } else { num_pes };

        log::debug!(
            "LVM v{}: {} PEs, data_offset=0x{:x}, mdAlignment={}, numPEMaps={}",
            major_version, actual_num_pes, data_offset, md_alignment, num_pe_maps
        );

        // Calculate offsets to PE bitmap and table
        let (device_metadata_size, max_volumes, pe_bitmap_size) = if is_lvm6 {
            (
                md_alignment as u64,
                1u32,
                std::cmp::max(md_alignment, 1024) as u64,
            )
        } else {
            (512u64, 512u32, 1024u64)
        };

        let unused_md_sectors = 1024u64 - max_volumes as u64;
        let unused_md_size = unused_md_sectors * 512;
        let reserved_size = unused_md_size - (256 * 32); // LVM_SIZEOF_SDTENTRY * FS_PLIST_DEF_MAX_PARTITIONS

        let offset_to_volume_table = device_metadata_size;
        let offset_to_sd_table =
            offset_to_volume_table + (max_volumes as u64 * 512) + reserved_size;
        let offset_to_pe_bitmap = offset_to_sd_table + (256 * 32);

        // Read volume descriptor to get logical volume size
        let vol_table_offset = LVM_HEADER_OFFSET + device_metadata_size;
        file.seek(SeekFrom::Start(vol_table_offset))
            .map_err(VmkatzError::Io)?;
        let mut vol_desc = [0u8; 0x200];
        file.read_exact(&mut vol_desc).map_err(VmkatzError::Io)?;
        let volume_size = u64::from_le_bytes(vol_desc[0x00..0x08].try_into().unwrap());
        let volume_id = u32::from_le_bytes(vol_desc[0x70..0x74].try_into().unwrap());

        log::debug!(
            "LVM volume: size=0x{:x} ({}GB), id={}",
            volume_size,
            volume_size / (1024 * 1024 * 1024),
            volume_id
        );

        // Read PE table entries
        let pe_bitmap_offset = LVM_HEADER_OFFSET + offset_to_pe_bitmap;
        let pe_table_size = LVM_PES_PER_BITMAP as u64 * LVM_PE_ENTRY_SIZE as u64;
        let num_maps = std::cmp::max(1, num_pe_maps);

        let mut extents = Vec::new();

        for map_idx in 0..num_maps {
            let map_offset =
                pe_bitmap_offset + (map_idx as u64 * (pe_bitmap_size + pe_table_size));
            let table_offset = map_offset + pe_bitmap_size;

            let pes_this_map =
                std::cmp::min(actual_num_pes - (map_idx * LVM_PES_PER_BITMAP), LVM_PES_PER_BITMAP);

            // PE table entry is 0x25 bytes (1 byte used flag + 0x24 bytes PE descriptor)
            // But the actual stride is LVM_SIZEOF_PTENTRY = 128 bytes per dissect constants
            // Wait, dissect says sizeof = 0x25 and uses that for iteration...
            // Let me re-check: c_lvm says LVM_SIZEOF_PTENTRY = 128
            // But the struct is only 0x25 bytes. The SIZEOF is the allocation size.
            // Actually looking at _iter_pe: table_offset += c_lvm.LVM_SIZEOF_PTENTRY
            // And LVM_SIZEOF_PTENTRY = 128
            // So each PE entry occupies 128 bytes in the table even though the struct is 37 bytes.
            for pe_idx in 0..pes_this_map {
                let entry_offset = table_offset + pe_idx as u64 * 128; // LVM_SIZEOF_PTENTRY = 128
                file.seek(SeekFrom::Start(entry_offset))
                    .map_err(VmkatzError::Io)?;
                let mut entry = [0u8; 0x25];
                file.read_exact(&mut entry).map_err(VmkatzError::Io)?;

                let used = entry[0];
                if used == 0 {
                    continue;
                }

                // PE descriptor starts at offset 1
                let pe_volume_id =
                    u32::from_le_bytes(entry[0x05..0x09].try_into().unwrap());
                let p_offset =
                    u64::from_le_bytes(entry[0x09..0x11].try_into().unwrap());
                let l_offset =
                    u64::from_le_bytes(entry[0x11..0x19].try_into().unwrap());
                let length =
                    u64::from_le_bytes(entry[0x19..0x21].try_into().unwrap());

                if pe_volume_id != volume_id {
                    continue;
                }

                log::debug!(
                    "PE[{}]: phys=0x{:x} log=0x{:x} len=0x{:x}",
                    pe_idx,
                    p_offset,
                    l_offset,
                    length
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

        Ok(LvmLayer {
            extents: merged,
        })
    }

    /// Translate logical volume offset to physical device offset.
    fn logical_to_physical(&self, logical: u64) -> Option<u64> {
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

// ── VMFS Superblock ──────────────────────────────────────────────────

/// Parsed FS3_Descriptor (VMFS-6 superblock).
#[derive(Debug)]
struct VmfsSuperblock {
    _magic: u32,
    _major_version: u32,
    file_block_size: u64,
    sub_block_size: u32,
    fdc_cluster_group_offset: u32,
    fdc_clusters_per_group: u32,
    md_alignment: u32,
    sfb_to_lfb_shift: u16,
    _ptr_block_shift: u16,
    _sfb_addr_bits: u16,
    _label: String,
}

impl VmfsSuperblock {
    fn parse(file: &mut File, lvm: &LvmLayer) -> Result<Self> {
        let vol_offset = FS3_FS_HEADER_OFFSET;
        let phys = lvm.logical_to_physical(vol_offset).ok_or_else(|| {
            VmkatzError::DiskFormatError("Cannot map superblock offset to physical".into())
        })?;

        file.seek(SeekFrom::Start(phys)).map_err(VmkatzError::Io)?;
        let mut buf = [0u8; 0x170];
        file.read_exact(&mut buf).map_err(VmkatzError::Io)?;

        let magic = u32::from_le_bytes(buf[0x00..0x04].try_into().unwrap());
        if magic != VMFS_MAGIC && magic != VMFSL_MAGIC {
            return Err(VmkatzError::DiskFormatError(format!(
                "Invalid VMFS magic 0x{:08x} at vol offset 0x{:x}",
                magic, vol_offset
            )));
        }

        let major_version = u32::from_le_bytes(buf[0x04..0x08].try_into().unwrap());
        if major_version < 24 {
            return Err(VmkatzError::DiskFormatError(format!(
                "Unsupported VMFS version {} (need VMFS-6, majorVersion >= 24)",
                major_version
            )));
        }

        let label_bytes = &buf[0x1D..0x9D];
        let label = String::from_utf8_lossy(
            &label_bytes[..label_bytes.iter().position(|&b| b == 0).unwrap_or(label_bytes.len())],
        )
        .to_string();

        let file_block_size = u64::from_le_bytes(buf[0xA1..0xA9].try_into().unwrap());
        let fdc_cluster_group_offset = u32::from_le_bytes(buf[0xD1..0xD5].try_into().unwrap());
        let fdc_clusters_per_group = u32::from_le_bytes(buf[0xD5..0xD9].try_into().unwrap());
        let sub_block_size = u32::from_le_bytes(buf[0xD9..0xDD].try_into().unwrap());
        let md_alignment = u32::from_le_bytes(buf[0x134..0x138].try_into().unwrap());
        let sfb_to_lfb_shift = u16::from_le_bytes(buf[0x138..0x13A].try_into().unwrap());
        let ptr_block_shift = u16::from_le_bytes(buf[0x13E..0x140].try_into().unwrap());
        let sfb_addr_bits = u16::from_le_bytes(buf[0x140..0x142].try_into().unwrap());

        log::info!(
            "VMFS-6 '{}': blockSize=0x{:x}, mdAlign=0x{:x}, subBlockSize=0x{:x}",
            label,
            file_block_size,
            md_alignment,
            sub_block_size
        );

        Ok(VmfsSuperblock {
            _magic: magic,
            _major_version: major_version,
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

    fn fd_size(&self) -> u64 {
        2 * self.md_alignment as u64
    }

    fn fd_meta_offset(&self) -> u64 {
        self.md_alignment as u64
    }

    fn fd_data_addrs_size(&self) -> usize {
        if self.md_alignment <= 0x1000 {
            2560
        } else {
            self.md_alignment as usize >> 1
        }
    }

    fn fd_max_data_addrs(&self) -> usize {
        if self.md_alignment <= 0x1000 {
            320
        } else {
            self.md_alignment as usize >> 4
        }
    }

    fn fd_data_addrs_offset(&self) -> usize {
        self.fd_size() as usize - self.fd_data_addrs_size()
    }

    fn file_block_size_shift(&self) -> u32 {
        self.file_block_size.trailing_zeros()
    }

    fn ptr_block_num_ptrs(&self) -> usize {
        if self.md_alignment < 0x10000 {
            8192
        } else {
            self.md_alignment as usize >> 3
        }
    }

    /// SFB resources per cluster — needed for SFB→volume offset calculation.
    fn sfb_size(&self) -> u64 {
        if self.file_block_size == 0 { return 0x2000; }
        std::cmp::min(0x2000, 0x2000_0000u64 / self.file_block_size)
    }
}

// ── Resource File Metadata ───────────────────────────────────────────

/// Parsed FS3_ResFileMetadata (88 bytes, "rfmd" signature).
#[derive(Debug, Clone)]
struct ResFileMeta {
    resources_per_cluster: u32,
    clusters_per_group: u32,
    cluster_group_offset: u32,
    resource_size: u32,
    cluster_group_size: u32,
    child_meta_offset: u32,
    flags: u32,
    parent_resources_per_cluster: u32,
    parent_clusters_per_group: u32,
    parent_cluster_group_size: u32,
}

impl ResFileMeta {
    fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 0x58 {
            return None;
        }
        let signature = u32::from_le_bytes(data[0x20..0x24].try_into().unwrap());
        if signature != RFMD_SIGNATURE {
            log::warn!("Invalid rfmd signature: 0x{:08x}", signature);
            return None;
        }

        Some(ResFileMeta {
            resources_per_cluster: u32::from_le_bytes(data[0x00..0x04].try_into().unwrap()),
            clusters_per_group: u32::from_le_bytes(data[0x04..0x08].try_into().unwrap()),
            cluster_group_offset: u32::from_le_bytes(data[0x08..0x0C].try_into().unwrap()),
            resource_size: u32::from_le_bytes(data[0x0C..0x10].try_into().unwrap()),
            cluster_group_size: u32::from_le_bytes(data[0x10..0x14].try_into().unwrap()),
            flags: u32::from_le_bytes(data[0x28..0x2C].try_into().unwrap()),
            child_meta_offset: u32::from_le_bytes(data[0x34..0x38].try_into().unwrap()),
            parent_resources_per_cluster: u32::from_le_bytes(
                data[0x38..0x3C].try_into().unwrap(),
            ),
            parent_clusters_per_group: u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()),
            parent_cluster_group_size: u32::from_le_bytes(data[0x40..0x44].try_into().unwrap()),
        })
    }

}

// ── File Descriptor ──────────────────────────────────────────────────

/// Parsed FS3_FileMetadata from a file descriptor.
#[derive(Debug, Clone)]
struct FileDescriptor {
    address: u32,
    desc_type: u32,
    file_length: u64,
    num_blocks: u64,
    zla: u32,
    block_offset_shift: u8,
    /// Block pointer array (up to 320 u64 entries)
    blocks: Vec<u64>,
}

// ── Address Parsing ──────────────────────────────────────────────────

/// Parse FD address (32-bit) → (cluster, resource).
fn parse_fd_addr(addr: u32) -> (u32, u32) {
    let cluster = (addr >> 6) & 0xFFFF;
    let resource = (addr >> 22) & 0x3FF;
    (cluster, resource)
}

/// Parse SFB address (64-bit) → (cluster, resource).
fn parse_sfb_addr(addr: u64) -> (u64, u64) {
    let cluster = (addr >> 15) & 0x7FFF_FFFF;
    let resource = (addr >> 51) & 0x1FFF;
    (cluster, resource)
}

/// Parse PB/PB2/SB address (64-bit) → (cluster, resource).
/// PB, PB2, and SB all use the same encoding on VMFS6.
fn parse_pb_addr(addr: u64) -> (u64, u64) {
    let cluster = (addr >> 6) & 0xF_FFFF_FFFF;
    let resource = (addr >> 56) & 0xFF;
    (cluster, resource)
}

/// Parse LFB address (64-bit) → block number.
fn parse_lfb_addr(addr: u64) -> u64 {
    (addr >> 15) & 0x7FFF_FFFF
}

/// Get address type from lower 3 bits.
fn addr_type(addr: u64) -> u8 {
    (addr & 0x07) as u8
}

/// Check TBZ bitmap for SFB/LFB (bits [14:7]).
fn addr_tbz(addr: u64) -> u8 {
    ((addr >> 7) & 0xFF) as u8
}

// ── Directory Entry ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct DirEntry {
    entry_type: u32,
    fd_addr: u32,
    name: String,
}

// ── Main VMFS-6 Volume Handle ────────────────────────────────────────

/// Self-contained VMFS-6 volume reader.
/// Reads everything from the raw SCSI device via LVM → volume offset translation.
struct Vmfs6Volume {
    file: File,
    lvm: LvmLayer,
    sb: VmfsSuperblock,
    /// FDC resource metadata (for reading file descriptors by address)
    fdc_meta: ResFileMeta,
    /// FDC file descriptor (to read FDC data blocks)
    fdc_fd: FileDescriptor,
    /// FBB (LFB) resource metadata
    fbb_meta: Option<ResFileMeta>,
    /// SFB child resource metadata (from FBB child)
    sfb_meta: Option<ResFileMeta>,
    /// PBC resource metadata
    pbc_meta: Option<ResFileMeta>,
    /// PBC file descriptor
    pbc_fd: Option<FileDescriptor>,
    /// PB2 resource metadata
    pb2_meta: Option<ResFileMeta>,
    /// PB2 file descriptor
    pb2_fd: Option<FileDescriptor>,
    /// SBC resource metadata
    sbc_meta: Option<ResFileMeta>,
    /// SBC file descriptor
    sbc_fd: Option<FileDescriptor>,
}

impl Vmfs6Volume {
    /// Open a VMFS-6 volume from a raw device.
    fn open(path: &Path) -> Result<Self> {
        let mut file = File::open(path).map_err(VmkatzError::Io)?;

        // Step 1: Parse LVM
        let lvm = LvmLayer::parse(&mut file)?;

        // Step 2: Parse superblock
        let sb = VmfsSuperblock::parse(&mut file, &lvm)?;

        // Step 3: Bootstrap system FDs
        // Read FDC descriptor using SFD offset calculation
        let fdc_fd = Self::read_sfd(&mut file, &lvm, &sb, FDC_DESC_ADDR)?;

        log::info!(
            "FDC: size={}, zla={}, blocks={}",
            fdc_fd.file_length,
            fdc_fd.zla,
            fdc_fd.blocks.len()
        );

        // Step 4: Read FDC resource metadata from the FDC file data
        // The metadata is at offset 0 of the FDC file data
        let fdc_data = Self::read_fd_data_range(&mut file, &lvm, &sb, &fdc_fd, 0, 0x58)?;
        let fdc_meta = ResFileMeta::parse(&fdc_data).ok_or_else(|| {
            VmkatzError::DiskFormatError("Cannot parse FDC resource metadata".into())
        })?;

        log::info!(
            "FDC meta: {}R/C, {}C/CG, resSize={}, cgOffset=0x{:x}, cgSize=0x{:x}",
            fdc_meta.resources_per_cluster,
            fdc_meta.clusters_per_group,
            fdc_meta.resource_size,
            fdc_meta.cluster_group_offset,
            fdc_meta.cluster_group_size
        );

        let mut vol = Vmfs6Volume {
            file,
            lvm,
            sb,
            fdc_meta,
            fdc_fd,
            fbb_meta: None,
            sfb_meta: None,
            pbc_meta: None,
            pbc_fd: None,
            pb2_meta: None,
            pb2_fd: None,
            sbc_meta: None,
            sbc_fd: None,
        };

        // Step 5: Read other system resource files via FDC
        // FBB (file block bitmap) — contains LFB resource + SFB child resource
        if let Ok(fbb_fd) = vol.read_fd(FBB_DESC_ADDR) {
            if let Some(fbb_meta) = vol.read_resource_meta(&fbb_fd, 0) {
                log::info!(
                    "FBB meta: {}R/C, resSize={}, childOffset=0x{:x}",
                    fbb_meta.resources_per_cluster,
                    fbb_meta.resource_size,
                    fbb_meta.child_meta_offset
                );
                // Read SFB child metadata
                if fbb_meta.child_meta_offset > 0 {
                    if let Some(sfb_meta) =
                        vol.read_resource_meta(&fbb_fd, fbb_meta.child_meta_offset as u64)
                    {
                        log::info!(
                            "SFB meta: {}R/C, resSize={}",
                            sfb_meta.resources_per_cluster,
                            sfb_meta.resource_size
                        );
                        vol.sfb_meta = Some(sfb_meta);
                    }
                }
                vol.fbb_meta = Some(fbb_meta);
            }
        }

        // PBC (pointer block cluster)
        if let Ok(pbc_fd) = vol.read_fd(PBC_DESC_ADDR) {
            if let Some(pbc_meta) = vol.read_resource_meta(&pbc_fd, 0) {
                log::info!(
                    "PBC meta: {}R/C, resSize=0x{:x}",
                    pbc_meta.resources_per_cluster,
                    pbc_meta.resource_size
                );
                vol.pbc_fd = Some(pbc_fd);
                vol.pbc_meta = Some(pbc_meta);
            }
        }

        // PB2 (pointer block v2)
        if let Ok(pb2_fd) = vol.read_fd(PB2_DESC_ADDR) {
            if let Some(pb2_meta) = vol.read_resource_meta(&pb2_fd, 0) {
                log::info!(
                    "PB2 meta: {}R/C, resSize=0x{:x}",
                    pb2_meta.resources_per_cluster,
                    pb2_meta.resource_size
                );
                vol.pb2_fd = Some(pb2_fd);
                vol.pb2_meta = Some(pb2_meta);
            }
        }

        // SBC (sub-block cluster)
        if let Ok(sbc_fd) = vol.read_fd(SBC_DESC_ADDR) {
            if let Some(sbc_meta) = vol.read_resource_meta(&sbc_fd, 0) {
                log::info!(
                    "SBC meta: {}R/C, resSize=0x{:x}",
                    sbc_meta.resources_per_cluster,
                    sbc_meta.resource_size
                );
                vol.sbc_fd = Some(sbc_fd);
                vol.sbc_meta = Some(sbc_meta);
            }
        }

        Ok(vol)
    }

    /// Compute SFD offset for VMFS-6 system file descriptors (bootstrap, before FDC is available).
    fn sfd_offset(sb: &VmfsSuperblock, addr: u32) -> u64 {
        let (_, resource) = parse_fd_addr(addr);
        let md = sb.md_alignment as u64;
        // From dissect: cg_offset = (((mdAlignment << 10) + 0x3FFFFF) & 0xFFFFFFFFFFF00000) + fdcClusterGroupOffset
        let cg_offset =
            (((md << 10) + 0x3FFFFF) & 0xFFFF_FFFF_FFF0_0000) + sb.fdc_cluster_group_offset as u64;
        let resource_size = 2 * md;
        let resource_offset = resource as u64 * resource_size;
        cg_offset + (sb.fdc_clusters_per_group as u64 * resource_size) + resource_offset
    }

    /// Read a system file descriptor by its well-known address (bootstrap path).
    fn read_sfd(
        file: &mut File,
        lvm: &LvmLayer,
        sb: &VmfsSuperblock,
        addr: u32,
    ) -> Result<FileDescriptor> {
        let vol_offset = Self::sfd_offset(sb, addr);
        let phys = lvm.logical_to_physical(vol_offset).ok_or_else(|| {
            VmkatzError::DiskFormatError(format!(
                "Cannot map SFD offset 0x{:x} to physical",
                vol_offset
            ))
        })?;

        let fd_size = sb.fd_size() as usize;
        file.seek(SeekFrom::Start(phys)).map_err(VmkatzError::Io)?;
        let mut buf = vec![0u8; fd_size];
        file.read_exact(&mut buf).map_err(VmkatzError::Io)?;

        Self::parse_fd_buf(&buf, sb, addr)
    }

    /// Parse a file descriptor from a raw buffer.
    fn parse_fd_buf(buf: &[u8], sb: &VmfsSuperblock, addr: u32) -> Result<FileDescriptor> {
        let fd_size = sb.fd_size() as usize;
        if buf.len() < fd_size {
            return Err(VmkatzError::DiskFormatError(format!(
                "FD buffer too small: {} < {}",
                buf.len(),
                fd_size
            )));
        }

        let meta_off = sb.fd_meta_offset() as usize;

        // FS3_FileMetadata starts at meta_off within the FD
        let desc_type =
            u32::from_le_bytes(buf[meta_off + 0x0C..meta_off + 0x10].try_into().unwrap());
        let file_length =
            u64::from_le_bytes(buf[meta_off + 0x14..meta_off + 0x1C].try_into().unwrap());
        let _block_size =
            u64::from_le_bytes(buf[meta_off + 0x1C..meta_off + 0x24].try_into().unwrap());
        let num_blocks =
            u64::from_le_bytes(buf[meta_off + 0x24..meta_off + 0x2C].try_into().unwrap());
        let zla = u32::from_le_bytes(buf[meta_off + 0x44..meta_off + 0x48].try_into().unwrap());
        let block_offset_shift = buf[meta_off + 0x89];

        // Block pointer array
        let addrs_off = sb.fd_data_addrs_offset();
        let max_addrs = sb.fd_max_data_addrs();
        let mut blocks = Vec::with_capacity(max_addrs);
        for i in 0..max_addrs {
            let off = addrs_off + i * 8;
            if off + 8 > buf.len() {
                break;
            }
            let val = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap());
            blocks.push(val);
        }

        Ok(FileDescriptor {
            address: addr,
            desc_type,
            file_length,
            num_blocks,
            zla,
            block_offset_shift,
            blocks,
        })
    }

    /// Read raw bytes from a file's data stream at a given offset (uses FD block pointers).
    /// This is the core data reading function.
    fn read_fd_data_range(
        file: &mut File,
        lvm: &LvmLayer,
        sb: &VmfsSuperblock,
        fd: &FileDescriptor,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>> {
        let mut result = vec![0u8; length];
        let mut buf_offset = 0usize;
        let mut file_offset = offset;

        while buf_offset < length {
            let remaining = length - buf_offset;
            let block_size = if fd.block_offset_shift > 0 {
                1u64 << fd.block_offset_shift
            } else {
                sb.file_block_size
            };
            let block_num = file_offset / block_size;
            let offset_in_block = file_offset % block_size;
            let chunk = remaining.min((block_size - offset_in_block) as usize);

            // Get block address from FD block pointers (direct for ZLA=1)
            if fd.zla == ZLA_FILE_BLOCK || fd.zla == ZLA_SUB_BLOCK {
                if let Some(&block_addr) = fd.blocks.get(block_num as usize) {
                    let ba_type = addr_type(block_addr);
                    let is_tbz = (ba_type == ADDR_SFB || ba_type == ADDR_LFB) && addr_tbz(block_addr) != 0;
                    if block_addr != 0 && !is_tbz {
                        if let Some(vol_off) =
                            Self::resolve_block_addr_simple(sb, block_addr)
                        {
                            let phys_off =
                                lvm.logical_to_physical(vol_off + offset_in_block)
                                    .ok_or_else(|| {
                                        VmkatzError::DiskFormatError(format!(
                                            "Cannot map vol offset 0x{:x}",
                                            vol_off + offset_in_block
                                        ))
                                    })?;
                            file.seek(SeekFrom::Start(phys_off))
                                .map_err(VmkatzError::Io)?;
                            file.read_exact(&mut result[buf_offset..buf_offset + chunk])
                                .map_err(VmkatzError::Io)?;
                        }
                        // else: zero-filled (sparse)
                    }
                    // else: zero-filled (TBZ or null)
                }
            } else if fd.zla == ZLA_RESIDENT {
                // Resident data: stored in the FD itself
                // Data starts at fd_data_offset within the FD
                // We don't have the raw FD buffer here, so skip (shouldn't happen for system files)
            }

            buf_offset += chunk;
            file_offset += chunk as u64;
        }

        Ok(result)
    }

    /// Resolve a block address to a volume offset (simple path, without resource files).
    fn resolve_block_addr_simple(sb: &VmfsSuperblock, addr: u64) -> Option<u64> {
        if addr == 0 {
            return None;
        }
        match addr_type(addr) {
            ADDR_SFB => {
                let (cluster, resource) = parse_sfb_addr(addr);
                let sfb_size = sb.sfb_size();
                Some((cluster * sfb_size + resource) << sb.file_block_size_shift())
            }
            ADDR_LFB => {
                let block = parse_lfb_addr(addr);
                let shift = sb.file_block_size_shift() + sb.sfb_to_lfb_shift as u32;
                Some(block << shift)
            }
            _ => None,
        }
    }

    /// Read a file descriptor by its FD address (via the FDC resource).
    fn read_fd(&mut self, fd_addr: u32) -> Result<FileDescriptor> {
        let (cluster, resource) = parse_fd_addr(fd_addr);
        let res_offset = self.resource_offset(&self.fdc_meta, cluster, resource);

        log::debug!(
            "read_fd(0x{:08x}): cluster={}, resource={}, fdc_offset=0x{:x}",
            fd_addr, cluster, resource, res_offset
        );

        // Read the FD data from the FDC file stream at this offset
        let fd_size = self.sb.fd_size() as usize;
        let buf = self.read_resource_file_data(&self.fdc_fd.clone(), res_offset, fd_size)?;

        let fd = Self::parse_fd_buf(&buf, &self.sb, fd_addr)?;
        log::debug!(
            "  FD 0x{:08x}: type={}, size={}, zla={}, blocks={}, blockShift={}",
            fd_addr, fd.desc_type, fd.file_length, fd.zla,
            fd.blocks.iter().filter(|&&b| b != 0).count(),
            fd.block_offset_shift,
        );

        Ok(fd)
    }

    /// Compute the offset within a resource file for a given (cluster, resource) pair.
    fn resource_offset(&self, meta: &ResFileMeta, cluster: u32, resource: u32) -> u64 {
        let md = self.sb.md_alignment as u64;
        if meta.clusters_per_group == 0 { return 0; }
        let group = cluster / meta.clusters_per_group;
        let cluster_in_group = cluster % meta.clusters_per_group;

        let cluster_header_size = 2 * md;
        let cluster_data_offset = meta.clusters_per_group as u64 * cluster_header_size;
        let cluster_size = meta.resources_per_cluster as u64 * meta.resource_size as u64;

        if meta.flags & 2 == 0 {
            // Simple layout
            meta.cluster_group_offset as u64
                + (group as u64 * meta.cluster_group_size as u64)
                + (cluster_in_group as u64 * cluster_size)
                + cluster_data_offset
                + (resource as u64 * meta.resource_size as u64)
        } else {
            // Parent layout (flags & 2)
            let parent_resources_per_group = (meta.parent_clusters_per_group as u64
                * meta.parent_resources_per_cluster as u64)
                / meta.clusters_per_group as u64;
            if parent_resources_per_group == 0 { return 0; }
            let parent_group = group as u64 / parent_resources_per_group;
            let parent_cluster_in_group = group as u64 % parent_resources_per_group;

            meta.cluster_group_offset as u64
                + (parent_group * meta.parent_cluster_group_size as u64)
                + (meta.parent_clusters_per_group as u64 * 2 * md)
                + (parent_cluster_in_group * meta.cluster_group_size as u64)
                + (cluster_in_group as u64 * cluster_size)
                + cluster_data_offset
                + (resource as u64 * meta.resource_size as u64)
        }
    }

    /// Read resource metadata from a system file's data stream.
    fn read_resource_meta(&mut self, fd: &FileDescriptor, offset: u64) -> Option<ResFileMeta> {
        let buf = self
            .read_resource_file_data(fd, offset, 0x58)
            .ok()?;
        ResFileMeta::parse(&buf)
    }

    /// Read data from a resource file at a given offset within the file's data stream.
    /// Handles all ZLA types including sub-blocks (ZLA=2) via SBC resource file.
    fn read_resource_file_data(
        &mut self,
        fd: &FileDescriptor,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>> {
        let mut result = vec![0u8; length];
        let mut buf_pos = 0usize;
        let mut file_pos = offset;

        let block_size = if fd.block_offset_shift > 0 {
            1u64 << fd.block_offset_shift
        } else if fd.zla == ZLA_SUB_BLOCK {
            self.sb.sub_block_size as u64
        } else {
            self.sb.file_block_size
        };

        let fd_clone = fd.clone();

        while buf_pos < length {
            let remaining = length - buf_pos;
            let block_num = file_pos / block_size;
            let off_in_block = file_pos % block_size;
            let chunk = remaining.min((block_size - off_in_block) as usize);

            // For direct ZLA (1/2), check block address directly for early-out
            // For indirect ZLA (3/5/0x10D0), blocks[] contains PB addresses, not data addresses
            if fd_clone.zla == ZLA_FILE_BLOCK || fd_clone.zla == ZLA_SUB_BLOCK {
                let block_addr = fd_clone.blocks.get(block_num as usize).copied().unwrap_or(0);

                if block_addr == 0 {
                    buf_pos += chunk;
                    file_pos += chunk as u64;
                    continue;
                }

                // TBZ bits only apply to SFB and LFB addresses
                let atype = addr_type(block_addr);
                if (atype == ADDR_SFB || atype == ADDR_LFB) && addr_tbz(block_addr) != 0 {
                    buf_pos += chunk;
                    file_pos += chunk as u64;
                    continue;
                }

                // Sub-block address — read from SBC resource file
                if atype == ADDR_SB {
                    let sb_data = self.read_sub_block(block_addr)?;
                    let copy_start = off_in_block as usize;
                    let copy_end = std::cmp::min(copy_start + chunk, sb_data.len());
                    if copy_start < copy_end {
                        result[buf_pos..buf_pos + (copy_end - copy_start)]
                            .copy_from_slice(&sb_data[copy_start..copy_end]);
                    }
                    buf_pos += chunk;
                    file_pos += chunk as u64;
                    continue;
                }
            }

            // Resolve block to volume offset (handles all ZLA types including PB/PB2 indirect)
            let vol_off = match self.resolve_file_block(&fd_clone, block_num)? {
                Some(v) => v,
                None => {
                    buf_pos += chunk;
                    file_pos += chunk as u64;
                    continue;
                }
            };

            let phys = self
                .lvm
                .logical_to_physical(vol_off + off_in_block)
                .ok_or_else(|| {
                    VmkatzError::DiskFormatError(format!(
                        "Cannot map vol offset 0x{:x}",
                        vol_off + off_in_block
                    ))
                })?;
            self.file
                .seek(SeekFrom::Start(phys))
                .map_err(VmkatzError::Io)?;
            self.file
                .read_exact(&mut result[buf_pos..buf_pos + chunk])
                .map_err(VmkatzError::Io)?;

            buf_pos += chunk;
            file_pos += chunk as u64;
        }

        Ok(result)
    }

    /// Read a sub-block from the SBC resource file by its SB address.
    fn read_sub_block(&mut self, sb_addr: u64) -> Result<Vec<u8>> {
        let (cluster, resource) = parse_pb_addr(sb_addr);
        let sbc_meta = self.sbc_meta.as_ref().ok_or_else(|| {
            VmkatzError::DiskFormatError("SBC metadata not available for sub-block read".into())
        })?.clone();
        let sbc_fd = self.sbc_fd.as_ref().ok_or_else(|| {
            VmkatzError::DiskFormatError("SBC FD not available for sub-block read".into())
        })?.clone();

        let res_offset = self.resource_offset(&sbc_meta, cluster as u32, resource as u32);
        let size = self.sb.sub_block_size as usize;

        log::info!(
            "read_sub_block(0x{:x}): cluster={}, resource={}, sbc_offset=0x{:x}, sbc_fd.zla={}, sbc_fd.size={}, sbc_fd blocks[0..4]={:?}",
            sb_addr, cluster, resource, res_offset, sbc_fd.zla, sbc_fd.file_length,
            sbc_fd.blocks.iter().take(4).map(|b| format!("0x{:x}", b)).collect::<Vec<_>>()
        );

        let data = self.read_resource_file_data(&sbc_fd, res_offset, size)?;

        // Check if we got actual data
        let non_zero = data.iter().filter(|&&b| b != 0).count();
        if non_zero == 0 {
            log::info!("  sub-block data is all zeros!");
        } else {
            log::info!("  sub-block data: {} non-zero bytes, first 16: {:02x?}", non_zero, &data[..16]);
        }

        Ok(data)
    }

    // ── Directory Parsing ────────────────────────────────────────────

    /// Read directory entries from a directory file descriptor.
    fn read_directory(&mut self, dir_fd: &FileDescriptor) -> Result<Vec<DirEntry>> {
        // Read the directory header (first 0x10000 bytes)
        let header_size = FS6_DIR_HEADER_BLOCK_SIZE as usize;
        // Use the full allocated block space, not just file_length — DIRENT blocks
        // may exist beyond file_length but within the allocated file blocks.
        let block_size = if dir_fd.block_offset_shift > 0 {
            1u64 << dir_fd.block_offset_shift
        } else {
            self.sb.file_block_size
        };
        let allocated_size = dir_fd.num_blocks * block_size;
        let dir_data_len = std::cmp::max(dir_fd.file_length as usize, allocated_size as usize)
            .min(4 * 1024 * 1024);

        log::debug!(
            "read_directory: fd=0x{:08x}, size={}, zla={}, reading {} bytes, first_blocks=[{:?}]",
            dir_fd.address, dir_fd.file_length, dir_fd.zla, dir_data_len,
            dir_fd.blocks.iter().take(4).map(|b| format!("0x{:x}", b)).collect::<Vec<_>>()
        );

        let dir_data = self.read_resource_file_data(dir_fd, 0, dir_data_len)?;

        // Debug: show first 32 bytes
        log::debug!(
            "dir_data[0..32]: {:02x?}",
            &dir_data[..std::cmp::min(32, dir_data.len())]
        );

        if dir_data.len() < 0x5F8 {
            return Err(VmkatzError::DiskFormatError(
                "Directory data too small for FS6_DirHeader".into(),
            ));
        }

        let version = u32::from_le_bytes(dir_data[0x00..0x04].try_into().unwrap());
        if version != FS6_DIR_HEADER_VERSION && version != FS6_DIR_HEADER_DEBUG_VERSION {
            return Err(VmkatzError::DiskFormatError(format!(
                "Invalid directory version 0x{:08x}",
                version
            )));
        }

        let num_entries = u32::from_le_bytes(dir_data[0x04..0x08].try_into().unwrap());
        let num_alloc_map_blocks = u32::from_le_bytes(dir_data[0x0C..0x10].try_into().unwrap());

        log::debug!(
            "Directory header: version=0x{:08x}, numEntries={}, numAllocMapBlocks={}",
            version, num_entries, num_alloc_map_blocks
        );

        let mut entries = Vec::new();

        // Parse self and parent entries from header
        // Self entry at 0x3B8, parent at 0x4D8 (each 0x120 bytes)
        log::debug!(
            "Self entry bytes at 0x3B8: {:02x?}",
            &dir_data[0x3B8..std::cmp::min(0x3B8 + 32, dir_data.len())]
        );
        let self_entry = Self::parse_dir_entry(&dir_data[0x3B8..0x3B8 + FS6_DIR_ENTRY_SIZE]);
        log::debug!("Self entry: {:?}", self_entry);
        if let Some(e) = self_entry {
            if !e.name.is_empty() && e.name != "." && e.name != ".." {
                entries.push(e);
            }
        }
        let parent_entry = Self::parse_dir_entry(&dir_data[0x4D8..0x4D8 + FS6_DIR_ENTRY_SIZE]);
        log::debug!("Parent entry: {:?}", parent_entry);
        if let Some(e) = parent_entry {
            if !e.name.is_empty() && e.name != "." && e.name != ".." {
                entries.push(e);
            }
        }

        // Read allocation map blocks to find DIRENT blocks
        let mut alloc_map_blocks: Vec<u32> = Vec::new();
        for i in 0..std::cmp::min(num_alloc_map_blocks, 128) {
            let off = 0x10 + i as usize * 4;
            if off + 4 <= dir_data.len() {
                alloc_map_blocks
                    .push(u32::from_le_bytes(dir_data[off..off + 4].try_into().unwrap()));
            }
        }

        let md_align = self.sb.md_alignment as u64;

        // Iterate allocation map blocks to find DIRENT blocks
        let mut dirent_blocks = Vec::new();
        for (map_idx, &alloc_block_num) in alloc_map_blocks.iter().enumerate() {
            // Block number 0xFFFFFFFF = unused; any valid block number is OK (including 0)
            if alloc_block_num == 0xFFFF_FFFF {
                continue;
            }
            let alloc_block_offset = header_size as u64 + alloc_block_num as u64 * md_align;
            if alloc_block_offset + md_align > dir_data.len() as u64 {
                log::debug!(
                    "Alloc map[{}] block {} at offset 0x{:x} exceeds dir_data (len=0x{:x})",
                    map_idx, alloc_block_num, alloc_block_offset, dir_data.len()
                );
                continue;
            }
            let alloc_data =
                &dir_data[alloc_block_offset as usize..(alloc_block_offset + md_align) as usize];

            log::debug!(
                "Alloc map[{}] block {} at 0x{:x}: header[0..16]: {:02x?}, map_data[0..16]: {:02x?}",
                map_idx, alloc_block_num, alloc_block_offset,
                &alloc_data[..std::cmp::min(16, alloc_data.len())],
                &alloc_data[FS6_DIR_BLOCK_HEADER_SIZE..std::cmp::min(FS6_DIR_BLOCK_HEADER_SIZE + 16, alloc_data.len())]
            );

            // Skip block header (0x40 bytes)
            let map_data = &alloc_data[FS6_DIR_BLOCK_HEADER_SIZE..];
            // Each entry is 4 bits (high nibble first, then low nibble per dissect.vmfs)
            for (idx, &byte) in map_data.iter().enumerate() {
                for nibble_idx in 0..2 {
                    let entry = if nibble_idx == 0 {
                        byte >> 4
                    } else {
                        byte & 0x0F
                    };
                    let entry_type = entry & 0x03;
                    let is_free = (entry & 0x04) != 0;
                    if entry_type != 0 {
                        let block_idx = idx * 2 + nibble_idx;
                        log::debug!(
                            "  alloc entry[{}]: type={}, free={} (raw nibble=0x{:x})",
                            block_idx, entry_type, is_free, entry
                        );
                    }
                    // Include ALL DIRENT blocks regardless of free flag —
                    // dissect.vmfs processes all type=1 blocks; the per-entry
                    // bitmap in the block header determines which entries are active.
                    if entry_type == 1 {
                        let block_idx = idx * 2 + nibble_idx;
                        dirent_blocks.push(block_idx as u32);
                    }
                }
            }
        }

        log::debug!(
            "Directory: {} alloc_map_blocks, {} DIRENT blocks found: {:?}",
            alloc_map_blocks.len(),
            dirent_blocks.len(),
            &dirent_blocks
        );

        // Parse DIRENT blocks
        for block_num in dirent_blocks {
            let block_offset = header_size as u64 + block_num as u64 * md_align;
            if block_offset + md_align > dir_data.len() as u64 {
                continue;
            }
            let block_data =
                &dir_data[block_offset as usize..(block_offset + md_align) as usize];

            // Parse block header
            if block_data.len() < FS6_DIR_BLOCK_HEADER_SIZE {
                continue;
            }
            let block_type = u16::from_le_bytes(block_data[0x02..0x04].try_into().unwrap());
            if block_type != 1 {
                continue; // Not a DIRENT block
            }
            let total_slots = u16::from_le_bytes(block_data[0x04..0x06].try_into().unwrap());
            let bitmap = &block_data[0x08..0x40]; // 56 bytes of bitmap

            let entries_data = &block_data[FS6_DIR_BLOCK_HEADER_SIZE..];

            for slot in 0..total_slots as usize {
                // Check bitmap: bit 0 = allocated (inverted: 0=allocated, 1=free)
                let byte_idx = slot >> 3;
                let bit_idx = slot & 7;
                if byte_idx >= bitmap.len() {
                    break;
                }
                let is_free = (bitmap[byte_idx] >> bit_idx) & 1 != 0;
                if is_free {
                    continue;
                }

                let entry_offset = slot * FS6_DIR_ENTRY_SIZE;
                if entry_offset + FS6_DIR_ENTRY_SIZE > entries_data.len() {
                    break;
                }
                if let Some(entry) =
                    Self::parse_dir_entry(&entries_data[entry_offset..entry_offset + FS6_DIR_ENTRY_SIZE])
                {
                    if !entry.name.is_empty() && entry.name != "." && entry.name != ".." {
                        entries.push(entry);
                    }
                }
            }

            if entries.len() >= num_entries as usize {
                break;
            }
        }

        log::debug!(
            "Directory 0x{:08x}: {} entries found (expected {})",
            dir_fd.address, entries.len(), num_entries
        );
        for e in &entries {
            log::debug!("  {} (type={}, fd=0x{:08x})", e.name, e.entry_type, e.fd_addr);
        }

        Ok(entries)
    }

    /// Parse a single FS6_DirEntry from raw bytes.
    fn parse_dir_entry(data: &[u8]) -> Option<DirEntry> {
        if data.len() < FS6_DIR_ENTRY_SIZE {
            return None;
        }
        let entry_type = u32::from_le_bytes(data[0x00..0x04].try_into().unwrap());
        let fd_addr = u32::from_le_bytes(data[0x04..0x08].try_into().unwrap());

        if fd_addr == 0 || entry_type == 0 {
            return None;
        }

        let name_bytes = &data[0x18..0x118]; // 256 bytes
        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(256);
        let name = String::from_utf8_lossy(&name_bytes[..name_end]).to_string();

        if name.is_empty() {
            return None;
        }

        Some(DirEntry {
            entry_type,
            fd_addr,
            name,
        })
    }

    // ── Path Navigation ──────────────────────────────────────────────

    /// Find a file by path within the VMFS filesystem.
    fn find_file_by_path(&mut self, path: &str) -> Result<FileDescriptor> {
        let root_fd = self.read_fd(ROOT_DIR_ADDR)?;
        let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

        let mut current = root_fd;
        for component in &components {
            let entries = self.read_directory(&current)?;
            let entry = entries
                .iter()
                .find(|e| e.name.eq_ignore_ascii_case(component))
                .ok_or_else(|| {
                    VmkatzError::DiskFormatError(format!(
                        "'{}' not found in VMFS directory",
                        component
                    ))
                })?;
            current = self.read_fd(entry.fd_addr)?;
        }

        Ok(current)
    }

    /// List root directory entries.
    fn list_root(&mut self) -> Result<Vec<DirEntry>> {
        let root_fd = self.read_fd(ROOT_DIR_ADDR)?;
        self.read_directory(&root_fd)
    }

    // ── Block Resolution (with PB/PB2 indirection) ───────────────────

    /// Resolve a file block number to a volume offset, handling all ZLA types.
    fn resolve_file_block(
        &mut self,
        fd: &FileDescriptor,
        block_num: u64,
    ) -> Result<Option<u64>> {
        match fd.zla {
            ZLA_FILE_BLOCK | ZLA_SUB_BLOCK => {
                // Direct: blocks[block_num] is the block address
                let addr = fd.blocks.get(block_num as usize).copied().unwrap_or(0);
                Ok(self.resolve_block_addr(addr)?)
            }
            ZLA_POINTER_BLOCK | ZLA_POINTER2_BLOCK => {
                // Single indirect via PB or PB2
                let ptrs_per_pb = self.sb.ptr_block_num_ptrs();
                let primary = block_num as usize / ptrs_per_pb;
                let secondary = block_num as usize % ptrs_per_pb;

                let pb_addr = fd.blocks.get(primary).copied().unwrap_or(0);
                if pb_addr == 0 {
                    return Ok(None);
                }

                log::debug!(
                    "resolve_file_block: zla={}, block_num={}, primary={}, secondary={}, pb_addr=0x{:x}",
                    fd.zla, block_num, primary, secondary, pb_addr
                );

                let pb_data = self.read_pb_resource(pb_addr)?;

                // Debug: check if pb_data is all zeros
                let pb_nonzero = pb_data.iter().filter(|&&b| b != 0).count();
                if pb_nonzero == 0 && block_num == 0 {
                    log::info!("  PB data is all zeros for block 0!");
                }

                let sfb_addr = if secondary * 8 + 8 <= pb_data.len() {
                    u64::from_le_bytes(
                        pb_data[secondary * 8..(secondary + 1) * 8]
                            .try_into()
                            .unwrap(),
                    )
                } else {
                    0
                };

                if sfb_addr != 0 && block_num < 3 {
                    log::debug!("  pb[{}] = 0x{:x}", secondary, sfb_addr);
                }

                Ok(self.resolve_block_addr(sfb_addr)?)
            }
            ZLA_DOUBLE_INDIRECT => {
                // Double indirect: blocks[i] → PB → PB → SFB
                let ptrs_per_pb = self.sb.ptr_block_num_ptrs();
                let primary = block_num as usize / (ptrs_per_pb * ptrs_per_pb);
                let secondary =
                    (block_num as usize / ptrs_per_pb) % ptrs_per_pb;
                let tertiary = block_num as usize % ptrs_per_pb;

                let pb1_addr = fd.blocks.get(primary).copied().unwrap_or(0);
                if pb1_addr == 0 {
                    return Ok(None);
                }
                let pb1 = self.read_pb_resource(pb1_addr)?;

                let pb2_addr = if secondary * 8 + 8 <= pb1.len() {
                    u64::from_le_bytes(pb1[secondary * 8..(secondary + 1) * 8].try_into().unwrap())
                } else {
                    0
                };
                if pb2_addr == 0 {
                    return Ok(None);
                }
                let pb2 = self.read_pb_resource(pb2_addr)?;

                let sfb_addr = if tertiary * 8 + 8 <= pb2.len() {
                    u64::from_le_bytes(pb2[tertiary * 8..(tertiary + 1) * 8].try_into().unwrap())
                } else {
                    0
                };

                Ok(self.resolve_block_addr(sfb_addr)?)
            }
            _ => Ok(None),
        }
    }

    /// Resolve a block address (SFB/LFB/SB) to a volume offset.
    fn resolve_block_addr(&self, addr: u64) -> Result<Option<u64>> {
        if addr == 0 {
            return Ok(None);
        }
        // TBZ bits only apply to SFB and LFB addresses
        let atype = addr_type(addr);
        if (atype == ADDR_SFB || atype == ADDR_LFB) && addr_tbz(addr) != 0 {
            return Ok(None);
        }

        match addr_type(addr) {
            ADDR_SFB => {
                let (cluster, resource) = parse_sfb_addr(addr);
                if let Some(ref sfb_meta) = self.sfb_meta {
                    // Use SFB resource metadata for accurate resolution
                    let vol_off = (cluster * sfb_meta.resources_per_cluster as u64 + resource)
                        << self.sb.file_block_size_shift();
                    Ok(Some(vol_off))
                } else {
                    // Fallback: use sfb_size
                    let sfb_size = self.sb.sfb_size();
                    Ok(Some(
                        (cluster * sfb_size + resource) << self.sb.file_block_size_shift(),
                    ))
                }
            }
            ADDR_LFB => {
                let block = parse_lfb_addr(addr);
                let shift = self.sb.file_block_size_shift() + self.sb.sfb_to_lfb_shift as u32;
                Ok(Some(block << shift))
            }
            ADDR_SB => {
                // Sub-block: read from SBC resource file
                // For now, return None (sub-blocks are small metadata, not file data)
                Ok(None)
            }
            _ => {
                log::warn!("Unknown block address type {} for addr 0x{:x}", addr_type(addr), addr);
                Ok(None)
            }
        }
    }

    /// Read a pointer block resource (PB or PB2) by its address.
    fn read_pb_resource(&mut self, pb_addr: u64) -> Result<Vec<u8>> {
        let atype = addr_type(pb_addr);
        let (cluster, resource) = parse_pb_addr(pb_addr);

        // Determine which resource file to use
        let (meta, fd) = match atype {
            ADDR_PB => {
                let m = self.pbc_meta.as_ref().ok_or_else(|| {
                    VmkatzError::DiskFormatError("PBC metadata not available".into())
                })?;
                let f = self.pbc_fd.as_ref().ok_or_else(|| {
                    VmkatzError::DiskFormatError("PBC FD not available".into())
                })?;
                (m.clone(), f.clone())
            }
            ADDR_PB2 => {
                let m = self.pb2_meta.as_ref().ok_or_else(|| {
                    VmkatzError::DiskFormatError("PB2 metadata not available".into())
                })?;
                let f = self.pb2_fd.as_ref().ok_or_else(|| {
                    VmkatzError::DiskFormatError("PB2 FD not available".into())
                })?;
                (m.clone(), f.clone())
            }
            ADDR_SB => {
                // SB addresses pointing to SBC for sub-block data
                let m = self.sbc_meta.as_ref().ok_or_else(|| {
                    VmkatzError::DiskFormatError("SBC metadata not available".into())
                })?;
                let f = self.sbc_fd.as_ref().ok_or_else(|| {
                    VmkatzError::DiskFormatError("SBC FD not available".into())
                })?;
                (m.clone(), f.clone())
            }
            _ => {
                return Err(VmkatzError::DiskFormatError(format!(
                    "Invalid PB address type {} for 0x{:x}",
                    atype, pb_addr
                )));
            }
        };

        // Calculate offset within the resource file
        let res_offset = self.resource_offset(&meta, cluster as u32, resource as u32);

        log::debug!(
            "read_pb_resource(0x{:x}): type={}, cluster={}, resource={}, res_offset=0x{:x}, fd.zla={}, fd.blocks[0..2]={:?}",
            pb_addr, atype, cluster, resource, res_offset, fd.zla,
            fd.blocks.iter().take(2).map(|b| format!("0x{:x}", b)).collect::<Vec<_>>()
        );

        // Read the pointer block page (64KB for VMFS6)
        let page_size = 0x10000usize; // ptr_block_page_size
        let data = self.read_resource_file_data(&fd, res_offset, page_size)?;

        let nonzero = data.iter().filter(|&&b| b != 0).count();
        if nonzero == 0 {
            log::info!(
                "  PB resource all zeros: addr=0x{:x}, cluster={}, resource={}, offset=0x{:x}",
                pb_addr, cluster, resource, res_offset
            );
        }

        Ok(data)
    }

    // ── Build block map for flat VMDK ────────────────────────────────

    /// Build a block map for a flat VMDK file by resolving all block pointers.
    fn build_block_map(&mut self, fd: &FileDescriptor) -> Result<Vec<Option<u64>>> {
        let file_block_size = self.sb.file_block_size;
        let total_blocks = fd.file_length.div_ceil(file_block_size);

        log::info!(
            "Building block map: {} blocks (zla={}, {} block ptrs)",
            total_blocks,
            fd.zla,
            fd.blocks.len()
        );

        let mut block_map: Vec<Option<u64>> = vec![None; total_blocks as usize];

        match fd.zla {
            ZLA_FILE_BLOCK | ZLA_SUB_BLOCK => {
                // Direct: blocks[i] is the block address
                for (i, &addr) in fd.blocks.iter().enumerate() {
                    if i >= total_blocks as usize {
                        break;
                    }
                    if let Some(vol_off) = self.resolve_block_addr(addr)? {
                        if let Some(phys) = self.lvm.logical_to_physical(vol_off) {
                            block_map[i] = Some(phys);
                        }
                    }
                }
            }
            ZLA_POINTER_BLOCK | ZLA_POINTER2_BLOCK => {
                // Batch: read each PB resource once, then resolve all entries
                let ptrs_per_pb = self.sb.ptr_block_num_ptrs();
                for (primary, &pb_addr) in fd.blocks.iter().enumerate() {
                    if pb_addr == 0 {
                        continue;
                    }
                    let base_block = primary * ptrs_per_pb;
                    if base_block >= total_blocks as usize {
                        break;
                    }
                    let pb_data = match self.read_pb_resource(pb_addr) {
                        Ok(d) => d,
                        Err(_) => continue,
                    };
                    let entries = std::cmp::min(
                        ptrs_per_pb,
                        total_blocks as usize - base_block,
                    );
                    for secondary in 0..entries {
                        if secondary * 8 + 8 > pb_data.len() {
                            break;
                        }
                        let sfb_addr = u64::from_le_bytes(
                            pb_data[secondary * 8..(secondary + 1) * 8]
                                .try_into()
                                .unwrap(),
                        );
                        if let Some(vol_off) = self.resolve_block_addr(sfb_addr)? {
                            if let Some(phys) = self.lvm.logical_to_physical(vol_off) {
                                block_map[base_block + secondary] = Some(phys);
                            }
                        }
                    }
                    log::debug!(
                        "Block map: PB[{}] done, base_block={}, entries={}",
                        primary, base_block, entries
                    );
                }
            }
            ZLA_DOUBLE_INDIRECT => {
                // Double indirect: batch both levels
                let ptrs_per_pb = self.sb.ptr_block_num_ptrs();
                let blocks_per_pb1 = ptrs_per_pb * ptrs_per_pb;
                for (primary, &pb1_addr) in fd.blocks.iter().enumerate() {
                    if pb1_addr == 0 {
                        continue;
                    }
                    let pb1 = match self.read_pb_resource(pb1_addr) {
                        Ok(d) => d,
                        Err(_) => continue,
                    };
                    for secondary in 0..ptrs_per_pb {
                        if secondary * 8 + 8 > pb1.len() {
                            break;
                        }
                        let pb2_addr = u64::from_le_bytes(
                            pb1[secondary * 8..(secondary + 1) * 8]
                                .try_into()
                                .unwrap(),
                        );
                        if pb2_addr == 0 {
                            continue;
                        }
                        let pb2 = match self.read_pb_resource(pb2_addr) {
                            Ok(d) => d,
                            Err(_) => continue,
                        };
                        let base = primary * blocks_per_pb1 + secondary * ptrs_per_pb;
                        let entries = std::cmp::min(
                            ptrs_per_pb,
                            total_blocks as usize - base.min(total_blocks as usize),
                        );
                        for tertiary in 0..entries {
                            if tertiary * 8 + 8 > pb2.len() {
                                break;
                            }
                            let sfb_addr = u64::from_le_bytes(
                                pb2[tertiary * 8..(tertiary + 1) * 8]
                                    .try_into()
                                    .unwrap(),
                            );
                            let block_idx = base + tertiary;
                            if block_idx < total_blocks as usize {
                                if let Some(vol_off) = self.resolve_block_addr(sfb_addr)? {
                                    if let Some(phys) = self.lvm.logical_to_physical(vol_off) {
                                        block_map[block_idx] = Some(phys);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            _ => {
                log::warn!("Unknown ZLA type {} for block map building", fd.zla);
            }
        }

        let populated = block_map.iter().filter(|b| b.is_some()).count();
        log::info!(
            "Block map complete: {}/{} blocks populated",
            populated,
            total_blocks
        );

        Ok(block_map)
    }
}

// ── Vmfs6FlatVmdk — Read+Seek over resolved flat VMDK ────────────────

/// A flat VMDK file read through VMFS-6 block resolution.
/// Implements Read+Seek+DiskImage for integration with the VMkatz pipeline.
pub struct Vmfs6FlatVmdk {
    file: File,
    block_map: Vec<Option<u64>>,
    block_size: u64,
    virtual_size: u64,
    position: u64,
}

impl Vmfs6FlatVmdk {
    /// Resolve a virtual position to a physical device offset.
    fn resolve_position(&self, pos: u64) -> Option<u64> {
        let block_idx = (pos / self.block_size) as usize;
        let offset_in_block = pos % self.block_size;

        if block_idx >= self.block_map.len() {
            return None;
        }

        self.block_map[block_idx].map(|phys| phys + offset_in_block)
    }
}

impl Read for Vmfs6FlatVmdk {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.position >= self.virtual_size {
            return Ok(0);
        }

        let remaining = (self.virtual_size - self.position) as usize;
        let to_read = buf.len().min(remaining);
        let mut total = 0;

        while total < to_read {
            let current_pos = self.position + total as u64;
            let block_offset = current_pos % self.block_size;
            let chunk_size = ((self.block_size - block_offset) as usize).min(to_read - total);

            match self.resolve_position(current_pos) {
                Some(phys) => {
                    self.file.seek(SeekFrom::Start(phys))?;
                    self.file.read_exact(&mut buf[total..total + chunk_size])?;
                }
                None => {
                    // Sparse/TBZ block — fill with zeros
                    buf[total..total + chunk_size].fill(0);
                }
            }

            total += chunk_size;
        }

        self.position += total as u64;
        Ok(total)
    }
}

impl Seek for Vmfs6FlatVmdk {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(p) => p as i64,
            SeekFrom::Current(delta) => self.position as i64 + delta,
            SeekFrom::End(delta) => self.virtual_size as i64 + delta,
        };

        if new_pos < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Seek before start of file",
            ));
        }

        self.position = new_pos as u64;
        Ok(self.position)
    }
}

impl super::DiskImage for Vmfs6FlatVmdk {
    fn disk_size(&self) -> u64 {
        self.virtual_size
    }
}

// ── Public API ───────────────────────────────────────────────────────

/// Open a flat VMDK from a VMFS-6 raw device.
///
/// # Arguments
/// * `device_path` - Path to the raw SCSI partition device (e.g., `/vmfs/devices/disks/naa.xxx:1`)
/// * `vmdk_path` - Relative path within the datastore (e.g., `VM-Name/VM-Name-flat.vmdk`)
pub fn open_vmfs6_vmdk(device_path: &Path, vmdk_path: &str) -> Result<Vmfs6FlatVmdk> {
    let mut volume = Vmfs6Volume::open(device_path)?;
    let fd = volume.find_file_by_path(vmdk_path)?;

    log::info!(
        "VMDK '{}': size={} ({} GB), zla={}, blocks={}",
        vmdk_path,
        fd.file_length,
        fd.file_length / (1024 * 1024 * 1024),
        fd.zla,
        fd.blocks.len()
    );

    let block_map = volume.build_block_map(&fd)?;

    Ok(Vmfs6FlatVmdk {
        file: volume.file.try_clone().map_err(VmkatzError::Io)?,
        block_map,
        block_size: volume.sb.file_block_size,
        virtual_size: fd.file_length,
        position: 0,
    })
}

/// List all VM directories and their flat VMDKs on a VMFS-6 datastore.
///
/// Returns Vec of (vm_dir_name, flat_vmdk_name) pairs.
pub fn list_vmfs6_vmdks(device_path: &Path) -> Result<Vec<(String, String)>> {
    let mut volume = Vmfs6Volume::open(device_path)?;
    let root_entries = volume.list_root()?;

    let mut vmdks = Vec::new();
    for entry in &root_entries {
        // Directories have type 2
        if entry.entry_type != 2 {
            continue;
        }
        // Skip system files
        if entry.name.starts_with('.') {
            continue;
        }

        if let Ok(dir_fd) = volume.read_fd(entry.fd_addr) {
            if let Ok(dir_entries) = volume.read_directory(&dir_fd) {
                for file_entry in &dir_entries {
                    if file_entry.name.ends_with("-flat.vmdk") {
                        vmdks.push((entry.name.clone(), file_entry.name.clone()));
                    }
                }
            }
        }
    }

    Ok(vmdks)
}

/// Open a VMFS-6 datastore and scan all VMs for secrets.
/// Returns a Vec of (vm_name, vmdk_name, Box<dyn DiskImage>) tuples.
pub fn open_all_vmfs6_vmdks(
    device_path: &Path,
) -> Result<Vec<(String, String, Vmfs6FlatVmdk)>> {
    let vmdks = list_vmfs6_vmdks(device_path)?;

    let mut results = Vec::new();
    for (vm_name, vmdk_name) in vmdks {
        let vmdk_path = format!("{}/{}", vm_name, vmdk_name);
        match open_vmfs6_vmdk(device_path, &vmdk_path) {
            Ok(vmdk) => {
                results.push((vm_name, vmdk_name, vmdk));
            }
            Err(e) => {
                log::warn!("Failed to open {}: {}", vmdk_path, e);
            }
        }
    }

    Ok(results)
}

/// A discovered VMFS-6 device with its datastore label.
#[derive(Debug)]
pub struct Vmfs6Device {
    pub path: PathBuf,
    pub label: String,
}

/// Scan for VMFS-6 partitions by probing partition devices in `/dev/disks/`.
///
/// Checks each partition device (those containing `:`) for the LVM magic
/// `0xC001D00D` at offset 0x100000, then reads the VMFS superblock label.
pub fn list_vmfs6_devices() -> Vec<Vmfs6Device> {
    let disks_dir = Path::new("/dev/disks");
    if !disks_dir.is_dir() {
        // Not on ESXi or no /dev/disks
        return Vec::new();
    }

    let mut devices = Vec::new();
    let entries = match fs::read_dir(disks_dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        // Partition devices have a colon separator (e.g., naa.xxx:1)
        // Skip vml. symlinks — they duplicate naa. devices
        if !name_str.contains(':') || name_str.starts_with("vml.") {
            continue;
        }

        let path = entry.path();
        if let Some(dev) = probe_vmfs6_device(&path) {
            devices.push(dev);
        }
    }

    devices.sort_by(|a, b| a.path.cmp(&b.path));
    devices
}

/// Probe a single device path for VMFS-6 LVM header and read the datastore label.
fn probe_vmfs6_device(path: &Path) -> Option<Vmfs6Device> {
    let mut f = File::open(path).ok()?;

    // Check LVM magic at offset 0x100000
    f.seek(SeekFrom::Start(LVM_HEADER_OFFSET)).ok()?;
    let mut magic_buf = [0u8; 4];
    f.read_exact(&mut magic_buf).ok()?;
    let magic = u32::from_le_bytes(magic_buf);
    if magic != LVM_MAGIC {
        return None;
    }

    // Read VMFS superblock label at FS3_FS_HEADER_OFFSET
    let label = read_vmfs_label(&mut f).unwrap_or_default();

    Some(Vmfs6Device {
        path: path.to_path_buf(),
        label,
    })
}

/// Read the VMFS datastore label from the superblock.
fn read_vmfs_label(f: &mut File) -> Option<String> {
    // The superblock is at a fixed volume offset; for single-extent volumes
    // with data_offset at 0x1100000, the physical offset is:
    //   data_offset + FS3_FS_HEADER_OFFSET = 0x1100000 + 0x200000 = 0x1300000
    // But we need the LVM data_offset first. Read it from the LVM header.
    f.seek(SeekFrom::Start(LVM_HEADER_OFFSET)).ok()?;
    let mut lvm_buf = [0u8; 0x200];
    f.read_exact(&mut lvm_buf).ok()?;

    let magic = u32::from_le_bytes(lvm_buf[0x00..0x04].try_into().ok()?);
    if magic != LVM_MAGIC {
        return None;
    }
    // data_offset at 0x7A in the LVM header (matches main parser)
    let data_offset = u64::from_le_bytes(lvm_buf[0x7A..0x82].try_into().ok()?);

    // Superblock at data_offset + FS3_FS_HEADER_OFFSET
    let sb_offset = data_offset + FS3_FS_HEADER_OFFSET;
    f.seek(SeekFrom::Start(sb_offset)).ok()?;
    let mut sb_buf = [0u8; 0x170];
    f.read_exact(&mut sb_buf).ok()?;

    let sb_magic = u32::from_le_bytes(sb_buf[0..4].try_into().ok()?);
    if sb_magic != VMFS_MAGIC && sb_magic != VMFSL_MAGIC {
        return None;
    }

    // Label is at offset 0x1D, 128 bytes, null-terminated
    let label_bytes = &sb_buf[0x1D..0x9D];
    let end = label_bytes.iter().position(|&b| b == 0).unwrap_or(label_bytes.len());
    let label = String::from_utf8_lossy(&label_bytes[..end]).into_owned();
    Some(label)
}
