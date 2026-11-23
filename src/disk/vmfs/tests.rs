use super::{FS6_DIR_HEADER_BLOCK_SIZE, Vmfs6Volume, VmfsSuperblock, lfb_intra_offset};

#[test]
fn vmfs5_dense_sub_block_address_keeps_high_resource_bits() {
    // Real directory address: truncating resource 21 to 5 read unrelated data.
    assert_eq!(super::parse_sb_addr_v5(0x5000_458A, true), (278, 21));
    assert_eq!(super::parse_sb_addr_v5(0x5000_4592, true), (278, 37));
    assert_eq!(super::parse_sb_addr_v5(0x5000_459A, true), (278, 53));
    // The COW bit is not part of the resource; non-dense volumes ignore bits 3–4.
    assert_eq!(super::parse_sb_addr_v5(0x5000_45BA, true), (278, 53));
    assert_eq!(super::parse_sb_addr_v5(0x5000_459A, false), (278, 5));
    assert_eq!(super::parse_pb_addr_v5(0x5000_4593), (278, 5));
}

#[test]
fn directory_maps_keep_both_nibbles_and_ignore_unused_blocks() {
    let header_size = FS6_DIR_HEADER_BLOCK_SIZE as usize;
    let mut data = vec![0; header_size + 0x80];
    // Map 0 is valid; the other references are unused or outside the data.
    data[0x14..0x18].copy_from_slice(&u32::MAX.to_le_bytes());
    data[0x18..0x1C].copy_from_slice(&2u32.to_le_bytes());
    // Types 1 and 5 both designate DIRENT blocks, despite the free flag.
    data[header_size + 0x40..header_size + 0x42].copy_from_slice(&[0x15, 0x21]);
    assert_eq!(
        Vmfs6Volume::directory_entry_blocks(&data, 3, 0x80),
        [0, 1, 3]
    );
}

#[test]
fn directory_maps_skip_blocks_shorter_than_the_header() {
    // An alignment below the 64-byte header previously caused an OOB slice.
    for alignment in [0, 1, 0x20, 0x3F, 0x40] {
        let data = vec![0; FS6_DIR_HEADER_BLOCK_SIZE as usize + alignment];
        assert_eq!(
            Vmfs6Volume::directory_entry_blocks(&data, 1, alignment as u32),
            [] as [u32; 0]
        );
    }
}

#[test]
fn directory_slots_skip_free_special_and_truncated_entries() {
    let mut block = vec![0; 0x40 + 4 * 0x120 + 12];
    block[4..6].copy_from_slice(&6u16.to_le_bytes());
    block[8] = 0b0000_0010; // Slot 1 is free; zero bits designate occupied slots.
    for (slot, name) in ["live.vmdk", "deleted.vmdk", ".", ".."].iter().enumerate() {
        let entry = 0x40 + slot * 0x120;
        block[entry..entry + 4].copy_from_slice(&2u32.to_le_bytes());
        block[entry + 4..entry + 8].copy_from_slice(&(0x10 + slot as u32).to_le_bytes());
        block[entry + 0x18..entry + 0x18 + name.len()].copy_from_slice(name.as_bytes());
    }

    let mut entries = Vec::new();
    Vmfs6Volume::append_directory_entries(&block, &mut entries);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "live.vmdk");
    assert_eq!(entries[0].fd_addr, 0x10);
    assert_eq!(entries[0].entry_type, 2);
}

// Regression: an NTFS VBR at LFB + 117 MiB previously resolved to the LFB base.
#[test]
fn lfb_intra_offset_selects_subblock_within_large_file_block() {
    let fbs = 0x0010_0000u64; // 1 MiB file blocks
    let shift = 9u16; // 512 file blocks per LFB
    // Block 0 is at the LFB base.
    assert_eq!(lfb_intra_offset(shift, fbs, 0), 0);
    // Block 117 (the real NTFS-VBR case) is 117 MiB into the LFB.
    assert_eq!(lfb_intra_offset(shift, fbs, 117), 117 * fbs);
    // The first block of the next LFB wraps back to offset 0.
    assert_eq!(lfb_intra_offset(shift, fbs, 512), 0);
    // A block inside the second LFB maps to its in-LFB position.
    assert_eq!(lfb_intra_offset(shift, fbs, 600), 88 * fbs);
}

fn sb_with_md_alignment(md_alignment: u32) -> VmfsSuperblock {
    VmfsSuperblock {
        _magic: 0,
        _major_version: 24,
        is_vmfs6: true,
        dense_sub_blocks: false,
        file_block_size: 0x0010_0000,
        sub_block_size: 0,
        fdc_cluster_group_offset: 0,
        fdc_clusters_per_group: 0,
        md_alignment,
        sfb_to_lfb_shift: 0,
        _ptr_block_shift: 0,
        _sfb_addr_bits: 0,
        _label: String::new(),
    }
}

/// Regression: a crafted VMFS-6 superblock with a tiny `md_alignment` used to
/// panic in `parse_fd_buf` — the FS3_FileMetadata fields sit at fixed offsets
/// up to `meta_off + 0x89`, but the buffer is only `2 * md_alignment` bytes.
/// It must now return an error instead of reading out of bounds.
#[test]
fn parse_fd_buf_rejects_tiny_md_alignment() {
    // All below 0x8A, so meta_off + 0x8A exceeds the 2*md_alignment buffer.
    for md_alignment in [0u32, 0x08, 0x20, 0x80] {
        let sb = sb_with_md_alignment(md_alignment);
        // Buffer sized exactly as parse_fd would allocate it.
        let buf = vec![0u8; sb.fd_size() as usize];
        let r = Vmfs6Volume::parse_fd_buf(&buf, &sb, 0);
        assert!(
            r.is_err(),
            "md_alignment={md_alignment:#x}: expected Err, not a panic/OOB read"
        );
    }
}

/// `fd_data_addrs_offset` must not underflow (debug-panic) when a small
/// `md_alignment` makes the data-addr region larger than the whole FD.
#[test]
fn fd_data_addrs_offset_saturates() {
    let sb = sb_with_md_alignment(0x20); // fd_size=0x40, fd_data_addrs_size=2560
    assert_eq!(sb.fd_data_addrs_offset(), 0);
}
