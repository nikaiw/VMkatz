#![cfg(feature = "sam")]

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use vmkatz::disk::DiskImage;
use vmkatz::disk::qcow2::QcowDisk;
use vmkatz::disk::vdi::VdiDisk;

#[test]
fn test_open_qcow2() {
    let path = Path::new("/tmp/test.qcow2");
    if !path.exists() {
        return;
    }
    let mut disk = QcowDisk::open(path).expect("failed to open QCOW2");
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
fn test_qcow2_sam_extraction() {
    let path = Path::new("/tmp/test.qcow2");
    if !path.exists() {
        return;
    }
    let secrets = vmkatz::sam::extract_disk_secrets(path).expect("SAM extraction failed");
    assert!(!secrets.sam_entries.is_empty(), "should find SAM entries");
    // At minimum, Administrator (RID 500) and Guest (RID 501) should exist
    let admin = secrets.sam_entries.iter().find(|e| e.rid == 500);
    assert!(admin.is_some(), "Administrator account not found");
}

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

// Self-contained QCOW2 test: crafts a minimal parent + child image (512-byte
// clusters) to exercise the backing chain and the QCOW_OFLAG_ZERO flag. The
// child marks virtual cluster 0 explicitly-zeroed over a parent cluster full of
// 0xAB; before the zero-flag fix this read back 0xAB from the parent.
#[test]
fn test_qcow2_zero_flag_overrides_backing() {
    // BE writers into a fixed-size cluster buffer.
    fn put_u32(b: &mut [u8], off: usize, v: u32) {
        b[off..off + 4].copy_from_slice(&v.to_be_bytes());
    }
    fn put_u64(b: &mut [u8], off: usize, v: u64) {
        b[off..off + 8].copy_from_slice(&v.to_be_bytes());
    }
    // header at cluster 0; l1_table_offset points at `l1_off`.
    fn header(disk_size: u64, l1_off: u64, backing: Option<(u64, u32)>) -> Vec<u8> {
        let mut h = vec![0u8; 512];
        put_u32(&mut h, 0, 0x5146_49FB); // magic
        put_u32(&mut h, 4, 3); // version 3
        if let Some((off, len)) = backing {
            put_u64(&mut h, 8, off);
            put_u32(&mut h, 16, len);
        }
        put_u32(&mut h, 20, 9); // cluster_bits = 9 (512-byte clusters)
        put_u64(&mut h, 24, disk_size);
        put_u32(&mut h, 32, 0); // no encryption
        put_u32(&mut h, 36, 1); // l1_size = 1 entry
        put_u64(&mut h, 40, l1_off);
        h
    }

    let dir = std::env::temp_dir().join(format!("vmkatz_qcow_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let parent_path = dir.join("parent.qcow2");
    let child_path = dir.join("child.qcow2");

    // Parent: L2[0] -> data 0xAB, L2[1] -> data 0xCD.
    let mut parent = header(1024, 512, None); // cluster 0
    let mut l1 = vec![0u8; 512]; // cluster 1 @512
    put_u64(&mut l1, 0, 1024); // L1[0] -> L2 table @1024
    let mut l2 = vec![0u8; 512]; // cluster 2 @1024
    put_u64(&mut l2, 0, 1536); // L2[0] -> data @1536
    put_u64(&mut l2, 8, 2048); // L2[1] -> data @2048
    parent.extend_from_slice(&l1);
    parent.extend_from_slice(&l2);
    parent.extend_from_slice(&[0xAB; 512]); // cluster 3 @1536
    parent.extend_from_slice(&[0xCD; 512]); // cluster 4 @2048
    std::fs::write(&parent_path, &parent).unwrap();

    // Child: backing = parent; L2[0] = ZERO_FLAG (explicitly zeroed),
    // L2[1] = 0 (unallocated -> falls through to parent's 0xCD).
    let backing_name = b"parent.qcow2";
    let mut child = header(1024, 512, Some((48, backing_name.len() as u32)));
    child[48..48 + backing_name.len()].copy_from_slice(backing_name);
    let mut cl1 = vec![0u8; 512];
    put_u64(&mut cl1, 0, 1024); // L1[0] -> L2 @1024
    let mut cl2 = vec![0u8; 512];
    put_u64(&mut cl2, 0, 1); // L2[0] = QCOW_OFLAG_ZERO
    // L2[1] left 0 (unallocated)
    child.extend_from_slice(&cl1);
    child.extend_from_slice(&cl2);
    std::fs::write(&child_path, &child).unwrap();

    let mut disk = QcowDisk::open(&child_path).expect("open child qcow2");
    assert_eq!(disk.disk_size(), 1024);

    // Cluster 0: zero-flagged -> must read zeros, NOT the parent's 0xAB.
    let mut c0 = [0xFFu8; 512];
    disk.read_exact(&mut c0).unwrap();
    assert!(
        c0.iter().all(|&b| b == 0),
        "zero-flagged cluster must read zeros, not backing data"
    );

    // Cluster 1: unallocated in child -> backing chain returns parent's 0xCD.
    disk.seek(SeekFrom::Start(512)).unwrap();
    let mut c1 = [0u8; 512];
    disk.read_exact(&mut c1).unwrap();
    assert!(
        c1.iter().all(|&b| b == 0xCD),
        "unallocated cluster must read from backing file"
    );

    std::fs::remove_dir_all(&dir).ok();
}

// Self-contained VDI tests (512-byte blocks): a normal physical block, a
// VDI_IMAGE_BLOCK_ZERO (0xFFFFFFFE) block, and an unallocated block. Before the
// zero-block fix, 0xFFFFFFFE was treated as a physical index and seeked past EOF.
fn build_vdi(block_size: u32) -> Vec<u8> {
    fn p32(b: &mut [u8], off: usize, v: u32) {
        b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn p64(b: &mut [u8], off: usize, v: u64) {
        b[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }
    let mut img = vec![0u8; 0x600];
    p32(&mut img, 0x40, 0xBEDA_107F); // magic
    p32(&mut img, 0x4C, 1); // image_type = normal (no parent)
    p32(&mut img, 0x154, 0x200); // offset_blocks (BAT)
    p32(&mut img, 0x158, 0x400); // offset_data
    p64(&mut img, 0x170, 1536); // disk_size = 3 blocks
    p32(&mut img, 0x178, block_size);
    p32(&mut img, 0x180, 3); // blocks_total
    // BAT @0x200: block0 -> physical 0, block1 -> ZERO, block2 -> unallocated
    p32(&mut img, 0x200, 0);
    p32(&mut img, 0x204, 0xFFFF_FFFE);
    p32(&mut img, 0x208, 0xFFFF_FFFF);
    img[0x400..0x600].fill(0xAB); // data block 0
    img
}

#[test]
fn test_vdi_zero_and_unallocated_blocks() {
    let dir = std::env::temp_dir().join(format!("vmkatz_vdi_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("t.vdi");
    std::fs::write(&path, build_vdi(512)).unwrap();

    let mut disk = VdiDisk::open(&path).expect("open vdi");
    assert_eq!(disk.disk_size(), 1536);

    let mut b0 = [0u8; 512];
    disk.read_exact(&mut b0).unwrap();
    assert!(
        b0.iter().all(|&x| x == 0xAB),
        "physical block must read its data"
    );

    disk.seek(SeekFrom::Start(512)).unwrap();
    let mut b1 = [0xFFu8; 512];
    disk.read_exact(&mut b1).unwrap();
    assert!(
        b1.iter().all(|&x| x == 0),
        "BLOCK_ZERO must read zeros, not a far seek"
    );

    disk.seek(SeekFrom::Start(1024)).unwrap();
    let mut b2 = [0xFFu8; 512];
    disk.read_exact(&mut b2).unwrap();
    assert!(
        b2.iter().all(|&x| x == 0),
        "unallocated block must read zeros"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_vdi_zero_block_size_rejected() {
    let dir = std::env::temp_dir().join(format!("vmkatz_vdi0_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("z.vdi");
    std::fs::write(&path, build_vdi(0)).unwrap(); // corrupt: block_size = 0
    assert!(
        VdiDisk::open(&path).is_err(),
        "zero block_size must be rejected, not divide-by-zero"
    );
    std::fs::remove_dir_all(&dir).ok();
}
