#![cfg(feature = "disk")]

use std::io::{Cursor, ErrorKind, Read, Seek, SeekFrom};
use vmkatz::disk::bitlocker_decrypt::BitLockerReader;
use vmkatz::disk::vmdk::VmdkDisk;
use vmkatz::fs::PartitionReader;

#[test]
fn high_qcow2_table_index_does_not_alias_block_zero() -> anyhow::Result<()> {
    use vmkatz::disk::qcow2::QcowDisk;

    let path = std::env::temp_dir().join(format!("vmkatz_qcow_index_{}.qcow2", std::process::id()));
    let high_offset = 1u64 << 47; // L1 index 2^32 with 512-byte clusters
    let mut img = vec![0u8; 2048];
    img[..4].copy_from_slice(&0x5146_49FBu32.to_be_bytes());
    img[4..8].copy_from_slice(&2u32.to_be_bytes());
    img[20..24].copy_from_slice(&9u32.to_be_bytes()); // cluster_bits
    img[24..32].copy_from_slice(&(high_offset + 512).to_be_bytes());
    img[36..40].copy_from_slice(&1u32.to_be_bytes()); // one L1 entry
    img[40..48].copy_from_slice(&512u64.to_be_bytes()); // L1 offset
    img[512..520].copy_from_slice(&1024u64.to_be_bytes()); // L2 offset
    img[1024..1032].copy_from_slice(&1536u64.to_be_bytes()); // data offset
    img[1536..].fill(0xAB);
    std::fs::write(&path, img)?;

    let mut disk = QcowDisk::open(&path)?;
    let mut byte = [0];
    disk.read_exact(&mut byte)?;
    assert_eq!(byte, [0xAB]);
    disk.seek(SeekFrom::Start(high_offset))?;
    disk.read_exact(&mut byte)?;
    assert_eq!(byte, [0]);
    drop(disk);
    std::fs::remove_file(path)?;
    Ok(())
}

#[test]
fn partition_seeks_reject_overflow_and_positions_before_partition() -> anyhow::Result<()> {
    let mut inner = Cursor::new(vec![0xA5; 300]);
    let mut part = PartitionReader::new(&mut inner, 200);
    assert_eq!(part.seek(SeekFrom::Start(0))?, 0);
    for seek in [
        SeekFrom::Start(u64::MAX),
        SeekFrom::Current(-1),
        SeekFrom::End(-101),
    ] {
        assert_eq!(part.seek(seek).unwrap_err().kind(), ErrorKind::InvalidInput);
        assert_eq!(part.stream_position()?, 0);
    }
    assert_eq!(part.seek(SeekFrom::End(-1))?, 99);
    let mut byte = [0];
    part.read_exact(&mut byte)?;
    assert_eq!(byte, [0xA5]);
    Ok(())
}

#[test]
fn bitlocker_seek_handles_minimum_signed_delta_without_panicking() -> anyhow::Result<()> {
    let mut reader = BitLockerReader::new(Cursor::new(vec![0; 512]), 0, vec![0; 32]);
    assert_eq!(reader.seek(SeekFrom::Start(1 << 63))?, 1 << 63);
    assert_eq!(reader.seek(SeekFrom::Current(i64::MIN))?, 0);
    assert_eq!(
        reader.seek(SeekFrom::Current(i64::MIN)).unwrap_err().kind(),
        ErrorKind::InvalidInput
    );
    assert_eq!(reader.stream_position()?, 0);
    Ok(())
}

#[test]
fn eight_tib_vmdk_supports_small_reads_and_full_width_seeks() -> anyhow::Result<()> {
    let dir = std::env::temp_dir().join(format!(
        "vmkatz-io-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir(&dir)?;
    std::fs::write(dir.join("disk-flat.vmdk"), [0xA5; 512])?;
    std::fs::write(
        dir.join("disk.vmdk"),
        format!(
            "# Disk DescriptorFile\nRW {} FLAT \"disk-flat.vmdk\" 0\n",
            (8u64 << 40) / 512
        ),
    )?;
    let mut disk = VmdkDisk::open(&dir.join("disk.vmdk"))?;
    let mut byte = [0];
    // On a 32-bit host, casting the remaining 8 TiB to usize used to yield EOF.
    disk.read_exact(&mut byte)?;
    assert_eq!(byte, [0xA5]);
    assert_eq!(
        disk.seek(SeekFrom::End(i64::MAX))?,
        (8u64 << 40) + i64::MAX as u64
    );
    assert_eq!(disk.seek(SeekFrom::Start(u64::MAX))?, u64::MAX);
    assert_eq!(
        disk.seek(SeekFrom::Current(1)).unwrap_err().kind(),
        ErrorKind::InvalidInput
    );
    assert_eq!(disk.stream_position()?, u64::MAX);
    assert_eq!(disk.read(&mut byte)?, 0);
    disk.seek(SeekFrom::Start(1 << 63))?;
    assert_eq!(disk.seek(SeekFrom::Current(i64::MIN))?, 0);
    drop(disk);
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn extract_file_rejects_missing_destination_before_opening_the_disk() -> anyhow::Result<()> {
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_extract_file"))
        .args(["missing.vmdk", "get", "\\Windows\\file"])
        .output()?;
    assert!(!result.status.success());
    let error = String::from_utf8_lossy(&result.stderr);
    assert!(error.contains("get requires a destination"), "{error}");
    assert!(!error.contains("panicked"), "{error}");
    Ok(())
}

#[test]
fn cyclic_vmdk_parent_chain_returns_an_error() -> anyhow::Result<()> {
    let dir = std::env::temp_dir().join(format!(
        "vmkatz-cycle-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir(&dir)?;
    std::fs::write(dir.join("disk-flat.vmdk"), [0u8; 512])?;
    let path = dir.join("disk.vmdk");
    std::fs::write(
        &path,
        "# Disk DescriptorFile\nparentFileNameHint=\"disk.vmdk\"\nRW 1 FLAT \"disk-flat.vmdk\" 0\n",
    )?;
    assert!(matches!(
        VmdkDisk::open(&path),
        Err(vmkatz::error::VmkatzError::DiskChainLimit)
    ));
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn overflowing_vmdk_capacities_and_offsets_are_rejected() -> anyhow::Result<()> {
    let dir = std::env::temp_dir().join(format!(
        "vmkatz-overflow-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir(&dir)?;
    std::fs::write(dir.join("disk-flat.vmdk"), [0u8; 512])?;
    let path = dir.join("disk.vmdk");
    for extents in [
        format!("RW {} FLAT \"disk-flat.vmdk\" 0\n", u64::MAX),
        format!("RW 1 FLAT \"disk-flat.vmdk\" {}\n", u64::MAX),
        format!("RW {} FLAT \"disk-flat.vmdk\" {}\n", 1u64 << 54, 1u64 << 54),
        format!(
            "RW {} FLAT \"disk-flat.vmdk\" 0\nRW {} FLAT \"disk-flat.vmdk\" 0\n",
            1u64 << 54,
            1u64 << 54
        ),
    ] {
        std::fs::write(&path, format!("# Disk DescriptorFile\n{extents}"))?;
        assert!(
            matches!(
                VmdkDisk::open(&path),
                Err(vmkatz::error::VmkatzError::DiskFormatError(_))
            ),
            "{extents}"
        );
    }
    std::fs::remove_dir_all(dir)?;
    Ok(())
}
