#![cfg(feature = "disk")]

use std::io::{Read, Seek, SeekFrom};
#[cfg(feature = "sam")]
use vmkatz::error::VmkatzError;

// Only the partition headers exist in memory; the advertised disk is 8 TiB.
struct LargeDisk {
    headers: Vec<u8>,
    pos: u64,
    bytes_read: usize,
}

impl LargeDisk {
    fn mbr(kind: u8, signature: [u8; 8]) -> Self {
        let mut headers = vec![0; 8192];
        headers[510..512].copy_from_slice(&[0x55, 0xAA]);
        headers[0x1BE + 4] = kind;
        headers[0x1BE + 8..0x1BE + 12].copy_from_slice(&8u32.to_le_bytes());
        headers[4099..4107].copy_from_slice(&signature);
        Self {
            headers,
            pos: 0,
            bytes_read: 0,
        }
    }

    fn gpt(signature: [u8; 8]) -> Self {
        let mut disk = Self::mbr(0xEE, signature);
        disk.headers[512..520].copy_from_slice(b"EFI PART");
        disk.headers[512 + 0x48..512 + 0x50].copy_from_slice(&2u64.to_le_bytes());
        disk.headers[512 + 0x50..512 + 0x54].copy_from_slice(&1u32.to_le_bytes());
        disk.headers[512 + 0x54..512 + 0x58].copy_from_slice(&128u32.to_le_bytes());
        disk.headers[1024..1040].fill(0x11);
        disk.headers[1024 + 0x20..1024 + 0x28].copy_from_slice(&8u64.to_le_bytes());
        disk
    }
}

impl Read for LargeDisk {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.bytes_read += buf.len();
        assert!(
            self.bytes_read < 128 * 1024,
            "unexpected full-disk recovery"
        );
        buf.fill(0);
        for (i, b) in buf.iter_mut().enumerate() {
            if let Some(value) = self.headers.get((self.pos + i as u64) as usize) {
                *b = *value;
            }
        }
        self.pos += buf.len() as u64;
        Ok(buf.len())
    }
}

impl Seek for LargeDisk {
    fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
        self.pos = match from {
            SeekFrom::Start(pos) => Some(pos),
            SeekFrom::Current(delta) => self.pos.checked_add_signed(delta),
            SeekFrom::End(delta) => (8u64 << 40).checked_add_signed(delta),
        }
        .ok_or_else(|| std::io::Error::other("invalid seek"))?;
        Ok(self.pos)
    }
}

#[test]
fn linux_mbr_and_gpt_never_trigger_recovery() {
    for mut disk in [
        LargeDisk::mbr(0x83, *b"        "),
        LargeDisk::gpt(*b"        "),
        LargeDisk::mbr(0x07, *b"EXFAT   "),
    ] {
        assert!(vmkatz::fs::find_ntfs_partitions(&mut disk).is_err());
        #[cfg(feature = "sam")]
        {
            assert!(vmkatz::sam::extract_secrets_from_reader(&mut disk).is_err());
            let result = vmkatz::sam::with_ntds_bootkey(
                &mut disk,
                None,
                &[],
                |_, _| -> vmkatz::error::Result<()> {
                    panic!("NTDS consumer called on a non-NTFS disk");
                },
            );
            assert!(result.is_err());
        }
        assert!(disk.bytes_read < 8192);
    }
}

#[cfg(feature = "sam")]
#[test]
fn damaged_ntfs_on_eight_tib_disk_does_not_start_raw_scans() {
    let mut disk = LargeDisk::mbr(0x07, *b"NTFS    ");
    assert!(matches!(
        vmkatz::sam::extract_secrets_from_reader(&mut disk),
        Err(VmkatzError::RecoveryLimit(_))
    ));
    let result =
        vmkatz::sam::with_ntds_bootkey(&mut disk, None, &[], |_, _| -> vmkatz::error::Result<()> {
            panic!("NTDS consumer called on a damaged filesystem");
        });
    assert!(result.is_err());
    assert!(disk.bytes_read < 8192);
}

#[test]
fn bitlocker_is_still_detected_on_both_partition_tables() -> anyhow::Result<()> {
    for mut disk in [
        LargeDisk::mbr(0x07, *b"-FVE-FS-"),
        LargeDisk::gpt(*b"-FVE-FS-"),
    ] {
        assert_eq!(vmkatz::fs::find_ntfs_partitions(&mut disk)?, vec![4096]);
        assert!(vmkatz::fs::is_bitlocker_partition(&mut disk, 4096));
    }
    Ok(())
}

#[cfg(feature = "sam")]
#[test]
fn flat_vmdk_descriptor_with_eight_tib_capacity_stops_before_raw_recovery() -> anyhow::Result<()> {
    let dir = std::env::temp_dir().join(format!(
        "vmkatz-recovery-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir(&dir)?;
    let disk = LargeDisk::mbr(0x07, *b"NTFS    ");
    std::fs::write(dir.join("disk-flat.vmdk"), disk.headers)?;
    let descriptor = dir.join("disk.vmdk");
    std::fs::write(
        &descriptor,
        format!(
            "# Disk DescriptorFile\nRW {} FLAT \"disk-flat.vmdk\" 0\n",
            (8u64 << 40) / 512
        ),
    )?;
    assert!(matches!(
        vmkatz::sam::extract_disk_secrets(&descriptor),
        Err(VmkatzError::RecoveryLimit(_))
    ));

    // A flat file must not be loaded wholesale as descriptor text by recovery.
    std::fs::write(&descriptor, vec![b'x'; 2 * 1024 * 1024])?;
    assert!(matches!(vmkatz::disk::vmdk::VmdkDisk::open(&descriptor),
        Err(VmkatzError::DiskFormatError(msg)) if msg.contains("descriptor exceeds")));
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[cfg(feature = "ntds.dit")]
#[test]
fn all_reports_failure_when_no_disk_extractor_succeeds() -> anyhow::Result<()> {
    let dir = std::env::temp_dir().join(format!(
        "vmkatz-linux-all-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir(&dir)?;
    let path = dir.join("disk-flat.vmdk");
    std::fs::write(&path, LargeDisk::mbr(0x83, *b"        ").headers)?;
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_vmkatz"))
        .arg(&path)
        .arg("--all")
        .output()?;
    std::fs::remove_file(path)?;
    std::fs::remove_dir(dir)?;
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("No secrets found by the enabled disk extractors")
    );
    Ok(())
}
