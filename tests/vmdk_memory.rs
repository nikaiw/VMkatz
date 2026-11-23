#![cfg(feature = "disk")]

use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use vmkatz::disk::DiskImage as _;
use vmkatz::disk::vmdk::VmdkDisk;
use vmkatz::error::VmkatzError;

const SECTOR: u64 = 512;
const GT_ENTRIES: u64 = 512;
const EIGHT_TIB: u64 = 8 << 40;

#[cfg(target_os = "linux")]
fn limit_test_memory() -> std::io::Result<()> {
    for (resource, bytes) in [(libc::RLIMIT_AS, 64 * 1024 * 1024), (libc::RLIMIT_CORE, 0)] {
        let limit = libc::rlimit {
            rlim_cur: bytes,
            rlim_max: bytes,
        };
        // SAFETY: limit is a valid rlimit, and setrlimit retains no pointer.
        if unsafe { libc::setrlimit(resource, &raw const limit) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn check_in_bounded_process() -> anyhow::Result<()> {
    use std::os::unix::process::CommandExt as _;

    let mut command = std::process::Command::new(std::env::current_exe()?);
    command
        .args([
            "--exact",
            "eight_tib_sparse_directory_supports_reads_across_windows",
            "--nocapture",
        ])
        .env("VMKATZ_VMDK_MEMORY_CHILD", "1");
    // SAFETY: the pre-exec hook only calls setrlimit and reads errno on failure;
    // it does not allocate, lock, or access other threads' state after fork.
    unsafe { command.pre_exec(limit_test_memory) };
    let output = command.output()?;
    anyhow::ensure!(
        output.status.success(),
        "VMDK test exceeded its budget or failed: {}\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

struct Fixture(PathBuf);

impl Fixture {
    fn new(name: &str) -> anyhow::Result<Self> {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("vmkatz-gd-{name}-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&dir)?;
        Ok(Self(dir))
    }

    /// Sparse host files keep the large directory on disk without writing its zeros.
    fn extent(&self, name: &str, sectors: u64, grains: &[(u64, u8)]) -> anyhow::Result<()> {
        let mut file = File::create(self.0.join(name))?;
        let mut header = [0u8; 512];
        header[..4].copy_from_slice(&0x564D_444Bu32.to_le_bytes());
        header[4..8].copy_from_slice(&1u32.to_le_bytes());
        header[12..20].copy_from_slice(&sectors.to_le_bytes());
        header[20..28].copy_from_slice(&1u64.to_le_bytes()); // 512-byte grains
        header[44..48].copy_from_slice(&u32::try_from(GT_ENTRIES)?.to_le_bytes());
        header[56..64].copy_from_slice(&1u64.to_le_bytes()); // GD at sector 1
        file.write_all(&header)?;
        let directory_end = SECTOR + sectors.div_ceil(GT_ENTRIES) * 4;
        file.set_len(directory_end)?;
        let mut next = directory_end.div_ceil(SECTOR) * SECTOR;

        // Fixtures use a different grain table for each allocated grain.
        for &(grain, value) in grains {
            let table = next;
            let data = table + GT_ENTRIES * 4;
            file.seek(SeekFrom::Start(SECTOR + grain / GT_ENTRIES * 4))?;
            file.write_all(&u32::try_from(table / SECTOR)?.to_le_bytes())?;
            file.seek(SeekFrom::Start(table + grain % GT_ENTRIES * 4))?;
            file.write_all(&u32::try_from(data / SECTOR)?.to_le_bytes())?;
            file.seek(SeekFrom::Start(data))?;
            file.write_all(&[value; 512])?;
            next = data + SECTOR;
        }
        Ok(())
    }

    fn descriptor(&self, name: &str, lines: &str) -> anyhow::Result<PathBuf> {
        let path = self.0.join(name);
        std::fs::write(&path, format!("# Disk DescriptorFile\n{lines}"))?;
        Ok(path)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.0) {
            eprintln!("cannot remove fixture {}: {error}", self.0.display());
        }
    }
}

#[test]
fn eight_tib_sparse_directory_supports_reads_across_windows() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    if std::env::var_os("VMKATZ_VMDK_MEMORY_CHILD").is_none() {
        return check_in_bounded_process();
    }
    let fixture = Fixture::new("large")?;
    let sectors = EIGHT_TIB / SECTOR;
    let boundary = 1024 * GT_ENTRIES;
    let grains = [
        (0, 0x11),
        (boundary - 1, 0x22),
        (boundary, 0x33),
        (sectors - 1, 0x44),
    ];
    fixture.extent("disk-s001.vmdk", sectors, &grains)?;
    let path = fixture.descriptor(
        "disk.vmdk",
        &format!("RW {sectors} SPARSE \"disk-s001.vmdk\"\n"),
    )?;
    let mut disk = VmdkDisk::open(&path)?;
    assert_eq!(disk.disk_size(), EIGHT_TIB);
    for &(grain, value) in grains.iter().rev().chain(grains.iter()) {
        disk.seek(SeekFrom::Start(grain * SECTOR + 17))?;
        let mut bytes = [0; 128];
        disk.read_exact(&mut bytes)?;
        assert_eq!(bytes, [value; 128]);
    }
    disk.seek(SeekFrom::Start(boundary * SECTOR - 2))?;
    let mut crossing = [0; 4];
    disk.read_exact(&mut crossing)?;
    assert_eq!(crossing, [0x22, 0x22, 0x33, 0x33]);
    disk.seek(SeekFrom::Start(SECTOR))?;
    disk.read_exact(&mut crossing)?;
    assert_eq!(crossing, [0; 4]);
    let mut seen = 0;
    disk.scan_all_grains(|offset, data| {
        assert_eq!(offset, 0);
        assert_eq!(data, [0x11; 512]);
        seen += 1;
        false
    })?;
    assert_eq!(seen, 1);
    Ok(())
}

#[test]
fn directory_cache_separates_extents_and_parent_disks() -> anyhow::Result<()> {
    let fixture = Fixture::new("chain")?;
    fixture.extent("base-s001.vmdk", 1024, &[(0, 0x55), (512, 0x66)])?;
    fixture.descriptor("base.vmdk", "RW 1024 SPARSE \"base-s001.vmdk\"\n")?;
    fixture.extent("child-s001.vmdk", 512, &[])?;
    fixture.extent("child-s002.vmdk", 512, &[(0, 0x77)])?;
    let path = fixture.descriptor(
        "child.vmdk",
        concat!(
            "parentFileNameHint=\"base.vmdk\"\n",
            "RW 512 SPARSE \"child-s001.vmdk\"\n",
            "RW 512 SPARSE \"child-s002.vmdk\"\n",
        ),
    )?;
    let mut disk = VmdkDisk::open(&path)?;
    for _ in 0..3 {
        for (sector, expected) in [(0, 0x55), (512, 0x77), (1, 0), (513, 0)] {
            disk.seek(SeekFrom::Start(sector * SECTOR))?;
            let mut bytes = [0; 16];
            disk.read_exact(&mut bytes)?;
            assert_eq!(bytes, [expected; 16]);
        }
    }
    Ok(())
}

#[test]
fn full_parent_chain_reads_without_large_stack_frames() -> anyhow::Result<()> {
    let fixture = Fixture::new("deep-chain")?;
    fixture.extent("empty-s001.vmdk", 512, &[])?;
    fixture.extent("base-s001.vmdk", 512, &[(0, 0xAB)])?;
    for level in 0..=64 {
        let contents = if level == 64 {
            "RW 512 SPARSE \"base-s001.vmdk\"\n".to_string()
        } else {
            format!(
                "parentFileNameHint=\"level-{}.vmdk\"\nRW 512 SPARSE \"empty-s001.vmdk\"\n",
                level + 1
            )
        };
        fixture.descriptor(&format!("level-{level}.vmdk"), &contents)?;
    }
    let mut disk = VmdkDisk::open(&fixture.0.join("level-0.vmdk"))?;
    let mut bytes = [0; 16];
    disk.read_exact(&mut bytes)?;
    assert_eq!(bytes, [0xAB; 16]);
    disk.seek(SeekFrom::Start(SECTOR))?;
    disk.read_exact(&mut bytes)?;
    assert_eq!(bytes, [0; 16]);
    Ok(())
}

#[test]
fn grain_scan_handles_a_partial_last_directory_window() -> anyhow::Result<()> {
    let fixture = Fixture::new("scan")?;
    let last = 1024 * GT_ENTRIES;
    let grains = [(0, 0x11), (last, 0x22)];
    fixture.extent("disk-s001.vmdk", last + 1, &grains)?;
    let path = fixture.descriptor(
        "disk.vmdk",
        &format!("RW {} SPARSE \"disk-s001.vmdk\"\n", last + 1),
    )?;
    let mut disk = VmdkDisk::open(&path)?;
    let mut seen = Vec::new();
    disk.scan_all_grains(|offset, data| {
        seen.push((offset / SECTOR, data[0]));
        assert!(data.iter().all(|&b| b == data[0]));
        true
    })?;
    assert_eq!(seen, grains);
    disk.seek(SeekFrom::End(-1))?;
    let mut byte = [0];
    disk.read_exact(&mut byte)?;
    assert_eq!(byte, [0x22]);
    Ok(())
}

#[test]
fn truncated_directories_fail_before_open_and_during_refill() -> anyhow::Result<()> {
    let fixture = Fixture::new("truncated")?;
    let sectors = 1024 * GT_ENTRIES + 1;
    fixture.extent("disk-s001.vmdk", sectors, &[])?;
    let path = fixture.descriptor(
        "disk.vmdk",
        &format!("RW {sectors} SPARSE \"disk-s001.vmdk\"\n"),
    )?;
    let mut disk = VmdkDisk::open(&path)?;
    disk.read_exact(&mut [0])?;
    let file = OpenOptions::new()
        .write(true)
        .open(fixture.0.join("disk-s001.vmdk"))?;
    file.set_len(SECTOR + 4097)?;
    disk.seek(SeekFrom::End(-1))?;
    assert!(disk.read_exact(&mut [0]).is_err());
    assert!(disk.read_exact(&mut [0]).is_err()); // Failed refills must not become cached.
    assert!(
        matches!(VmdkDisk::open(&path), Err(VmkatzError::Io(e)) if e.kind() == ErrorKind::UnexpectedEof)
    );
    Ok(())
}
