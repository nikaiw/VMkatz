#![cfg(feature = "disk")]

use std::io::SeekFrom;
use vmkatz::error::VmkatzError;

#[path = "ntfs_stream/fixture.rs"]
mod fixture;

#[cfg(feature = "ntds.dit")]
#[test]
fn all_succeeds_on_a_workstation_without_ntds_but_with_sam() -> anyhow::Result<()> {
    let dir = std::env::temp_dir().join(format!(
        "vmkatz-workstation-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir(&dir)?;
    let path = dir.join("disk-flat.vmdk");
    fixture::write_workstation(
        &path,
        [
            hive_fixture::system().regions,
            hive_fixture::sam().regions,
            hive_fixture::security().regions,
        ],
        hive_fixture::HIVE_LEN,
    )?;
    let output = run_workstation(&path, "--all")?;
    let ntds_only = run_workstation(&path, "--ntds")?;
    std::fs::remove_file(path)?;
    std::fs::remove_dir(dir)?;
    assert!(
        output.status.success(),
        "{}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("fixture-user"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("NTDS extraction skipped"));
    assert!(!ntds_only.status.success());
    Ok(())
}

#[cfg(feature = "ntds.dit")]
fn run_workstation(path: &std::path::Path, mode: &str) -> std::io::Result<std::process::Output> {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_vmkatz"));
    command.arg(path).args([mode, "--format", "text"]);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt as _;
        // SAFETY: the child hook only calls setrlimit and reads errno.
        unsafe { command.pre_exec(limit_memory) };
    }
    command.output()
}

#[test]
fn buffered_reads_reject_large_files_before_reading_the_payload() -> anyhow::Result<()> {
    let mut disk = fixture::disk(false);
    let ntfs = ntfs::Ntfs::new(&mut disk)?;
    let file = ntfs.file(&mut disk, 12)?;
    let before = disk.bytes_read;
    assert!(matches!(
        vmkatz::fs::read_file_data(&file, &mut disk),
        Err(VmkatzError::AllocTooLarge { .. })
    ));
    assert_eq!(disk.bytes_read, before);
    let file = ntfs.file(&mut disk, 15)?;
    assert_eq!(vmkatz::fs::read_file_data(&file, &mut disk)?, b"fixture");
    assert!(matches!(
        vmkatz::fs::read_file_data_bounded(&file, &mut disk, 3),
        Err(VmkatzError::AllocTooLarge { limit: 3, .. })
    ));
    Ok(())
}

#[test]
fn streams_seek_across_sparse_and_fragmented_data_without_loading_it() -> anyhow::Result<()> {
    let mut disk = fixture::disk(false);
    let ntfs = ntfs::Ntfs::new(&mut disk)?;
    let file = ntfs.file(&mut disk, 12)?;
    vmkatz::fs::with_file_data(&file, &mut disk, |stream, len| {
        assert_eq!(len, fixture::HUGE_FILE);
        let mut bytes = [0xFF; 64];
        stream.seek(SeekFrom::Start(1 << 32))?;
        stream.read_exact(&mut bytes)?;
        assert_eq!(bytes, [0; 64]);
        stream.seek(SeekFrom::End(-4096))?;
        stream.read_exact(&mut bytes)?;
        assert_eq!(&bytes[46..50], &[0x78, 0x56, 0x34, 0x12]);
        Ok(())
    })?;
    Ok(())
}

#[cfg(feature = "sam")]
#[test]
fn invalid_large_hive_does_not_trigger_recovery() {
    let mut disk = fixture::disk(true);
    assert!(matches!(
        vmkatz::sam::extract_secrets_from_reader(&mut disk),
        Err(VmkatzError::DecryptionError(_))
    ));
    assert!(disk.bytes_read < 128 * 1024);
}

#[cfg(feature = "sam")]
#[test]
fn consumer_errors_do_not_trigger_recovery_or_disappear() -> anyhow::Result<()> {
    let mut disk = fixture::disk(false);
    disk.replace_hive(15, hive_fixture::HIVE_LEN, hive_fixture::system().regions);
    let result = vmkatz::sam::with_ntds_bootkey(
        &mut disk,
        None,
        &[],
        |_, _| -> vmkatz::error::Result<()> { Err(VmkatzError::Parse("consumer failure".into())) },
    )?;
    assert!(
        matches!(result.output, Err(VmkatzError::Parse(message)) if message == "consumer failure")
    );
    assert!(disk.bytes_read < 256 * 1024);
    Ok(())
}

#[cfg(feature = "ntds.dit")]
#[test]
fn ese_reads_an_eight_tib_ntfs_stream_in_bounded_memory() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    if std::env::var_os("VMKATZ_NTFS_STREAM_CHILD").is_none() {
        use std::os::unix::process::CommandExt as _;
        let mut command = std::process::Command::new(std::env::current_exe()?);
        command
            .args([
                "--exact",
                "ese_reads_an_eight_tib_ntfs_stream_in_bounded_memory",
                "--nocapture",
            ])
            .env("VMKATZ_NTFS_STREAM_CHILD", "1");
        // SAFETY: the hook only calls setrlimit and reads errno.
        unsafe { command.pre_exec(limit_memory) };
        let output = command.output()?;
        anyhow::ensure!(
            output.status.success(),
            "{}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return Ok(());
    }
    let mut disk = fixture::disk(false);
    disk.replace_hive(15, hive_fixture::HIVE_LEN, hive_fixture::system().regions);
    let result = vmkatz::sam::with_ntds_bootkey(&mut disk, None, &[], |stream, key| {
        assert_eq!(*key, [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]);
        let db = vmkatz::ntds::ese::EseDb::from_reader(stream)?;
        assert_eq!(db.len(), fixture::HUGE_FILE);
        let mut rows = 0;
        db.for_each_row("datatable", |column| {
            assert_eq!(column("value"), Some(0x1234_5678u32.to_le_bytes().to_vec()));
            rows += 1;
        })?;
        Ok(rows)
    })?;
    assert_eq!(result.output?, 1);
    assert_eq!(result.system_size, hive_fixture::HIVE_LEN);
    assert!(disk.bytes_read < 256 * 1024);
    Ok(())
}

#[cfg(all(feature = "sam", target_os = "linux"))]
fn limit_memory() -> std::io::Result<()> {
    for (resource, bytes) in [(libc::RLIMIT_AS, 64 * 1024 * 1024), (libc::RLIMIT_CORE, 0)] {
        let limit = libc::rlimit {
            rlim_cur: bytes,
            rlim_max: bytes,
        };
        // SAFETY: limit is valid for this call, which retains no pointer.
        if unsafe { libc::setrlimit(resource, &raw const limit) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(feature = "sam")]
#[path = "hive_stream/fixture.rs"]
mod hive_fixture;

#[cfg(feature = "sam")]
#[test]
fn large_hives_are_read_sequentially_without_a_combined_file_size_limit() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    if run_hive_child("large_hives_are_read_sequentially_without_a_combined_file_size_limit")? {
        return Ok(());
    }
    let mut disk = fixture::disk(false);
    for (number, hive) in [
        (15, hive_fixture::system()),
        (16, hive_fixture::sam()),
        (17, hive_fixture::security()),
    ] {
        disk.replace_hive(number, hive_fixture::HIVE_LEN, hive.regions);
    }
    let secrets = vmkatz::sam::extract_secrets_from_reader(&mut disk)?;
    assert_eq!(secrets.sam_entries.len(), 1);
    assert!(disk.bytes_read < 512 * 1024);
    Ok(())
}

#[cfg(feature = "ntds.dit")]
#[test]
fn ntds_accepts_a_two_gib_system_hive() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    if run_hive_child("ntds_accepts_a_two_gib_system_hive")? {
        return Ok(());
    }
    let mut disk = fixture::disk(false);
    disk.replace_hive(15, hive_fixture::HIVE_LEN, hive_fixture::system().regions);
    let result = vmkatz::sam::with_ntds_bootkey(&mut disk, None, &[], |stream, key| {
        assert_eq!(*key, [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]);
        let db = vmkatz::ntds::ese::EseDb::from_reader(stream)?;
        assert_eq!(db.len(), fixture::HUGE_FILE);
        let mut rows = 0;
        db.for_each_row("datatable", |_| rows += 1)?;
        Ok(rows)
    })?;
    assert_eq!(result.system_size, hive_fixture::HIVE_LEN);
    assert_eq!(result.output?, 1);
    assert!(disk.bytes_read < 256 * 1024);
    Ok(())
}

#[cfg(all(feature = "sam", target_os = "linux"))]
fn run_hive_child(name: &str) -> anyhow::Result<bool> {
    use std::os::unix::process::CommandExt as _;
    if std::env::var_os("VMKATZ_NTFS_HIVE_CHILD").is_some() {
        return Ok(false);
    }
    let mut child = std::process::Command::new(std::env::current_exe()?);
    child
        .args(["--exact", name, "--nocapture"])
        .env("VMKATZ_NTFS_HIVE_CHILD", "1");
    // SAFETY: the hook only calls setrlimit and reads errno.
    unsafe { child.pre_exec(limit_memory) };
    let output = child.output()?;
    anyhow::ensure!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(true)
}

#[cfg(feature = "sam")]
#[test]
fn system_parser_failure_is_preserved_without_reading_ntds() -> anyhow::Result<()> {
    let mut disk = fixture::disk(false);
    let result = vmkatz::sam::with_ntds_bootkey(
        &mut disk,
        None,
        &[],
        |_, _| -> vmkatz::error::Result<()> {
            panic!("NTDS consumer called after SYSTEM parser failure");
        },
    )?;
    assert!(matches!(
        result.output,
        Err(VmkatzError::DecryptionError(_))
    ));
    assert_eq!(result.system_size, 7);
    assert!(disk.bytes_read < 64 * 1024);
    Ok(())
}
