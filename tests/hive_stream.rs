#![cfg(feature = "sam")]

mod fixture {
    include!("hive_stream/fixture.rs");
}

#[test]
fn two_gib_hives_with_distant_cells_fit_a_64_mib_process() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    if std::env::var_os("VMKATZ_LARGE_HIVE_CHILD").is_none() {
        use std::os::unix::process::CommandExt as _;
        let mut child = std::process::Command::new(std::env::current_exe()?);
        child
            .args([
                "--exact",
                "two_gib_hives_with_distant_cells_fit_a_64_mib_process",
                "--nocapture",
            ])
            .env("VMKATZ_LARGE_HIVE_CHILD", "1");
        // SAFETY: only setrlimit and errno access run after fork.
        unsafe { child.pre_exec(limit_memory) };
        let output = child.output()?;
        anyhow::ensure!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Ok(());
    }
    let mut system = fixture::system();
    let key = vmkatz::sam::bootkey::extract_bootkey_from_reader(&mut system)?;
    assert_eq!(key, [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]);
    let mut sam = fixture::sam();
    let hive = vmkatz::sam::hive::Hive::from_reader(&mut sam)?;
    let entries = vmkatz::sam::hashes::extract_hashes_from_hive(&hive, &key)?;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].username, "fixture-user");
    drop(hive);
    let mut security = fixture::security();
    let hive = vmkatz::sam::hive::Hive::from_reader(&mut security)?;
    assert!(vmkatz::sam::lsa::extract_lsa_secrets_from_hive(&hive, &key)?.is_empty());
    drop(hive);
    assert!(system.bytes_read + sam.bytes_read + security.bytes_read <= 6 * 65536);
    check_raw_cli()?;
    Ok(())
}

fn check_raw_cli() -> anyhow::Result<()> {
    use std::io::{Seek, Write};
    struct Temporary(std::path::PathBuf);
    impl Drop for Temporary {
        fn drop(&mut self) {
            let _removed = std::fs::remove_dir_all(&self.0);
        }
    }
    let path = std::env::temp_dir().join(format!(
        "vmkatz-hives-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir(&path)?;
    let dir = Temporary(path);
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_vmkatz"));
    command.args(["--format", "csv", "--color", "never"]);
    for (name, hive) in [
        ("SAM", fixture::sam()),
        ("SECURITY", fixture::security()),
        ("SYSTEM", fixture::system()),
    ] {
        let path = dir.0.join(name);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path)?;
        file.set_len(fixture::HIVE_LEN)?;
        for (offset, data) in hive.regions {
            file.seek(std::io::SeekFrom::Start(offset))?;
            file.write_all(&data)?;
        }
        command.arg(path);
    }
    let output = command.output()?;
    anyhow::ensure!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("(1 accounts)"));
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("provider,username,"));
    Ok(())
}

#[cfg(target_os = "linux")]
fn limit_memory() -> std::io::Result<()> {
    for (resource, bytes) in [(libc::RLIMIT_AS, 64 * 1024 * 1024), (libc::RLIMIT_CORE, 0)] {
        let limit = libc::rlimit {
            rlim_cur: bytes,
            rlim_max: bytes,
        };
        // SAFETY: limit is valid and setrlimit retains no pointer.
        if unsafe { libc::setrlimit(resource, &raw const limit) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}
