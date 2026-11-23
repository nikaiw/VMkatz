//! The guardrails that keep a sweep from exhausting host memory.
//!
//! Run for the Windows target too (`cargo test --target x86_64-pc-windows-gnu`
//! under wine) so the `VirtualUnlock` drop-behind branch and the
//! `GlobalMemoryStatusEx` query are executed, not just compiled.

use anyhow::Context as _;
use std::fs::File;
use std::io::Write;

use vmkatz::memory::VirtualMemory;
use vmkatz::memory::reader::MAX_READ_BYTES;

/// Minimal `VirtualMemory` over a flat buffer: enough to drive the shared
/// `read_virt_bytes` allocator without building a page-table fixture.
struct FlatMem(Vec<u8>);

impl VirtualMemory for FlatMem {
    fn read_virt(&self, vaddr: u64, buf: &mut [u8]) -> vmkatz::error::Result<()> {
        let start = vaddr as usize;
        let end = start
            .checked_add(buf.len())
            .filter(|&e| e <= self.0.len())
            .ok_or(vmkatz::error::VmkatzError::PageFault(vaddr, "test"))?;
        buf.copy_from_slice(&self.0[start..end]);
        Ok(())
    }
}

/// A PE `virtual_size` (or any length field) read out of a hostile image must
/// come back as an error, not a multi-gigabyte allocation. `panic = "abort"` in
/// release means a failed allocation is not recoverable, so the check has to
/// happen before the `vec!`.
#[test]
fn oversized_read_is_refused_not_allocated() -> anyhow::Result<()> {
    let mem = FlatMem(vec![0xAA; 0x1000]);

    for len in [MAX_READ_BYTES + 1, u32::MAX as usize, usize::MAX / 2] {
        let err = mem
            .read_virt_bytes(0, len)
            .expect_err("oversized read must be refused");
        assert!(
            matches!(err, vmkatz::error::VmkatzError::AllocTooLarge { .. }),
            "expected AllocTooLarge for len={len}, got {err}"
        );
    }

    // A plausible length still works, and still reads the right bytes.
    assert_eq!(mem.read_virt_bytes(0, 16)?, vec![0xAA; 16]);
    Ok(())
}

#[cfg(target_os = "linux")]
fn restrict_child_memory() -> std::io::Result<()> {
    for (resource, bytes) in [(libc::RLIMIT_AS, 64 * 1024 * 1024), (libc::RLIMIT_CORE, 0)] {
        let limit = libc::rlimit {
            rlim_cur: bytes,
            rlim_max: bytes,
        };
        // SAFETY: limit has the expected layout and lives throughout the call.
        if unsafe { libc::setrlimit(resource, &raw const limit) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn allowed_read_returns_an_error_when_memory_is_unavailable() -> anyhow::Result<()> {
    use std::os::unix::process::CommandExt as _;

    if std::env::var_os("VMKATZ_ALLOC_TEST_CHILD").is_none() {
        let mut command = std::process::Command::new(std::env::current_exe()?);
        command
            .args([
                "--exact",
                "allowed_read_returns_an_error_when_memory_is_unavailable",
                "--nocapture",
            ])
            .env("VMKATZ_ALLOC_TEST_CHILD", "1");
        // SAFETY: the hook only calls setrlimit and reads errno; no allocation or locking.
        unsafe { command.pre_exec(restrict_child_memory) };
        let output = command.output()?;
        anyhow::ensure!(
            output.status.success(),
            "bounded allocation test failed: {}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return Ok(());
    }
    let memory = FlatMem(vec![0; 16]);
    assert!(matches!(memory.read_virt_bytes(0, MAX_READ_BYTES),
        Err(vmkatz::error::VmkatzError::Io(error)) if error.kind() == std::io::ErrorKind::OutOfMemory));
    Ok(())
}

/// Drop-behind must release pages without losing data: both `madvise(DONTNEED)`
/// and Windows' `VirtualUnlock` are only valid here because the mapping is
/// read-only and file-backed, so the pages re-fault from the file. If either
/// branch ever discarded something it shouldn't, this read-back changes.
#[test]
fn advise_dontneed_keeps_the_data_readable() -> anyhow::Result<()> {
    let path = std::env::temp_dir().join("vmkatz_advise.bin");
    let len = 4 * 1024 * 1024;
    let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    File::create(&path)?.write_all(&data)?;

    let f = File::open(&path)?;
    let m = vmkatz::utils::mmap_file(&f, &path)?;

    let mut buf = vec![0u8; 0x1000];
    for round in 0..3 {
        for off in (0..len as u64).step_by(0x1000) {
            m.read_at(off, &mut buf)?;
            assert_eq!(
                buf[..],
                data[off as usize..off as usize + 0x1000],
                "round {round} offset {off:#x} changed after drop-behind"
            );
            // Release what was just consumed, as the real scan loops do.
            m.advise_dontneed(off, 0x1000);
        }
    }
    drop(m);
    drop(f);
    std::fs::remove_file(&path)?;
    Ok(())
}

/// The host-memory query backs both the oversize warning and the adaptive scan
/// cache budget. It must produce a plausible figure on every supported host, or
/// the caches silently fall back to their static (much larger) budgets.
#[test]
fn host_memory_figure_is_plausible() -> anyhow::Result<()> {
    let avail = vmkatz::utils::available_memory_bytes()
        .context("no host-memory figure on this platform")?;
    assert!(avail > 1 << 20, "implausible available memory: {avail}");
    let budget =
        vmkatz::utils::cache_budget_bytes().context("no cache budget computed from host memory")?;
    assert!(budget > 0 && budget < avail);
    Ok(())
}

/// `FileBytes` replaced `fs::read` on the multi-GB inputs; it must still hand
/// back exactly the file's bytes whichever backing it picked.
#[test]
fn file_bytes_matches_the_file() -> anyhow::Result<()> {
    let path = std::env::temp_dir().join("vmkatz_filebytes.bin");
    let data: Vec<u8> = (0..70_000).map(|i| (i % 251) as u8).collect();
    File::create(&path)?.write_all(&data)?;

    let bytes = vmkatz::utils::FileBytes::open(&path)?;
    assert_eq!(&bytes[..], &data[..]);
    drop(bytes);
    std::fs::remove_file(&path)?;
    Ok(())
}
