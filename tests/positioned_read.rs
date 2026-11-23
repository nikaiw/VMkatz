//! `utils::read_exact_at` — the portable positioned read (pread / seek_read).
//! Run for the Windows target too (`cargo test --target x86_64-pc-windows-gnu`
//! under wine) so the `seek_read` loop is actually executed, not just compiled.

use std::fs::File;
use std::io::Write;
use vmkatz::utils::read_exact_at;

#[test]
fn mapped_bytes_are_optional_and_pread_remains_readable() -> std::io::Result<()> {
    use vmkatz::utils::MappedFile;

    let (path, data) = fixture("vmkatz_mapping_access.bin", 8192)?;
    let pread = MappedFile::Pread {
        file: std::sync::Mutex::new(File::open(&path)?),
        size: data.len() as u64,
    };
    assert!(pread.as_bytes().is_none());
    let mut buf = [0; 100];
    pread.read_at(4000, &mut buf)?;
    assert_eq!(buf, data[4000..4100]);

    let mut map = memmap2::MmapMut::map_anon(data.len())?;
    map.copy_from_slice(&data);
    let mapped = MappedFile::Mmap(map.make_read_only()?);
    assert_eq!(mapped.as_bytes(), Some(data.as_slice()));

    drop(pread);
    std::fs::remove_file(path)?;
    Ok(())
}

#[cfg(test)]
fn fixture(name: &str, len: usize) -> std::io::Result<(std::path::PathBuf, Vec<u8>)> {
    let path = std::env::temp_dir().join(name);
    // Non-repeating pattern so a wrong offset can't accidentally match.
    let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    File::create(&path)?.write_all(&data)?;
    Ok((path, data))
}

#[test]
fn reads_at_offset() -> std::io::Result<()> {
    let (path, data) = fixture("vmkatz_pread.bin", 70_000)?;
    let f = File::open(&path)?;
    for &(off, len) in &[(0u64, 1usize), (1, 4095), (4096, 8192), (69_999, 1)] {
        let mut buf = vec![0u8; len];
        read_exact_at(&f, &mut buf, off)?;
        assert_eq!(
            buf,
            data[off as usize..off as usize + len],
            "off={off} len={len}"
        );
    }
    // The file position must not leak between reads: read the tail, then the head.
    let mut tail = [0u8; 16];
    read_exact_at(&f, &mut tail, 69_984)?;
    let mut head = [0u8; 16];
    read_exact_at(&f, &mut head, 0)?;
    assert_eq!(head, data[..16]);
    drop(f);
    std::fs::remove_file(path)?;
    Ok(())
}

#[test]
fn past_eof_errors() -> std::io::Result<()> {
    let (path, _) = fixture("vmkatz_pread_eof.bin", 100)?;
    let f = File::open(&path)?;
    let mut buf = [0u8; 64];
    assert!(
        read_exact_at(&f, &mut buf, 90).is_err(),
        "straddling EOF must fail"
    );
    assert!(
        read_exact_at(&f, &mut buf, 1_000).is_err(),
        "wholly past EOF must fail"
    );
    drop(f);
    std::fs::remove_file(path)?;
    Ok(())
}

#[test]
fn shared_handle_across_threads() -> std::io::Result<()> {
    // How `VmrsLayer::par_scan` uses it: one handle, concurrent positioned reads.
    let (path, data) = fixture("vmkatz_pread_mt.bin", 1 << 20)?;
    let f = File::open(&path)?;
    std::thread::scope(|s| -> std::io::Result<()> {
        let mut readers = Vec::new();
        for t in 0..8u64 {
            let f = &f;
            let data = &data;
            readers.push(s.spawn(move || -> std::io::Result<()> {
                for i in 0..64u64 {
                    let off = (t * 64 + i) * 2048;
                    let mut buf = [0u8; 2048];
                    read_exact_at(f, &mut buf, off)?;
                    assert_eq!(buf[..], data[off as usize..off as usize + 2048]);
                }
                Ok(())
            }));
        }
        for reader in readers {
            reader
                .join()
                .map_err(|_| std::io::Error::other("positioned-read worker panicked"))??;
        }
        Ok(())
    })?;
    drop(f);
    std::fs::remove_file(path)?;
    Ok(())
}
