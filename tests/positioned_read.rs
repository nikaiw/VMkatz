//! `utils::read_exact_at` — the portable positioned read (pread / seek_read).
//! Run for the Windows target too (`cargo test --target x86_64-pc-windows-gnu`
//! under wine) so the `seek_read` loop is actually executed, not just compiled.

use std::fs::File;
use std::io::Write;
use vmkatz::utils::read_exact_at;

fn fixture(name: &str, len: usize) -> (std::path::PathBuf, Vec<u8>) {
    let path = std::env::temp_dir().join(name);
    // Non-repeating pattern so a wrong offset can't accidentally match.
    let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    File::create(&path).unwrap().write_all(&data).unwrap();
    (path, data)
}

#[test]
fn reads_at_offset() {
    let (path, data) = fixture("vmkatz_pread.bin", 70_000);
    let f = File::open(&path).unwrap();
    for &(off, len) in &[(0u64, 1usize), (1, 4095), (4096, 8192), (69_999, 1)] {
        let mut buf = vec![0u8; len];
        read_exact_at(&f, &mut buf, off).unwrap();
        assert_eq!(
            buf,
            data[off as usize..off as usize + len],
            "off={off} len={len}"
        );
    }
    // The file position must not leak between reads: read the tail, then the head.
    let mut tail = [0u8; 16];
    read_exact_at(&f, &mut tail, 69_984).unwrap();
    let mut head = [0u8; 16];
    read_exact_at(&f, &mut head, 0).unwrap();
    assert_eq!(head, data[..16]);
    std::fs::remove_file(path).ok();
}

#[test]
fn past_eof_errors() {
    let (path, _) = fixture("vmkatz_pread_eof.bin", 100);
    let f = File::open(&path).unwrap();
    let mut buf = [0u8; 64];
    assert!(
        read_exact_at(&f, &mut buf, 90).is_err(),
        "straddling EOF must fail"
    );
    assert!(
        read_exact_at(&f, &mut buf, 1_000).is_err(),
        "wholly past EOF must fail"
    );
    std::fs::remove_file(path).ok();
}

#[test]
fn shared_handle_across_threads() {
    // How `VmrsLayer::par_scan` uses it: one handle, concurrent positioned reads.
    let (path, data) = fixture("vmkatz_pread_mt.bin", 1 << 20);
    let f = File::open(&path).unwrap();
    std::thread::scope(|s| {
        for t in 0..8u64 {
            let f = &f;
            let data = &data;
            s.spawn(move || {
                for i in 0..64u64 {
                    let off = (t * 64 + i) * 2048;
                    let mut buf = [0u8; 2048];
                    read_exact_at(f, &mut buf, off).unwrap();
                    assert_eq!(buf[..], data[off as usize..off as usize + 2048]);
                }
            });
        }
    });
    std::fs::remove_file(path).ok();
}
