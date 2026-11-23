use super::*;

#[test]
fn reads_cross_page_boundaries_and_gaps() {
    let mut bytes = vec![0xA5; 4096];
    bytes.extend_from_slice(&[0xC3; 4096]);
    let (path, mmap) = crate::qemu::pread_fixture("savevm-spans", &bytes, bytes.len() as u64);
    let layer = QemuSavevmLayer {
        mmap,
        pages: {
            let mut pages = PageIndex::default();
            pages.insert(0, Some(0)).unwrap();
            pages.insert(8192, Some(4096)).unwrap();
            pages
        },
        phys_end: 12288,
    };
    let mut expected = vec![0; 16384];
    expected[..4096].fill(0xA5);
    expected[8192..12288].fill(0xC3);
    for start in [0, 4090, 4096, 8190, 8192, 12285] {
        for len in [0, 1, 7, 4096] {
            let mut buf = vec![0xFF; len];
            layer.read_phys(start as u64, &mut buf).unwrap();
            assert_eq!(
                buf,
                expected[start..start + len],
                "start={start}, len={len}"
            );
        }
    }
    drop(layer);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn mapped_page_propagates_backing_io_errors() {
    let (path, mmap) = crate::qemu::truncated_pread_fixture("savevm");
    let layer = QemuSavevmLayer {
        mmap,
        pages: {
            let mut pages = PageIndex::default();
            pages.insert(0, Some(0)).unwrap();
            pages
        },
        phys_end: 8192,
    };
    let mut buf = [0; 16];
    assert!(matches!(
        layer.read_phys(0, &mut buf),
        Err(VmkatzError::UnmappablePhysical(0))
    ));
    buf.fill(0xFF);
    layer.read_phys(4096, &mut buf).unwrap();
    assert_eq!(buf, [0; 16]);
    drop(layer);
    std::fs::remove_file(path).unwrap();
}
