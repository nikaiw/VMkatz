use super::*;
use std::io::{Cursor, Write};

fn record(kind: u8, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut data = vec![
        0x80 | kind,
        0xF0 | ((len >> 18) as u8 & 7),
        0x80 | ((len >> 12) as u8 & 63),
        0x80 | ((len >> 6) as u8 & 63),
        0x80 | (len as u8 & 63),
    ];
    data.extend_from_slice(payload);
    data
}

fn repeated_lzf(value: u8, len: usize) -> Vec<u8> {
    let mut data = vec![(len / 1024) as u8, 0, value];
    let mut left = len - 1;
    while left >= 3 {
        let count = left.min(264);
        if count < 9 {
            data.extend_from_slice(&[((count - 2) << 5) as u8, 0]);
        } else {
            data.extend_from_slice(&[0xE0, (count - 9) as u8, 0]);
        }
        left -= count;
    }
    for _ in 0..left {
        data.extend_from_slice(&[0, value]);
    }
    record(3, &data)
}

#[test]
fn mixed_records_support_backward_reads_and_cache_eviction() -> io::Result<()> {
    let mut file = record(2, b"hello");
    let mut expected = b"hello".to_vec();
    for value in 1..=32 {
        file.extend_from_slice(&repeated_lzf(value, 255 * 1024));
        expected.extend(std::iter::repeat_n(value, 255 * 1024));
        file.extend_from_slice(&record(4, &[1]));
        expected.extend_from_slice(&[0; 1024]);
    }
    file.push(0x81);
    let len = file.len() as u64;
    let mut stream = SsmStream::new(Cursor::new(file), 0, len)?;
    let mut buffer = [0; 4099];
    for start in
        (0..expected.len() - buffer.len())
            .step_by(130_001)
            .chain([3, 255 * 1024, 1, 8_000_000, 0])
    {
        stream.seek_logical(start as u64)?;
        stream.read_exact(&mut buffer)?;
        assert_eq!(buffer, expected[start..start + buffer.len()]);
        assert!(stream.cache.len() <= CACHE_RECORDS);
        assert!(
            stream
                .cache
                .iter()
                .map(|(_, data)| data.len())
                .sum::<usize>()
                <= CACHE_RECORDS * 255 * 1024
        );
    }
    Ok(())
}

#[test]
fn checkpoints_thin_out_without_growing_forever() -> io::Result<()> {
    let mut file = Vec::new();
    for n in 0..70_000 {
        file.extend_from_slice(&record(2, &[(n % 251) as u8]));
    }
    let len = file.len() as u64;
    let mut stream = SsmStream::new(Cursor::new(file), 0, len)?;
    stream.interval = 1;
    stream.skip(70_000)?;
    assert!(stream.checkpoints.len() <= MAX_CHECKPOINTS);
    assert!(stream.interval > 1);
    assert_eq!(stream.checkpoints[0].logical, 0);
    assert!(
        stream
            .checkpoints
            .windows(2)
            .all(|pair| pair[0].logical < pair[1].logical)
    );
    for position in [69_999, 0, 65_535, 65_536, 8, 68_000] {
        stream.seek_logical(position)?;
        assert_eq!(stream.read_u8()?, (position % 251) as u8);
    }
    Ok(())
}

#[test]
fn corrupt_record_lengths_and_strings_return_errors() -> io::Result<()> {
    for file in [
        vec![0x82, 127, 0],
        vec![0x83, 0],
        vec![0x84, 2, 1],
        record(3, &[1, 0, 0]),
        record(2, &u32::MAX.to_le_bytes()),
    ] {
        let len = file.len() as u64;
        let mut stream = SsmStream::new(Cursor::new(file), 0, len)?;
        assert!(stream.read_strz().is_err());
    }
    Ok(())
}

#[test]
fn large_saved_state_fits_in_64_mib() -> anyhow::Result<()> {
    use crate::memory::PhysicalMemory as _;
    if crate::memory::test_limit::child(
        "vbox::layer::ssm::tests::large_saved_state_fits_in_64_mib",
    )? {
        return Ok(());
    }
    let path = std::env::temp_dir().join(format!("vmkatz-vbox-stream-{}.sav", std::process::id()));
    let mut file = std::io::BufWriter::new(std::fs::File::create(&path)?);
    let mut header = [0; 64];
    let magic = b"\x7fVirtualBox SavedState V2.0\n";
    header[..magic.len()].copy_from_slice(magic);
    header[45] = 8;
    file.write_all(&header)?;
    file.write_all(b"\nUnit\n\x00\x00")?;
    let mut unit = [0; 36];
    unit[16..20].copy_from_slice(&14u32.to_le_bytes());
    unit[32..36].copy_from_slice(&4u32.to_le_bytes());
    file.write_all(&unit)?;
    file.write_all(b"pgm\0")?;
    let mut config = vec![0; 82];
    config.extend_from_slice(&(512u64 * 1024 * 1024).to_le_bytes());
    config.extend_from_slice(&[0xFF, 0xFF]);
    file.write_all(&record(2, &config))?;
    let mut page = record(2, &[1]);
    page.extend_from_slice(&repeated_lzf(0xA5, 4096));
    for _ in 0..131_072 {
        file.write_all(&page)?;
    }
    // High GPA and an overwrite must not expand the index or retain stale data.
    let high = 8u64 * 1024 * 1024 * 1024 * 1024;
    let mut address = vec![0x81];
    address.extend_from_slice(&high.to_le_bytes());
    file.write_all(&record(2, &address))?;
    file.write_all(&repeated_lzf(0xC3, 4096))?;
    address[0] = 0x80;
    address[1..].copy_from_slice(&4096u64.to_le_bytes());
    address.push(0xFF);
    file.write_all(&record(2, &address))?;
    file.flush()?;
    #[cfg(target_os = "linux")]
    file.get_ref().set_len(high)?;
    drop(file);
    let layer = crate::vbox::VBoxLayer::open(&path)?;
    assert_eq!(layer.phys_size(), high + 4096);
    assert_eq!(layer.page_count(), 131_073);
    for (address, fill) in [
        (high, 0xC3),
        (512 * 1024 * 1024 - 4096, 0xA5),
        (4096, 0),
        (0, 0xA5),
        (4096 * 999, 0xA5),
    ] {
        assert_eq!(layer.read_phys_bytes(address, 4096)?, vec![fill; 4096]);
    }
    let mut crossing = [0; 12];
    layer.read_phys(4090, &mut crossing)?;
    assert_eq!(&crossing[..6], &[0xA5; 6]);
    assert_eq!(&crossing[6..], &[0; 6]);
    drop(layer);
    std::fs::remove_file(path)?;
    Ok(())
}
