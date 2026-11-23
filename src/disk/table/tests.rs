use super::*;
use std::io::Cursor;

struct Counted {
    file: Cursor<Vec<u8>>,
    reads: usize,
}

impl Read for Counted {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.reads += 1;
        self.file.read(buf)
    }
}

impl Seek for Counted {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
        self.file.seek(pos)
    }
}

fn fixture(windows: usize) -> Counted {
    Counted {
        file: Cursor::new(vec![0xA5; windows * WINDOW_BYTES]),
        reads: 0,
    }
}

#[test]
fn table_ranges_are_checked_before_any_read() {
    for (offset, entries, len, error) in [
        (u64::MAX, 1, u64::MAX, ErrorKind::InvalidData),
        (0, u64::MAX, u64::MAX, ErrorKind::InvalidData),
        (8, 2, 23, ErrorKind::UnexpectedEof),
    ] {
        assert_eq!(
            Table::new(offset, entries, Encoding::Le64, len)
                .err()
                .unwrap()
                .kind(),
            error
        );
    }
}

#[test]
fn all_encodings_support_unaligned_tables_and_partial_windows() -> Result<()> {
    for encoding in [
        Encoding::Le32,
        Encoding::Be32,
        Encoding::Le64,
        Encoding::Be64,
    ] {
        let width = encoding.width();
        let entries = (WINDOW_BYTES / width + 3) as u64;
        let mut bytes = vec![0xFF; 7];
        for value in 0..entries {
            match encoding {
                Encoding::Le32 => bytes.extend_from_slice(&(value as u32).to_le_bytes()),
                Encoding::Be32 => bytes.extend_from_slice(&(value as u32).to_be_bytes()),
                Encoding::Le64 => bytes.extend_from_slice(&value.to_le_bytes()),
                Encoding::Be64 => bytes.extend_from_slice(&value.to_be_bytes()),
            }
        }
        let mut file = Cursor::new(bytes);
        let table = Table::open(&mut file, 7, entries, encoding)?;
        let mut cache = TableCache::default();
        for index in (0..entries).rev() {
            assert_eq!(cache.read(&mut file, table, index)?, Some(index));
        }
        assert_eq!(cache.read(&mut file, table, entries)?, None);
        assert_eq!(cache.read(&mut file, table, u64::MAX)?, None);
    }
    Ok(())
}

#[test]
fn nearby_and_distant_lookups_reuse_bounded_windows() -> Result<()> {
    let mut file = fixture(CACHE_WINDOWS + 1);
    let entries = file.file.get_ref().len() as u64 / 8;
    let table = Table::open(&mut file, 0, entries, Encoding::Le64)?;
    let mut cache = TableCache::default();
    assert!(cache.windows.is_empty());
    for _ in 0..10 {
        for window in 0..CACHE_WINDOWS {
            for entry in 0..4 {
                cache.read(&mut file, table, (window * WINDOW_BYTES / 8 + entry) as u64)?;
            }
        }
    }
    assert_eq!(file.reads, CACHE_WINDOWS);
    cache.read(&mut file, table, entries - 1)?;
    cache.read(&mut file, table, 0)?;
    assert_eq!(file.reads, CACHE_WINDOWS + 2);
    assert_eq!(cache.windows.len(), CACHE_WINDOWS);
    Ok(())
}

#[test]
fn overlapping_tables_do_not_reuse_a_short_window() -> Result<()> {
    let mut file = fixture(1);
    let small = Table::open(&mut file, 0, 1, Encoding::Le32)?;
    let large = Table::open(&mut file, 0, 512, Encoding::Le64)?;
    let mut cache = TableCache::default();
    assert_eq!(cache.read(&mut file, small, 0)?, Some(0xA5A5_A5A5));
    assert_eq!(
        cache.read(&mut file, large, 0)?,
        Some(0xA5A5_A5A5_A5A5_A5A5)
    );
    assert_eq!(file.reads, 2);
    Ok(())
}

#[test]
fn failed_refill_cannot_expose_partial_or_stale_bytes() -> Result<()> {
    let mut file = fixture(CACHE_WINDOWS + 1);
    let entries = file.file.get_ref().len() as u64 / 8;
    let table = Table::open(&mut file, 0, entries, Encoding::Le64)?;
    let mut cache = TableCache::default();
    for window in 0..CACHE_WINDOWS {
        cache.read(&mut file, table, (window * WINDOW_BYTES / 8) as u64)?;
    }
    file.file
        .get_mut()
        .truncate(CACHE_WINDOWS * WINDOW_BYTES + 10);
    assert_eq!(
        cache
            .read(&mut file, table, entries - 1)
            .unwrap_err()
            .kind(),
        ErrorKind::UnexpectedEof
    );
    file.file.get_mut()[..8].copy_from_slice(&123u64.to_le_bytes());
    assert_eq!(cache.read(&mut file, table, 0)?, Some(123));
    assert_eq!(
        cache
            .read(&mut file, table, entries - 1)
            .unwrap_err()
            .kind(),
        ErrorKind::UnexpectedEof
    );
    Ok(())
}
