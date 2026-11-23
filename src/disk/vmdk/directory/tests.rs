use super::*;
use std::io::Cursor;

struct CountedReader {
    data: Cursor<Vec<u8>>,
    reads: usize,
}

impl Read for CountedReader {
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize> {
        self.reads += 1;
        self.data.read(buffer)
    }
}

impl Seek for CountedReader {
    fn seek(&mut self, position: SeekFrom) -> Result<u64> {
        self.data.seek(position)
    }
}

fn fixture(windows: u32) -> Result<(CountedReader, GrainDirectory)> {
    let entries = windows * 1024;
    let data = (0..entries).flat_map(u32::to_le_bytes).collect();
    let mut reader = CountedReader {
        data: Cursor::new(data),
        reads: 0,
    };
    let directory = GrainDirectory::open(&mut reader, 0, u64::from(entries))?;
    Ok((reader, directory))
}

#[test]
fn alternating_four_distant_regions_only_reads_four_windows() -> Result<()> {
    let (mut reader, directory) = fixture(8)?;
    let mut cache = DirectoryCache::default();
    for _ in 0..1000 {
        for index in [7, 2055, 4103, 6151] {
            assert_eq!(
                cache.read_entry(&mut reader, directory, 0, u64::from(index))?,
                index
            );
        }
    }
    assert_eq!(reader.reads, 4);
    Ok(())
}

#[test]
fn a_fifth_region_evicts_the_oldest_window() -> Result<()> {
    let (mut reader, directory) = fixture(5)?;
    let mut cache = DirectoryCache::default();
    for index in [0, 1024, 2048, 3072, 4096, 1024, 2048, 3072, 4096] {
        assert_eq!(
            cache.read_entry(&mut reader, directory, 0, u64::from(index))?,
            index
        );
    }
    assert_eq!(reader.reads, 5);
    assert_eq!(cache.read_entry(&mut reader, directory, 0, 0)?, 0);
    assert_eq!(reader.reads, 6);
    Ok(())
}

#[test]
fn same_window_offset_in_different_extents_stays_distinct() -> Result<()> {
    let (mut first, directory) = fixture(1)?;
    let (mut second, _) = fixture(1)?;
    second.data.get_mut()[..4].copy_from_slice(&42u32.to_le_bytes());
    let mut cache = DirectoryCache::default();
    for _ in 0..10 {
        assert_eq!(cache.read_entry(&mut first, directory, 0, 0)?, 0);
        assert_eq!(cache.read_entry(&mut second, directory, 1, 0)?, 42);
    }
    assert_eq!((first.reads, second.reads), (1, 1));
    Ok(())
}

#[test]
fn failed_replacement_does_not_expose_partial_or_stale_data() -> Result<()> {
    let (mut reader, directory) = fixture(5)?;
    let mut cache = DirectoryCache::default();
    for index in [0, 1024, 2048, 3072] {
        assert_eq!(
            cache.read_entry(&mut reader, directory, 0, u64::from(index))?,
            index
        );
    }
    reader.data.get_mut().truncate(4 * 4096 + 2);
    for _ in 0..2 {
        assert_eq!(
            cache
                .read_entry(&mut reader, directory, 0, 4096)
                .unwrap_err()
                .kind(),
            ErrorKind::UnexpectedEof
        );
    }
    let reads = reader.reads;
    assert_eq!(cache.read_entry(&mut reader, directory, 0, 1024)?, 1024);
    assert_eq!(reader.reads, reads);
    assert_eq!(cache.read_entry(&mut reader, directory, 0, 0)?, 0);
    assert_eq!(reader.reads, reads + 1);
    Ok(())
}
