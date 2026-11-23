use super::*;
use std::io::{Cursor, ErrorKind};

#[test]
fn window_cache_stays_bounded_and_handles_boundaries_and_eof() -> Result<()> {
    let bytes: Vec<u8> = (0..20 * WINDOW_BYTES + 17)
        .map(|i| (i % 251) as u8)
        .collect();
    let source = Source::reader(Cursor::new(&bytes))?;
    for window in 0..20 {
        let offset = window * WINDOW_BYTES + WINDOW_BYTES - 3;
        assert_eq!(
            &*source.read(offset as u64, 12)?,
            &bytes[offset..offset + 12]
        );
    }
    assert_eq!(
        &*source.read((bytes.len() - 2) as u64, 2)?,
        &bytes[bytes.len() - 2..]
    );
    assert!(source.read(bytes.len() as u64, 1).is_err());
    if let Backing::Reader(reader) = &source.backing {
        let reader = reader.borrow();
        assert_eq!(reader.windows.len(), CACHE_WINDOWS);
        assert!(
            reader
                .windows
                .iter()
                .map(|(_, bytes)| bytes.len())
                .sum::<usize>()
                <= CACHE_WINDOWS * WINDOW_BYTES
        );
    }
    Ok(())
}

#[test]
fn skipped_reads_cannot_hide_io_or_allocation_failures() -> Result<()> {
    struct Fault(Cursor<Vec<u8>>);
    impl Read for Fault {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(ErrorKind::PermissionDenied.into())
        }
    }
    impl Seek for Fault {
        fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
            self.0.seek(position)
        }
    }
    let source = Source::reader(Fault(Cursor::new(vec![0; WINDOW_BYTES])))?;
    assert!(source.read(0, 4).is_err());
    assert!(
        matches!(source.finish(Ok(())), Err(VmkatzError::Io(error)) if error.kind() == ErrorKind::PermissionDenied)
    );
    if let Backing::Reader(reader) = &source.backing {
        assert!(reader.borrow().windows.is_empty());
    }
    assert!(source.read(0, MAX_READ_BYTES + 1).is_err());
    assert!(matches!(
        source.finish(Ok(())),
        Err(VmkatzError::AllocTooLarge { .. })
    ));
    Ok(())
}
