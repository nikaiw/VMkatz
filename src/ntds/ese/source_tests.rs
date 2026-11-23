use super::*;
use std::cell::Cell;
use std::io::Cursor;

struct Counted {
    bytes: Cursor<Vec<u8>>,
    reads: Rc<Cell<usize>>,
}

impl Read for Counted {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reads.set(self.reads.get() + 1);
        self.bytes.read(buf)
    }
}

impl Seek for Counted {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.bytes.seek(pos)
    }
}

#[test]
fn repeated_pages_hit_the_cache_and_eviction_preserves_active_pages() -> Result<()> {
    let reads = Rc::new(Cell::new(0));
    let source = Source::reader(Counted {
        bytes: Cursor::new(vec![0xA5; 2 * CACHE_BYTES]),
        reads: Rc::clone(&reads),
    })?;
    let active = source.read(0, 4096)?.expect("first page");
    for _ in 0..10 {
        source.read(0, 4096)?;
    }
    assert_eq!(reads.get(), 1);
    for offset in (4096..2 * CACHE_BYTES).step_by(4096) {
        source.read(offset as u64, 4096)?;
    }
    if let Source::Reader { reader, .. } = &source {
        let cache = reader.borrow();
        assert_eq!(cache.bytes, CACHE_BYTES);
        assert_eq!(cache.pages.len(), CACHE_BYTES / 4096);
    }
    assert_eq!(&*active, &[0xA5; 4096]);
    let before = reads.get();
    source.read(0, 4096)?;
    assert_eq!(reads.get(), before + 1);
    Ok(())
}
