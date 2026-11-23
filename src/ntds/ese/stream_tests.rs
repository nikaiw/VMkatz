use super::*;
use std::io::{Cursor, ErrorKind, SeekFrom};

struct Faulty {
    bytes: Cursor<Vec<u8>>,
    fail_at: u64,
    kind: ErrorKind,
}

impl Read for Faulty {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.bytes.position() == self.fail_at {
            return Err(std::io::Error::new(self.kind, "injected page failure"));
        }
        self.bytes.read(buf)
    }
}

impl Seek for Faulty {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.bytes.seek(pos)
    }
}

#[test]
fn catalog_io_errors_are_not_reported_as_an_empty_database() {
    let mut bytes = vec![0; 6 * 4096];
    bytes[4..8].copy_from_slice(&[0xEF, 0xCD, 0xAB, 0x89]);
    bytes[0xEC..0xF0].copy_from_slice(&4096u32.to_le_bytes());
    let result = EseDb::from_reader(Faulty {
        bytes: Cursor::new(bytes),
        fail_at: 5 * 4096,
        kind: ErrorKind::PermissionDenied,
    });
    assert!(
        matches!(result,Err(VmkatzError::Io(error)) if error.kind()==ErrorKind::PermissionDenied)
    );
}

#[test]
fn long_value_read_errors_escape_the_optional_column_callback() -> Result<()> {
    let mut bytes = vec![0; 5 * 4096];
    let page = &mut bytes[2 * 4096..3 * 4096];
    page[0x22..0x24].copy_from_slice(&2u16.to_le_bytes());
    page[0x24..0x28].copy_from_slice(&PAGE_FLAG_LEAF.to_le_bytes());
    // Empty leaf key, then one tagged column whose value is a separated LID.
    let row = [0, 127, 4, 0, 0, 1, 4, 0x40, 4, 123, 0, 0, 0];
    page[42..42 + row.len()].copy_from_slice(&row);
    page[4096 - 8..4096 - 4].copy_from_slice(&((row.len() + 2) as u32).to_le_bytes());
    let column = EseColumn {
        id: 256,
        name: "value".into(),
        col_type: 0,
        offset: 0,
        size: 0,
        is_fixed: false,
        is_variable: false,
        is_tagged: true,
    };
    let table = EseTable {
        _obj_id: 1,
        data_pgno: 1,
        lv_pgno: 3,
        columns: vec![column],
    };
    let db = EseDb {
        data: Source::reader(Faulty {
            bytes: Cursor::new(bytes),
            fail_at: 4 * 4096,
            kind: ErrorKind::OutOfMemory,
        })?,
        page_size: 4096,
        tables: HashMap::from([("test".into(), table)]),
    };
    let mut rows = 0;
    let result = db.for_each_row("test", |column| {
        rows += 1;
        assert!(column("value").is_none());
    });
    assert_eq!(rows, 1);
    assert!(matches!(result,Err(VmkatzError::Io(error)) if error.kind()==ErrorKind::OutOfMemory));
    Ok(())
}
