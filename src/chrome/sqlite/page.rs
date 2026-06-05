use super::header::DbHeader;
use crate::error::{Result, VmkatzError as Error};
use std::collections::HashMap;

pub struct Pager<'a> {
    pub bytes: &'a [u8],
    pub header: DbHeader,
    /// WAL overlay: committed page contents keyed by 1-based page number.
    /// When non-empty, `page(p)` returns the WAL copy if present, falling back
    /// to the base file otherwise. This is exactly the algorithm SQLite uses
    /// when servicing reads with a non-empty WAL.
    pub wal: HashMap<u32, Vec<u8>>,
}

impl<'a> Pager<'a> {
    pub fn open(bytes: &'a [u8]) -> Result<Self> {
        let header = super::header::parse_header(bytes)?;
        Ok(Self {
            bytes,
            header,
            wal: HashMap::new(),
        })
    }

    /// Open the database with an accompanying WAL file. Frames after the last
    /// commit-frame are discarded per the SQLite spec.
    pub fn open_with_wal(bytes: &'a [u8], wal_bytes: &[u8]) -> Result<Self> {
        let header = super::header::parse_header(bytes)?;
        let wal = super::wal::parse_wal(wal_bytes, header.page_size as usize)?;
        Ok(Self { bytes, header, wal })
    }

    /// 1-indexed page fetch. Page 1 contains the 100-byte file header at
    /// offset 0. WAL overlay takes precedence when present.
    ///
    /// Return type is `&[u8]` (lifetime tied to `&self`) rather than `&'a [u8]`
    /// because the WAL branch yields a borrow into the WAL `HashMap`.
    pub fn page(&self, page_no: u32) -> Result<&[u8]> {
        if page_no == 0 {
            return Err(Error::Parse("page 0 requested".into()));
        }
        if let Some(buf) = self.wal.get(&page_no) {
            return Ok(buf.as_slice());
        }
        let ps = self.header.page_size as usize;
        let off = (page_no as usize - 1) * ps;
        if off + ps > self.bytes.len() {
            return Err(Error::Parse(format!("page {} out of range", page_no)));
        }
        Ok(&self.bytes[off..off + ps])
    }

    /// Offset within page 1 where the B-tree header starts (after the 100-byte file header).
    pub fn page1_btree_offset(&self) -> usize {
        100
    }
}
