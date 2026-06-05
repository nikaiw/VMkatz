use super::header::DbHeader;
use crate::error::{Result, VmkatzError as Error};

pub struct Pager<'a> {
    pub bytes: &'a [u8],
    pub header: DbHeader,
}

impl<'a> Pager<'a> {
    pub fn open(bytes: &'a [u8]) -> Result<Self> {
        let header = super::header::parse_header(bytes)?;
        Ok(Self { bytes, header })
    }

    /// 1-indexed page fetch. Page 1 contains the 100-byte file header at offset 0.
    pub fn page(&self, page_no: u32) -> Result<&'a [u8]> {
        if page_no == 0 {
            return Err(Error::Parse("page 0 requested".into()));
        }
        let ps = self.header.page_size as usize;
        let off = (page_no as usize - 1) * ps;
        if off + ps > self.bytes.len() {
            return Err(Error::Parse(format!("page {} out of range", page_no)));
        }
        Ok(&self.bytes[off..off + ps])
    }

    /// Offset within page 1 where the B-tree header starts (after the 100-byte file header).
    pub fn page1_btree_offset(&self) -> usize { 100 }
}
