use crate::error::{Result, VmkatzError as Error};

pub const HEADER_MAGIC: &[u8; 16] = b"SQLite format 3\x00";

#[derive(Debug, Clone, Copy)]
pub enum TextEncoding {
    Utf8,
    Utf16Le,
    Utf16Be,
}

#[derive(Debug, Clone, Copy)]
pub struct DbHeader {
    pub page_size: u32,        // 512 .. 65536 (stored as u16; 1 == 65536)
    pub page_count: u32,
    pub text_encoding: TextEncoding,
    pub first_freelist_page: u32,
    pub freelist_pages: u32,
    pub schema_root_page: u32, // always 1
}

pub fn parse_header(bytes: &[u8]) -> Result<DbHeader> {
    if bytes.len() < 100 {
        return Err(Error::Parse("sqlite header < 100 bytes".into()));
    }
    if &bytes[..16] != HEADER_MAGIC {
        return Err(Error::Parse("sqlite magic mismatch".into()));
    }
    let page_size_raw = u16::from_be_bytes([bytes[16], bytes[17]]) as u32;
    let page_size = if page_size_raw == 1 { 65536 } else { page_size_raw };
    let page_count = u32::from_be_bytes(bytes[28..32].try_into().unwrap());
    let first_freelist_page = u32::from_be_bytes(bytes[32..36].try_into().unwrap());
    let freelist_pages = u32::from_be_bytes(bytes[36..40].try_into().unwrap());
    let enc = u32::from_be_bytes(bytes[56..60].try_into().unwrap());
    let text_encoding = match enc {
        1 => TextEncoding::Utf8,
        2 => TextEncoding::Utf16Le,
        3 => TextEncoding::Utf16Be,
        _ => TextEncoding::Utf8,
    };
    Ok(DbHeader {
        page_size,
        page_count,
        text_encoding,
        first_freelist_page,
        freelist_pages,
        schema_root_page: 1,
    })
}
