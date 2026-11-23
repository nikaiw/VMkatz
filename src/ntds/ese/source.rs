use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{Read, Seek, SeekFrom};
use std::rc::Rc;

use crate::error::Result;

pub(super) trait ReadSeek: Read + Seek {}
impl<R: Read + Seek> ReadSeek for R {}

const CACHE_BYTES: usize = 512 * 1024;

pub(super) enum Page<'a> {
    Borrowed(&'a [u8]),
    Cached(Rc<Vec<u8>>),
}

#[cfg(test)]
#[path = "source_tests.rs"]
mod tests;

impl std::ops::Deref for Page<'_> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Self::Borrowed(bytes) => bytes,
            Self::Cached(bytes) => bytes,
        }
    }
}

impl AsRef<[u8]> for Page<'_> {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

pub(super) struct CachedReader<'a> {
    reader: Box<dyn ReadSeek + 'a>,
    pages: VecDeque<(u64, Rc<Vec<u8>>)>,
    bytes: usize,
}

impl CachedReader<'_> {
    fn read(&mut self, offset: u64, len: usize) -> Result<Rc<Vec<u8>>> {
        if let Some((_, page)) = self
            .pages
            .iter()
            .find(|(at, bytes)| *at == offset && bytes.len() == len)
        {
            return Ok(Rc::clone(page));
        }
        let mut bytes = crate::utils::zeroed_buffer(len)?;
        self.reader.seek(SeekFrom::Start(offset))?;
        self.reader.read_exact(&mut bytes)?;
        let page = Rc::new(bytes);
        while self.bytes + len > CACHE_BYTES {
            let Some((_, oldest)) = self.pages.pop_front() else {
                break;
            };
            self.bytes -= oldest.len();
        }
        self.pages
            .try_reserve(1)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::OutOfMemory, e))?;
        self.pages.push_back((offset, Rc::clone(&page)));
        self.bytes += len;
        Ok(page)
    }
}

pub(super) enum Source<'a> {
    Bytes(&'a [u8]),
    Reader {
        reader: RefCell<CachedReader<'a>>,
        len: u64,
    },
}

impl<'a> Source<'a> {
    pub(super) fn reader<R: Read + Seek + 'a>(mut reader: R) -> Result<Self> {
        let len = reader.seek(SeekFrom::End(0))?;
        Ok(Self::Reader {
            reader: RefCell::new(CachedReader {
                reader: Box::new(reader),
                pages: VecDeque::new(),
                bytes: 0,
            }),
            len,
        })
    }

    pub(super) const fn len(&self) -> u64 {
        match self {
            Self::Bytes(bytes) => bytes.len() as u64,
            Self::Reader { len, .. } => *len,
        }
    }

    /// Only ESE headers and individual pages (at most 32 KiB) are read here.
    pub(super) fn read(&self, offset: u64, len: usize) -> Result<Option<Page<'a>>> {
        if offset
            .checked_add(len as u64)
            .is_none_or(|end| end > self.len())
        {
            return Ok(None);
        }
        match self {
            Self::Bytes(bytes) => {
                let start = usize::try_from(offset).map_err(std::io::Error::other)?;
                Ok(bytes.get(start..start + len).map(Page::Borrowed))
            }
            Self::Reader { reader, .. } => {
                Ok(Some(Page::Cached(reader.borrow_mut().read(offset, len)?)))
            }
        }
    }
}
