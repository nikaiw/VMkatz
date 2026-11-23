use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{Read, Seek, SeekFrom};

use crate::error::{Result, VmkatzError};

const WINDOW_BYTES: usize = 64 * 1024;
const CACHE_WINDOWS: usize = 8;
pub(super) const MAX_READ_BYTES: usize = 16 * 1024 * 1024;

trait ReadSeek: Read + Seek {}
impl<T: Read + Seek> ReadSeek for T {}

struct Reader<'a> {
    inner: Box<dyn ReadSeek + 'a>,
    windows: VecDeque<(u64, Vec<u8>)>,
}

enum Backing<'a> {
    Bytes(&'a [u8]),
    Reader(RefCell<Reader<'a>>),
}

pub(super) struct Source<'a> {
    backing: Backing<'a>,
    len: u64,
    failure: RefCell<Option<VmkatzError>>,
}

impl<'a> Source<'a> {
    pub(super) const fn bytes(bytes: &'a [u8]) -> Self {
        Self {
            backing: Backing::Bytes(bytes),
            len: bytes.len() as u64,
            failure: RefCell::new(None),
        }
    }

    pub(super) fn reader<R: Read + Seek + 'a>(mut inner: R) -> Result<Self> {
        let len = inner.seek(SeekFrom::End(0))?;
        Ok(Self {
            backing: Backing::Reader(RefCell::new(Reader {
                inner: Box::new(inner),
                windows: VecDeque::new(),
            })),
            len,
            failure: RefCell::new(None),
        })
    }

    pub(super) const fn len(&self) -> u64 {
        self.len
    }

    /// Optional registry values must not hide a failed read or a resource refusal.
    pub(super) fn finish<T>(&self, result: Result<T>) -> Result<T> {
        self.failure.borrow_mut().take().map_or(result, Err)
    }

    pub(super) fn remember<T>(&self, result: Result<T>) -> Result<T> {
        match result {
            Err(error) if error.is_resource_limit() || matches!(error, VmkatzError::Io(_)) => {
                let forwarded = forward_error(&error);
                self.failure.borrow_mut().get_or_insert(error);
                Err(forwarded)
            }
            result => result,
        }
    }

    pub(super) fn read(&self, offset: u64, len: usize) -> Result<Cow<'a, [u8]>> {
        if let Some(error) = self.failure.borrow().as_ref() {
            return Err(forward_error(error));
        }
        self.remember(self.read_inner(offset, len))
    }

    fn read_inner(&self, offset: u64, len: usize) -> Result<Cow<'a, [u8]>> {
        if len > MAX_READ_BYTES {
            return Err(VmkatzError::AllocTooLarge {
                what: "registry cell/value",
                requested: len,
                limit: MAX_READ_BYTES,
            });
        }
        if offset
            .checked_add(len as u64)
            .is_none_or(|end| end > self.len)
        {
            return Err(super::hive_err("Read outside hive"));
        }
        match &self.backing {
            Backing::Bytes(bytes) => {
                let start = usize::try_from(offset).map_err(std::io::Error::other)?;
                Ok(Cow::Borrowed(&bytes[start..start + len]))
            }
            Backing::Reader(reader) => {
                let mut result = crate::utils::zeroed_buffer(len)?;
                reader.borrow_mut().read(offset, &mut result, self.len)?;
                Ok(Cow::Owned(result))
            }
        }
    }
}

impl Reader<'_> {
    fn read(&mut self, mut offset: u64, mut output: &mut [u8], len: u64) -> Result<()> {
        while !output.is_empty() {
            let window_start = offset / WINDOW_BYTES as u64 * WINDOW_BYTES as u64;
            let index = self.windows.iter().position(|(at, _)| *at == window_start);
            let index = if let Some(index) = index {
                index
            } else {
                let size = (len - window_start).min(WINDOW_BYTES as u64) as usize;
                let mut bytes = crate::utils::zeroed_buffer(size)?;
                self.inner.seek(SeekFrom::Start(window_start))?;
                self.inner.read_exact(&mut bytes)?;
                if self.windows.len() == CACHE_WINDOWS {
                    self.windows.pop_front();
                }
                self.windows
                    .try_reserve(1)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::OutOfMemory, e))?;
                self.windows.push_back((window_start, bytes));
                self.windows.len() - 1
            };
            let bytes = &self.windows[index].1;
            let within = (offset - window_start) as usize;
            let count = output.len().min(bytes.len() - within);
            output[..count].copy_from_slice(&bytes[within..within + count]);
            output = &mut output[count..];
            offset += count as u64;
        }
        Ok(())
    }
}

fn forward_error(error: &VmkatzError) -> VmkatzError {
    let kind = if error.is_resource_limit() {
        std::io::ErrorKind::OutOfMemory
    } else if let VmkatzError::Io(io) = error {
        io.kind()
    } else {
        std::io::ErrorKind::Other
    };
    std::io::Error::new(kind, error.to_string()).into()
}

#[cfg(test)]
#[path = "source_tests.rs"]
mod tests;
