use std::io::{Error, ErrorKind, Read, Result, Seek, SeekFrom};

const WINDOW_BYTES: usize = 4096;
const CACHE_WINDOWS: usize = 16;

#[cfg(test)]
mod tests;

#[derive(Clone, Copy)]
pub(super) enum Encoding {
    Le32,
    Be32,
    Le64,
    Be64,
}

impl Encoding {
    const fn width(self) -> usize {
        match self {
            Self::Le32 | Self::Be32 => 4,
            Self::Le64 | Self::Be64 => 8,
        }
    }

    fn decode(self, bytes: &[u8], offset: usize) -> u64 {
        match self {
            Self::Le32 => u64::from(crate::utils::u32_le(bytes, offset)),
            Self::Be32 => u64::from(crate::utils::u32_be(bytes, offset)),
            Self::Le64 => crate::utils::u64_le(bytes, offset),
            Self::Be64 => crate::utils::u64_be(bytes, offset),
        }
    }
}

/// An allocation table whose complete byte range has been validated.
#[derive(Clone, Copy)]
pub(super) struct Table {
    offset: u64,
    entries: u64,
    encoding: Encoding,
}

impl Table {
    pub(super) const fn empty(encoding: Encoding) -> Self {
        Self {
            offset: 0,
            entries: 0,
            encoding,
        }
    }

    pub(super) fn new(
        offset: u64,
        entries: u64,
        encoding: Encoding,
        file_len: u64,
    ) -> Result<Self> {
        let end = entries
            .checked_mul(encoding.width() as u64)
            .and_then(|bytes| offset.checked_add(bytes))
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidData,
                    "Disk allocation table range overflow",
                )
            })?;
        if end > file_len {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "Disk allocation table extends beyond the file",
            ));
        }
        Ok(Self {
            offset,
            entries,
            encoding,
        })
    }

    pub(super) fn open<R: Seek>(
        file: &mut R,
        offset: u64,
        entries: u64,
        encoding: Encoding,
    ) -> Result<Self> {
        Self::new(offset, entries, encoding, file.seek(SeekFrom::End(0))?)
    }
}

struct Window {
    key: Option<(u64, usize)>,
    bytes: [u8; WINDOW_BYTES],
}

impl Default for Window {
    fn default() -> Self {
        Self {
            key: None,
            bytes: [0; WINDOW_BYTES],
        }
    }
}

/// At most 64 KiB per disk, shared by all its allocation tables. Allocate on
/// first use, so opening a snapshot chain does not put buffers on the stack.
#[derive(Default)]
pub(super) struct TableCache {
    windows: Vec<Window>,
    next: usize,
}

impl TableCache {
    pub(super) fn read<R: Read + Seek>(
        &mut self,
        file: &mut R,
        table: Table,
        index: u64,
    ) -> Result<Option<u64>> {
        if index >= table.entries {
            return Ok(None);
        }
        let width = table.encoding.width();
        let per_window = (WINDOW_BYTES / width) as u64;
        let first = index / per_window * per_window;
        let count = (table.entries - first).min(per_window) as usize * width;
        let start = table.offset + first * width as u64;
        let key = (start, count);
        let slot = if let Some(slot) = self.windows.iter().position(|w| w.key == Some(key)) {
            slot
        } else {
            if self.windows.is_empty() {
                self.windows
                    .try_reserve_exact(CACHE_WINDOWS)
                    .map_err(|e| Error::new(ErrorKind::OutOfMemory, e))?;
                self.windows.resize_with(CACHE_WINDOWS, Window::default);
            }
            let slot = self.next;
            let window = &mut self.windows[slot];
            window.key = None;
            file.seek(SeekFrom::Start(start))?;
            file.read_exact(&mut window.bytes[..count])?;
            window.key = Some(key);
            self.next = (slot + 1) % CACHE_WINDOWS;
            slot
        };
        let offset = (index - first) as usize * width;
        Ok(Some(
            table.encoding.decode(&self.windows[slot].bytes, offset),
        ))
    }
}
