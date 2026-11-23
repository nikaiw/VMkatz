use std::io::{Error, ErrorKind, Read, Result, Seek, SeekFrom};

const WINDOW_BYTES: usize = 4096;
const WINDOW_ENTRIES: u64 = (WINDOW_BYTES / 4) as u64;
const CACHE_WINDOWS: usize = 4;

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Default)]
pub(super) struct GrainDirectory {
    offset: u64,
    pub(super) entries: u64,
}

impl GrainDirectory {
    pub(super) fn open<R: Seek>(file: &mut R, offset: u64, entries: u64) -> Result<Self> {
        let end = entries
            .checked_mul(4)
            .and_then(|bytes| offset.checked_add(bytes))
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "VMDK grain directory overflow"))?;
        if end > file.seek(SeekFrom::End(0))? {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "VMDK grain directory extends beyond the extent file",
            ));
        }
        Ok(Self { offset, entries })
    }
}

struct Window {
    key: Option<(usize, u64)>,
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

/// Four FIFO windows shared by all extents of a disk. Allocate them on first use
/// to keep unused disks cheap and recursive snapshot opens off large stack frames.
#[derive(Default)]
pub(super) struct DirectoryCache {
    windows: Vec<Window>,
    next: usize,
}

impl DirectoryCache {
    pub(super) fn read_entry<R: Read + Seek>(
        &mut self,
        file: &mut R,
        directory: GrainDirectory,
        extent_index: usize,
        index: u64,
    ) -> Result<u32> {
        if index >= directory.entries {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "VMDK grain directory index out of bounds",
            ));
        }
        let first = index / WINDOW_ENTRIES * WINDOW_ENTRIES;
        let key = (extent_index, first);
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
            let count = (directory.entries - first).min(WINDOW_ENTRIES) as usize * 4;
            // The complete directory range was checked when opening the extent.
            file.seek(SeekFrom::Start(directory.offset + first * 4))?;
            file.read_exact(&mut window.bytes[..count])?;
            window.key = Some(key);
            self.next = (slot + 1) % CACHE_WINDOWS;
            slot
        };
        let offset = (index - first) as usize * 4;
        Ok(crate::utils::u32_le(&self.windows[slot].bytes, offset))
    }
}
