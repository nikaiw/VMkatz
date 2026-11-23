//! Random-access byte source abstraction shared by the disk-image walkers.

use super::{FsError, FsResult};

/// A read-only, position-independent byte source (a disk image or a partition window).
pub trait ByteReader {
    /// Read into `buffer` starting at `offset`, returning the number of bytes read (which
    /// may be short at end of source).
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying source fails.
    fn read_at(&self, buffer: &mut [u8], offset: u64) -> FsResult<usize>;

    /// Total size of the source in bytes.
    fn size(&self) -> u64;
}

/// Read exactly `length` bytes at `offset`, erroring if the source is too short.
///
/// # Errors
///
/// Returns [`FsError::Truncated`] when fewer than `length` bytes are available.
pub fn read_exact_at<R: ByteReader + ?Sized>(
    reader: &R,
    offset: u64,
    length: usize,
) -> FsResult<Vec<u8>> {
    let mut buffer = vec![0_u8; length];
    let read = reader.read_at(&mut buffer, offset)?;
    if read != length {
        return Err(FsError::Truncated { offset, length });
    }
    Ok(buffer)
}

/// A window onto a parent [`ByteReader`]: bytes `[start, start + length)` re-based to zero.
#[derive(Debug)]
pub struct SubReader<'a, R: ByteReader + ?Sized> {
    inner: &'a R,
    start: u64,
    length: u64,
}

impl<'a, R: ByteReader + ?Sized> SubReader<'a, R> {
    /// Create a window; it is clamped to the parent's bounds so reads never escape it.
    #[must_use]
    pub fn new(inner: &'a R, start: u64, length: u64) -> Self {
        let available = inner.size().saturating_sub(start);
        Self {
            inner,
            start,
            length: length.min(available),
        }
    }
}

impl<R: ByteReader + ?Sized> ByteReader for SubReader<'_, R> {
    fn read_at(&self, buffer: &mut [u8], offset: u64) -> FsResult<usize> {
        if offset >= self.length {
            return Ok(0);
        }
        let remaining = self.length.saturating_sub(offset);
        let want = u64::try_from(buffer.len())
            .unwrap_or(u64::MAX)
            .min(remaining);
        let want = usize::try_from(want).unwrap_or(0);
        let absolute = self.start.saturating_add(offset);
        let target = buffer.get_mut(..want).ok_or_else(|| FsError::Io {
            message: "sub-reader window overflow".to_owned(),
        })?;
        self.inner.read_at(target, absolute)
    }

    fn size(&self) -> u64 {
        self.length
    }
}

impl ByteReader for [u8] {
    fn read_at(&self, buffer: &mut [u8], offset: u64) -> FsResult<usize> {
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(self.len());
        let source = self.get(start..).unwrap_or(&[]);
        let count = source.len().min(buffer.len());
        let target = buffer.get_mut(..count).ok_or_else(|| FsError::Io {
            message: "slice reader window overflow".to_owned(),
        })?;
        let bytes = source.get(..count).ok_or_else(|| FsError::Io {
            message: "slice reader source overflow".to_owned(),
        })?;
        target.copy_from_slice(bytes);
        Ok(count)
    }

    fn size(&self) -> u64 {
        u64::try_from(self.len()).unwrap_or(u64::MAX)
    }
}
