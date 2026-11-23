use std::io::{ErrorKind, Read, Seek, SeekFrom};

/// Preserve registry recovery's zero-fill policy without materializing a file.
pub struct ResilientReader<R> {
    inner: R,
    len: u64,
    position: u64,
    warned: bool,
}

impl<R> ResilientReader<R> {
    pub(crate) const fn new(inner: R, len: u64) -> Self {
        Self {
            inner,
            len,
            position: 0,
            warned: false,
        }
    }
}

impl<R: Read + Seek> Read for ResilientReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let len = crate::disk::read_len(self.len.saturating_sub(self.position), buf.len());
        if len == 0 {
            return Ok(0);
        }
        let buf = &mut buf[..len];
        let read = self
            .inner
            .seek(SeekFrom::Start(self.position))
            .and_then(|_| self.inner.read_exact(buf));
        if let Err(error) = read {
            if error.kind() == ErrorKind::OutOfMemory {
                return Err(error);
            }
            let mut offset = self.position;
            for chunk in buf.chunks_mut(4096) {
                let read = self
                    .inner
                    .seek(SeekFrom::Start(offset))
                    .and_then(|_| self.inner.read_exact(chunk));
                if let Err(error) = read {
                    if error.kind() == ErrorKind::OutOfMemory {
                        return Err(error);
                    }
                    chunk.fill(0);
                    if !self.warned {
                        log::warn!(
                            "NTFS data unreadable at offset {offset:#x}; zero-filled — file is incomplete ({error})"
                        );
                        self.warned = true;
                    }
                }
                offset += chunk.len() as u64;
            }
        }
        self.position += len as u64;
        Ok(len)
    }
}

impl<R: Read + Seek> Seek for ResilientReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.position = crate::disk::seek_position(self.position, self.len, pos)?;
        Ok(self.position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocation_failures_are_not_zero_filled_or_retried() {
        struct NoMemory {
            reads: usize,
        }
        impl Read for NoMemory {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                self.reads += 1;
                Err(std::io::Error::from(ErrorKind::OutOfMemory))
            }
        }
        impl Seek for NoMemory {
            fn seek(&mut self, _: SeekFrom) -> std::io::Result<u64> {
                Ok(0)
            }
        }
        let mut inner = NoMemory { reads: 0 };
        let mut reader = ResilientReader::new(&mut inner, 4096);
        let mut bytes = [0xFF; 4096];
        assert_eq!(
            reader.read_exact(&mut bytes).unwrap_err().kind(),
            ErrorKind::OutOfMemory
        );
        assert_eq!(bytes, [0xFF; 4096]);
        assert_eq!(inner.reads, 1);
    }
}
