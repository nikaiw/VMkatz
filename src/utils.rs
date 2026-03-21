/// Safe little-endian read helpers.
/// Bounds-checked alternatives to `data[off..off+N].try_into().unwrap()`.
#[inline]
pub fn read_u16_le(data: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(data.get(off..off + 2)?.try_into().ok()?))
}

#[inline]
pub fn read_u32_le(data: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(off..off + 4)?.try_into().ok()?))
}

#[inline]
pub fn read_u64_le(data: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(data.get(off..off + 8)?.try_into().ok()?))
}

#[inline]
pub fn read_i32_le(data: &[u8], off: usize) -> Option<i32> {
    Some(i32::from_le_bytes(data.get(off..off + 4)?.try_into().ok()?))
}

/// SHA-1 digest (FIPS 180-4). Returns 20-byte hash.
///
/// Used for MSV credential cross-validation (SHA1(NT_hash) == ShaOwPassword)
/// and DPAPI master key verification.
pub fn sha1_digest(data: &[u8]) -> [u8; 20] {
    let (mut h0, mut h1, mut h2, mut h3, mut h4) = (
        0x67452301u32,
        0xEFCDAB89u32,
        0x98BADCFEu32,
        0x10325476u32,
        0xC3D2E1F0u32,
    );
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for block in msg.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }
    let mut r = [0u8; 20];
    r[0..4].copy_from_slice(&h0.to_be_bytes());
    r[4..8].copy_from_slice(&h1.to_be_bytes());
    r[8..12].copy_from_slice(&h2.to_be_bytes());
    r[12..16].copy_from_slice(&h3.to_be_bytes());
    r[16..20].copy_from_slice(&h4.to_be_bytes());
    r
}

/// Get the real size of a file or block device.
/// `metadata().len()` returns 0 for block devices; this uses seek instead.
pub fn file_size(file: &mut std::fs::File) -> std::io::Result<u64> {
    use std::io::{Seek, SeekFrom};
    let pos = file.stream_position()?;
    let size = file.seek(SeekFrom::End(0))?;
    file.seek(SeekFrom::Start(pos))?;
    Ok(size)
}

/// File-backed memory: mmap when available, pread fallback for platforms
/// where mmap is unsupported (e.g. ESXi 6.5 VMkernel returns EINVAL on VMFS).
#[cfg(any(feature = "vmware", feature = "qemu", feature = "hyperv"))]
pub enum MappedFile {
    Mmap(memmap2::Mmap),
    /// Fallback: file handle for pread-based access.
    /// The Vec is a read buffer used by `slice()` — grown on demand.
    Pread {
        file: std::sync::Mutex<std::fs::File>,
        size: u64,
    },
}

#[cfg(any(feature = "vmware", feature = "qemu", feature = "hyperv"))]
impl MappedFile {
    pub fn len(&self) -> usize {
        match self {
            MappedFile::Mmap(m) => m.len(),
            MappedFile::Pread { size, .. } => *size as usize,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Read bytes at an offset into the provided buffer.
    /// Works for both mmap (memcpy) and pread (syscall) variants.
    pub fn read_at(&self, offset: usize, buf: &mut [u8]) -> std::io::Result<()> {
        match self {
            MappedFile::Mmap(m) => {
                let end = offset + buf.len();
                if end > m.len() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        format!("mmap read_at: offset=0x{:x} len={} exceeds file size {}", offset, buf.len(), m.len()),
                    ));
                }
                buf.copy_from_slice(&m[offset..end]);
                Ok(())
            }
            MappedFile::Pread { file, size } => {
                let end = offset as u64 + buf.len() as u64;
                if end > *size {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        format!("pread read_at: offset=0x{:x} len={} exceeds file size {}", offset, buf.len(), size),
                    ));
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::FileExt;
                    let f = file.lock().unwrap();
                    f.read_exact_at(buf, offset as u64)?;
                }
                #[cfg(not(unix))]
                {
                    use std::io::{Read, Seek, SeekFrom};
                    let mut f = file.lock().unwrap();
                    f.seek(SeekFrom::Start(offset as u64))?;
                    f.read_exact(buf)?;
                }
                Ok(())
            }
        }
    }

    /// Get a byte slice (only works for mmap variant).
    /// Panics on Pread variant — callers that need slicing must use read_at instead.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            MappedFile::Mmap(m) => m,
            MappedFile::Pread { .. } => panic!("as_bytes() not supported on pread fallback — use read_at()"),
        }
    }

    /// Whether this is using the pread fallback (for logging).
    pub fn is_pread(&self) -> bool {
        matches!(self, MappedFile::Pread { .. })
    }
}

#[cfg(any(feature = "vmware", feature = "qemu", feature = "hyperv"))]
impl std::ops::Deref for MappedFile {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Read the first `max_bytes` of a file into a Vec.
/// Used to parse headers/tags from files where mmap is unavailable.
#[cfg(any(feature = "vmware", feature = "qemu", feature = "hyperv"))]
pub fn read_file_header(file: &std::fs::File, max_bytes: usize) -> std::io::Result<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = file.try_clone()?;
    let size = f.seek(SeekFrom::End(0))?;
    f.seek(SeekFrom::Start(0))?;
    let to_read = (size as usize).min(max_bytes);
    let mut buf = vec![0u8; to_read];
    f.read_exact(&mut buf)?;
    Ok(buf)
}

/// Open a file as MappedFile: tries mmap first, falls back to pread on failure.
/// Handles block devices where fstat returns size 0.
#[cfg(any(feature = "vmware", feature = "qemu", feature = "hyperv"))]
pub fn mmap_file(file: &std::fs::File) -> std::io::Result<MappedFile> {
    use std::io::{Seek, SeekFrom};
    let mut f = file.try_clone()?;
    let size = f.seek(SeekFrom::End(0))?;
    f.seek(SeekFrom::Start(0))?;
    if size == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Empty file or unreadable device",
        ));
    }

    // Try mmap first
    let mmap_result = unsafe {
        memmap2::MmapOptions::new()
            .len(size as usize)
            .map(file)
    };

    match mmap_result {
        Ok(m) => Ok(MappedFile::Mmap(m)),
        Err(mmap_err) => {
            eprintln!(
                "[!] mmap failed ({:.1} MB): {} — falling back to file I/O (slower)",
                size as f64 / (1024.0 * 1024.0),
                mmap_err,
            );
            let f = file.try_clone()?;
            Ok(MappedFile::Pread {
                file: std::sync::Mutex::new(f),
                size,
            })
        }
    }
}

/// Decode UTF-16LE bytes to a String without intermediate Vec<u16> allocation.
/// NUL-terminated: stops at first U+0000. Replaces invalid surrogates with U+FFFD.
pub fn utf16le_decode(data: &[u8]) -> String {
    char::decode_utf16(
        data.chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&c| c != 0),
    )
    .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
    .collect()
}
