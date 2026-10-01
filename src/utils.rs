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
///
/// Memory profile: the mmap variant keeps whatever pages the scan has faulted
/// resident until told otherwise, so a full-image sweep would grow RSS to the
/// image size. Callers doing large sequential scans call [`advise_dontneed`] on
/// each range as they finish with it, which drops those pages and bounds RSS to
/// roughly one scan window. The pread variant is intrinsically low-memory (each
/// read only touches the caller's buffer), which is why it stays the safe path
/// on old ESXi where mmap is unavailable.
///
/// [`advise_dontneed`]: MappedFile::advise_dontneed
#[cfg(any(feature = "vmware", feature = "qemu", feature = "hyperv"))]
pub enum MappedFile {
    Mmap(memmap2::Mmap),
    /// Fallback: pread-based access via a shared file handle. No image bytes are
    /// held resident — each `read_at` copies straight into the caller's buffer.
    Pread {
        file: std::sync::Mutex<std::fs::File>,
        size: u64,
    },
}

#[cfg(any(feature = "vmware", feature = "qemu", feature = "hyperv"))]
impl MappedFile {
    pub fn len(&self) -> usize {
        match self {
            Self::Mmap(m) => m.len(),
            Self::Pread { size, .. } => *size as usize,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Read bytes at an offset into the provided buffer.
    /// Works for both mmap (memcpy) and pread (syscall) variants.
    ///
    /// `offset` is a `u64` so callers never have to truncate a guest-physical or
    /// file offset to `usize` — which would silently corrupt reads above 4 GiB on
    /// 32-bit targets (armv7/arm builds) parsing large memory snapshots.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
        let eof = || {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!(
                    "read_at: offset=0x{offset:x} len={} exceeds file size {}",
                    buf.len(),
                    self.len()
                ),
            )
        };
        match self {
            Self::Mmap(m) => {
                // On 32-bit, an offset past usize is necessarily past the mmap.
                let start = usize::try_from(offset).map_err(|_| eof())?;
                let end = start
                    .checked_add(buf.len())
                    .filter(|&e| e <= m.len())
                    .ok_or_else(eof)?;
                buf.copy_from_slice(&m[start..end]);
                Ok(())
            }
            Self::Pread { file, size } => {
                if offset
                    .checked_add(buf.len() as u64)
                    .is_none_or(|end| end > *size)
                {
                    return Err(eof());
                }
                let f = file.lock().unwrap();
                read_exact_at(&f, buf, offset)?;
                Ok(())
            }
        }
    }

    /// Get a byte slice (only works for mmap variant).
    /// Panics on Pread variant — callers that need slicing must use read_at instead.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Mmap(m) => m,
            Self::Pread { .. } => {
                panic!("as_bytes() not supported on pread fallback — use read_at()")
            }
        }
    }

    /// Whether this is using the pread fallback (for logging).
    pub const fn is_pread(&self) -> bool {
        matches!(self, Self::Pread { .. })
    }

    /// Tell the kernel the pages backing `[offset, offset + len)` won't be needed
    /// again soon, so it can reclaim them. Used by large sequential scans to drop
    /// each chunk once consumed, keeping resident memory near one scan window
    /// instead of the whole image — the key to not ballooning RSS on a
    /// memory-constrained host (e.g. an ESXi userworld).
    ///
    /// No-op on the pread fallback (nothing is resident there) and best-effort on
    /// mmap (an advisory syscall; harmless if the platform ignores it).
    // Windows: body is cfg'd out, so clippy sees a trivially-const empty fn.
    #[cfg_attr(not(unix), allow(clippy::missing_const_for_fn))]
    pub fn advise_dontneed(&self, offset: u64, len: u64) {
        // madvise(DONTNEED) is unix-only; elsewhere the OS reclaims mapped pages on
        // its own, so the whole body is gated and this is a no-op.
        #[cfg(not(unix))]
        let _ = (self, offset, len);
        #[cfg(unix)]
        {
            // Round the range inward to page boundaries: only whole pages fully
            // inside the scanned span are dropped, never a partial page that may
            // share bytes with data still in use.
            const PAGE: u64 = 4096;
            let Self::Mmap(m) = self else { return };
            let map_len = m.len() as u64;
            if len == 0 || offset >= map_len {
                return;
            }
            let end = offset.saturating_add(len).min(map_len);
            let start = offset.div_ceil(PAGE) * PAGE;
            let aligned_end = (end / PAGE) * PAGE;
            if aligned_end <= start {
                return;
            }
            // SAFETY: `m` is a read-only, file-backed mapping. MADV_DONTNEED on such
            // a mapping discards only clean resident pages; a later access
            // transparently re-faults them from the file with no data loss. (memmap2
            // gates this as `unchecked` because on a *dirty private* mapping it would
            // lose writes — not our case.)
            unsafe {
                let _ = m.unchecked_advise_range(
                    memmap2::UncheckedAdvice::DontNeed,
                    start as usize,
                    (aligned_end - start) as usize,
                );
            }
        }
    }
}

/// Best-effort available-RAM figure from `/proc/meminfo` (present on Linux and the
/// ESXi userworld). Returns `None` when it can't be read/parsed.
#[cfg(any(feature = "vmware", feature = "qemu", feature = "hyperv"))]
fn available_memory_bytes() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("MemAvailable:") {
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb.saturating_mul(1024));
        }
    }
    None
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
pub fn mmap_file(file: &std::fs::File, path: &std::path::Path) -> std::io::Result<MappedFile> {
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
    let mmap_result = unsafe { memmap2::MmapOptions::new().len(size as usize).map(file) };

    match mmap_result {
        Ok(m) => {
            // The scans read the image front-to-back, so hint sequential access:
            // the kernel reads ahead (faster) and may drop pages behind the cursor.
            // Combined with the explicit `advise_dontneed` calls the scan loops
            // make, this keeps resident memory near one scan window. Best-effort.
            #[cfg(unix)]
            let _ = m.advise(memmap2::Advice::Sequential);

            // Guardrail: on a memory-constrained host (notably an ESXi userworld)
            // a large image can pressure the memory scheduler. We already bound RSS
            // via drop-behind, but warn so the operator can prefer an off-host scan.
            if let Some(avail) = available_memory_bytes() {
                if size > avail {
                    const GB: f64 = 1024.0 * 1024.0 * 1024.0;
                    eprintln!(
                        "[!] image is {:.1} GB but only {:.1} GB RAM is available — \
                         scanned pages are released as they're consumed to bound memory; \
                         on a constrained host prefer copying the image off-host to scan",
                        size as f64 / GB,
                        avail as f64 / GB,
                    );
                }
            }
            Ok(MappedFile::Mmap(m))
        }
        Err(mmap_err) => {
            eprintln!(
                "[!] mmap failed for '{}' ({:.1} MB): {} — falling back to file I/O (slower)",
                path.display(),
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

/// Format a 16-byte little-endian GUID as `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.
///
/// Mixed-endian per the GUID layout: Data1(4)/Data2(2)/Data3(2) little-endian,
/// Data4(8) big-endian. Falls back to plain hex for inputs shorter than 16 bytes.
pub fn format_guid(bytes: &[u8]) -> String {
    if bytes.len() < 16 {
        return hex::encode(bytes);
    }
    let d1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let d2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let d3 = u16::from_le_bytes([bytes[6], bytes[7]]);
    format!(
        "{d1:08x}-{d2:04x}-{d3:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    )
}

/// Positioned read, portable. `pread` on unix, `seek_read` on Windows (which can
/// return short, hence the loop). Both take `&File`, so callers can share one
/// handle across threads without a lock.
pub fn read_exact_at(file: &std::fs::File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.read_exact_at(buf, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let mut done = 0;
        while done < buf.len() {
            match file.seek_read(&mut buf[done..], offset + done as u64) {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "short positioned read",
                    ));
                }
                Ok(n) => done += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}
