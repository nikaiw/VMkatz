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

/// Memory-map a file, handling block devices where fstat returns size 0.
#[cfg(any(feature = "vmware", feature = "qemu", feature = "hyperv"))]
pub fn mmap_file(file: &std::fs::File) -> std::io::Result<memmap2::Mmap> {
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
    unsafe { memmap2::MmapOptions::new().len(size as usize).map(file) }
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
