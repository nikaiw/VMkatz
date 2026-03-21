//! BitLocker transparent decryption wrapper.
//!
//! Wraps a `Read + Seek` disk reader and transparently decrypts BitLocker-encrypted
//! sectors using an FVEK extracted from memory. The decrypted stream appears as a
//! plain NTFS volume to downstream parsers (NTFS hive reader, etc.).
//!
//! Supports AES-XTS-128 (method 0x8004) and AES-XTS-256 (method 0x8005).

use std::io::{self, Read, Seek, SeekFrom};

use super::aes_xts;

/// Sector size for BitLocker decryption.
const SECTOR_SIZE: u64 = 512;

/// A decrypting reader that transparently decrypts BitLocker-encrypted sectors.
///
/// Reads from the underlying reader at `partition_offset + position`, decrypts
/// each 512-byte sector with AES-XTS, and presents a plain-text view.
pub struct BitLockerReader<R: Read + Seek> {
    inner: R,
    /// Byte offset of the BitLocker partition on the disk image.
    partition_offset: u64,
    /// Full XTS key (32 bytes for AES-128-XTS, 64 bytes for AES-256-XTS).
    xts_key: Vec<u8>,
    /// Current read position relative to partition start.
    position: u64,
}

impl<R: Read + Seek> BitLockerReader<R> {
    /// Create a new BitLocker decrypting reader.
    ///
    /// `partition_offset` is the byte offset of the encrypted partition on disk.
    /// `xts_key` is the full AES-XTS key (key1 || key2): 32 bytes for XTS-128, 64 for XTS-256.
    pub fn new(inner: R, partition_offset: u64, xts_key: Vec<u8>) -> Self {
        Self {
            inner,
            partition_offset,
            xts_key,
            position: 0,
        }
    }

    /// Try to decrypt sector 0 and check for NTFS signature at offset 3.
    ///
    /// Returns true if the decrypted first sector starts with "NTFS" at byte 3,
    /// indicating a valid NTFS boot sector and correct FVEK.
    pub fn validate_ntfs_signature(&mut self) -> bool {
        let mut sector = [0u8; SECTOR_SIZE as usize];

        // Read encrypted sector 0
        if self.inner.seek(SeekFrom::Start(self.partition_offset)).is_err() {
            return false;
        }
        if self.inner.read_exact(&mut sector).is_err() {
            return false;
        }

        // Decrypt sector 0 (sector number = 0)
        if aes_xts::aes_xts_decrypt_sector(&self.xts_key, &mut sector, 0).is_err() {
            return false;
        }

        // Check for "NTFS" OEM ID at offset 3 in the NTFS boot sector
        sector.get(3..7) == Some(b"NTFS")
    }
}

impl<R: Read + Seek> Read for BitLockerReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let mut total_read = 0usize;

        while total_read < buf.len() {
            let current_pos = self.position;
            let sector_number = current_pos / SECTOR_SIZE;
            let offset_in_sector = (current_pos % SECTOR_SIZE) as usize;

            // Read the full encrypted sector from the underlying reader
            let disk_offset = self.partition_offset + sector_number * SECTOR_SIZE;
            self.inner.seek(SeekFrom::Start(disk_offset)).map_err(|e| {
                io::Error::other(
                    format!("BitLocker seek to sector {}: {}", sector_number, e),
                )
            })?;

            let mut sector_buf = [0u8; SECTOR_SIZE as usize];
            match self.inner.read_exact(&mut sector_buf) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof && total_read > 0 => {
                    // Partial read at end of volume
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    return Ok(0); // EOF
                }
                Err(e) => return Err(e),
            }

            // Decrypt the sector
            aes_xts::aes_xts_decrypt_sector(&self.xts_key, &mut sector_buf, sector_number)
                .map_err(|e| {
                    io::Error::other(
                        format!("BitLocker XTS decrypt sector {}: {}", sector_number, e),
                    )
                })?;

            // Copy the relevant portion to the output buffer
            let available = SECTOR_SIZE as usize - offset_in_sector;
            let remaining = buf.len() - total_read;
            let to_copy = available.min(remaining);

            buf[total_read..total_read + to_copy]
                .copy_from_slice(&sector_buf[offset_in_sector..offset_in_sector + to_copy]);

            total_read += to_copy;
            self.position += to_copy as u64;
        }

        Ok(total_read)
    }
}

impl<R: Read + Seek> Seek for BitLockerReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_position = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::Current(delta) => {
                if delta >= 0 {
                    self.position.checked_add(delta as u64)
                } else {
                    self.position.checked_sub((-delta) as u64)
                }
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "Seek position overflow")
                })?
            }
            SeekFrom::End(_) => {
                // We don't know the partition size easily, so pass through to inner.
                // This is rarely used by NTFS parsers (they use SeekFrom::Start).
                let abs = self.inner.seek(pos)?;
                let relative = abs.saturating_sub(self.partition_offset);
                self.position = relative;
                return Ok(relative);
            }
        };

        self.position = new_position;
        Ok(new_position)
    }
}

/// Build the full AES-XTS key from a `BitLockerKey`.
///
/// For XTS modes (0x8004, 0x8005), the key is key1 || key2 where:
/// - key1 = data encryption key
/// - key2 = tweak encryption key
///
/// The Cngb extraction stores only one AES key in `fvek` (the two internal
/// copies are validated to be equal). For XTS we need both halves, so this
/// function tries multiple strategies:
/// 1. If fvek is already the full size (32/64 bytes), use as-is
/// 2. If fvek is half size (16/32 bytes), duplicate it (fvek || fvek)
///
/// Returns `None` for unsupported encryption methods (Diffuser/CBC).
pub fn build_xts_key(key: &crate::lsass::bitlocker::BitLockerKey) -> Option<Vec<u8>> {
    let expected_full_len = match key.method {
        0x8004 => 32, // AES-128-XTS: 2 x 16 bytes
        0x8005 => 64, // AES-256-XTS: 2 x 32 bytes
        _ => return None, // CBC/Diffuser modes not yet supported
    };

    let expected_half = expected_full_len / 2;

    if key.fvek.len() == expected_full_len {
        // Already the full XTS key
        Some(key.fvek.clone())
    } else if key.fvek.len() == expected_half {
        // Half key — duplicate for both data and tweak
        // This is common with Cngb extraction where only one AES key is captured.
        // The real tweak key may differ; the caller should validate with NTFS signature.
        let mut full = Vec::with_capacity(expected_full_len);
        full.extend_from_slice(&key.fvek);
        full.extend_from_slice(&key.fvek);
        Some(full)
    } else {
        log::warn!(
            "BitLocker: unexpected FVEK length {} for method 0x{:04x} (expected {} or {})",
            key.fvek.len(),
            key.method,
            expected_half,
            expected_full_len,
        );
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Create a fake "encrypted" volume by XTS-encrypting known plaintext.
    fn make_encrypted_ntfs_volume(key: &[u8], partition_offset: u64) -> Vec<u8> {
        use aes::cipher::generic_array::GenericArray;
        use aes::cipher::{BlockEncrypt, KeyInit};
        use aes::Aes128;

        // Create a 2-sector volume with NTFS signature
        let mut plaintext = vec![0u8; 1024];
        // NTFS boot sector: "NTFS" at offset 3
        plaintext[0] = 0xEB; // JMP short
        plaintext[1] = 0x52;
        plaintext[2] = 0x90;
        plaintext[3..7].copy_from_slice(b"NTFS");
        plaintext[7] = 0x20; // space
        // Fill rest with recognizable pattern
        for (i, byte) in plaintext[8..512].iter_mut().enumerate() {
            *byte = ((i + 8) & 0xFF) as u8;
        }
        for (i, byte) in plaintext[512..1024].iter_mut().enumerate() {
            *byte = ((i + 512 + 0x55) & 0xFF) as u8;
        }

        // Encrypt each sector with AES-XTS
        let key1 = &key[..16];
        let key2 = &key[16..32];
        let cipher1 = Aes128::new(GenericArray::from_slice(key1));
        let cipher2 = Aes128::new(GenericArray::from_slice(key2));

        let mut encrypted = plaintext.clone();
        for s in 0..2u64 {
            let sector = &mut encrypted[(s as usize * 512)..((s as usize + 1) * 512)];
            let mut tweak = [0u8; 16];
            tweak[..8].copy_from_slice(&s.to_le_bytes());
            let mut tweak_block = GenericArray::clone_from_slice(&tweak);
            cipher2.encrypt_block(&mut tweak_block);
            tweak.copy_from_slice(&tweak_block);

            for i in 0..(512 / 16) {
                let offset = i * 16;
                let block = &mut sector[offset..offset + 16];
                for (b, t) in block.iter_mut().zip(tweak.iter()) {
                    *b ^= *t;
                }
                let mut aes_block = GenericArray::clone_from_slice(block);
                cipher1.encrypt_block(&mut aes_block);
                block.copy_from_slice(&aes_block);
                for (b, t) in block.iter_mut().zip(tweak.iter()) {
                    *b ^= *t;
                }
                super::super::aes_xts::gf128_mul_x(&mut tweak);
            }
        }

        // Build disk image: padding + encrypted partition
        let mut disk = vec![0u8; partition_offset as usize];
        disk.extend_from_slice(&encrypted);
        disk
    }

    #[test]
    fn test_bitlocker_reader_validates_ntfs() {
        let key = [0x42u8; 32]; // AES-128-XTS key
        let partition_offset = 1048576u64; // 1 MB

        let disk = make_encrypted_ntfs_volume(&key, partition_offset);
        let cursor = Cursor::new(disk);

        let mut reader = BitLockerReader::new(cursor, partition_offset, key.to_vec());
        assert!(reader.validate_ntfs_signature());
    }

    #[test]
    fn test_bitlocker_reader_rejects_wrong_key() {
        let key = [0x42u8; 32];
        let partition_offset = 1048576u64;

        let disk = make_encrypted_ntfs_volume(&key, partition_offset);
        let cursor = Cursor::new(disk);

        let wrong_key = [0x99u8; 32];
        let mut reader = BitLockerReader::new(cursor, partition_offset, wrong_key.to_vec());
        assert!(!reader.validate_ntfs_signature());
    }

    #[test]
    fn test_bitlocker_reader_read_and_seek() {
        use aes::cipher::generic_array::GenericArray;
        use aes::cipher::{BlockEncrypt, KeyInit};
        use aes::Aes128;

        let key = [0x42u8; 32];
        let partition_offset = 512u64; // Small offset for simplicity

        // Create plaintext
        let mut plaintext = vec![0u8; 1024];
        for (i, byte) in plaintext.iter_mut().enumerate() {
            *byte = (i & 0xFF) as u8;
        }
        plaintext[3..7].copy_from_slice(b"NTFS");

        // Encrypt
        let key1 = &key[..16];
        let key2 = &key[16..32];
        let cipher1 = Aes128::new(GenericArray::from_slice(key1));
        let cipher2 = Aes128::new(GenericArray::from_slice(key2));

        let mut encrypted = plaintext.clone();
        for s in 0..2u64 {
            let sector = &mut encrypted[(s as usize * 512)..((s as usize + 1) * 512)];
            let mut tweak = [0u8; 16];
            tweak[..8].copy_from_slice(&s.to_le_bytes());
            let mut tweak_block = GenericArray::clone_from_slice(&tweak);
            cipher2.encrypt_block(&mut tweak_block);
            tweak.copy_from_slice(&tweak_block);

            for i in 0..(512 / 16) {
                let off = i * 16;
                let block = &mut sector[off..off + 16];
                for (b, t) in block.iter_mut().zip(tweak.iter()) {
                    *b ^= *t;
                }
                let mut aes_block = GenericArray::clone_from_slice(block);
                cipher1.encrypt_block(&mut aes_block);
                block.copy_from_slice(&aes_block);
                for (b, t) in block.iter_mut().zip(tweak.iter()) {
                    *b ^= *t;
                }
                super::super::aes_xts::gf128_mul_x(&mut tweak);
            }
        }

        let mut disk = vec![0u8; partition_offset as usize];
        disk.extend_from_slice(&encrypted);
        let cursor = Cursor::new(disk);

        let mut reader = BitLockerReader::new(cursor, partition_offset, key.to_vec());

        // Read first 16 bytes
        let mut buf = [0u8; 16];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(&buf[3..7], b"NTFS");
        assert_eq!(&buf[..3], &plaintext[..3]);

        // Seek to sector 1 start and read
        reader.seek(SeekFrom::Start(512)).unwrap();
        let mut buf2 = [0u8; 16];
        reader.read_exact(&mut buf2).unwrap();
        assert_eq!(&buf2, &plaintext[512..528]);

        // Seek back to start
        reader.seek(SeekFrom::Start(0)).unwrap();
        let mut full = vec![0u8; 1024];
        reader.read_exact(&mut full).unwrap();
        assert_eq!(&full, &plaintext);
    }
}
