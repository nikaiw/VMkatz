//! BitLocker FVEK extraction from physical memory.
//!
//! Scans for Windows pool tags `FVEc` (Win7) and `Cngb` (Win8+) to extract
//! Full Volume Encryption Keys from VM memory snapshots.
//!
//! The extracted FVEK can be written as a dislocker-compatible `.fvek` file
//! for offline volume decryption: `dislocker-fuse -K fvek.bin -- /dev/sdX /mnt`

use crate::memory::PhysicalMemory;

/// Pool tag bytes for FVE context (Windows 7).
const FVEC_TAG: &[u8; 4] = b"FVEc";
/// Pool tag bytes for CNG buffer (Windows 8+).
const CNGB_TAG: &[u8; 4] = b"Cngb";

/// Scan chunk size: 1 MB (same as carve module — reduces I/O syscall overhead).
const SCAN_CHUNK_SIZE: usize = 256 * 4096;

/// Buffer size to read around a pool tag hit for structure extraction.
const EXTRACT_BUF_SIZE: usize = 1024;

/// An extracted BitLocker FVEK candidate.
#[derive(Debug, Clone)]
pub struct BitLockerKey {
    /// Encryption method in dislocker format (0x8000..0x8005).
    pub method: u16,
    /// Human-readable cipher name.
    pub cipher: &'static str,
    /// FVEK key material (16 or 32 bytes).
    pub fvek: Vec<u8>,
    /// Tweak key for Diffuser modes (16 or 32 bytes), empty for CBC/XTS.
    pub tweak: Vec<u8>,
    /// Physical address where the pool tag was found.
    pub phys_addr: u64,
    /// Source pool tag ("FVEc" or "Cngb").
    pub pool_tag: &'static str,
}

impl BitLockerKey {
    /// Build the dislocker-compatible FVEK file contents.
    ///
    /// Format: 2-byte LE encryption method + raw key material.
    /// For Diffuser modes, key material = FVEK + tweak key.
    pub fn to_dislocker_fvek(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.fvek.len() + self.tweak.len());
        out.extend_from_slice(&self.method.to_le_bytes());
        out.extend_from_slice(&self.fvek);
        if !self.tweak.is_empty() {
            out.extend_from_slice(&self.tweak);
        }
        out
    }

    /// Key size in bits (128 or 256).
    pub fn key_bits(&self) -> usize {
        self.fvek.len() * 8
    }
}

/// Mode byte to (dislocker_method, cipher_name, fvek_len, has_tweak) mapping.
fn decode_fvec_mode(mode: u8) -> Option<(u16, &'static str, usize, bool)> {
    match mode {
        0x00 => Some((0x8000, "AES-128-CBC + Elephant Diffuser", 16, true)),
        0x01 => Some((0x8001, "AES-256-CBC + Elephant Diffuser", 32, true)),
        0x02 => Some((0x8002, "AES-128-CBC", 16, false)),
        0x03 => Some((0x8003, "AES-256-CBC", 32, false)),
        _ => None,
    }
}

/// Mode byte to (dislocker_method, cipher_name, fvek_len) mapping for Cngb.
fn decode_cngb_mode(mode: u8) -> Option<(u16, &'static str, usize)> {
    match mode {
        0x10 => Some((0x8004, "AES-128-XTS", 16)),
        0x20 => Some((0x8005, "AES-256-XTS", 32)),
        _ => None,
    }
}

/// Check that key material has sufficient entropy to be a real AES key.
///
/// Rejects all-zero, all-same-byte, and low-diversity buffers.
fn has_sufficient_entropy(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    // All zeros
    if data.iter().all(|&b| b == 0) {
        return false;
    }
    // All same byte
    if data.iter().all(|&b| b == data[0]) {
        return false;
    }
    // Count unique byte values — a valid AES key should have high diversity
    let mut seen = [false; 256];
    for &b in data {
        seen[b as usize] = true;
    }
    let unique = seen.iter().filter(|&&s| s).count();
    // At least 25% unique bytes (a 16-byte random key has ~15 unique bytes on average)
    unique > data.len() / 4
}

/// Extract BitLocker FVEK candidates from physical memory.
///
/// Scans every physical page for `FVEc` and `Cngb` pool tags, then extracts
/// and validates the FVEK from the surrounding structure.
/// Both x64 and x86 offset variants are tried for each hit.
pub fn extract_bitlocker_keys<M: PhysicalMemory>(mem: &M) -> Vec<BitLockerKey> {
    let phys_size = mem.phys_size();
    let mut candidates = Vec::new();

    log::info!(
        "BitLocker: scanning {} MB of physical memory for FVEK pool tags",
        phys_size / (1024 * 1024)
    );

    let mut chunk_buf = vec![0u8; SCAN_CHUNK_SIZE];
    let mut chunk_addr: u64 = 0;

    while chunk_addr < phys_size {
        let read_len = SCAN_CHUNK_SIZE.min((phys_size - chunk_addr) as usize);
        if mem.read_phys(chunk_addr, &mut chunk_buf[..read_len]).is_err() {
            chunk_addr += read_len as u64;
            continue;
        }

        // Scan each byte position in the chunk for pool tags.
        // Pool tags are 4-byte aligned in practice, but we scan every byte
        // to avoid missing hits in unusual layouts.
        let chunk = &chunk_buf[..read_len];
        let mut off = 0usize;
        while off + 4 <= read_len {
            let tag = &chunk[off..off + 4];
            let abs_addr = chunk_addr + off as u64;

            if tag == FVEC_TAG {
                // Try both x64 and x86 interpretations
                for key in try_extract_fvec(mem, abs_addr) {
                    log::info!(
                        "BitLocker: FVEc hit at 0x{:x} — {} ({})",
                        abs_addr,
                        key.cipher,
                        if key.tweak.is_empty() { "no tweak" } else { "with tweak" }
                    );
                    candidates.push(key);
                }
            } else if tag == CNGB_TAG {
                for key in try_extract_cngb(mem, abs_addr) {
                    log::info!(
                        "BitLocker: Cngb hit at 0x{:x} — {}",
                        abs_addr,
                        key.cipher
                    );
                    candidates.push(key);
                }
            }

            off += 1;
        }

        chunk_addr += read_len as u64;
    }

    // Deduplicate by FVEK content (same key may appear at multiple addresses)
    candidates.sort_by(|a, b| a.fvek.cmp(&b.fvek));
    candidates.dedup_by(|a, b| a.fvek == b.fvek && a.method == b.method);

    log::info!(
        "BitLocker: scan complete — {} unique FVEK candidate(s)",
        candidates.len()
    );

    candidates
}

/// Try to extract a Win7 FVEc-based FVEK from the given pool tag address.
///
/// Returns 0-2 candidates (trying both x64 and x86 offset layouts).
fn try_extract_fvec<M: PhysicalMemory>(mem: &M, tag_addr: u64) -> Vec<BitLockerKey> {
    let mut results = Vec::new();

    // Read a generous buffer around the tag.
    // The pool header is before the tag; data fields are after.
    // We read from tag_addr - 32 to capture any pool header, plus enough
    // forward data for both offset variants.
    let base = tag_addr.saturating_sub(32);
    let buf = match mem.read_phys_bytes(base, EXTRACT_BUF_SIZE) {
        Ok(b) => b,
        Err(_) => return results,
    };

    // Offset of the tag within our buffer
    let tag_off = (tag_addr - base) as usize;

    // The pool header precedes the tag. After the pool header, the data region starts.
    // For FVEc, we assume the tag is at offset +4 in the 16-byte pool header (x64)
    // or offset +4 in the 8-byte pool header (x86).
    // data_start = tag_addr - 4 + pool_header_size
    //
    // x64 pool header: 16 bytes, tag at +4, so data_start = tag_addr - 4 + 16 = tag_addr + 12
    // x86 pool header:  8 bytes, tag at +4, so data_start = tag_addr - 4 +  8 = tag_addr + 4

    // --- x64 offsets ---
    // data_start relative to base = tag_off + 12
    let x64_data = tag_off + 12;
    if x64_data + 0x230 < buf.len() {
        let mode = buf[x64_data + 0x2C];
        if let Some((method, cipher, key_len, has_tweak)) = decode_fvec_mode(mode) {
            let fvek_off = x64_data + 0x30;
            let fvek = &buf[fvek_off..fvek_off + key_len];
            if has_sufficient_entropy(fvek) {
                let tweak = if has_tweak {
                    let tw_off = x64_data + 0x210;
                    buf[tw_off..tw_off + key_len].to_vec()
                } else {
                    Vec::new()
                };
                // For Diffuser modes, tweak key should also have entropy
                if !has_tweak || has_sufficient_entropy(&tweak) {
                    results.push(BitLockerKey {
                        method,
                        cipher,
                        fvek: fvek.to_vec(),
                        tweak,
                        phys_addr: tag_addr,
                        pool_tag: "FVEc",
                    });
                }
            }
        }
    }

    // --- x86 offsets ---
    // data_start relative to base = tag_off + 4
    let x86_data = tag_off + 4;
    if x86_data + 0x218 < buf.len() {
        let mode = buf[x86_data + 0x18];
        if let Some((method, cipher, key_len, has_tweak)) = decode_fvec_mode(mode) {
            let fvek_off = x86_data + 0x20;
            let fvek = &buf[fvek_off..fvek_off + key_len];
            if has_sufficient_entropy(fvek) {
                let tweak = if has_tweak {
                    let tw_off = x86_data + 0x1F8;
                    buf[tw_off..tw_off + key_len].to_vec()
                } else {
                    Vec::new()
                };
                if !has_tweak || has_sufficient_entropy(&tweak) {
                    results.push(BitLockerKey {
                        method,
                        cipher,
                        fvek: fvek.to_vec(),
                        tweak,
                        phys_addr: tag_addr,
                        pool_tag: "FVEc",
                    });
                }
            }
        }
    }

    results
}

/// Try to extract a Win8+ Cngb-based FVEK from the given pool tag address.
///
/// Returns 0-2 candidates (trying both x64 and x86 offset layouts).
fn try_extract_cngb<M: PhysicalMemory>(mem: &M, tag_addr: u64) -> Vec<BitLockerKey> {
    let mut results = Vec::new();

    let base = tag_addr.saturating_sub(32);
    let buf = match mem.read_phys_bytes(base, EXTRACT_BUF_SIZE) {
        Ok(b) => b,
        Err(_) => return results,
    };

    let tag_off = (tag_addr - base) as usize;

    // x64: 16-byte pool header, tag at +4, data starts at tag+12
    let x64_data = tag_off + 12;
    if x64_data + 0xC0 < buf.len() {
        let mode = buf[x64_data + 0x68];
        if let Some((method, cipher, key_len)) = decode_cngb_mode(mode) {
            let fvek1_off = x64_data + 0x6C;
            let fvek2_off = x64_data + 0x90;
            if fvek1_off + key_len <= buf.len() && fvek2_off + key_len <= buf.len() {
                let fvek1 = &buf[fvek1_off..fvek1_off + key_len];
                let fvek2 = &buf[fvek2_off..fvek2_off + key_len];
                // Validation: the two FVEK copies must match
                if fvek1 == fvek2 && has_sufficient_entropy(fvek1) {
                    results.push(BitLockerKey {
                        method,
                        cipher,
                        fvek: fvek1.to_vec(),
                        tweak: Vec::new(),
                        phys_addr: tag_addr,
                        pool_tag: "Cngb",
                    });
                }
            }
        }
    }

    // x86: 8-byte pool header, tag at +4, data starts at tag+4
    let x86_data = tag_off + 4;
    if x86_data + 0xA4 < buf.len() {
        let mode = buf[x86_data + 0x5C];
        if let Some((method, cipher, key_len)) = decode_cngb_mode(mode) {
            let fvek1_off = x86_data + 0x60;
            let fvek2_off = x86_data + 0x84;
            if fvek1_off + key_len <= buf.len() && fvek2_off + key_len <= buf.len() {
                let fvek1 = &buf[fvek1_off..fvek1_off + key_len];
                let fvek2 = &buf[fvek2_off..fvek2_off + key_len];
                if fvek1 == fvek2 && has_sufficient_entropy(fvek1) {
                    results.push(BitLockerKey {
                        method,
                        cipher,
                        fvek: fvek1.to_vec(),
                        tweak: Vec::new(),
                        phys_addr: tag_addr,
                        pool_tag: "Cngb",
                    });
                }
            }
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_check() {
        assert!(!has_sufficient_entropy(&[]));
        assert!(!has_sufficient_entropy(&[0u8; 16]));
        assert!(!has_sufficient_entropy(&[0xAA; 16]));
        // Random-ish key should pass
        let key: Vec<u8> = (0..16).collect();
        assert!(has_sufficient_entropy(&key));
    }

    #[test]
    fn test_decode_fvec_mode() {
        assert_eq!(decode_fvec_mode(0x00).unwrap().0, 0x8000);
        assert_eq!(decode_fvec_mode(0x01).unwrap().0, 0x8001);
        assert_eq!(decode_fvec_mode(0x02).unwrap().0, 0x8002);
        assert_eq!(decode_fvec_mode(0x03).unwrap().0, 0x8003);
        assert!(decode_fvec_mode(0x10).is_none());
        assert!(decode_fvec_mode(0xFF).is_none());
    }

    #[test]
    fn test_decode_cngb_mode() {
        assert_eq!(decode_cngb_mode(0x10).unwrap().0, 0x8004);
        assert_eq!(decode_cngb_mode(0x20).unwrap().0, 0x8005);
        assert!(decode_cngb_mode(0x00).is_none());
        assert!(decode_cngb_mode(0x03).is_none());
    }

    #[test]
    fn test_dislocker_format() {
        let key = BitLockerKey {
            method: 0x8004,
            cipher: "AES-128-XTS",
            fvek: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                       0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10],
            tweak: Vec::new(),
            phys_addr: 0x1000,
            pool_tag: "Cngb",
        };
        let blob = key.to_dislocker_fvek();
        assert_eq!(blob[0], 0x04); // 0x8004 LE low byte
        assert_eq!(blob[1], 0x80); // 0x8004 LE high byte
        assert_eq!(&blob[2..], &key.fvek);
        assert_eq!(blob.len(), 18); // 2 + 16
    }

    #[test]
    fn test_dislocker_format_with_tweak() {
        let key = BitLockerKey {
            method: 0x8000,
            cipher: "AES-128-CBC + Elephant Diffuser",
            fvek: vec![0xAA; 16],
            tweak: vec![0xBB; 16],
            phys_addr: 0x2000,
            pool_tag: "FVEc",
        };
        let blob = key.to_dislocker_fvek();
        assert_eq!(blob.len(), 34); // 2 + 16 + 16
        assert_eq!(&blob[2..18], &[0xAA; 16]);
        assert_eq!(&blob[18..34], &[0xBB; 16]);
    }
}
