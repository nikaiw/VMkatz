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

/// One entry of the Chrome elevation-service key table (56 bytes on disk):
/// `version(+0)`, `flag(+8)`, `algo(+0xC)`, `key(+0x10, 32 bytes)`.
///
/// `flag`: 1 = the 32-byte `key` is used DIRECTLY as the AEAD key; 0 = the `key`
/// is only an XOR mask and the real AEAD key is derived from a machine NCrypt key
/// (Chrome ≥ ~140 "v3" path — see `abe::decrypt_aes_encrypted_key`).
/// `algo`: 2 = AES-256-GCM, 4 = ChaCha20-Poly1305.
#[derive(Debug, Clone, Copy)]
pub struct AbeKey {
    pub version: u8,
    pub flag: u8,
    pub algo: u8,
    pub key: [u8; 32],
}

/// Maps an ABE version byte to its key-table entry.
#[derive(Debug, Clone, Default)]
pub struct BrowserKeyMap {
    /// Key-table entries, keyed by version byte.
    pub entries: Vec<AbeKey>,
    /// True when these are the hardcoded fallback (not from the user's binary).
    pub fallback: bool,
    /// Raw bytes of candidate machine CNG "Software KSP" key files (from
    /// `%ProgramData%\Microsoft\Crypto\SystemKeys` / `Keys`) that hold the NCrypt
    /// AES key used to unwrap the flag=0 (v3) app-bound key. Populated at discovery
    /// time; resolved to the AES key by [`crate::chrome::cng_ksp`] when a v3 blob is hit.
    pub cng_ksp_files: Vec<Vec<u8>>,
}

impl BrowserKeyMap {
    /// Look up the AES key bytes for an ABE version byte.
    pub fn resolve(&self, version: u8) -> Option<[u8; 32]> {
        self.entries
            .iter()
            .find(|e| e.version == version)
            .map(|e| e.key)
    }

    /// Look up the full key-table entry for an ABE version byte.
    pub fn resolve_entry(&self, version: u8) -> Option<AbeKey> {
        self.entries.iter().find(|e| e.version == version).copied()
    }

    /// Returns true if no entries were found.
    pub const fn is_empty(&self) -> bool {
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
                    cng_ksp_files: Vec::new(),
                };
            }
        }
        Self::fallback()
    }

    /// Hardcoded Chrome 135.0.7049.115 keys. flag/algo mirror the real table:
    /// v1 = AES-GCM/direct, v2 = ChaCha20/direct, v3 = AES-GCM/NCrypt-derived.
    pub fn fallback() -> Self {
        Self {
            entries: vec![
                AbeKey {
                    version: 1,
                    flag: 1,
                    algo: 2,
                    key: CHROME_135_V1,
                },
                AbeKey {
                    version: 2,
                    flag: 1,
                    algo: 4,
                    key: CHROME_135_V2,
                },
                AbeKey {
                    version: 3,
                    flag: 0,
                    algo: 2,
                    key: CHROME_135_V3,
                },
            ],
            fallback: true,
            cng_ksp_files: Vec::new(),
        }
    }

    /// Merge another map's entries in. Existing version slots are kept; the merged
    /// map's entries with the same version are dropped (first wins). CNG KSP files
    /// are unioned. Returns `true` if at least one key entry was added.
    pub fn merge(&mut self, other: Self) -> bool {
        let mut added = false;
        for e in other.entries {
            if !self.entries.iter().any(|ev| ev.version == e.version) {
                self.entries.push(e);
                added = true;
            }
        }
        self.cng_ksp_files.extend(other.cng_ksp_files);
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

/// Returns the key-table entries for each plausible 3-entry table in `rdata`.
fn scan_for_key_table(rdata: &[u8]) -> Vec<AbeKey> {
    let mut hits: Vec<AbeKey> = Vec::new();
    if rdata.len() < STRIDE * 3 {
        return hits;
    }
    let mut i = 0;
    while i + STRIDE * 3 <= rdata.len() {
        if let Some(entries) = try_table_at(&rdata[i..]) {
            for e in entries {
                if !hits.iter().any(|h| h.version == e.version) {
                    hits.push(e);
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
/// `+0x8` = flag (1 = static key direct, 0 = NCrypt-derived), `+0xC` = algo
/// (2 = AES-256-GCM, 4 = ChaCha20-Poly1305).
fn try_table_at(buf: &[u8]) -> Option<Vec<AbeKey>> {
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
        // flag (+8) and algo (+0xC): both are small enums (flag 0/1, algo 2/4).
        let flag = u32::from_le_bytes(e[8..12].try_into().unwrap());
        let algo = u32::from_le_bytes(e[12..16].try_into().unwrap());
        if flag > 32 || algo > 32 {
            return None;
        }
        // Entropy gate on the 32 key bytes: distinct byte values >= 20.
        let key: [u8; 32] = e[16..48].try_into().unwrap();
        if distinct_bytes(&key) < 20 {
            return None;
        }
        // Trail bytes (e[48..56]) can be zero or a sentinel/pointer; don't gate on them.
        out.push(AbeKey {
            version: v,
            flag: flag as u8,
            algo: algo as u8,
            key,
        });
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
    fn make_entry(version: u8, m1: u32, m2: u32, key: &[u8; 32], trail: [u8; 8]) -> Vec<u8> {
        let mut e = Vec::with_capacity(56);
        e.push(version);
        e.extend_from_slice(&[0u8; 7]);
        e.extend_from_slice(&m1.to_le_bytes());
        e.extend_from_slice(&m2.to_le_bytes());
        e.extend_from_slice(key);
        e.extend_from_slice(&trail);
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
        t.extend(make_entry(1, 1, 1, &CHROME_135_V1, [0u8; 8]));
        t.extend(make_entry(2, 1, 3, &CHROME_135_V2, [0u8; 8]));
        // Real Chrome 135 has a pointer in the v=3 trail; emulate that.
        t.extend(make_entry(
            3,
            0,
            1,
            &CHROME_135_V3,
            [0x30, 0xc0, 0x1e, 0x40, 0x01, 0x00, 0x00, 0x00],
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
        // v1 = AES-GCM/direct, v2 = ChaCha/direct, v3 = AES-GCM/NCrypt-derived.
        assert_eq!(map.resolve_entry(1).map(|e| (e.flag, e.algo)), Some((1, 2)));
        assert_eq!(map.resolve_entry(2).map(|e| (e.flag, e.algo)), Some((1, 4)));
        assert_eq!(map.resolve_entry(3).map(|e| (e.flag, e.algo)), Some((0, 2)));
    }

    #[test]
    fn merge_first_wins() {
        let mk = |v: u8, k: u8| AbeKey {
            version: v,
            flag: 1,
            algo: 2,
            key: [k; 32],
        };
        let mut a = BrowserKeyMap {
            entries: vec![mk(1, 0x11)],
            fallback: false,
            cng_ksp_files: Vec::new(),
        };
        let b = BrowserKeyMap {
            entries: vec![mk(1, 0x22), mk(2, 0x33)],
            fallback: false,
            cng_ksp_files: Vec::new(),
        };
        let added = a.merge(b);
        assert!(added);
        assert_eq!(a.resolve(1), Some([0x11u8; 32]));
        assert_eq!(a.resolve(2), Some([0x33u8; 32]));
    }
}
