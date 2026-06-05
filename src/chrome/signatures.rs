//! Per-Chromium-major-version memory patterns.
//!
//! Patterns identify well-known structures (CookieMonster, PasswordStore) in chrome.dll
//! using stable byte sequences from chrome.dll's .rdata + .text sections.
//!
//! Adding support for a new version:
//! 1. Open chrome.dll vN in IDA, locate the target symbol
//! 2. Capture a 16-32 byte stable pattern referencing it
//! 3. Add a `Signature` entry for the major version below

#[derive(Debug, Clone, Copy)]
pub enum Target {
    CookieMonster,
    PasswordStore,
}

#[derive(Debug, Clone)]
pub struct Signature {
    pub target: Target,
    pub major_version: u32,  // 0 = generic / fallback
    /// Byte pattern; `None` is a wildcard byte.
    pub pattern: &'static [Option<u8>],
    /// Offset from match start to the field of interest.
    pub field_offset: i32,
}

pub fn signatures() -> &'static [Signature] {
    // Initial set: empty + heuristic fallback (Task 14). Real per-version signatures land
    // in follow-up PRs as Chrome versions are reverse-engineered.
    static SIGS: &[Signature] = &[];
    SIGS
}

/// Match `pattern` against `haystack`. Returns offsets of every match.
pub fn scan(haystack: &[u8], pattern: &[Option<u8>]) -> Vec<usize> {
    if pattern.is_empty() || haystack.len() < pattern.len() {
        return Vec::new();
    }
    let mut hits = Vec::new();
    'outer: for i in 0..=haystack.len() - pattern.len() {
        for (j, p) in pattern.iter().enumerate() {
            if let Some(b) = p {
                if haystack[i + j] != *b { continue 'outer; }
            }
        }
        hits.push(i);
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_finds_pattern_with_wildcard() {
        let h = b"AAACDDFFEE";
        let pat = [Some(b'A'), None, Some(b'C')];
        assert_eq!(scan(h, &pat), vec![1]);
    }

    #[test]
    fn scan_no_match() {
        assert!(scan(b"hello", &[Some(b'z')]).is_empty());
    }
}
