use crate::error::{Result, VmkatzError as Error};
use std::collections::HashMap;

/// Frame header descriptor (kept for documentation / potential future use).
/// A frame is a commit frame iff `db_size_after_commit != 0` (SQLite §3.0).
#[derive(Debug)]
pub struct WalFrame {
    pub page_no: u32,
    pub db_size_after_commit: u32,
}

/// Parse a SQLite WAL file. Returns the latest committed page contents keyed
/// by page number. Frames after the last commit-frame in the file are
/// uncommitted and discarded.
///
/// Format reference: <https://www.sqlite.org/walformat.html>.
///
/// The function is panic-free on hostile input: every fixed-width slice read
/// is preceded by an explicit bounds check.
pub fn parse_wal(bytes: &[u8], page_size: usize) -> Result<HashMap<u32, Vec<u8>>> {
    // No WAL or stub WAL — treat as empty overlay.
    if bytes.len() < 32 {
        return Ok(HashMap::new());
    }
    // Defensive: parse_wal is called with page_size pulled from the DB header,
    // but a malformed header could yield 0. Frame size would then collapse to
    // 24 and the loop would happily iterate forever over an attacker-supplied
    // file. Reject up front.
    if page_size == 0 {
        return Err(Error::Parse("zero page_size for WAL parse".into()));
    }
    // Cap page_size to a sane maximum so frame_size arithmetic can't overflow
    // usize on 32-bit targets. 65536 is SQLite's documented maximum.
    if page_size > 65_536 {
        return Err(Error::Parse(format!(
            "implausible page_size {} for WAL parse",
            page_size
        )));
    }

    let magic = u32::from_be_bytes(bytes[..4].try_into().unwrap());
    // 0x377F0682 = legacy/native-byte-order checksums, 0x377F0683 = big-endian
    // checksums. Both are valid WAL headers and the frame layout is identical.
    if magic != 0x377F_0682 && magic != 0x377F_0683 {
        return Err(Error::Parse("bad WAL magic".into()));
    }

    let frame_size = 24usize
        .checked_add(page_size)
        .ok_or_else(|| Error::Parse("WAL frame size overflow".into()))?;

    let mut cursor = 32usize;
    let mut pending: Vec<(u32, Vec<u8>)> = Vec::new();
    let mut latest: HashMap<u32, Vec<u8>> = HashMap::new();

    while cursor.checked_add(frame_size).map(|e| e <= bytes.len()).unwrap_or(false) {
        let h = &bytes[cursor..cursor + 24];
        let page_no = u32::from_be_bytes(h[..4].try_into().unwrap());
        let db_size = u32::from_be_bytes(h[4..8].try_into().unwrap());
        // page_no == 0 is reserved (used by some SQLite versions as a sentinel
        // for frames that have been overwritten). Discard rather than panic.
        if page_no != 0 {
            let data = bytes[cursor + 24..cursor + frame_size].to_vec();
            pending.push((page_no, data));
        }
        if db_size != 0 {
            // Commit point: flush pending writes into the latest-overlay map.
            for (p, d) in pending.drain(..) {
                latest.insert(p, d);
            }
        }
        cursor += frame_size;
    }
    // Any frames left in `pending` came after the final commit frame and are
    // therefore uncommitted; per the WAL spec they MUST be ignored on replay.
    Ok(latest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_returns_empty_map() {
        let map = parse_wal(&[], 4096).unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn rejects_bad_magic() {
        let mut buf = vec![0u8; 32];
        buf[..4].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        assert!(parse_wal(&buf, 4096).is_err());
    }

    #[test]
    fn rejects_zero_page_size() {
        let mut buf = vec![0u8; 32];
        buf[..4].copy_from_slice(&0x377F_0682u32.to_be_bytes());
        assert!(parse_wal(&buf, 0).is_err());
    }

    #[test]
    fn rejects_oversize_page_size() {
        let mut buf = vec![0u8; 32];
        buf[..4].copy_from_slice(&0x377F_0682u32.to_be_bytes());
        assert!(parse_wal(&buf, 1 << 20).is_err());
    }

    #[test]
    fn discards_uncommitted_trailing_frame() {
        // Header + one non-commit frame (db_size_after_commit = 0).
        let page_size = 64usize;
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x377F_0682u32.to_be_bytes()); // magic
        buf.extend_from_slice(&[0u8; 28]); // rest of header (unused fields)
        // Frame header: page_no=7, db_size=0 (no commit), then 16 bytes of
        // checksum/salt that we don't validate.
        buf.extend_from_slice(&7u32.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&[0u8; 16]);
        buf.extend_from_slice(&vec![0xAA; page_size]);
        let map = parse_wal(&buf, page_size).unwrap();
        // Trailing non-commit frame must NOT appear in the overlay.
        assert!(map.is_empty(), "uncommitted frame leaked into overlay");
    }
}
