/// RFC 4648 standard base64 decode. Returns None on invalid input.
pub fn b64_decode(input: &str) -> Option<Vec<u8>> {
    const TBL: [i8; 256] = {
        let mut t = [-1i8; 256];
        let mut i = 0u8;
        while i < 26 { t[(b'A' + i) as usize] = i as i8; i += 1; }
        let mut i = 0u8;
        while i < 26 { t[(b'a' + i) as usize] = (26 + i) as i8; i += 1; }
        let mut i = 0u8;
        while i < 10 { t[(b'0' + i) as usize] = (52 + i) as i8; i += 1; }
        t[b'+' as usize] = 62;
        t[b'/' as usize] = 63;
        t
    };
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &b in bytes {
        if b == b'=' || b == b'\n' || b == b'\r' || b == b' ' {
            if b == b'=' { break; }
            continue;
        }
        let v = TBL[b as usize];
        if v < 0 { return None; }
        buf = (buf << 6) | (v as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Chrome time epoch (1601-01-01) to Unix epoch (1970-01-01), in seconds.
/// Returns None for the sentinel value 0 (no expiry).
pub fn chrome_time_to_unix(chrome_us: i64) -> Option<i64> {
    if chrome_us == 0 { return None; }
    // Chrome stores microseconds since 1601-01-01 UTC.
    const EPOCH_DELTA_SECS: i64 = 11_644_473_600;
    Some(chrome_us / 1_000_000 - EPOCH_DELTA_SECS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_basic() {
        assert_eq!(b64_decode("aGVsbG8="), Some(b"hello".to_vec()));
        assert_eq!(b64_decode("aGVsbG8"), Some(b"hello".to_vec())); // no padding
        assert_eq!(b64_decode("YWJjZGVm"), Some(b"abcdef".to_vec()));
    }

    #[test]
    fn b64_invalid() {
        assert_eq!(b64_decode("!!!!"), None);
    }

    #[test]
    fn chrome_epoch() {
        // 13_000_000_000_000_000 microseconds = ~2012-something
        let unix = chrome_time_to_unix(13_000_000_000_000_000).unwrap();
        assert!(unix > 1_300_000_000 && unix < 1_400_000_000);
    }

    #[test]
    fn chrome_epoch_zero_is_none() {
        assert_eq!(chrome_time_to_unix(0), None);
    }
}
