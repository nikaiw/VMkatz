//! Parser for the decrypted Windows `CREDENTIAL` on-disk structure.

use crate::error::{Result, VmkatzError};

/// A parsed Credential Manager entry.
#[derive(Debug, Clone)]
pub struct CredmanEntry {
    pub target: String,
    pub username: String,
    pub password: String,
    pub cred_type: u32,
}

fn read_u32(bytes: &[u8], cur: &mut usize) -> Result<u32> {
    let end = cur
        .checked_add(4)
        .ok_or_else(|| VmkatzError::Parse("CREDENTIAL offset overflow".into()))?;
    let b = bytes
        .get(*cur..end)
        .ok_or_else(|| VmkatzError::Parse("CREDENTIAL truncated (u32)".into()))?;
    *cur = end;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Read `len` raw bytes, bounds-checked against the remaining slice.
fn read_bytes<'a>(bytes: &'a [u8], cur: &mut usize, len: usize) -> Result<&'a [u8]> {
    let end = cur
        .checked_add(len)
        .filter(|&e| e <= bytes.len())
        .ok_or_else(|| VmkatzError::Parse("CREDENTIAL length exceeds data".into()))?;
    let b = &bytes[*cur..end];
    *cur = end;
    Ok(b)
}

/// Read a u32 length-prefixed byte run.
fn read_lp_bytes<'a>(bytes: &'a [u8], cur: &mut usize) -> Result<&'a [u8]> {
    let len = read_u32(bytes, cur)? as usize;
    read_bytes(bytes, cur, len)
}

/// Strictly decode UTF-16LE (even length, valid surrogates).
fn decode_utf16(b: &[u8]) -> Option<String> {
    if !b.len().is_multiple_of(2) {
        return None;
    }
    let units = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]]));
    char::decode_utf16(units)
        .collect::<std::result::Result<String, _>>()
        .ok()
}

/// Read a u32 byte-length-prefixed UTF-16LE string (lossy on bad data).
fn read_lp_utf16(bytes: &[u8], cur: &mut usize) -> Result<String> {
    let raw = read_lp_bytes(bytes, cur)?;
    Ok(decode_utf16(raw).unwrap_or_else(|| {
        let units: Vec<u16> = raw
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    }))
}

/// Parse a decrypted `CREDENTIAL` blob.
///
/// Layout: flags u32, type u32, TargetName, Comment, LastWritten (8),
/// CredentialBlobSize u32 + blob, Persist u32, AttributeCount u32,
/// attributes (keyword, flags u32, value), TargetAlias, UserName.
pub fn parse_credential_blob(decrypted: &[u8]) -> Result<CredmanEntry> {
    let mut cur = 0usize;
    let _flags = read_u32(decrypted, &mut cur)?;
    let cred_type = read_u32(decrypted, &mut cur)?;
    let target = read_lp_utf16(decrypted, &mut cur)?;
    let _comment = read_lp_utf16(decrypted, &mut cur)?;
    read_bytes(decrypted, &mut cur, 8)?; // LastWritten
    let blob = read_lp_bytes(decrypted, &mut cur)?;
    let _persist = read_u32(decrypted, &mut cur)?;
    let attr_count = read_u32(decrypted, &mut cur)?;
    for _ in 0..attr_count {
        read_lp_bytes(decrypted, &mut cur)?; // keyword
        read_u32(decrypted, &mut cur)?; // flags
        read_lp_bytes(decrypted, &mut cur)?; // value
    }
    let _alias = read_lp_utf16(decrypted, &mut cur)?;
    let username = read_lp_utf16(decrypted, &mut cur)?;
    let password = decode_utf16(blob).unwrap_or_else(|| hex::encode(blob));
    Ok(CredmanEntry {
        target,
        username,
        password,
        cred_type,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lp(out: &mut Vec<u8>, s: &str) {
        let units: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
        out.extend_from_slice(&(units.len() as u32).to_le_bytes());
        out.extend_from_slice(&units);
    }

    fn build_fixture_raw_blob(target: &str, blob: &[u8], user: &str) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&0u32.to_le_bytes()); // flags
        v.extend_from_slice(&1u32.to_le_bytes()); // type
        lp(&mut v, target);
        lp(&mut v, ""); // comment
        v.extend_from_slice(&0u64.to_le_bytes()); // LastWritten
        v.extend_from_slice(&(blob.len() as u32).to_le_bytes());
        v.extend_from_slice(blob);
        v.extend_from_slice(&2u32.to_le_bytes()); // persist
        v.extend_from_slice(&0u32.to_le_bytes()); // attribute count
        lp(&mut v, ""); // target alias
        lp(&mut v, user);
        v
    }

    fn build_fixture(target: &str, pass: &str, user: &str) -> Vec<u8> {
        let blob: Vec<u8> = pass.encode_utf16().flat_map(u16::to_le_bytes).collect();
        build_fixture_raw_blob(target, &blob, user)
    }

    #[test]
    fn parses_target_user_password() {
        let bytes = build_fixture("TERMSRV/dc01", "P@ss", "LAB\\jdoe");
        let e = parse_credential_blob(&bytes).unwrap();
        assert_eq!(e.target, "TERMSRV/dc01");
        assert_eq!(e.username, "LAB\\jdoe");
        assert_eq!(e.password, "P@ss");
        assert_eq!(e.cred_type, 1);
    }

    #[test]
    fn empty_password_blob_ok() {
        let e = parse_credential_blob(&build_fixture("x", "", "u")).unwrap();
        assert_eq!(e.password, "");
    }

    #[test]
    fn truncated_blob_errors_no_panic() {
        assert!(parse_credential_blob(&[0u8; 6]).is_err());
        let full = build_fixture("TERMSRV/dc01", "P@ss", "LAB\\jdoe");
        for n in 0..full.len() {
            assert!(parse_credential_blob(&full[..n]).is_err());
        }
    }

    #[test]
    fn huge_length_prefix_errors() {
        let mut b = vec![0u8; 8];
        b.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_credential_blob(&b).is_err());
    }

    #[test]
    fn non_utf16_password_hex_fallback() {
        let e =
            parse_credential_blob(&build_fixture_raw_blob("x", &[0x01, 0x02, 0x03], "u")).unwrap();
        assert_eq!(e.password, "010203");
    }
}
