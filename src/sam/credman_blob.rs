//! Parser for the decrypted Windows `CREDENTIAL` on-disk structure.

use crate::error::{Result, VmkatzError};

/// A parsed Credential Manager entry.
#[derive(Debug, Clone)]
pub struct CredmanEntry {
    pub target: String,
    pub username: String,
    pub password: String,
    pub cred_type: u32,
    pub attributes: Vec<CredAttribute>,
}

/// A `CREDENTIAL_ATTRIBUTE` (keyword + raw value; may be a nested DPAPI blob).
#[derive(Debug, Clone)]
pub struct CredAttribute {
    pub keyword: String,
    pub value: Vec<u8>,
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

/// True when every char is plausible text (no control / private-use / presentation-form / specials).
fn looks_printable(s: &str) -> bool {
    s.chars().all(|c| {
        !c.is_control()
            && !matches!(c, '\u{E000}'..='\u{F8FF}' | '\u{FB50}'..='\u{FDFF}' | '\u{FE70}'..='\u{FEFF}' | '\u{FFF0}'..='\u{FFFF}')
    })
}

/// Decode a CredentialBlob password. Windows stores UTF-16LE, but some helpers
/// (git-credential-manager, docker-credential-wincred) store raw UTF-8.
/// Order: UTF-16LE if every odd byte is 0x00 (ASCII/Latin-1 range); else strict
/// UTF-8 if printable; else UTF-16LE with other printable text (non-Latin scripts);
/// else lowercase hex. Trailing NULs are trimmed from text results.
fn decode_password(blob: &[u8]) -> String {
    if blob.is_empty() {
        return String::new();
    }
    let utf16 = decode_utf16(blob).map(|s| s.trim_end_matches('\0').to_owned());
    let ascii_range = blob.len().is_multiple_of(2) && blob.chunks_exact(2).all(|c| c[1] == 0);
    if ascii_range {
        if let Some(s) = utf16.as_deref().filter(|s| looks_printable(s)) {
            return s.to_owned();
        }
    }
    if let Ok(s) = std::str::from_utf8(blob) {
        let s = s.trim_end_matches('\0');
        if looks_printable(s) {
            return s.to_owned();
        }
    }
    if let Some(s) = utf16.filter(|s| looks_printable(s)) {
        return s;
    }
    hex::encode(blob)
}

/// Read a u32 byte-length-prefixed UTF-16LE string (lossy on bad data).
fn read_lp_utf16(bytes: &[u8], cur: &mut usize) -> Result<String> {
    let raw = read_lp_bytes(bytes, cur)?;
    let s = decode_utf16(raw).unwrap_or_else(|| {
        let units: Vec<u16> = raw
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    });
    Ok(s.trim_end_matches('\0').to_owned())
}

/// Parse a decrypted DPAPI `CREDENTIAL_BLOB` (impacket layout).
///
/// Layout: Version, Size, Unknown0, Type, Flags (u32 each), LastWritten u64,
/// Unknown1, Persist, AttributeCount, Unknown2, Unknown3 (u32 each), then
/// SIZED_WSTRs Target, TargetAlias, Comment, Unknown4, UserName, then
/// CredentialBlobSize u32 + CredentialBlob. Trailing attributes are parsed best-effort.
pub fn parse_credential_blob(decrypted: &[u8]) -> Result<CredmanEntry> {
    let mut cur = 0usize;
    let _version = read_u32(decrypted, &mut cur)?;
    let _size = read_u32(decrypted, &mut cur)?;
    let _unknown0 = read_u32(decrypted, &mut cur)?;
    let cred_type = read_u32(decrypted, &mut cur)?;
    let _flags = read_u32(decrypted, &mut cur)?;
    read_bytes(decrypted, &mut cur, 8)?; // LastWritten
    read_u32(decrypted, &mut cur)?; // Unknown1
    read_u32(decrypted, &mut cur)?; // Persist
    let attr_count = read_u32(decrypted, &mut cur)? as usize;
    read_u32(decrypted, &mut cur)?; // Unknown2
    read_u32(decrypted, &mut cur)?; // Unknown3
    let target = read_lp_utf16(decrypted, &mut cur)?;
    let _alias = read_lp_utf16(decrypted, &mut cur)?;
    let _comment = read_lp_utf16(decrypted, &mut cur)?;
    let _unknown4 = read_lp_utf16(decrypted, &mut cur)?;
    let username = read_lp_utf16(decrypted, &mut cur)?;
    let blob = read_lp_bytes(decrypted, &mut cur)?;
    let password = decode_password(blob);
    let attributes = parse_attributes(decrypted, &mut cur, attr_count);
    Ok(CredmanEntry {
        target,
        username,
        password,
        cred_type,
        attributes,
    })
}

/// Best-effort attribute parse: stops at the first malformed/truncated attribute,
/// bounded by `count` and the remaining data.
///
/// Per attribute: Flags u32, Keyword SIZED_WSTR, ValueSize u32, Value[ValueSize].
fn parse_attributes(bytes: &[u8], cur: &mut usize, count: usize) -> Vec<CredAttribute> {
    let mut out = Vec::new();
    for _ in 0..count {
        if read_u32(bytes, cur).is_err() {
            break; // Flags
        }
        let Ok(keyword) = read_lp_utf16(bytes, cur) else {
            break;
        };
        let Ok(value) = read_lp_bytes(bytes, cur) else {
            break;
        };
        out.push(CredAttribute {
            keyword,
            value: value.to_vec(),
        });
    }
    out
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
        build_fixture_attrs(target, blob, user, &[], 0)
    }

    /// `declared` is the AttributeCount header value (may differ from `attrs.len()`).
    fn build_fixture_attrs(
        target: &str,
        blob: &[u8],
        user: &str,
        attrs: &[(&str, &[u8])],
        declared: u32,
    ) -> Vec<u8> {
        let mut v = Vec::new();
        for x in [1u32, 0x100, 0, 1, 0] {
            v.extend_from_slice(&x.to_le_bytes()); // Version, Size, Unk0, Type, Flags
        }
        v.extend_from_slice(&0u64.to_le_bytes()); // LastWritten
        for x in [0u32, 2, declared, 0, 0] {
            v.extend_from_slice(&x.to_le_bytes()); // Unk1, Persist, AttrCount, Unk2, Unk3
        }
        lp(&mut v, target);
        lp(&mut v, ""); // alias
        lp(&mut v, ""); // comment
        lp(&mut v, ""); // unknown4
        lp(&mut v, user);
        v.extend_from_slice(&(blob.len() as u32).to_le_bytes());
        v.extend_from_slice(blob);
        for (kw, val) in attrs {
            v.extend_from_slice(&0u32.to_le_bytes()); // Flags
            lp(&mut v, kw);
            v.extend_from_slice(&(val.len() as u32).to_le_bytes()); // ValueSize
            v.extend_from_slice(val);
        }
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
    fn wide_string_trailing_nul_trimmed() {
        let bytes = build_fixture("TERMSRV/dc01\0", "P@ss", "LAB\\jdoe\0");
        let e = parse_credential_blob(&bytes).unwrap();
        assert_eq!(e.target, "TERMSRV/dc01");
        assert_eq!(e.username, "LAB\\jdoe");
        assert_eq!(e.password, "P@ss");
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
        let mut b = vec![0u8; 48];
        b.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_credential_blob(&b).is_err());
    }

    #[test]
    fn non_utf16_password_hex_fallback() {
        let e =
            parse_credential_blob(&build_fixture_raw_blob("x", &[0x01, 0x02, 0x03], "u")).unwrap();
        assert_eq!(e.password, "010203");
    }

    fn pw(blob: &[u8]) -> String {
        parse_credential_blob(&build_fixture_raw_blob("x", blob, "u"))
            .unwrap()
            .password
    }

    #[test]
    fn utf8_password_decoded_as_utf8() {
        assert_eq!(pw(b"abcd"), "abcd");
        assert_eq!(pw(b"ab"), "ab");
        assert_eq!(pw(b"abc"), "abc");
        assert_eq!(pw(b"abcd\0"), "abcd");
    }

    #[test]
    fn utf16_password_still_decoded() {
        assert_eq!(pw(&[0x50, 0, 0x40, 0, 0x73, 0, 0x73, 0]), "P@ss");
        // non-Latin UTF-16 (Cyrillic "Пароль")
        let cy: Vec<u8> = "Пароль".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(pw(&cy), "Пароль");
    }

    #[test]
    fn password_trailing_nul_trimmed() {
        let b: Vec<u8> = "P@ss\0\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(pw(&b), "P@ss");
    }

    #[test]
    fn binary_password_hex() {
        assert_eq!(pw(&[1, 2, 3]), "010203");
        assert_eq!(pw(&[1, 0, 2, 0]), "01000200");
        assert_eq!(pw(&[0xff, 0xfe, 0xfd, 0xfc]), "fffefdfc");
    }

    fn dpapi(tag: u8, data_len: usize) -> Vec<u8> {
        vec![tag; data_len]
    }

    fn attrs_fixture() -> (Vec<u8>, [Vec<u8>; 2]) {
        let vals = [dpapi(0xAA, 300), dpapi(0xBB, 20)];
        let b = build_fixture_attrs(
            "t",
            b"p\0",
            "u",
            &[
                ("Microsoft_WindowsLive:authstate:a", &vals[0]),
                ("kw2", &vals[1]),
            ],
            2,
        );
        (b, vals)
    }

    #[test]
    fn parses_two_attributes() {
        let (b, vals) = attrs_fixture();
        let e = parse_credential_blob(&b).unwrap();
        assert_eq!(e.attributes.len(), 2);
        assert_eq!(e.attributes[0].keyword, "Microsoft_WindowsLive:authstate:a");
        assert_eq!(e.attributes[1].keyword, "kw2");
        for (a, v) in e.attributes.iter().zip(&vals) {
            assert_eq!(&a.value, v);
        }
    }

    #[test]
    fn attributes_truncated_best_effort() {
        let (full, _) = attrs_fixture();
        let base = build_fixture_attrs("t", b"p\0", "u", &[], 0).len();
        for n in base..full.len() {
            let e = parse_credential_blob(&full[..n]).unwrap();
            assert_eq!(e.target, "t");
            assert_eq!(e.username, "u");
            assert!(e.attributes.len() < 2);
        }
        // Huge declared count: bounded by data.
        let mut b = full.clone();
        b[36..40].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(parse_credential_blob(&b).unwrap().attributes.len(), 2);
    }
}
