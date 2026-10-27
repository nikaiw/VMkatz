//! Windows Vault `Policy.vpol` parsing and vault AES key extraction.

use crate::error::{Result, VmkatzError};

/// The two AES keys held in a decrypted `Policy.vpol`.
#[derive(Debug, Clone)]
pub struct VaultKeys {
    pub aes128: Vec<u8>,
    pub aes256: Vec<u8>,
}

fn err(msg: &str) -> VmkatzError {
    VmkatzError::Parse(msg.to_string())
}

fn take<'a>(bytes: &'a [u8], cur: &mut usize, n: usize) -> Result<&'a [u8]> {
    let end = cur.checked_add(n).ok_or_else(|| err("vault offset overflow"))?;
    let s = bytes.get(*cur..end).ok_or_else(|| err("vault data truncated"))?;
    *cur = end;
    Ok(s)
}

fn read_u32(bytes: &[u8], cur: &mut usize) -> Result<u32> {
    let s = take(bytes, cur, 4)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Parse the `Policy.vpol` header and return the inner DPAPI blob slice.
///
/// Layout: version u32, vault GUID (16), description (u32 byte length + UTF-16LE),
/// three unknown u32, StoreSize u32, two key GUIDs (16 each), BlobSize u32, blob.
pub fn parse_vpol(file: &[u8]) -> Result<&[u8]> {
    let mut cur = 0usize;
    let _version = read_u32(file, &mut cur)?;
    take(file, &mut cur, 16)?;
    let desc_len = read_u32(file, &mut cur)? as usize;
    take(file, &mut cur, desc_len)?;
    for _ in 0..3 {
        read_u32(file, &mut cur)?;
    }
    let store_size = read_u32(file, &mut cur)? as usize;
    let store_start = cur;
    take(file, &mut cur, 32)?;
    let blob_size = read_u32(file, &mut cur)? as usize;
    let store_end = store_start
        .checked_add(store_size)
        .ok_or_else(|| err("vpol store size overflow"))?;
    if store_size < 36 || store_end > file.len() {
        return Err(err("vpol store size out of range"));
    }
    let blob = take(file, &mut cur, blob_size)?;
    if cur > store_end {
        return Err(err("vpol blob exceeds key store"));
    }
    Ok(blob)
}

const KDBM: [u8; 4] = *b"KDBM";

/// Read one VAULT_KEY: header (version, GUID, size) then a BCRYPT_KEY_DATA_BLOB
/// (`KDBM` magic, version u32, key length u32, key bytes). The header is located
/// by scanning for the magic so minor header variations are tolerated.
fn read_key(buf: &[u8], cur: &mut usize) -> Result<Vec<u8>> {
    let rest = buf.get(*cur..).ok_or_else(|| err("vault key offset"))?;
    let pos = rest
        .windows(4)
        .position(|w| w == KDBM)
        .ok_or_else(|| err("vault key magic not found"))?;
    *cur += pos + 4;
    let _ver = read_u32(buf, cur)?;
    let len = read_u32(buf, cur)? as usize;
    if len != 16 && len != 24 && len != 32 {
        return Err(err("unexpected vault key length"));
    }
    Ok(take(buf, cur, len)?.to_vec())
}

/// Extract the two AES keys from a decrypted VAULT_POL_STORE.
pub fn parse_vault_keys(decrypted_vpol: &[u8]) -> Result<VaultKeys> {
    let mut cur = 0usize;
    let aes128 = read_key(decrypted_vpol, &mut cur)?;
    let aes256 = read_key(decrypted_vpol, &mut cur)?;
    Ok(VaultKeys { aes128, aes256 })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(blob: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&1u32.to_le_bytes());
        v.extend_from_slice(&[0xAA; 16]);
        let desc: Vec<u8> = "Web Credentials\0".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        v.extend_from_slice(&(desc.len() as u32).to_le_bytes());
        v.extend_from_slice(&desc);
        for x in [1u32, 0, 1] {
            v.extend_from_slice(&x.to_le_bytes());
        }
        v.extend_from_slice(&((32 + 4 + blob.len()) as u32).to_le_bytes());
        v.extend_from_slice(&[0xBB; 32]);
        v.extend_from_slice(&(blob.len() as u32).to_le_bytes());
        v.extend_from_slice(blob);
        v
    }

    fn key_entry(len: usize) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&1u32.to_le_bytes());
        v.extend_from_slice(&[0xCC; 16]);
        v.extend_from_slice(&((12 + len) as u32).to_le_bytes());
        v.extend_from_slice(&KDBM);
        v.extend_from_slice(&1u32.to_le_bytes());
        v.extend_from_slice(&(len as u32).to_le_bytes());
        v.extend(std::iter::repeat_n(0x42u8, len));
        v
    }

    #[test]
    fn parse_vpol_returns_inner_blob() {
        let blob = [1u8, 0, 0, 0, 0xd0, 0x8c, 0x9d, 0xdf, 9, 8, 7];
        let f = fixture(&blob);
        assert_eq!(parse_vpol(&f).unwrap(), &blob);
    }

    #[test]
    fn parse_vpol_bounds() {
        let f = fixture(&[1, 2, 3, 4, 5, 6, 7, 8]);
        for n in 0..f.len() {
            assert!(parse_vpol(&f[..n]).is_err(), "len {n}");
        }
        assert!(parse_vpol(&[0xFF; 100]).is_err());
    }

    #[test]
    fn parse_vault_keys_two_keys() {
        let mut d = key_entry(16);
        d.extend(key_entry(32));
        let k = parse_vault_keys(&d).unwrap();
        assert_eq!(k.aes128.len(), 16);
        assert_eq!(k.aes256.len(), 32);
    }

    #[test]
    fn parse_vault_keys_bounds() {
        let mut d = key_entry(16);
        d.extend(key_entry(32));
        for n in 0..d.len() {
            assert!(parse_vault_keys(&d[..n]).is_err(), "len {n}");
        }
        assert!(parse_vault_keys(&[0xFF; 64]).is_err());
    }
}
