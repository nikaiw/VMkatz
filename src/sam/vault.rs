//! Windows Vault `Policy.vpol` parsing and vault AES key extraction.

use aes::{Aes128, Aes256};
use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};

use crate::error::{Result, VmkatzError};

/// The two AES keys held in a decrypted `Policy.vpol`.
#[derive(Debug, Clone)]
pub struct VaultKeys {
    pub aes128: Vec<u8>,
    pub aes256: Vec<u8>,
}

impl VaultKeys {
    /// Number of keys actually held (non-empty).
    pub fn count(&self) -> usize {
        usize::from(!self.aes128.is_empty()) + usize::from(!self.aes256.is_empty())
    }
}

fn err(msg: &str) -> VmkatzError {
    VmkatzError::Parse(msg.to_string())
}

fn take<'a>(bytes: &'a [u8], cur: &mut usize, n: usize) -> Result<&'a [u8]> {
    let end = cur
        .checked_add(n)
        .ok_or_else(|| err("vault offset overflow"))?;
    let s = bytes
        .get(*cur..end)
        .ok_or_else(|| err("vault data truncated"))?;
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
    // `aes_cbc` only accepts AES-128/256; reject anything else here.
    if len != 16 && len != 32 {
        return Err(err("unexpected vault key length"));
    }
    Ok(take(buf, cur, len)?.to_vec())
}

/// Extract the two AES keys from a decrypted VAULT_POL_STORE.
pub fn parse_vault_keys(decrypted_vpol: &[u8]) -> Result<VaultKeys> {
    let mut cur = 0usize;
    let first = read_key(decrypted_vpol, &mut cur)?;
    let second = read_key(decrypted_vpol, &mut cur)?;
    // Label by actual key length rather than position, so a store that emits
    // them the other way round still yields a usable pair. Real vaults seen so
    // far are (16, 32), for which this is identical to positional.
    if first.len() == 32 && second.len() == 16 {
        Ok(VaultKeys {
            aes128: second,
            aes256: first,
        })
    } else {
        Ok(VaultKeys {
            aes128: first,
            aes256: second,
        })
    }
}

/// A decrypted Vault credential (resource / identity / authenticator).
#[derive(Debug, Clone, Default)]
pub struct VaultCred {
    pub resource: String,
    pub identity: String,
    pub secret: String,
}

/// Cap on attribute-map entries and on any single decoded string.
const MAX_ATTRS: usize = 64;

fn utf16(b: &[u8]) -> String {
    let u: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&u)
        .trim_end_matches('\0')
        .to_string()
}

/// AES-CBC decrypt (no padding) then strip PKCS#7 padding when valid.
fn aes_cbc(key: &[u8], iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() || !data.len().is_multiple_of(16) {
        return Err(err("vault ciphertext not block aligned"));
    }
    let mut buf = data.to_vec();
    let bad = |_| err("vault AES key size invalid");
    match key.len() {
        32 => {
            cbc::Decryptor::<Aes256>::new_from_slices(key, iv)
                .map_err(bad)?
                .decrypt_padded_mut::<NoPadding>(&mut buf)
                .map_err(|_| err("vault AES decrypt failed"))?;
        }
        16 => {
            cbc::Decryptor::<Aes128>::new_from_slices(key, iv)
                .map_err(bad)?
                .decrypt_padded_mut::<NoPadding>(&mut buf)
                .map_err(|_| err("vault AES decrypt failed"))?;
        }
        _ => return Err(err("vault AES key size invalid")),
    }
    if let Some(&p) = buf.last() {
        let p = p as usize;
        if (1..=16).contains(&p)
            && p <= buf.len()
            && buf[buf.len() - p..].iter().all(|&b| b as usize == p)
        {
            buf.truncate(buf.len() - p);
        }
    }
    Ok(buf)
}

/// Parse and decrypt one VAULT_ATTRIBUTE at `off`, returning the clear data.
fn decrypt_attribute(file: &[u8], off: usize, keys: &VaultKeys) -> Result<Vec<u8>> {
    let mut cur = off;
    let id = read_u32(file, &mut cur)?;
    for _ in 0..3 {
        read_u32(file, &mut cur)?;
    }
    // impacket VAULT_ATTRIBUTE order: optional 6-byte zero pad (present iff
    // the next 6 bytes are all zero), Unknown5 (u32, only when id >= 100), Size.
    if file
        .get(cur..cur + 6)
        .is_some_and(|p| p.iter().all(|&b| b == 0))
    {
        cur += 6;
    }
    if id >= 100 {
        read_u32(file, &mut cur)?;
    }
    let size = read_u32(file, &mut cur)? as usize;
    let has_iv = take(file, &mut cur, 1)?[0] != 0;
    let (iv, overhead) = if has_iv {
        let ivlen = read_u32(file, &mut cur)? as usize;
        if ivlen != 16 {
            return Err(err("unexpected vault IV size"));
        }
        let mut iv = [0u8; 16];
        iv.copy_from_slice(take(file, &mut cur, 16)?);
        (iv, 1 + 4 + 16)
    } else {
        ([0u8; 16], 1)
    };
    let dlen = size
        .checked_sub(overhead)
        .ok_or_else(|| err("vault attribute size too small"))?;
    let data = take(file, &mut cur, dlen)?;
    let key = if has_iv { &keys.aes256 } else { &keys.aes128 };
    aes_cbc(key, &iv, data)
}

/// Parse a decrypted vault attribute: a 12-byte header (version, item count,
/// unknown) followed by `count` items of `{u32 type, u32 byte-len, UTF-16LE}`.
/// Item types follow the Windows vault schema: 1 = resource, 2 = identity,
/// 3 = authenticator. Validated against a real Windows 10 web-credential vault.
fn parse_vault_items(clear: &[u8]) -> Result<VaultCred> {
    let mut cur = 0usize;
    read_u32(clear, &mut cur)?; // version
    let count = read_u32(clear, &mut cur)? as usize;
    read_u32(clear, &mut cur)?; // unknown
    if count == 0 || count > MAX_ATTRS {
        return Err(err("vault item count out of range"));
    }
    let mut out = VaultCred::default();
    let mut unknown: Vec<String> = Vec::new();
    for _ in 0..count {
        let ty = read_u32(clear, &mut cur)?;
        let len = read_u32(clear, &mut cur)? as usize;
        let s = utf16(take(clear, &mut cur, len)?)
            .trim_end_matches('\0')
            .to_string();
        match ty {
            1 => out.resource = s,
            2 => out.identity = s,
            3 => out.secret = s,
            _ => unknown.push(s),
        }
    }
    if out.resource.is_empty() && out.identity.is_empty() && out.secret.is_empty() {
        // Unknown schema: fall back to positional order.
        let mut it = unknown.into_iter();
        out.resource = it.next().unwrap_or_default();
        out.identity = it.next().unwrap_or_default();
        out.secret = it.next().unwrap_or_default();
    }
    Ok(out)
}

/// Parse a `.vcrd` file: VAULT_VCRD header (schema GUID, unknown, FILETIME,
/// two unknowns, friendly name, attribute map of {id, offset, unknown}), then
/// each attribute (optional IV + AES ciphertext). The first attribute whose
/// clear parses as three length-prefixed strings (resource, identity,
/// authenticator) is returned.
///
/// Attribute framing validated against a real Windows 10 `.vcrd`.
pub fn parse_vcrd(file: &[u8], keys: &VaultKeys) -> Result<VaultCred> {
    let mut cur = 0usize;
    take(file, &mut cur, 16)?; // schema GUID
    read_u32(file, &mut cur)?;
    take(file, &mut cur, 8)?; // last written
    read_u32(file, &mut cur)?;
    read_u32(file, &mut cur)?;
    let name_len = read_u32(file, &mut cur)? as usize;
    take(file, &mut cur, name_len)?;
    let maps_len = read_u32(file, &mut cur)? as usize;
    let count = maps_len / 12;
    if count == 0 || count > MAX_ATTRS {
        return Err(err("vcrd attribute map size out of range"));
    }
    let mut offsets = Vec::with_capacity(count);
    for _ in 0..count {
        read_u32(file, &mut cur)?;
        offsets.push(read_u32(file, &mut cur)? as usize);
        read_u32(file, &mut cur)?;
    }
    let mut last = err("vcrd has no usable attribute");
    for off in offsets {
        let clear = match decrypt_attribute(file, off, keys) {
            Ok(c) => c,
            Err(e) => {
                last = e;
                continue;
            }
        };
        match parse_vault_items(&clear) {
            Ok(v) => return Ok(v),
            Err(e) => last = e,
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(blob: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&1u32.to_le_bytes());
        v.extend_from_slice(&[0xAA; 16]);
        let desc: Vec<u8> = "Web Credentials\0"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
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

    fn enc(key: &[u8], iv: &[u8; 16], clear: &[u8]) -> Vec<u8> {
        use cbc::cipher::{BlockEncryptMut, block_padding::Pkcs7};
        if key.len() == 32 {
            cbc::Encryptor::<Aes256>::new_from_slices(key, iv)
                .unwrap()
                .encrypt_padded_vec_mut::<Pkcs7>(clear)
        } else {
            cbc::Encryptor::<Aes128>::new_from_slices(key, iv)
                .unwrap()
                .encrypt_padded_vec_mut::<Pkcs7>(clear)
        }
    }

    fn item(s: &str) -> Vec<u8> {
        let b: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut v = (b.len() as u32).to_le_bytes().to_vec();
        v.extend(b);
        v
    }

    fn keys() -> VaultKeys {
        VaultKeys {
            aes128: vec![0x11; 16],
            aes256: vec![0x22; 32],
        }
    }

    fn vcrd_ext(with_iv: bool, ext: bool) -> Vec<u8> {
        vcrd_attr(with_iv, ext, 1, 0)
    }

    /// `ext` = 6-byte zero pad; `unknown5` is emitted (after the pad) iff `id >= 100`.
    fn vcrd_attr(with_iv: bool, ext: bool, id: u32, unknown5: u32) -> Vec<u8> {
        // Real layout: u32 version, u32 item count, u32 unknown, then items of
        // {u32 type, u32 byte-len, UTF-16LE}. Identity (type 2) is emitted
        // first, as real vaults do, so type-based mapping is exercised.
        let mut clear = Vec::new();
        clear.extend_from_slice(&1u32.to_le_bytes());
        clear.extend_from_slice(&3u32.to_le_bytes());
        clear.extend_from_slice(&1u32.to_le_bytes());
        for (ty, text) in [
            (2u32, "alice\0"),
            (1u32, "https://example.com\0"),
            (3u32, "s3cret!\0"),
        ] {
            let w: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
            clear.extend_from_slice(&ty.to_le_bytes());
            clear.extend_from_slice(&(w.len() as u32).to_le_bytes());
            clear.extend(w);
        }
        let iv = [0x33u8; 16];
        let k = keys();
        let ct = if with_iv {
            enc(&k.aes256, &iv, &clear)
        } else {
            enc(&k.aes128, &[0; 16], &clear)
        };
        let mut attr = Vec::new();
        attr.extend_from_slice(&id.to_le_bytes());
        for _ in 0..3 {
            attr.extend_from_slice(&0u32.to_le_bytes());
        }
        let size = 1 + if with_iv { 4 + 16 } else { 0 } + ct.len();
        if ext {
            // Real vaults emit a 6-byte zero pad here.
            attr.extend_from_slice(&[0u8; 6]);
        }
        if id >= 100 {
            attr.extend_from_slice(&unknown5.to_le_bytes());
        }
        attr.extend_from_slice(&(size as u32).to_le_bytes());
        attr.push(u8::from(with_iv));
        if with_iv {
            attr.extend_from_slice(&16u32.to_le_bytes());
            attr.extend_from_slice(&iv);
        }
        attr.extend(ct);
        let name: Vec<u8> = "Web\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut v = vec![0xEE; 16];
        v.extend_from_slice(&[0; 4]);
        v.extend_from_slice(&[0; 8]);
        v.extend_from_slice(&[0; 8]);
        v.extend_from_slice(&(name.len() as u32).to_le_bytes());
        v.extend(name);
        v.extend_from_slice(&12u32.to_le_bytes());
        let off = v.len() + 12;
        v.extend_from_slice(&1u32.to_le_bytes());
        v.extend_from_slice(&(off as u32).to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend(attr);
        v
    }

    #[test]
    fn parse_vcrd_roundtrip() {
        // ext=true reproduces the 6-byte size extension seen on real vaults.
        for (iv, ext) in [(true, false), (false, false), (true, true)] {
            let c = parse_vcrd(&vcrd_ext(iv, ext), &keys()).unwrap();
            assert_eq!(c.resource, "https://example.com");
            assert_eq!(c.identity, "alice");
            assert_eq!(c.secret, "s3cret!");
        }
    }

    #[test]
    fn vcrd_attr_id_ge_100_with_pad_and_unknown5() {
        for (iv, ext, id, u5) in [
            (true, true, 100u32, 0xDEAD_BEEFu32),
            (false, true, 200, 0x0102_0304),
            (true, false, 100, 0x0A0B_0C0D),
            (true, true, 100, 0),
        ] {
            let c = parse_vcrd(&vcrd_attr(iv, ext, id, u5), &keys()).unwrap();
            assert_eq!(c.resource, "https://example.com");
            assert_eq!(c.identity, "alice");
            assert_eq!(c.secret, "s3cret!");
        }
    }

    #[test]
    fn vault_key_24_rejected_at_parse() {
        let mut d = key_entry(24);
        d.extend(key_entry(32));
        assert!(parse_vault_keys(&d).is_err());
        let mut d = key_entry(16);
        d.extend(key_entry(24));
        assert!(parse_vault_keys(&d).is_err());
        let mut d = key_entry(16);
        d.extend(key_entry(32));
        assert_eq!(parse_vault_keys(&d).unwrap().count(), 2);
    }

    #[test]
    fn parse_vcrd_bounds() {
        let f = vcrd_ext(true, false);
        for n in 0..f.len() {
            assert!(parse_vcrd(&f[..n], &keys()).is_err(), "len {n}");
        }
        assert!(parse_vcrd(&[0xFF; 128], &keys()).is_err());
        assert!(parse_vcrd(&[], &keys()).is_err());
    }

    #[test]
    fn parse_vcrd_bad_key() {
        let f = vcrd_ext(true, false);
        let short = VaultKeys {
            aes128: vec![1; 16],
            aes256: vec![1; 7],
        };
        assert!(parse_vcrd(&f, &short).is_err());
        let wrong = VaultKeys {
            aes128: vec![9; 16],
            aes256: vec![9; 32],
        };
        assert!(parse_vcrd(&f, &wrong).is_err());
    }
}
