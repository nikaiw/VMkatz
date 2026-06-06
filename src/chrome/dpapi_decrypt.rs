//! DPAPI blob parse + AES-256-CBC / HMAC-SHA512 decrypt primitive.
//!
//! Reference: impacket dpapi.py.

use crate::error::{Result, VmkatzError as Error};
use aes::Aes256;
use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha1::{Digest, Sha1};
use sha2::Sha512;

type Aes256CbcDec = cbc::Decryptor<Aes256>;

// Sanity caps on variable-length fields to prevent length-bomb allocations.
const MAX_DESC: usize = 4096;
const MAX_SALT: usize = 1024;
const MAX_HMAC_KEY: usize = 4096;
const MAX_HMAC: usize = 512;
const MAX_DATA: usize = 16 * 1024 * 1024;
const MAX_SIGN: usize = 1024;

/// Parsed DPAPI_BLOB. Fields per impacket dpapi.py.
#[derive(Debug)]
pub struct DpapiBlob<'a> {
    pub mk_guid: [u8; 16],
    pub mk_guid_str: String,
    pub flags: u32,
    pub description: String,
    pub crypt_alg: u32,
    pub hmac_alg: u32,
    pub salt: &'a [u8],
    pub hmac: &'a [u8],
    pub cipher_text: &'a [u8],
    pub sign: &'a [u8],
}

// Bounds-checked slice read + cursor advance.
fn take<'a>(bytes: &'a [u8], cur: &mut usize, len: usize) -> Result<&'a [u8]> {
    let end = cur
        .checked_add(len)
        .ok_or_else(|| Error::Parse("dpapi blob cursor overflow".into()))?;
    if end > bytes.len() {
        return Err(Error::Parse("dpapi blob truncated".into()));
    }
    let s = &bytes[*cur..end];
    *cur = end;
    Ok(s)
}

fn read_u32(bytes: &[u8], cur: &mut usize) -> Result<u32> {
    let s = take(bytes, cur, 4)?;
    Ok(u32::from_le_bytes(s.try_into().unwrap()))
}

fn read_len(bytes: &[u8], cur: &mut usize, cap: usize, label: &'static str) -> Result<usize> {
    let v = read_u32(bytes, cur)? as usize;
    if v > cap {
        return Err(Error::Parse(format!(
            "dpapi blob {} length {} exceeds cap {}",
            label, v, cap
        )));
    }
    Ok(v)
}

pub fn parse_blob(bytes: &[u8]) -> Result<DpapiBlob<'_>> {
    // DPAPI_BLOB layout (all little-endian unless noted):
    //  u32 version
    //  16   provider_guid
    //  u32 mk_version
    //  16   mk_guid
    //  u32 flags
    //  u32 description_len
    //  []   description (UTF-16LE)
    //  u32 crypt_alg
    //  u32 crypt_alg_len
    //  u32 salt_len
    //  []   salt
    //  u32 hmac_key_len
    //  []   hmac_key
    //  u32 hmac_alg
    //  u32 hmac_alg_len
    //  u32 hmac_len
    //  []   hmac
    //  u32 data_len
    //  []   data
    //  u32 sign_len
    //  []   sign
    let mut cur: usize = 0;
    let _version = read_u32(bytes, &mut cur)?;
    let _provider = take(bytes, &mut cur, 16)?;
    let _mk_version = read_u32(bytes, &mut cur)?;
    let mk_guid: [u8; 16] = take(bytes, &mut cur, 16)?.try_into().unwrap();
    let mk_guid_str = format_guid(&mk_guid);
    let flags = read_u32(bytes, &mut cur)?;
    let desc_len = read_len(bytes, &mut cur, MAX_DESC, "description")?;
    let description = utf16le(take(bytes, &mut cur, desc_len)?);
    let crypt_alg = read_u32(bytes, &mut cur)?;
    let _crypt_alg_len = read_u32(bytes, &mut cur)?;
    let salt_len = read_len(bytes, &mut cur, MAX_SALT, "salt")?;
    let salt = take(bytes, &mut cur, salt_len)?;
    let hmac_key_len = read_len(bytes, &mut cur, MAX_HMAC_KEY, "hmac_key")?;
    let _hmac_key = take(bytes, &mut cur, hmac_key_len)?;
    let hmac_alg = read_u32(bytes, &mut cur)?;
    let _hmac_alg_len = read_u32(bytes, &mut cur)?;
    let hmac_len = read_len(bytes, &mut cur, MAX_HMAC, "hmac")?;
    let hmac = take(bytes, &mut cur, hmac_len)?;
    let data_len = read_len(bytes, &mut cur, MAX_DATA, "data")?;
    let cipher_text = take(bytes, &mut cur, data_len)?;
    let sign_len = read_len(bytes, &mut cur, MAX_SIGN, "sign")?;
    let sign = take(bytes, &mut cur, sign_len)?;

    Ok(DpapiBlob {
        mk_guid,
        mk_guid_str,
        flags,
        description,
        crypt_alg,
        hmac_alg,
        salt,
        hmac,
        cipher_text,
        sign,
    })
}

fn utf16le(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
        .trim_end_matches('\0')
        .to_string()
}

fn format_guid(g: &[u8; 16]) -> String {
    // Mixed-endian: first 3 fields are little-endian, last 2 are big-endian.
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u32::from_le_bytes(g[0..4].try_into().unwrap()),
        u16::from_le_bytes(g[4..6].try_into().unwrap()),
        u16::from_le_bytes(g[6..8].try_into().unwrap()),
        g[8],
        g[9],
        g[10],
        g[11],
        g[12],
        g[13],
        g[14],
        g[15]
    )
}

/// Decrypt a DPAPI blob using a cleartext masterkey (typically 64 bytes).
pub fn decrypt_blob(blob: &DpapiBlob<'_>, masterkey: &[u8]) -> Result<Vec<u8>> {
    // Modern combo: crypt_alg = CALG_AES_256 (0x6610), hmac_alg = CALG_SHA512 (0x800E).
    if blob.crypt_alg != 0x6610 || blob.hmac_alg != 0x800E {
        return Err(Error::Parse(format!(
            "unsupported DPAPI blob crypto: crypt=0x{:x} hmac=0x{:x}",
            blob.crypt_alg, blob.hmac_alg
        )));
    }
    // DPAPI BLOB session-key derivation (per impacket dpapi.py DPAPI_BLOB.decrypt):
    //   keyHash    = SHA1(masterkey)
    //   sessionKey = HMAC-SHA512(keyHash, salt)
    //   derivedKey = sessionKey  (no further transform for SHA-512/AES-256)
    //   AES-256-CBC decrypt with key=derivedKey[:32] and IV = ALL ZEROS
    // The IV is NOT derived from sessionKey bytes — that's the masterkey-FILE
    // convention, which uses a different (PBKDF2) derivation entirely.
    type HmacSha512 = Hmac<Sha512>;
    let mk_sha1 = Sha1::digest(masterkey);
    let mut h =
        HmacSha512::new_from_slice(&mk_sha1).map_err(|_| Error::Parse("hmac key".into()))?;
    h.update(blob.salt);
    let session = h.finalize().into_bytes();

    let key = &session[..32];
    let iv = [0u8; 16];
    if blob.cipher_text.len() % 16 != 0 {
        return Err(Error::Parse("dpapi ciphertext not block-aligned".into()));
    }
    let mut buf = blob.cipher_text.to_vec();
    let cipher = Aes256CbcDec::new(key.into(), (&iv).into());
    let pt = cipher
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(|_| Error::Parse("dpapi aes decrypt".into()))?;
    Ok(pt.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_format() {
        let g = [
            0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x78, 0x56, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
            0x00, 0x11,
        ];
        assert_eq!(format_guid(&g), "12345678-1234-5678-aabb-ccddeeff0011");
    }
}
