//! DPAPI blob parse + AES-256-CBC / HMAC-SHA512 decrypt primitive, with the
//! blob signature (`sign`) verified before any plaintext is returned.
//!
//! Reference: impacket dpapi.py.

use crate::error::{Result, VmkatzError as Error};
use aes::Aes256;
use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use des::TdesEde3;
use hmac::{Hmac, Mac};
use sha1::{Digest, Sha1};
use sha2::Sha512;
use sha2::digest::core_api::BlockSizeUser;

type Aes256CbcDec = cbc::Decryptor<Aes256>;
type TdesCbcDec = cbc::Decryptor<TdesEde3>;

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
    /// Signed region: raw blob bytes from offset 20 (after version + provider
    /// GUID) up to, excluding, the `sign_len` field (impacket `toSign`).
    pub sign_data: &'a [u8],
}

const INTEGRITY_ERR: &str = "DPAPI blob integrity check failed";

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
            "dpapi blob {label} length {v} exceeds cap {cap}"
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
    let mk_guid_str = crate::utils::format_guid(&mk_guid);
    let flags = read_u32(bytes, &mut cur)?;
    let desc_len = read_len(bytes, &mut cur, MAX_DESC, "description")?;
    let description = crate::utils::utf16le_decode(take(bytes, &mut cur, desc_len)?);
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
    let sign_data = &bytes[20..cur];
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
        sign_data,
    })
}

/// Decrypt a DPAPI blob using a cleartext masterkey (typically 64 bytes).
pub fn decrypt_blob(blob: &DpapiBlob<'_>, masterkey: &[u8]) -> Result<Vec<u8>> {
    decrypt_blob_entropy(blob, masterkey, &[])
}

/// Decrypt a DPAPI blob with an optional application entropy value.
///
/// Entropy is appended to the salt in the session-key HMAC (per impacket
/// `DPAPI_BLOB.decrypt` / `CryptUnprotectData`'s `pOptionalEntropy`). CNG "Software
/// KSP" private-key blobs are protected with entropy `xT5rZW5qVVbrvpuA\0`.
pub fn decrypt_blob_entropy(
    blob: &DpapiBlob<'_>,
    masterkey: &[u8],
    entropy: &[u8],
) -> Result<Vec<u8>> {
    type HmacSha512 = Hmac<Sha512>;
    // Legacy combo (pre-Win8 / some domain accounts): 3DES (0x6603) + SHA1 (0x8004).
    if blob.crypt_alg == 0x6603 && blob.hmac_alg == 0x8004 {
        return decrypt_blob_legacy_3des_sha1(blob, masterkey, entropy);
    }
    // Modern combo: crypt_alg = CALG_AES_256 (0x6610), hmac_alg = CALG_SHA512 (0x800E).
    if blob.crypt_alg != 0x6610 || blob.hmac_alg != 0x800E {
        return Err(Error::Parse(format!(
            "unsupported DPAPI blob crypto: crypt=0x{:x} hmac=0x{:x}",
            blob.crypt_alg, blob.hmac_alg
        )));
    }
    // DPAPI BLOB session-key derivation (per impacket dpapi.py DPAPI_BLOB.decrypt):
    //   keyHash    = SHA1(masterkey)
    //   sessionKey = HMAC-SHA512(keyHash, salt || entropy)
    //   derivedKey = sessionKey  (no further transform for SHA-512/AES-256)
    //   AES-256-CBC decrypt with key=derivedKey[:32] and IV = ALL ZEROS
    //   sign       = HMAC-SHA512(keyHash, hmac || entropy || toSign)  (Win7+;
    //                the pre-Win7 variant is also accepted, as in impacket)
    //   plaintext  = unpad(PKCS#7)
    // The IV is NOT derived from sessionKey bytes — that's the masterkey-FILE
    // convention, which uses a different (PBKDF2) derivation entirely.
    let mk_sha1 = Sha1::digest(masterkey);
    let mut h =
        HmacSha512::new_from_slice(&mk_sha1).map_err(|_| Error::Parse("hmac key".into()))?;
    h.update(blob.salt);
    if !entropy.is_empty() {
        h.update(entropy);
    }
    let session = h.finalize().into_bytes();

    let key = &session[..32];
    let iv = [0u8; 16];
    if !blob.cipher_text.len().is_multiple_of(16) {
        return Err(Error::Parse("dpapi ciphertext not block-aligned".into()));
    }
    // Integrity first: a wrong masterkey / missing entropy / corrupted blob
    // must be an error, never Ok(garbage).
    let win7_ok = HmacSha512::new_from_slice(&mk_sha1)
        .map_err(|_| Error::Parse("hmac key".into()))?
        .chain_update(blob.hmac)
        .chain_update(entropy)
        .chain_update(blob.sign_data)
        .verify_slice(blob.sign)
        .is_ok();
    if !win7_ok && !xp_sign_matches::<Sha512>(&mk_sha1, blob, entropy) {
        return Err(Error::DecryptionError(INTEGRITY_ERR.into()));
    }
    let mut buf = blob.cipher_text.to_vec();
    let cipher = Aes256CbcDec::new(key.into(), (&iv).into());
    let pt = cipher
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(|_| Error::Parse("dpapi aes decrypt".into()))?;
    strip_pkcs7(pt, 16)
}

/// Strip PKCS#7 padding (impacket `unpad`). Windows `CryptEncrypt` always pads,
/// so a signed blob with invalid padding is malformed.
fn strip_pkcs7(pt: &[u8], block: usize) -> Result<Vec<u8>> {
    let bad = || Error::DecryptionError("DPAPI blob padding invalid".into());
    let pad = *pt.last().ok_or_else(bad)? as usize;
    if pad == 0 || pad > block || pad > pt.len() {
        return Err(bad());
    }
    if !pt[pt.len() - pad..].iter().all(|&b| b as usize == pad) {
        return Err(bad());
    }
    Ok(pt[..pt.len() - pad].to_vec())
}

/// Pre-Win7 ("XP") signature variant, impacket `hmacCalculated1` /
/// dpapick `CryptSessionKeyXP`: `H(opad || H(ipad || hmac) || entropy || toSign)`
/// with ipad/opad from `keyHash` zero-padded to the hash block size.
/// Compared in constant time.
fn xp_sign_matches<D: Digest + BlockSizeUser>(
    key_hash: &[u8],
    blob: &DpapiBlob<'_>,
    entropy: &[u8],
) -> bool {
    let bs = D::block_size();
    let mut ipad = vec![0x36u8; bs];
    let mut opad = vec![0x5cu8; bs];
    for (i, k) in key_hash.iter().take(bs).enumerate() {
        ipad[i] ^= k;
        opad[i] ^= k;
    }
    let inner = D::new()
        .chain_update(&ipad)
        .chain_update(blob.hmac)
        .finalize();
    let calc = D::new()
        .chain_update(&opad)
        .chain_update(inner)
        .chain_update(entropy)
        .chain_update(blob.sign_data)
        .finalize();
    calc.len() == blob.sign.len()
        && calc
            .iter()
            .zip(blob.sign)
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

/// Legacy DPAPI blob decrypt: 3DES-CBC + HMAC-SHA1 (per impacket `DPAPI_BLOB`).
/// Session key = HMAC-SHA1(SHA1(mk), salt+entropy), expanded via CryptDeriveKey
/// (ipad/opad) since 20 < 24. Zero IV; signature verified, PKCS#7 stripped.
fn decrypt_blob_legacy_3des_sha1(
    blob: &DpapiBlob<'_>,
    masterkey: &[u8],
    entropy: &[u8],
) -> Result<Vec<u8>> {
    type HmacSha1 = Hmac<Sha1>;
    let mk_sha1 = Sha1::digest(masterkey);
    let mut h = HmacSha1::new_from_slice(&mk_sha1).map_err(|_| Error::Parse("hmac key".into()))?;
    h.update(blob.salt);
    if !entropy.is_empty() {
        h.update(entropy);
    }
    let session = h.finalize().into_bytes(); // 20 bytes

    let mut ext = session.to_vec();
    ext.resize(session.len() + 64, 0);
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= ext[i];
        opad[i] ^= ext[i];
    }
    let mut derived = Vec::with_capacity(40);
    derived.extend_from_slice(&Sha1::digest(ipad));
    derived.extend_from_slice(&Sha1::digest(opad));

    let key = &derived[..24];
    let iv = [0u8; 8];
    if !blob.cipher_text.len().is_multiple_of(8) {
        return Err(Error::Parse(
            "dpapi 3des ciphertext not block-aligned".into(),
        ));
    }
    let win7_ok = HmacSha1::new_from_slice(&mk_sha1)
        .map_err(|_| Error::Parse("hmac key".into()))?
        .chain_update(blob.hmac)
        .chain_update(entropy)
        .chain_update(blob.sign_data)
        .verify_slice(blob.sign)
        .is_ok();
    if !win7_ok && !xp_sign_matches::<Sha1>(&mk_sha1, blob, entropy) {
        return Err(Error::DecryptionError(INTEGRITY_ERR.into()));
    }
    let mut buf = blob.cipher_text.to_vec();
    let cipher = TdesCbcDec::new(key.into(), (&iv).into());
    let pt = cipher
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(|_| Error::Parse("dpapi 3des decrypt".into()))?;
    strip_pkcs7(pt, 8)
}

#[cfg(test)]
mod tests {
    use super::{Sha1, decrypt_blob, decrypt_blob_entropy, parse_blob};
    use crate::error::VmkatzError;
    use cbc::cipher::{BlockEncryptMut, KeyIvInit, block_padding::NoPadding};
    use hmac::{Hmac, Mac};
    use sha1::Digest;
    use sha2::Sha512;
    type TdesCbcEnc = cbc::Encryptor<des::TdesEde3>;
    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

    fn pkcs7(pt: &[u8], bs: usize) -> Vec<u8> {
        let mut v = pt.to_vec();
        let pad = bs - (v.len() % bs);
        v.extend(std::iter::repeat_n(pad as u8, pad));
        v
    }

    /// Serialize every DPAPI_BLOB field up to (and excluding) `sign_len`.
    fn blob_head(crypt: u32, hash: u32, salt: &[u8], hmac: &[u8], ct: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&1u32.to_le_bytes()); // version
        b.extend_from_slice(&[0xD0u8; 16]); // provider guid
        b.extend_from_slice(&1u32.to_le_bytes()); // mk version
        b.extend_from_slice(&[0x11u8; 16]); // mk guid
        b.extend_from_slice(&0u32.to_le_bytes()); // flags
        let desc: Vec<u8> = "test\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
        b.extend_from_slice(&(desc.len() as u32).to_le_bytes());
        b.extend_from_slice(&desc);
        b.extend_from_slice(&crypt.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes()); // crypt_alg len
        b.extend_from_slice(&(salt.len() as u32).to_le_bytes());
        b.extend_from_slice(salt);
        b.extend_from_slice(&0u32.to_le_bytes()); // hmac_key len
        b.extend_from_slice(&hash.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes()); // hmac_alg len
        b.extend_from_slice(&(hmac.len() as u32).to_le_bytes());
        b.extend_from_slice(hmac);
        b.extend_from_slice(&(ct.len() as u32).to_le_bytes());
        b.extend_from_slice(ct);
        b
    }

    fn append_sign(mut b: Vec<u8>, sign: &[u8]) -> Vec<u8> {
        b.extend_from_slice(&(sign.len() as u32).to_le_bytes());
        b.extend_from_slice(sign);
        b
    }

    /// Build an AES-256/SHA-512 blob the impacket way (Win7+ sign:
    /// `HMAC-SHA512(SHA1(mk), hmac || entropy || raw[20..sign_len])`).
    fn build_aes_blob(mk: &[u8], pt: &[u8], entropy: &[u8]) -> Vec<u8> {
        type H = Hmac<Sha512>;
        let salt = [0x5Au8; 32];
        let hmac_field = [0xC3u8; 64];
        let kh = Sha1::digest(mk);
        let mut h = H::new_from_slice(&kh).unwrap();
        h.update(&salt);
        h.update(entropy);
        let session = h.finalize().into_bytes();
        let mut buf = pkcs7(pt, 16);
        let n = buf.len();
        Aes256CbcEnc::new(session[..32].into(), (&[0u8; 16]).into())
            .encrypt_padded_mut::<NoPadding>(&mut buf, n)
            .unwrap();
        let head = blob_head(0x6610, 0x800E, &salt, &hmac_field, &buf);
        let mut s = H::new_from_slice(&kh).unwrap();
        s.update(&hmac_field);
        s.update(entropy);
        s.update(&head[20..]);
        let sign = s.finalize().into_bytes();
        append_sign(head, &sign)
    }

    /// Encrypt `pt` into a legacy (3DES/SHA1) DPAPI blob under `mk`, mirroring
    /// impacket (CryptDeriveKey ipad/opad expansion, zero IV, PKCS#7, Win7+ sign).
    fn build_legacy_blob(mk: &[u8], salt: &[u8; 16], pt: &[u8]) -> Vec<u8> {
        type HmacSha1 = Hmac<Sha1>;
        let hmac_field = [0x77u8; 16];
        let key_hash = Sha1::digest(mk);
        let mut h = HmacSha1::new_from_slice(&key_hash).unwrap();
        h.update(salt);
        let session = h.finalize().into_bytes();
        let mut ext = session.to_vec();
        ext.resize(session.len() + 64, 0);
        let mut ipad = [0x36u8; 64];
        let mut opad = [0x5cu8; 64];
        for i in 0..64 {
            ipad[i] ^= ext[i];
            opad[i] ^= ext[i];
        }
        let mut derived = Vec::with_capacity(40);
        derived.extend_from_slice(&Sha1::digest(ipad));
        derived.extend_from_slice(&Sha1::digest(opad));
        let mut buf = pkcs7(pt, 8);
        let n = buf.len();
        TdesCbcEnc::new(derived[..24].into(), (&[0u8; 8]).into())
            .encrypt_padded_mut::<NoPadding>(&mut buf, n)
            .unwrap();
        let head = blob_head(0x6603, 0x8004, salt, &hmac_field, &buf);
        let mut s = HmacSha1::new_from_slice(&key_hash).unwrap();
        s.update(&hmac_field);
        s.update(&head[20..]);
        let sign = s.finalize().into_bytes();
        append_sign(head, &sign)
    }

    fn is_integrity_err(r: &crate::error::Result<Vec<u8>>) -> bool {
        matches!(r, Err(VmkatzError::DecryptionError(m)) if m.contains("integrity"))
    }

    #[test]
    fn legacy_3des_sha1_blob_roundtrip() {
        let mk = [0x42u8; 64];
        let salt = [0x9Cu8; 16];
        let v10_key = [0xA7u8; 32];
        let raw = build_legacy_blob(&mk, &salt, &v10_key);
        let blob = parse_blob(&raw).expect("parse");
        assert_eq!(blob.crypt_alg, 0x6603);
        assert_eq!(blob.hmac_alg, 0x8004);
        let pt = decrypt_blob(&blob, &mk).expect("legacy 3des decrypt");
        assert_eq!(pt, v10_key);
        assert!(is_integrity_err(&decrypt_blob(&blob, &[0x43u8; 64])));
    }

    #[test]
    fn aes256_sha512_roundtrip_with_sign() {
        let mk: Vec<u8> = (0u8..64).collect();
        let pt = b"credential plaintext, 37 bytes long!!";
        let raw = build_aes_blob(&mk, pt, &[]);
        let blob = parse_blob(&raw).expect("parse");
        assert_eq!(blob.sign.len(), 64);
        assert_eq!(blob.description, "test");
        let out = decrypt_blob(&blob, &mk).expect("aes decrypt");
        assert_eq!(out, pt);
    }

    #[test]
    fn aes256_block_aligned_plaintext_strips_full_pad_block() {
        let mk = [0x01u8; 64];
        let pt = [0xEEu8; 32];
        let raw = build_aes_blob(&mk, &pt, &[]);
        let blob = parse_blob(&raw).unwrap();
        assert_eq!(blob.cipher_text.len(), 48);
        assert_eq!(decrypt_blob(&blob, &mk).unwrap(), pt);
    }

    #[test]
    fn wrong_masterkey_is_integrity_error() {
        let mk: Vec<u8> = (0u8..64).collect();
        let raw = build_aes_blob(&mk, b"secret", &[]);
        let blob = parse_blob(&raw).unwrap();
        let mut wrong = mk.clone();
        wrong[0] ^= 1;
        assert!(is_integrity_err(&decrypt_blob(&blob, &wrong)));
    }

    #[test]
    fn corrupted_ciphertext_is_integrity_error() {
        let mk = [0x33u8; 64];
        let mut raw = build_aes_blob(&mk, b"secret", &[]);
        // Flip a byte inside the ciphertext (just before sign_len + 64-byte sign).
        let at = raw.len() - 4 - 64 - 1;
        raw[at] ^= 0x80;
        let blob = parse_blob(&raw).unwrap();
        assert!(is_integrity_err(&decrypt_blob(&blob, &mk)));
    }

    #[test]
    fn entropy_required_and_verified() {
        let mk = [0x24u8; 64];
        let ent = b"xT5rZW5qVVbrvpuA\0";
        let raw = build_aes_blob(&mk, b"ksp private key", ent);
        let blob = parse_blob(&raw).unwrap();
        assert_eq!(
            decrypt_blob_entropy(&blob, &mk, ent).unwrap(),
            b"ksp private key"
        );
        assert!(is_integrity_err(&decrypt_blob(&blob, &mk)));
    }

    #[test]
    fn trailing_bytes_after_blob_do_not_affect_sign() {
        let mk = [0x55u8; 64];
        let mut raw = build_aes_blob(&mk, b"abc", &[]);
        raw.extend_from_slice(&[0xFFu8; 13]);
        let blob = parse_blob(&raw).unwrap();
        assert_eq!(decrypt_blob(&blob, &mk).unwrap(), b"abc");
    }

    #[test]
    fn guid_format() {
        let g = [
            0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x78, 0x56, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
            0x00, 0x11,
        ];
        assert_eq!(
            crate::utils::format_guid(&g),
            "12345678-1234-5678-aabb-ccddeeff0011"
        );
    }
}
