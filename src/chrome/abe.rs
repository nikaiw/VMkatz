//! App-Bound Encryption (Chrome v127+) v20 blob decrypt.
//!
//! The Chrome Elevation Service wraps the per-install AES key three times:
//!
//!   1. `Local State.os_crypt.app_bound_encrypted_key` = "APPB" || user_DPAPI_blob
//!   2. user_DPAPI_blob decrypted → SYSTEM_DPAPI_blob
//!   3. SYSTEM_DPAPI_blob decrypted → aes_encrypted_key (= the layer Chrome itself adds)
//!
//! The `aes_encrypted_key` layout is `<flag(1)> <nonce(12)> <ciphertext> <tag(16)>`
//! where the AES-256-GCM key depends on `flag`:
//!
//!   - flag = 1  (Chrome 127–): static key embedded in `elevation_service.exe`
//!   - flag = 2  (Chrome 128–): different static key, XORed with the install path
//!   - flag = 3  (Chrome 130+): ChaCha20-Poly1305 with a derived key
//!
//! We ship the public/reverse-engineered Chrome flag-1 static key and accept
//! optional caller-supplied keys for the other flags. Flag-3 (ChaCha20) is
//! out of scope.

use aes::Aes256;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};

use crate::chrome::abe_keys::{AbeKey, BrowserKeyMap};
use crate::chrome::dpapi_decrypt::{decrypt_blob, parse_blob};
use crate::error::{Result, VmkatzError as Error};

type Aes256CbcDec = cbc::Decryptor<Aes256>;

/// AEAD algorithm enum from the elevation-service key table (`AbeKey.algo`).
const ALGO_AES_GCM: u8 = 2;
const ALGO_CHACHA20: u8 = 4;

/// Strip "APPB", run the two DPAPI layers via caller closures, then unwrap the
/// flag-byte-driven inner blob to return the 32-byte v20 AES-GCM key.
///
/// `ksp_keys` are candidate machine NCrypt AES keys (see [`crate::chrome::cng_ksp`])
/// needed only for the flag=0 "v3" path; pass `&[]` when unavailable.
pub fn unwrap_app_bound_key<FU, FS>(
    appb: &[u8],
    decrypt_user: FU,
    decrypt_system: FS,
    key_map: &BrowserKeyMap,
    ksp_keys: &[[u8; 32]],
) -> Result<[u8; 32]>
where
    FU: FnOnce(&[u8]) -> Result<Vec<u8>>,
    FS: FnOnce(&[u8]) -> Result<Vec<u8>>,
{
    if appb.len() < 4 || &appb[..4] != b"APPB" {
        return Err(Error::Parse("not an APPB blob".into()));
    }
    let inner = &appb[4..];
    let layer1 = decrypt_user(inner)?;
    let layer2 = decrypt_system(&layer1)?;
    decrypt_aes_encrypted_key(&layer2, key_map, ksp_keys)
}

/// Convenience wrapper: same as `decrypt_aes_encrypted_key` but uses the
/// hardcoded Chrome 135 fallback keys and no NCrypt keys.
pub fn decrypt_aes_encrypted_key_with_fallback(aes_encrypted_key: &[u8]) -> Result<[u8; 32]> {
    decrypt_aes_encrypted_key(aes_encrypted_key, &BrowserKeyMap::fallback(), &[])
}

/// Recover the 32-byte v20 key from the two-DPAPI-layer output.
///
/// Handles three inner shapes:
///
/// - Edge: `cipher` is 32 raw key bytes (no inner crypto).
/// - Chrome flag=1 (61 bytes): `version(1)|nonce(12)|ct(32)|tag(16)`; the version
///   byte's static key is the AEAD key directly.
/// - Chrome flag=0 / "v3" (93 bytes): `version(1)|wrapped(32)|nonce(12)|ct(32)|tag(16)`;
///   the AEAD key is `NCryptDecrypt(ksp_key, wrapped) XOR static_key`.
///
/// AAD is empty for all versions. AEAD is AES-256-GCM (algo 2) or, when supported,
/// ChaCha20-Poly1305 (algo 4).
pub fn decrypt_aes_encrypted_key(
    aes_encrypted_key: &[u8],
    key_map: &BrowserKeyMap,
    ksp_keys: &[[u8; 32]],
) -> Result<[u8; 32]> {
    // Layout (after SYSTEM-DPAPI decrypt, post-PKCS#7-strip):
    //   header_len(u32 LE) || flag(u8) || install_path((header_len - 1) bytes)
    //   cipher_len(u32 LE) || cipher(cipher_len bytes)
    // PKCS#7 padding to a 16-byte boundary follows.
    let (_header, cipher, _flag) = parse_aes_encrypted_key_struct(aes_encrypted_key)?;

    // Edge (Microsoft) stores the v20 key inline as 32 raw bytes — no inner crypto.
    if cipher.len() == 32 {
        return cipher
            .try_into()
            .map_err(|_| Error::Parse("ABE edge key len".into()));
    }
    if cipher.is_empty() {
        return Err(Error::Parse("ABE empty cipher".into()));
    }

    // Chrome: the leading byte is the version, indexing the elevation-service key
    // table. `flag` selects whether the table key is the AEAD key directly (flag=1)
    // or an XOR mask over an NCrypt-derived key (flag=0, the Chrome ≥ ~140 "v3" path).
    let version = cipher[0];
    let entry = key_map
        .resolve_entry(version)
        .ok_or_else(|| Error::Parse(format!("Chrome ABE version {version} not in key table")))?;

    if entry.flag == 0 {
        // v3: version(1) | wrapped(32) | nonce(12) | ct(32) | tag(16) = 93.
        if cipher.len() < 1 + 32 + 12 + 16 {
            return Err(Error::Parse(format!(
                "Chrome ABE v3 cipher_len={} too short (need >= 61)",
                cipher.len()
            )));
        }
        return decrypt_v3_multi(cipher, ksp_keys, &entry);
    }

    // flag=1: version(1) | nonce(12) | ct | tag(16); static key is the AEAD key.
    if cipher.len() < 1 + 12 + 16 {
        return Err(Error::Parse(format!(
            "Chrome ABE cipher_len={} too short",
            cipher.len()
        )));
    }
    let pt = aead_open(entry.algo, &entry.key, &cipher[1..13], &cipher[13..])?;
    pt.as_slice()
        .try_into()
        .map_err(|_| Error::Parse(format!("Chrome ABE plaintext len {} (want 32)", pt.len())))
}

/// Recover the flag=0 ("v3") key. For each candidate machine NCrypt AES key,
/// `AES-256-CBC-decrypt(ksp_key, wrapped, IV=0) XOR static_key` yields the AES-GCM
/// key; the GCM tag then validates which KSP key (normally there is exactly one).
fn decrypt_v3_multi(cipher: &[u8], ksp_keys: &[[u8; 32]], entry: &AbeKey) -> Result<[u8; 32]> {
    if ksp_keys.is_empty() {
        return Err(Error::Parse(
            "Chrome ABE v3 needs the machine NCrypt (CNG Software-KSP) key — none recovered".into(),
        ));
    }
    let wrapped = &cipher[1..33];
    let nonce = &cipher[33..45];
    let ct_tag = &cipher[45..];
    let mut last = Error::Parse("Chrome ABE v3: no KSP key authenticated".into());
    for ksp in ksp_keys {
        let ncrypt_out = match aes256_cbc_decrypt_zero_iv(ksp, wrapped) {
            Ok(v) => v,
            Err(e) => {
                last = e;
                continue;
            }
        };
        let mut aead_key = [0u8; 32];
        for i in 0..32 {
            aead_key[i] = ncrypt_out[i] ^ entry.key[i];
        }
        match aead_open(entry.algo, &aead_key, nonce, ct_tag) {
            Ok(pt) => {
                return pt
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::Parse("Chrome ABE v3 plaintext len".into()));
            }
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// AES-256-CBC decrypt with a zero IV and no padding (input must be a 16-byte
/// multiple). Models `NCryptDecrypt` on a Software-KSP AES key.
fn aes256_cbc_decrypt_zero_iv(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() || !data.len().is_multiple_of(16) {
        return Err(Error::Parse("ABE NCrypt input not block-aligned".into()));
    }
    let iv = [0u8; 16];
    let mut buf = data.to_vec();
    let pt = Aes256CbcDec::new(key.into(), (&iv).into())
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(|_| Error::Parse("ABE NCrypt AES-CBC decrypt".into()))?;
    Ok(pt.to_vec())
}

/// AEAD-open `ct_tag` (ciphertext followed by 16-byte tag) with empty AAD.
fn aead_open(algo: u8, key: &[u8; 32], nonce: &[u8], ct_tag: &[u8]) -> Result<Vec<u8>> {
    match algo {
        ALGO_AES_GCM => Aes256Gcm::new(key.into())
            .decrypt(Nonce::from_slice(nonce), ct_tag)
            .map_err(|_| Error::Parse("Chrome ABE inner GCM auth fail".into())),
        ALGO_CHACHA20 => Err(Error::Parse(
            "Chrome ABE ChaCha20-Poly1305 (algo 4 / v2) not yet supported".into(),
        )),
        other => Err(Error::Parse(format!(
            "Chrome ABE unknown AEAD algo {other}"
        ))),
    }
}

/// PKCS#7-strip then split `[header_len][flag][path][cipher_len][cipher]`.
/// Returns `(header_bytes, cipher_bytes, flag)`. `header_bytes` is the full
/// `header_len + 4` prefix usable as AAD for the inner GCM decrypt.
fn parse_aes_encrypted_key_struct(blob: &[u8]) -> Result<(&[u8], &[u8], u8)> {
    if blob.len() < 16 {
        return Err(Error::Parse("ABE blob too short".into()));
    }
    // Strip PKCS#7 padding if present.
    let pad = *blob.last().unwrap() as usize;
    let unpadded_len = if (1..=16).contains(&pad)
        && blob.len() >= pad
        && blob[blob.len() - pad..].iter().all(|&b| b as usize == pad)
    {
        blob.len() - pad
    } else {
        blob.len()
    };
    let buf = &blob[..unpadded_len];
    if buf.len() < 4 {
        return Err(Error::Parse("ABE blob: missing header_len".into()));
    }
    let header_len = u32::from_le_bytes(buf[..4].try_into().unwrap()) as usize;
    if header_len < 1 || 4 + header_len + 4 > buf.len() {
        return Err(Error::Parse(format!(
            "ABE header_len {header_len} out of range"
        )));
    }
    let flag = buf[4];
    let header = &buf[..4 + header_len];
    let cipher_len_off = 4 + header_len;
    let cipher_len =
        u32::from_le_bytes(buf[cipher_len_off..cipher_len_off + 4].try_into().unwrap()) as usize;
    let cipher_off = cipher_len_off + 4;
    if cipher_off + cipher_len > buf.len() {
        return Err(Error::Parse(format!(
            "ABE cipher_len {cipher_len} runs past buffer"
        )));
    }
    let cipher = &buf[cipher_off..cipher_off + cipher_len];
    Ok((header, cipher, flag))
}

/// Same as `decrypt_aes_encrypted_key` but with a caller-supplied flag-key. Use
/// when you've already identified the Chrome version's static key (e.g. via
/// reverse-engineering elevation_service.exe).
pub fn decrypt_aes_encrypted_key_with_key(
    aes_encrypted_key: &[u8],
    aes_key: &[u8; 32],
) -> Result<[u8; 32]> {
    if aes_encrypted_key.len() < 1 + 12 + 16 {
        return Err(Error::Parse("ABE aes_encrypted_key too short".into()));
    }
    let nonce = &aes_encrypted_key[1..13];
    let ct_and_tag = &aes_encrypted_key[13..];
    let cipher = Aes256Gcm::new(aes_key.into());
    let pt = cipher
        .decrypt(Nonce::from_slice(nonce), ct_and_tag)
        .map_err(|_| Error::Parse("ABE GCM auth fail (wrong flag key or corrupt blob)".into()))?;
    if pt.len() < 32 {
        return Err(Error::Parse(format!(
            "ABE plaintext expected ≥32 bytes, got {}",
            pt.len()
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&pt[..32]);
    Ok(key)
}

/// Decrypt a v20 blob with the unwrapped 32-byte AES key. Same wire layout as v10.
pub fn decrypt_v20(blob: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    if blob.len() < 3 + 12 + 16 {
        return Err(Error::Parse("v20 blob too short".into()));
    }
    let nonce = &blob[3..15];
    let ct = &blob[15..];
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|_| Error::Parse("v20 GCM auth fail".into()))
}

/// Helper to chain APPB unwrap using `MasterkeyResolver`s.
///
/// Both DPAPI layers
/// can reference MKs from either keyring — Chrome's elevation_service writes
/// the v20 wrap entirely under SYSTEM-context user MKs (`S-1-5-18\User\`),
/// not the desktop user's Protect dir. So both resolvers are consulted for
/// each layer.
///
/// The same GUID can resolve to different bytes in the two keyrings — on some
/// Win11 builds the lsass cache decrypt corrupts the first 8 bytes of the MK
/// (wrong CBC IV). `decrypt_blob` has no HMAC verify, so a wrong MK silently
/// produces garbage. We collect every candidate MK for the GUID and pick the
/// one whose decrypted output has the shape expected for that layer.
pub fn unwrap_app_bound_with_resolvers<R, S>(
    appb: &[u8],
    user_resolver: &R,
    system_resolver: &S,
    key_map: &BrowserKeyMap,
    ksp_keys: &[[u8; 32]],
) -> Result<[u8; 32]>
where
    R: crate::chrome::disk::MasterkeyResolver,
    S: crate::chrome::disk::MasterkeyResolver,
{
    let collect = |guid: &str| -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        if let Some(u) = user_resolver.resolve(guid) {
            out.push(u);
        }
        if let Some(s) = system_resolver.resolve(guid) {
            if !out.iter().any(|x| x == &s) {
                out.push(s);
            }
        }
        out
    };
    unwrap_app_bound_key(
        appb,
        |user_blob| decrypt_layer(user_blob, AbeLayer::User, &collect),
        |system_blob| decrypt_layer(system_blob, AbeLayer::System, &collect),
        key_map,
        ksp_keys,
    )
}

/// Which DPAPI layer we're unwrapping inside the v20 chain.
#[derive(Clone, Copy)]
enum AbeLayer {
    /// `Local State.app_bound_encrypted_key` (after "APPB") — decrypts to a
    /// SYSTEM-context DPAPI blob.
    User,
    /// SYSTEM-context DPAPI blob — decrypts to the inner `aes_encrypted_key`
    /// envelope (`header_len || flag || path || cipher_len || cipher`).
    System,
}

impl AbeLayer {
    const fn label(self) -> &'static str {
        match self {
            Self::User => "layer1",
            Self::System => "layer2",
        }
    }

    /// True if `out` has the shape expected for this layer's plaintext.
    /// Used to detect wrong-MK decrypts that succeeded (no HMAC verify in
    /// `decrypt_blob`) but produced garbage bytes.
    fn validates(self, out: &[u8]) -> bool {
        match self {
            Self::User => parse_blob(strip_pkcs7(out)).is_ok(),
            Self::System => {
                if out.len() < 4 {
                    return false;
                }
                let header_len = u32::from_le_bytes([out[0], out[1], out[2], out[3]]);
                (1..4096).contains(&header_len)
            }
        }
    }
}

/// Parse a DPAPI blob, gather every candidate masterkey from `collect`, and
/// return the first decrypted output that validates for `layer`.
fn decrypt_layer<F>(blob: &[u8], layer: AbeLayer, collect: &F) -> Result<Vec<u8>>
where
    F: Fn(&str) -> Vec<Vec<u8>>,
{
    let parsed = parse_blob(blob)?;
    let candidates = collect(&parsed.mk_guid_str);
    if candidates.is_empty() {
        return Err(Error::Parse(format!(
            "ABE {} MK {} missing",
            layer.label(),
            parsed.mk_guid_str
        )));
    }
    let mut last_err = Error::Parse(format!(
        "ABE {} MK {}: all {} candidate(s) failed",
        layer.label(),
        parsed.mk_guid_str,
        candidates.len()
    ));
    for (i, mk) in candidates.iter().enumerate() {
        match decrypt_blob(&parsed, mk) {
            Ok(out) if layer.validates(&out) => {
                if i > 0 {
                    log::debug!(
                        "[abe {}] MK {} candidate {}/{} succeeded",
                        layer.label(),
                        parsed.mk_guid_str,
                        i + 1,
                        candidates.len()
                    );
                }
                return Ok(out);
            }
            Ok(_) => {
                last_err = Error::Parse(format!(
                    "ABE {} candidate {}/{} produced invalid output",
                    layer.label(),
                    i + 1,
                    candidates.len()
                ));
            }
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

fn strip_pkcs7(pt: &[u8]) -> &[u8] {
    if let Some(&pad) = pt.last() {
        let pad = pad as usize;
        if pad > 0
            && pad <= 16
            && pt.len() >= pad
            && pt[pt.len() - pad..].iter().all(|&b| b as usize == pad)
        {
            return &pt[..pt.len() - pad];
        }
    }
    pt
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chrome::abe_keys::CHROME_135_V3;
    use aes::Aes256;
    use aes_gcm::aead::Aead;
    use cbc::cipher::block_padding::NoPadding;
    use cbc::cipher::{BlockEncryptMut, KeyIvInit};

    type Aes256CbcEnc = cbc::Encryptor<Aes256>;

    #[test]
    fn rejects_non_appb() {
        let r = unwrap_app_bound_key(
            b"NOPE",
            |_| Ok(vec![0u8; 32]),
            |_| Ok(vec![0u8; 32]),
            &BrowserKeyMap::fallback(),
            &[],
        );
        assert!(r.is_err());
    }

    /// Wrap an inner `cipher` in the `header_len|flag|path|cipher_len|cipher` +
    /// PKCS#7 envelope the two DPAPI layers produce.
    fn build_aes_encrypted_key(flag: u8, path: &[u8], cipher: &[u8]) -> Vec<u8> {
        let header_len = (path.len() as u32) + 1;
        let mut buf = Vec::new();
        buf.extend_from_slice(&header_len.to_le_bytes());
        buf.push(flag);
        buf.extend_from_slice(path);
        buf.extend_from_slice(&(cipher.len() as u32).to_le_bytes());
        buf.extend_from_slice(cipher);
        let pad = 16 - (buf.len() % 16);
        buf.extend(std::iter::repeat_n(pad as u8, pad));
        buf
    }

    fn build_edge_aes_encrypted_key(v20_key: &[u8; 32], path: &[u8]) -> Vec<u8> {
        build_aes_encrypted_key(0x02, path, v20_key)
    }

    #[test]
    fn edge_flag2_raw_key_roundtrip() {
        let v20_key = [0xC4u8; 32];
        let blob = build_edge_aes_encrypted_key(&v20_key, b"C:\\Program Files\\Microsoft\\Edge");
        let recovered = decrypt_aes_encrypted_key_with_fallback(&blob).unwrap();
        assert_eq!(recovered, v20_key);
    }

    #[test]
    fn full_unwrap_through_three_layers_edge_flag2() {
        // Pretend the two DPAPI layers pass through unchanged (closures echo input).
        let v20_key = [0xA9u8; 32];
        let aes_encrypted_key =
            build_edge_aes_encrypted_key(&v20_key, b"C:\\Program Files\\Microsoft\\Edge");

        let mut appb = b"APPB".to_vec();
        appb.extend_from_slice(b"opaque_user_dpapi_blob");
        let aes_key_clone = aes_encrypted_key;
        let key = unwrap_app_bound_key(
            &appb,
            |_| Ok(b"opaque_system_dpapi_blob".to_vec()),
            move |_| Ok(aes_key_clone),
            &BrowserKeyMap::fallback(),
            &[],
        )
        .unwrap();
        assert_eq!(key, v20_key);
    }

    /// Chrome flag=1 (61-byte) path: version(1)|nonce(12)|ct(32)|tag(16), key =
    /// the version byte's static AES-GCM key.
    #[test]
    fn chrome_v1_61byte_gcm_roundtrip() {
        let map = BrowserKeyMap::fallback();
        let v1 = map.resolve(1).unwrap();
        let v20_key = [0x5Au8; 32];
        let nonce = [0x11u8; 12];
        let ct_tag = Aes256Gcm::new((&v1).into())
            .encrypt(Nonce::from_slice(&nonce), v20_key.as_slice())
            .unwrap();
        let mut cipher = vec![1u8];
        cipher.extend_from_slice(&nonce);
        cipher.extend_from_slice(&ct_tag);
        assert_eq!(cipher.len(), 61);
        let blob = build_aes_encrypted_key(0x01, b"C:\\Chrome", &cipher);
        assert_eq!(
            decrypt_aes_encrypted_key(&blob, &map, &[]).unwrap(),
            v20_key
        );
    }

    /// Build a synthetic flag=0 "v3" cipher for arbitrary ksp/static/v20 keys, so
    /// the NCrypt-derive + AES-GCM algorithm is validated without lab material.
    fn build_v3_cipher(
        ksp_key: &[u8; 32],
        static_v3: &[u8; 32],
        v20_key: &[u8; 32],
        nonce: &[u8; 12],
    ) -> Vec<u8> {
        // aead_key = CBC-dec(ksp, wrapped) XOR static  =>  wrapped = CBC-enc(ksp, aead_key XOR static)
        let mut ncrypt_out = [0u8; 32];
        for i in 0..32 {
            ncrypt_out[i] = v20_gcm_key_placeholder(v20_key)[i] ^ static_v3[i];
        }
        let mut wrapped = ncrypt_out;
        Aes256CbcEnc::new(ksp_key.into(), (&[0u8; 16]).into())
            .encrypt_padded_mut::<NoPadding>(&mut wrapped, 32)
            .unwrap();
        let ct_tag = Aes256Gcm::new((&v20_gcm_key_placeholder(v20_key)).into())
            .encrypt(Nonce::from_slice(nonce), v20_key.as_slice())
            .unwrap();
        let mut cipher = vec![3u8];
        cipher.extend_from_slice(&wrapped);
        cipher.extend_from_slice(nonce);
        cipher.extend_from_slice(&ct_tag);
        cipher
    }

    // The AEAD (GCM) key for the synthetic test — any 32 bytes; derived
    // deterministically from v20_key so the roundtrip is self-consistent.
    fn v20_gcm_key_placeholder(v20_key: &[u8; 32]) -> [u8; 32] {
        let mut k = *v20_key;
        k[0] ^= 0xFF;
        k
    }

    #[test]
    fn chrome_v3_ncrypt_derived_roundtrip_synthetic() {
        let ksp_key = [0x27u8; 32];
        let static_v3 = CHROME_135_V3;
        let v20_key = [0x91u8; 32];
        let nonce = [0x42u8; 12];
        let cipher = build_v3_cipher(&ksp_key, &static_v3, &v20_key, &nonce);
        assert_eq!(cipher.len(), 93);
        let map = BrowserKeyMap::fallback();
        let blob = build_aes_encrypted_key(0x00, b"C:\\Chrome", &cipher);
        // Wrong KSP key fails, correct one succeeds (GCM tag validates).
        assert!(decrypt_aes_encrypted_key(&blob, &map, &[[0u8; 32]]).is_err());
        assert_eq!(
            decrypt_aes_encrypted_key(&blob, &map, &[ksp_key]).unwrap(),
            v20_key
        );
        // v3 with no KSP key available is a clear error, not a panic.
        assert!(decrypt_aes_encrypted_key(&blob, &map, &[]).is_err());
    }

    /// Self-validating vector captured from a real Chrome 154 install (lab VM).
    /// Proves the byte layout + AES-CBC(zero-IV) NCrypt mode + XOR + GCM match
    /// actual `elevation_service.exe` output. The recovered key AES-256-GCM-
    /// decrypted the real v20 Login Data blob to the known plaintext.
    #[test]
    fn chrome_v3_real_vector() {
        let ksp_key: [u8; 32] =
            hex::decode("59a1a29f0778eb9a8d581ca7c259594004887b700acc3ed51f343f9aa8506d56")
                .unwrap()
                .try_into()
                .unwrap();
        // The 93-byte inner `cipher` (after the header/PKCS#7 strip).
        let cipher = hex::decode(
            "0361fa8683fda07c8a45aab2a060a6f80c40fab0fde0a9b1b58d9d2a4d4dbea412\
30c925cd20d83b979b13d52d171a268f2661b161c83715ad1429da739bdbcfbf3e3\
8e43612b7def5cd32cc16d6a6eb6191e1265498aa5d83c1725501",
        )
        .unwrap();
        assert_eq!(cipher.len(), 93);
        let expected: [u8; 32] =
            hex::decode("9cbf9857dc7c7f70548ecef02a6882c086ac562aa563a86bce5929c9618a869b")
                .unwrap()
                .try_into()
                .unwrap();
        let map = BrowserKeyMap::fallback(); // v3 entry: flag=0, algo=2, CHROME_135_V3
        let blob = build_aes_encrypted_key(0x00, b"C:\\Program Files\\Google\\Chrome", &cipher);
        let got = decrypt_aes_encrypted_key(&blob, &map, &[ksp_key]).unwrap();
        assert_eq!(got, expected);
    }
}
