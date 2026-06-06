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

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};

use crate::chrome::abe_keys::BrowserKeyMap;
use crate::chrome::dpapi_decrypt::{decrypt_blob, parse_blob};
use crate::error::{Result, VmkatzError as Error};

/// Strip "APPB", run the two DPAPI layers via caller closures, then unwrap the
/// flag-byte-driven inner blob to return the 32-byte v20 AES-GCM key.
pub fn unwrap_app_bound_key<FU, FS>(
    appb: &[u8],
    decrypt_user: FU,
    decrypt_system: FS,
    key_map: &BrowserKeyMap,
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
    decrypt_aes_encrypted_key(&layer2, key_map)
}

/// Convenience wrapper: same as `decrypt_aes_encrypted_key` but uses the
/// hardcoded Chrome 135 fallback keys.
pub fn decrypt_aes_encrypted_key_with_fallback(aes_encrypted_key: &[u8]) -> Result<[u8; 32]> {
    decrypt_aes_encrypted_key(aes_encrypted_key, &BrowserKeyMap::fallback())
}

/// Given the output of the two DPAPI layers, parse the `<flag><nonce><ct><tag>`
/// envelope and AES-256-GCM-decrypt to recover the 32-byte v20 key.
pub fn decrypt_aes_encrypted_key(
    aes_encrypted_key: &[u8],
    key_map: &BrowserKeyMap,
) -> Result<[u8; 32]> {
    // Layout (after SYSTEM-DPAPI decrypt, post-PKCS#7-strip):
    //   header_len(u32 LE) || flag(u8) || install_path((header_len - 1) bytes)
    //   cipher_len(u32 LE) || cipher(cipher_len bytes)
    // PKCS#7 padding to a 16-byte boundary follows.
    let (_header, cipher, _flag) = parse_aes_encrypted_key_struct(aes_encrypted_key)?;

    // Edge (Microsoft) stores the v20 key inline as 32 raw bytes — no inner crypto.
    if cipher.len() == 32 {
        let mut key = [0u8; 32];
        key.copy_from_slice(cipher);
        return Ok(key);
    }
    // Chrome (Google) inner format: version(1) || nonce(12) || ct(32) || tag(16) = 61 bytes.
    // The version byte indexes a static AES-256-GCM key embedded in elevation_service.exe.
    if cipher.len() == 61 {
        let version = cipher[0];
        let key = key_map
            .resolve(version)
            .ok_or_else(|| Error::Parse(format!("Chrome ABE version {} unknown", version)))?;
        let nonce = &cipher[1..13];
        let ct = &cipher[13..];
        let gcm = Aes256Gcm::new((&key).into());
        let pt = gcm
            .decrypt(Nonce::from_slice(nonce), ct)
            .map_err(|_| Error::Parse("Chrome ABE inner GCM auth fail".into()))?;
        if pt.len() != 32 {
            return Err(Error::Parse(format!("Chrome ABE pt_len={} (want 32)", pt.len())));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&pt);
        return Ok(out);
    }
    Err(Error::Parse(format!(
        "ABE cipher_len={} unsupported (need 32 = Edge raw key or 61 = Chrome wrapped)",
        cipher.len()
    )))
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
    let unpadded_len = if pad >= 1 && pad <= 16 && blob.len() >= pad
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
            "ABE header_len {} out of range",
            header_len
        )));
    }
    let flag = buf[4];
    let header = &buf[..4 + header_len];
    let cipher_len_off = 4 + header_len;
    let cipher_len = u32::from_le_bytes(
        buf[cipher_len_off..cipher_len_off + 4].try_into().unwrap(),
    ) as usize;
    let cipher_off = cipher_len_off + 4;
    if cipher_off + cipher_len > buf.len() {
        return Err(Error::Parse(format!(
            "ABE cipher_len {} runs past buffer",
            cipher_len
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

/// Helper to chain APPB unwrap using `MasterkeyResolver`s. Both DPAPI layers
/// can reference MKs from either keyring — Chrome's elevation_service writes
/// the v20 wrap entirely under SYSTEM-context user MKs (`S-1-5-18\User\`),
/// not the desktop user's Protect dir. So both resolvers are consulted for
/// each layer.
pub fn unwrap_app_bound_with_resolvers<R, S>(
    appb: &[u8],
    user_resolver: &R,
    system_resolver: &S,
    key_map: &BrowserKeyMap,
) -> Result<[u8; 32]>
where
    R: crate::chrome::disk::MasterkeyResolver,
    S: crate::chrome::disk::MasterkeyResolver,
{
    // Same GUID may live in both keyrings with different bytes (some Win11
    // builds: lsass cache decrypt corrupts the first 8 bytes — wrong CBC IV).
    // Try each candidate and let per-layer output validation pick the survivor.
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
    // `decrypt_blob` returns garbage (not an error) on wrong MK because the
    // AES-CBC step succeeds regardless. So validate the OUTPUT shape per layer:
    //   - layer1: output must itself parse as a DPAPI blob (system layer).
    //   - layer2: output must start with a small `header_len` u32.
    let try_layer = |blob: &[u8], layer: &str,
                     valid: &dyn Fn(&[u8]) -> bool| -> Result<Vec<u8>> {
        let parsed = parse_blob(blob)?;
        let candidates = collect(&parsed.mk_guid_str);
        if candidates.is_empty() {
            return Err(Error::Parse(format!(
                "ABE {} MK {} missing",
                layer, parsed.mk_guid_str
            )));
        }
        let mut last_err: Option<Error> = None;
        for (i, mk) in candidates.iter().enumerate() {
            match decrypt_blob(&parsed, mk) {
                Ok(out) if valid(&out) => {
                    if i > 0 {
                        log::debug!(
                            "[abe {}] MK {} candidate {}/{} succeeded",
                            layer, parsed.mk_guid_str, i + 1, candidates.len()
                        );
                    }
                    return Ok(out);
                }
                Ok(_) => last_err = Some(Error::Parse(format!(
                    "ABE {} candidate {}/{} produced invalid output",
                    layer, i + 1, candidates.len()
                ))),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap())
    };
    let validate_layer1 = |out: &[u8]| -> bool {
        // Strip trailing PKCS#7 then try parsing as another DPAPI blob.
        let trimmed = strip_pkcs7(out);
        parse_blob(trimmed).is_ok()
    };
    let validate_layer2 = |out: &[u8]| -> bool {
        // Layer 2 output begins with header_len (u32 LE) which is small (path + 1).
        if out.len() < 4 {
            return false;
        }
        let header_len = u32::from_le_bytes([out[0], out[1], out[2], out[3]]);
        header_len > 0 && header_len < 4096
    };
    unwrap_app_bound_key(
        appb,
        |user_blob| try_layer(user_blob, "layer1", &validate_layer1),
        |system_blob| try_layer(system_blob, "layer2", &validate_layer2),
        key_map,
    )
}

fn strip_pkcs7(pt: &[u8]) -> &[u8] {
    if let Some(&pad) = pt.last() {
        let pad = pad as usize;
        if pad > 0 && pad <= 16 && pt.len() >= pad
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
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};

    #[test]
    fn rejects_non_appb() {
        let r = unwrap_app_bound_key(
            b"NOPE",
            |_| Ok(vec![0u8; 32]),
            |_| Ok(vec![0u8; 32]),
            &BrowserKeyMap::fallback(),
        );
        assert!(r.is_err());
    }

    /// Build an Edge-style flag=2 aes_encrypted_key with the v20 key embedded raw.
    fn build_edge_aes_encrypted_key(v20_key: &[u8; 32], path: &[u8]) -> Vec<u8> {
        let header_len = (path.len() as u32) + 1;
        let mut buf = Vec::new();
        buf.extend_from_slice(&header_len.to_le_bytes());
        buf.push(0x02);
        buf.extend_from_slice(path);
        buf.extend_from_slice(&32u32.to_le_bytes());
        buf.extend_from_slice(v20_key);
        // PKCS#7 pad to a multiple of 16.
        let pad = 16 - (buf.len() % 16);
        buf.extend(std::iter::repeat(pad as u8).take(pad));
        buf
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
        let aes_key_clone = aes_encrypted_key.clone();
        let key = unwrap_app_bound_key(
            &appb,
            |_| Ok(b"opaque_system_dpapi_blob".to_vec()),
            move |_| Ok(aes_key_clone),
            &BrowserKeyMap::fallback(),
        )
        .unwrap();
        assert_eq!(key, v20_key);
    }
}
