//! App-Bound Encryption (Chrome v127+) v20 blob decrypt.
//!
//! The chain unwraps `Local State.app_bound_encrypted_key` (APPB prefix) through two
//! DPAPI layers — user then SYSTEM — and yields a 32-byte AES-256-GCM key used for
//! blobs prefixed `v20`. The Chrome Elevation Service adds a per-install obfuscation
//! step on the inner key; we conservatively assume the unwrapped layer-2 output's
//! trailing 32 bytes are the AES key, which matches the layout observed in published
//! reversing notes. May need adjustment as Chrome iterates.

use crate::chrome::dpapi_decrypt::{decrypt_blob, parse_blob};
use crate::error::{Result, VmkatzError as Error};

/// Given the raw decoded base64 blob (starting with "APPB"), peel both DPAPI layers
/// via the caller-provided closures and return the inner 32-byte AES key.
///
/// `decrypt_user`   — decrypts a user-DPAPI blob -> bytes
/// `decrypt_system` — decrypts a SYSTEM-DPAPI blob -> bytes
pub fn unwrap_app_bound_key<FU, FS>(
    appb: &[u8],
    decrypt_user: FU,
    decrypt_system: FS,
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
    if layer2.len() < 32 {
        return Err(Error::Parse("ABE inner < 32 bytes".into()));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&layer2[layer2.len() - 32..]);
    Ok(key)
}

/// Decrypt a v20 blob with the unwrapped 32-byte AES key. Same wire layout as v10.
pub fn decrypt_v20(blob: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
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

/// Helper to chain APPB unwrap using the chrome MasterkeyResolver and DPAPI primitives.
/// Use this from the disk orchestrator; caller supplies a resolver for both user and SYSTEM SIDs.
pub fn unwrap_app_bound_with_resolvers<R, S>(
    appb: &[u8],
    user_resolver: &R,
    system_resolver: &S,
) -> Result<[u8; 32]>
where
    R: crate::chrome::disk::MasterkeyResolver,
    S: crate::chrome::disk::MasterkeyResolver,
{
    unwrap_app_bound_key(
        appb,
        |user_blob| {
            let parsed = parse_blob(user_blob)?;
            let mk = user_resolver
                .resolve(&parsed.mk_guid_str)
                .ok_or_else(|| Error::Parse(format!("ABE user MK {} missing", parsed.mk_guid_str)))?;
            decrypt_blob(&parsed, &mk)
        },
        |system_blob| {
            let parsed = parse_blob(system_blob)?;
            let mk = system_resolver
                .resolve(&parsed.mk_guid_str)
                .ok_or_else(|| Error::Parse(format!("ABE system MK {} missing", parsed.mk_guid_str)))?;
            decrypt_blob(&parsed, &mk)
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unwrap_rejects_non_appb() {
        let r = unwrap_app_bound_key(b"NOPE", |_| Ok(vec![0u8; 32]), |_| Ok(vec![0u8; 32]));
        assert!(r.is_err());
    }

    #[test]
    fn unwrap_extracts_trailing_key() {
        let trailing = [0xABu8; 32];
        let mut input = Vec::from(*b"APPB");
        input.extend_from_slice(b"user_layer_bytes");
        let key = unwrap_app_bound_key(
            &input,
            |_| Ok(b"system_layer".to_vec()),
            move |_| {
                let mut out = vec![0u8; 8];
                out.extend_from_slice(&trailing);
                Ok(out)
            },
        )
        .unwrap();
        assert_eq!(key, trailing);
    }

    #[test]
    fn unwrap_errors_when_layer2_too_short() {
        let mut input = Vec::from(*b"APPB");
        input.extend_from_slice(b"x");
        let r = unwrap_app_bound_key(&input, |_| Ok(b"a".to_vec()), |_| Ok(vec![0u8; 16]));
        assert!(r.is_err());
    }
}
