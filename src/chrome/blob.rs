use crate::error::{Result, VmkatzError as Error};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};

#[derive(Debug, PartialEq, Eq)]
pub enum BlobScheme {
    V10,
    V11,
    V20, // app-bound; handled in abe.rs
    Unknown,
}

pub fn classify(blob: &[u8]) -> BlobScheme {
    if blob.len() < 3 {
        return BlobScheme::Unknown;
    }
    match &blob[..3] {
        b"v10" => BlobScheme::V10,
        b"v11" => BlobScheme::V11,
        b"v20" => BlobScheme::V20,
        _ => BlobScheme::Unknown,
    }
}

/// Decrypt v10/v11 blob with a 32-byte AES-GCM key.
/// `aad` is the optional Additional Authenticated Data; Chrome cookies may bind to
/// the host string starting at some versions, while passwords use empty AAD.
pub fn decrypt_v10(blob: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    decrypt_v10_aad(blob, key, &[])
}

/// Same as `decrypt_v10` but with explicit AAD.
pub fn decrypt_v10_aad(blob: &[u8], key: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < 3 + 12 + 16 {
        return Err(Error::Parse("v10 blob too short".into()));
    }
    let nonce = &blob[3..15];
    let ct = &blob[15..];
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| Error::Parse("v10 GCM auth fail".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};

    #[test]
    fn classify_works() {
        assert_eq!(classify(b"v10xxxxxxxxxxxxx"), BlobScheme::V10);
        assert_eq!(classify(b"v11xxxxxxxxxxxxx"), BlobScheme::V11);
        assert_eq!(classify(b"v20xxxxxxxxxxxxx"), BlobScheme::V20);
        assert_eq!(classify(b"junk"), BlobScheme::Unknown);
    }

    #[test]
    fn v10_roundtrip() {
        let key = [0x55u8; 32];
        let nonce = [0x11u8; 12];
        let plaintext = b"my_password_123";
        let cipher = Aes256Gcm::new((&key).into());
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
            .unwrap();
        let mut blob = Vec::new();
        blob.extend_from_slice(b"v10");
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        let pt = decrypt_v10(&blob, &key).unwrap();
        assert_eq!(pt, plaintext);
    }
}
