//! DPAPI Master Key file parser and Hashcat hash generator.
//!
//! Extracts encrypted master key files from NTFS disk images at:
//!   `Users\{user}\AppData\Roaming\Microsoft\Protect\{SID}\{GUID}`
//!
//! Generates Hashcat-compatible hashes:
//!   - Mode 15300: DPAPI masterkey v1, local user (3DES/SHA1, SHA1 pre-key)
//!   - Mode 15310: DPAPI masterkey v1, domain user (3DES/SHA1, NTLM pre-key)
//!   - Mode 15900: DPAPI masterkey v2, local user (AES256/SHA512, SHA1 pre-key)
//!   - Mode 15910: DPAPI masterkey v2, domain user (AES256/SHA512, NTLM pre-key)

use std::io::{Read, Seek};

use aes::Aes256;
use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use des::TdesEde3;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Sha512;

use crate::error::{Result, VmkatzError};

type Aes256CbcDec = cbc::Decryptor<Aes256>;
type TdesCbcDec = cbc::Decryptor<TdesEde3>;
type HmacSha1 = Hmac<Sha1>;
type HmacSha512 = Hmac<Sha512>;

/// Maximum allowed PBKDF2 rounds — prevents pathological inputs from
/// burning CPU forever. Real-world MK files use 4k–8k rounds.
const MAX_PBKDF2_ROUNDS: u32 = 10_000_000;
/// Minimum cleartext masterkey blob size (64 MK + 64 HMAC = 128, padding may extend).
const MIN_DECRYPTED_LEN: usize = 64;

/// CryptoAPI algorithm identifiers (wincrypt.h).
const CALG_3DES: u32 = 0x6603;
const CALG_AES_256: u32 = 0x6610;
const CALG_SHA1: u32 = 0x8004;
const CALG_SHA_512: u32 = 0x800E;

/// Minimum master key file size: 128-byte header + 32-byte sub-header.
const MIN_FILE_SIZE: usize = 128 + 32;

/// Parsed DPAPI master key file header (128 bytes at offset 0).
#[derive(Debug)]
#[allow(dead_code)]
struct MasterKeyFileHeader {
    version: u32,
    guid: String,
    flags: u32,
    masterkey_len: u64,
    backupkey_len: u64,
    credhist_len: u64,
    domainkey_len: u64,
}

/// Parsed master key section (salt, rounds, algorithms, ciphertext).
#[derive(Debug)]
#[allow(dead_code)]
struct MasterKeySection {
    version: u32,
    salt: [u8; 16],
    rounds: u32,
    alg_hash: u32,
    alg_crypt: u32,
    ciphertext: Vec<u8>,
}

/// A DPAPI master key hash ready for Hashcat output.
#[derive(Debug)]
pub struct DpapiMasterKeyHash {
    /// User account name (from NTFS path).
    pub username: String,
    /// User SID (from Protect directory name).
    pub sid: String,
    /// Master key GUID.
    pub guid: String,
    /// Hashcat-format string ($DPAPImk$...).
    pub hash: String,
    /// Hashcat mode (15300 or 15900).
    pub mode: u32,
    /// NTFS modification time (Windows FILETIME, 0 if unavailable).
    pub modified: u64,
}

/// Parse the 128-byte file header.
fn parse_header(data: &[u8]) -> Result<MasterKeyFileHeader> {
    if data.len() < 128 {
        return Err(VmkatzError::DecryptionError(
            "DPAPI masterkey file too short for header".to_string(),
        ));
    }

    let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

    // GUID at offset 0x0C, 72 bytes of UTF-16LE (36 WCHAR = 72 bytes)
    let guid_bytes = &data[0x0C..0x0C + 72];
    let guid = String::from_utf16_lossy(
        &guid_bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&ch| ch != 0) // stop at null terminator
            .collect::<Vec<u16>>(),
    );

    let flags = u32::from_le_bytes([data[0x5C], data[0x5D], data[0x5E], data[0x5F]]);
    let masterkey_len = u64::from_le_bytes([
        data[0x60], data[0x61], data[0x62], data[0x63],
        data[0x64], data[0x65], data[0x66], data[0x67],
    ]);
    let backupkey_len = u64::from_le_bytes([
        data[0x68], data[0x69], data[0x6A], data[0x6B],
        data[0x6C], data[0x6D], data[0x6E], data[0x6F],
    ]);
    let credhist_len = u64::from_le_bytes([
        data[0x70], data[0x71], data[0x72], data[0x73],
        data[0x74], data[0x75], data[0x76], data[0x77],
    ]);
    let domainkey_len = u64::from_le_bytes([
        data[0x78], data[0x79], data[0x7A], data[0x7B],
        data[0x7C], data[0x7D], data[0x7E], data[0x7F],
    ]);

    Ok(MasterKeyFileHeader {
        version,
        guid,
        flags,
        masterkey_len,
        backupkey_len,
        credhist_len,
        domainkey_len,
    })
}

/// Parse the master key section (32-byte sub-header + ciphertext).
fn parse_masterkey_section(data: &[u8]) -> Result<MasterKeySection> {
    if data.len() < 32 {
        return Err(VmkatzError::DecryptionError(
            "Master key section too short".to_string(),
        ));
    }

    let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

    let mut salt = [0u8; 16];
    salt.copy_from_slice(&data[0x04..0x14]);

    let rounds = u32::from_le_bytes([data[0x14], data[0x15], data[0x16], data[0x17]]);
    let alg_hash = u32::from_le_bytes([data[0x18], data[0x19], data[0x1A], data[0x1B]]);
    let alg_crypt = u32::from_le_bytes([data[0x1C], data[0x1D], data[0x1E], data[0x1F]]);

    let ciphertext = data[0x20..].to_vec();

    Ok(MasterKeySection {
        version,
        salt,
        rounds,
        alg_hash,
        alg_crypt,
        ciphertext,
    })
}

/// Map CryptoAPI cipher ALG_ID to hashcat string.
fn cipher_name(alg: u32) -> Option<&'static str> {
    match alg {
        CALG_3DES => Some("des3"),
        CALG_AES_256 => Some("aes256"),
        _ => None,
    }
}

/// Map CryptoAPI hash ALG_ID to hashcat string.
fn hash_name(alg: u32) -> Option<&'static str> {
    match alg {
        CALG_SHA1 => Some("sha1"),
        CALG_SHA_512 => Some("sha512"),
        _ => None,
    }
}

/// Parsed MK section fields needed to actually decrypt the masterkey.
/// Public face of the private `MasterKeySection` so external callers can
/// drive `decrypt_masterkey_with_prekey` without re-parsing the file.
#[derive(Debug, Clone)]
pub struct MasterKeyDecryptInput {
    pub salt: [u8; 16],
    pub rounds: u32,
    pub alg_hash: u32,
    pub alg_crypt: u32,
    pub ciphertext: Vec<u8>,
}

/// Extract the MK section from a full masterkey file. Returns `None` if the
/// file is malformed, the algorithms aren't supported, or required fields are
/// missing. Validates the same invariants as `parse_masterkey_file`.
pub fn extract_mk_section(file_bytes: &[u8]) -> Option<MasterKeyDecryptInput> {
    if file_bytes.len() < MIN_FILE_SIZE {
        return None;
    }
    let header = parse_header(file_bytes).ok()?;
    if header.version == 0 || header.version > 2 {
        return None;
    }
    if header.masterkey_len < 32 || header.masterkey_len > 1024 {
        return None;
    }
    let mk_start = 0x80usize;
    let mk_end = mk_start + header.masterkey_len as usize;
    if mk_end > file_bytes.len() {
        return None;
    }
    let mk = parse_masterkey_section(&file_bytes[mk_start..mk_end]).ok()?;
    // Validate alg pair is one we can dispatch on.
    let (_c, _h) = (cipher_name(mk.alg_crypt)?, hash_name(mk.alg_hash)?);
    if mk.ciphertext.is_empty() || mk.rounds == 0 || mk.rounds > MAX_PBKDF2_ROUNDS {
        return None;
    }
    Some(MasterKeyDecryptInput {
        salt: mk.salt,
        rounds: mk.rounds,
        alg_hash: mk.alg_hash,
        alg_crypt: mk.alg_crypt,
        ciphertext: mk.ciphertext,
    })
}

/// Encode a SID into the UTF-16LE byte form DPAPI expects: each codepoint
/// little-endian, followed by a trailing NUL widechar.
fn sid_utf16le_with_nul(sid: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = sid
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    bytes.extend_from_slice(&[0u8, 0u8]);
    bytes
}

/// Compute the 20-byte DPAPI pre-key for a domain user (NTLM-hash path):
///   `HMAC-SHA1(key = nt_hash, msg = UTF-16LE(SID + "\0"))`.
///
/// For LOCAL accounts on Win10+, the canonical chain uses the actual password
/// (`HMAC-SHA1(SHA1(UTF-16LE password), sid_utf16)`) — see [`user_local_prekey_pw`].
fn user_local_prekey(nt_hash: &[u8; 16], sid: &str) -> Result<[u8; 20]> {
    let msg = sid_utf16le_with_nul(sid);
    let mut mac = HmacSha1::new_from_slice(nt_hash)
        .map_err(|_| VmkatzError::DecryptionError("HMAC-SHA1 key init".into()))?;
    mac.update(&msg);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 20];
    out.copy_from_slice(&tag);
    Ok(out)
}

/// Compute the 20-byte DPAPI pre-key for a local-account user MK from a known password:
///   `HMAC-SHA1(key = SHA1(UTF-16LE password), msg = UTF-16LE(SID + "\0"))`.
fn user_local_prekey_pw(password: &str, sid: &str) -> Result<[u8; 20]> {
    use sha1::{Digest, Sha1};
    let pwd_utf16: Vec<u8> = password
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    let pwd_sha1 = Sha1::digest(&pwd_utf16);
    let msg = sid_utf16le_with_nul(sid);
    let mut mac = HmacSha1::new_from_slice(&pwd_sha1)
        .map_err(|_| VmkatzError::DecryptionError("HMAC-SHA1 key init".into()))?;
    mac.update(&msg);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 20];
    out.copy_from_slice(&tag);
    Ok(out)
}

/// Decrypt a DPAPI masterkey file given an already-derived 20-byte pre-key.
///
/// Dispatches between AES-256/SHA-512 (modern, hashcat mode 15900) and
/// 3DES/SHA-1 (legacy, mode 15300) based on the file's `alg_crypt`/`alg_hash`.
/// Returns the 64-byte cleartext masterkey.
pub fn decrypt_masterkey_with_prekey(
    file_bytes: &[u8],
    pre_key: &[u8],
) -> Result<Vec<u8>> {
    let mk = extract_mk_section(file_bytes).ok_or_else(|| {
        VmkatzError::DecryptionError("malformed or unsupported DPAPI MK file".into())
    })?;
    if mk.ciphertext.len() < 64 {
        return Err(VmkatzError::DecryptionError(
            "MK ciphertext shorter than 64 bytes".into(),
        ));
    }
    let plaintext = match (mk.alg_crypt, mk.alg_hash) {
        (CALG_AES_256, CALG_SHA_512) => {
            // DPAPI's MK derivation is NOT standard PBKDF2 — Microsoft uses an
            // XOR-accumulator-feedback variant where each iteration's PRF input is
            // the accumulated XOR (not the previous round's output). Standard
            // PBKDF2 from the `pbkdf2` crate produces a different (wrong) key.
            let derived = dpapi_derive_key_sha512(pre_key, &mk.salt, 48, mk.rounds);
            let aes_key: [u8; 32] = derived[..32].try_into().unwrap();
            let iv: [u8; 16] = derived[32..48].try_into().unwrap();
            if mk.ciphertext.len() % 16 != 0 {
                return Err(VmkatzError::DecryptionError(
                    "AES MK ciphertext not block-aligned".into(),
                ));
            }
            let mut buf = mk.ciphertext.clone();
            let cipher = Aes256CbcDec::new((&aes_key).into(), (&iv).into());
            cipher
                .decrypt_padded_mut::<NoPadding>(&mut buf)
                .map_err(|_| {
                    VmkatzError::DecryptionError("AES-256-CBC MK decrypt failed".into())
                })?;
            buf
        }
        (CALG_3DES, CALG_SHA1) => {
            // DPAPI MK derivation variant (see above) using SHA-1.
            let derived = dpapi_derive_key_sha1(pre_key, &mk.salt, 32, mk.rounds);
            let des3_key = &derived[..24];
            let iv = &derived[24..32];
            if mk.ciphertext.len() % 8 != 0 {
                return Err(VmkatzError::DecryptionError(
                    "3DES MK ciphertext not block-aligned".into(),
                ));
            }
            let mut buf = mk.ciphertext.clone();
            let cipher = TdesCbcDec::new(des3_key.into(), iv.into());
            cipher
                .decrypt_padded_mut::<NoPadding>(&mut buf)
                .map_err(|_| {
                    VmkatzError::DecryptionError("3DES-CBC MK decrypt failed".into())
                })?;
            buf
        }
        _ => {
            return Err(VmkatzError::DecryptionError(format!(
                "unsupported MK alg pair: crypt=0x{:x} hash=0x{:x}",
                mk.alg_crypt, mk.alg_hash
            )));
        }
    };

    if plaintext.len() < MIN_DECRYPTED_LEN {
        return Err(VmkatzError::DecryptionError(
            "decrypted MK plaintext shorter than 64 bytes".into(),
        ));
    }
    // Cleartext layout per impacket dpapi.py MasterKey.decrypt:
    //   hmacSalt(16) || hmac(hash_size) || ... || decryptedKey(64)
    // Verify HMAC before trusting the result; on mismatch the pre-key was wrong
    // and the "decrypted" bytes are garbage.
    let hash_size = match mk.alg_hash {
        CALG_SHA_512 => 64,
        CALG_SHA1 => 20,
        _ => 0,
    };
    // Cleartext layout per impacket dpapi.py MasterKey.decrypt:
    //   hmacSalt(16) || hmac(hash_size) || ... || decryptedKey(64)
    // HMAC-verify before trusting the result; wrong pre-key → all-garbage decrypt.
    if hash_size > 0 && plaintext.len() >= 16 + hash_size + 64 {
        let hmac_salt = &plaintext[..16];
        let stored_hmac = &plaintext[16..16 + hash_size];
        let decrypted_key = &plaintext[plaintext.len() - 64..];
        let ok = match mk.alg_hash {
            CALG_SHA_512 => verify_mk_hmac_sha512(pre_key, hmac_salt, decrypted_key, stored_hmac),
            CALG_SHA1 => verify_mk_hmac_sha1(pre_key, hmac_salt, decrypted_key, stored_hmac),
            _ => false,
        };
        if !ok {
            return Err(VmkatzError::DecryptionError(
                "MK HMAC verification failed (wrong pre-key)".into(),
            ));
        }
    }
    Ok(plaintext[plaintext.len() - 64..].to_vec())
}

/// DPAPI's masterkey-file key-derivation function. Microsoft uses a non-standard
/// PBKDF2 variant where each iteration's PRF input is the accumulated XOR rather
/// than the previous round's PRF output. Standard PBKDF2 (RFC 2898) produces a
/// different key and will fail to decrypt real DPAPI files.
///
/// Algorithm (matching impacket's MasterKey.deriveKey):
///   for each output block:
///     U_1 = HMAC(passphrase, salt || INT(i))    where i = 1, 2, ...
///     acc = U_1
///     for r in 1..count:
///       acc = acc XOR HMAC(passphrase, acc)
///     append acc to output
fn dpapi_derive_key_sha512(passphrase: &[u8], salt: &[u8], keylen: usize, count: u32) -> Vec<u8> {
    use hmac::Mac;
    let mut out: Vec<u8> = Vec::with_capacity(keylen);
    let mut block_i: u32 = 1;
    while out.len() < keylen {
        let mut h = HmacSha512::new_from_slice(passphrase).expect("HMAC-SHA512 key");
        h.update(salt);
        h.update(&block_i.to_be_bytes());
        let mut acc = h.finalize().into_bytes().to_vec();
        for _ in 1..count {
            let mut h = HmacSha512::new_from_slice(passphrase).expect("HMAC-SHA512 key");
            h.update(&acc);
            let next = h.finalize().into_bytes();
            for (a, n) in acc.iter_mut().zip(next.iter()) {
                *a ^= *n;
            }
        }
        out.extend_from_slice(&acc);
        block_i += 1;
    }
    out.truncate(keylen);
    out
}

fn dpapi_derive_key_sha1(passphrase: &[u8], salt: &[u8], keylen: usize, count: u32) -> Vec<u8> {
    use hmac::Mac;
    let mut out: Vec<u8> = Vec::with_capacity(keylen);
    let mut block_i: u32 = 1;
    while out.len() < keylen {
        let mut h = HmacSha1::new_from_slice(passphrase).expect("HMAC-SHA1 key");
        h.update(salt);
        h.update(&block_i.to_be_bytes());
        let mut acc = h.finalize().into_bytes().to_vec();
        for _ in 1..count {
            let mut h = HmacSha1::new_from_slice(passphrase).expect("HMAC-SHA1 key");
            h.update(&acc);
            let next = h.finalize().into_bytes();
            for (a, n) in acc.iter_mut().zip(next.iter()) {
                *a ^= *n;
            }
        }
        out.extend_from_slice(&acc);
        block_i += 1;
    }
    out.truncate(keylen);
    out
}

fn verify_mk_hmac_sha512(pre_key: &[u8], salt: &[u8], mk: &[u8], stored: &[u8]) -> bool {
    use hmac::Mac;
    let mut h1 = match HmacSha512::new_from_slice(pre_key) { Ok(h) => h, Err(_) => return false };
    h1.update(salt);
    let key2 = h1.finalize().into_bytes();
    let mut h2 = match HmacSha512::new_from_slice(&key2) { Ok(h) => h, Err(_) => return false };
    h2.update(mk);
    h2.finalize().into_bytes().as_slice() == stored
}

fn verify_mk_hmac_sha1(pre_key: &[u8], salt: &[u8], mk: &[u8], stored: &[u8]) -> bool {
    use hmac::Mac;
    let mut h1 = match HmacSha1::new_from_slice(pre_key) { Ok(h) => h, Err(_) => return false };
    h1.update(salt);
    let key2 = h1.finalize().into_bytes();
    let mut h2 = match HmacSha1::new_from_slice(&key2) { Ok(h) => h, Err(_) => return false };
    h2.update(mk);
    h2.finalize().into_bytes().as_slice() == stored
}

/// Decrypt a user DPAPI masterkey file (local-account, mode 15900 or 15300).
///
/// `nt_hash` is the user's 16-byte NT hash from SAM.
/// `sid` is the user's SID (e.g. `"S-1-5-21-...-1000"`).
/// Returns the 64-byte cleartext masterkey.
pub fn decrypt_local_user_masterkey(
    file_bytes: &[u8],
    nt_hash: &[u8; 16],
    sid: &str,
) -> Result<Vec<u8>> {
    let pre_key = user_local_prekey(nt_hash, sid)?;
    decrypt_masterkey_with_prekey(file_bytes, &pre_key)
}

/// Decrypt a user DPAPI masterkey file using a known cleartext password
/// (typically sourced from LSA `DefaultPassword` or a memory snapshot).
pub fn decrypt_local_user_masterkey_pw(
    file_bytes: &[u8],
    password: &str,
    sid: &str,
) -> Result<Vec<u8>> {
    let pre_key = user_local_prekey_pw(password, sid)?;
    decrypt_masterkey_with_prekey(file_bytes, &pre_key)
}

/// Decrypt a SYSTEM DPAPI masterkey file (S-1-5-18) using the LSA
/// `DPAPI_SYSTEM` machine half (20 bytes).
pub fn decrypt_system_masterkey(
    file_bytes: &[u8],
    dpapi_system_machine_key: &[u8; 20],
) -> Result<Vec<u8>> {
    decrypt_masterkey_with_prekey(file_bytes, dpapi_system_machine_key)
}

/// Parse a DPAPI master key file and generate a Hashcat hash string.
///
/// Returns None if the file is not a valid DPAPI master key file.
/// `modified` is the NTFS modification time as a Windows FILETIME (0 if unavailable).
pub fn parse_masterkey_file(
    data: &[u8],
    username: &str,
    sid: &str,
    modified: u64,
) -> Option<DpapiMasterKeyHash> {
    if data.len() < MIN_FILE_SIZE {
        return None;
    }

    let header = parse_header(data).ok()?;

    // Validate: version should be 1 or 2
    if header.version == 0 || header.version > 2 {
        return None;
    }

    // Validate: masterkey_len should be reasonable (32 sub-header + ciphertext)
    if header.masterkey_len < 32 || header.masterkey_len > 1024 {
        return None;
    }

    // Master key section starts at offset 0x80
    let mk_start = 0x80usize;
    let mk_end = mk_start + header.masterkey_len as usize;
    if mk_end > data.len() {
        return None;
    }

    let mk = parse_masterkey_section(&data[mk_start..mk_end]).ok()?;

    // Validate algorithms
    let cipher = cipher_name(mk.alg_crypt)?;
    let hash = hash_name(mk.alg_hash)?;

    if mk.ciphertext.is_empty() || mk.rounds == 0 {
        return None;
    }

    // Determine hashcat version: 1 = 3DES/SHA1, 2 = AES256/SHA512
    let hc_version = match (mk.alg_crypt, mk.alg_hash) {
        (CALG_3DES, CALG_SHA1) => 1u32,
        (CALG_AES_256, CALG_SHA_512) => 2,
        _ => return None,
    };

    // Context: 1 = local user (SHA1 pre-key), 2 = domain user (NTLM pre-key)
    // Heuristic: if domainkey_len > 0, the master key has a domain key section,
    // indicating a domain-joined machine where NTLM pre-key was used.
    let context = if header.domainkey_len > 0 { 2u32 } else { 1u32 };

    // Hashcat mode: context 1 = local (SHA1 pre-key), context 2 = domain (NTLM pre-key)
    let mode = match (hc_version, context) {
        (1, 1) => 15300, // 3DES/SHA1, local
        (1, 2) => 15310, // 3DES/SHA1, domain
        (2, 1) => 15900, // AES256/SHA512, local
        (2, 2) => 15910, // AES256/SHA512, domain
        _ => return None,
    };

    // Build hashcat string:
    // $DPAPImk${version}*{context}*{SID}*{cipher}*{hash}*{rounds}*{iv_hex}*{contents_len}*{contents_hex}
    // contents_len = number of hex characters (2 × byte count)
    let iv_hex = hex::encode(mk.salt);
    let contents_hex = hex::encode(&mk.ciphertext);
    let contents_len = contents_hex.len();

    let hash_str = format!(
        "$DPAPImk${}*{}*{}*{}*{}*{}*{}*{}*{}",
        hc_version, context, sid, cipher, hash, mk.rounds, iv_hex, contents_len, contents_hex
    );

    Some(DpapiMasterKeyHash {
        username: username.to_string(),
        sid: sid.to_string(),
        guid: header.guid,
        hash: hash_str,
        mode,
        modified,
    })
}

/// Extract DPAPI master key hashes from all user profiles on an NTFS partition.
///
/// Scans `Users\*\AppData\Roaming\Microsoft\Protect\{SID}\{GUID}` for each user.
pub fn extract_masterkey_hashes_from_partition<R: Read + Seek>(
    reader: &mut R,
    partition_offset: u64,
) -> Vec<DpapiMasterKeyHash> {
    let mut results = Vec::new();

    let mut part_reader = super::ntfs_reader::PartitionReader::new(reader, partition_offset);

    let ntfs = match ntfs::Ntfs::new(&mut part_reader) {
        Ok(n) => n,
        Err(e) => {
            log::info!("NTFS parse error for DPAPI scan: {}", e);
            return results;
        }
    };

    let root = match ntfs.root_directory(&mut part_reader) {
        Ok(r) => r,
        Err(e) => {
            log::info!("NTFS root dir error for DPAPI scan: {}", e);
            return results;
        }
    };

    // Scan SYSTEM profile: Windows\System32\Microsoft\Protect\S-1-5-18\
    scan_protect_dir(
        &ntfs,
        &root,
        &mut part_reader,
        "Windows\\System32\\Microsoft\\Protect",
        "SYSTEM",
        &mut results,
    );

    // Find Users directory
    let users_dir = match super::ntfs_reader::find_entry(&ntfs, &root, &mut part_reader, "Users") {
        Ok(d) => d,
        Err(_) => return results,
    };

    // Scan each user profile: Users\{user}\AppData\Roaming\Microsoft\Protect
    let user_entries =
        match super::ntfs_reader::list_directory(&ntfs, &users_dir, &mut part_reader) {
            Ok(e) => e,
            Err(_) => return results,
        };

    for (username, is_dir) in &user_entries {
        if !is_dir {
            continue;
        }
        let lower = username.to_lowercase();
        if lower == "public" || lower == "default" || lower == "default user" || lower == "all users" {
            continue;
        }

        let protect_path = format!("{}\\AppData\\Roaming\\Microsoft\\Protect", username);
        scan_protect_dir(
            &ntfs,
            &users_dir,
            &mut part_reader,
            &protect_path,
            username,
            &mut results,
        );
    }

    results
}

/// Scan a Protect directory for DPAPI master key files.
fn scan_protect_dir<'n, R: Read + Seek>(
    ntfs: &'n ntfs::Ntfs,
    base_dir: &ntfs::NtfsFile<'n>,
    reader: &mut R,
    protect_path: &str,
    username: &str,
    results: &mut Vec<DpapiMasterKeyHash>,
) {
    let protect_dir =
        match super::ntfs_reader::navigate_to_dir(ntfs, base_dir, reader, protect_path) {
            Ok(d) => d,
            Err(_) => return,
        };

    let sid_entries =
        match super::ntfs_reader::list_directory(ntfs, &protect_dir, reader) {
            Ok(e) => e,
            Err(_) => return,
        };

    for (sid_name, is_sid_dir) in &sid_entries {
        if !is_sid_dir || !sid_name.starts_with("S-1-5-") {
            continue;
        }

        let sid_dir =
            match super::ntfs_reader::find_entry(ntfs, &protect_dir, reader, sid_name) {
                Ok(d) => d,
                Err(_) => continue,
            };

        let mk_entries =
            match super::ntfs_reader::list_directory(ntfs, &sid_dir, reader) {
                Ok(e) => e,
                Err(_) => continue,
            };

        for (mk_name, is_mk_dir) in &mk_entries {
            if *is_mk_dir || !is_guid_filename(mk_name) {
                continue;
            }

            let mk_file =
                match super::ntfs_reader::find_entry(ntfs, &sid_dir, reader, mk_name) {
                    Ok(f) => f,
                    Err(_) => continue,
                };

            let mk_data = match super::ntfs_reader::read_file_data(&mk_file, reader) {
                Ok(d) => d,
                Err(_) => continue,
            };

            // Read NTFS modification time as a proxy for key creation date
            let modified = mk_file
                .info()
                .ok()
                .map(|info| info.modification_time().nt_timestamp())
                .unwrap_or(0);

            if let Some(hash) = parse_masterkey_file(&mk_data, username, sid_name, modified) {
                log::info!(
                    "DPAPI masterkey: user={} SID={} GUID={} mode={}",
                    username, sid_name, hash.guid, hash.mode
                );
                results.push(hash);
            }
        }
    }
}

/// Check if a filename looks like a GUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx).
fn is_guid_filename(name: &str) -> bool {
    if name.len() != 36 {
        return false;
    }
    let bytes = name.as_bytes();
    bytes[8] == b'-' && bytes[13] == b'-' && bytes[18] == b'-' && bytes[23] == b'-'
        && bytes.iter().enumerate().all(|(i, &b)| {
            if i == 8 || i == 13 || i == 18 || i == 23 {
                true
            } else {
                b.is_ascii_hexdigit()
            }
        })
}

/// High-level extraction: scan all NTFS partitions on a disk for DPAPI master key files.
pub fn extract_from_disk<R: Read + Seek>(reader: &mut R) -> Vec<DpapiMasterKeyHash> {
    let partitions = super::find_ntfs_partitions(reader).unwrap_or_default();
    let mut results = Vec::new();

    for &offset in &partitions {
        log::info!(
            "Scanning NTFS partition at 0x{:x} for DPAPI master keys",
            offset
        );
        let mut hashes = extract_masterkey_hashes_from_partition(reader, offset);
        results.append(&mut hashes);
        if !results.is_empty() {
            break; // Found user profiles, stop scanning
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_guid_filename() {
        assert!(is_guid_filename("12345678-1234-1234-1234-123456789abc"));
        assert!(is_guid_filename("ABCDEF01-2345-6789-abcd-ef0123456789"));
        assert!(!is_guid_filename("not-a-guid"));
        assert!(!is_guid_filename("CREDHIST"));
        assert!(!is_guid_filename("Preferred"));
        assert!(!is_guid_filename("12345678-1234-1234-1234-12345678ZZZZ"));
    }

    #[test]
    fn test_parse_masterkey_v2() {
        // Construct a minimal v2 master key file
        let mut data = vec![0u8; 128 + 32 + 144]; // header + sub-header + ciphertext

        // Header
        data[0] = 2; // version
        // GUID at 0x0C (UTF-16LE "12345678-1234-1234-1234-123456789abc")
        let guid = "12345678-1234-1234-1234-123456789abc";
        for (i, ch) in guid.chars().enumerate() {
            let offset = 0x0C + i * 2;
            data[offset] = ch as u8;
            data[offset + 1] = 0;
        }
        // masterkey_len = 32 + 144 = 176
        data[0x60] = 176;
        // backupkey_len, credhist_len, domainkey_len = 0

        // MasterKey section at 0x80
        let mk_off = 0x80;
        data[mk_off] = 2; // version
        // salt (16 bytes of 0xAA)
        for b in &mut data[mk_off + 4..mk_off + 20] {
            *b = 0xAA;
        }
        // rounds = 8000
        let rounds: u32 = 8000;
        data[mk_off + 0x14..mk_off + 0x18].copy_from_slice(&rounds.to_le_bytes());
        // algHash = SHA-512
        data[mk_off + 0x18..mk_off + 0x1C].copy_from_slice(&CALG_SHA_512.to_le_bytes());
        // algCrypt = AES-256
        data[mk_off + 0x1C..mk_off + 0x20].copy_from_slice(&CALG_AES_256.to_le_bytes());
        // ciphertext = 144 bytes of 0xBB
        for b in &mut data[mk_off + 0x20..mk_off + 0x20 + 144] {
            *b = 0xBB;
        }

        let result = parse_masterkey_file(&data, "TestUser", "S-1-5-21-111-222-333-1001", 0);
        assert!(result.is_some());
        let hash = result.unwrap();
        assert_eq!(hash.mode, 15900);
        assert_eq!(hash.username, "TestUser");
        assert_eq!(hash.sid, "S-1-5-21-111-222-333-1001");
        assert!(hash.hash.starts_with("$DPAPImk$2*1*S-1-5-21-111-222-333-1001*aes256*sha512*8000*"));
        assert!(hash.hash.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")); // salt hex (16 bytes = 32 hex chars)
    }

    /// Build a synthetic MK file: 128-byte header + 32-byte MK sub-header +
    /// `ciphertext`. Returns the full file bytes.
    fn build_mk_file(
        version: u32,
        guid: &str,
        section_version: u32,
        salt: &[u8; 16],
        rounds: u32,
        alg_hash: u32,
        alg_crypt: u32,
        ciphertext: &[u8],
    ) -> Vec<u8> {
        let mk_sec_len = 32 + ciphertext.len();
        let mut data = vec![0u8; 128 + mk_sec_len];
        data[..4].copy_from_slice(&version.to_le_bytes());
        for (i, ch) in guid.chars().enumerate() {
            let o = 0x0C + i * 2;
            data[o] = ch as u8;
            data[o + 1] = 0;
        }
        data[0x60..0x68].copy_from_slice(&(mk_sec_len as u64).to_le_bytes());
        // backupkey/credhist/domainkey = 0 (already zeroed)

        let m = 0x80usize;
        data[m..m + 4].copy_from_slice(&section_version.to_le_bytes());
        data[m + 4..m + 20].copy_from_slice(salt);
        data[m + 0x14..m + 0x18].copy_from_slice(&rounds.to_le_bytes());
        data[m + 0x18..m + 0x1C].copy_from_slice(&alg_hash.to_le_bytes());
        data[m + 0x1C..m + 0x20].copy_from_slice(&alg_crypt.to_le_bytes());
        data[m + 0x20..m + 0x20 + ciphertext.len()].copy_from_slice(ciphertext);
        data
    }

    /// AES-256-CBC encrypt without padding for test fixture generation.
    fn aes_cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], pt: &[u8]) -> Vec<u8> {
        use aes::cipher::{BlockEncryptMut, KeyIvInit};
        type Enc = cbc::Encryptor<aes::Aes256>;
        assert_eq!(pt.len() % 16, 0);
        let mut buf = pt.to_vec();
        let n = buf.len();
        Enc::new(key.into(), iv.into())
            .encrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf, n)
            .unwrap();
        buf
    }

    #[test]
    fn decrypt_user_local_aes_roundtrip() {
        use hmac::Mac;
        // Synthesize a Win10+ local user MK file: known NT hash + SID -> pre-key ->
        // DPAPI-variant key derive -> AES-CBC encrypt -> assemble file -> decrypt.
        let nt_hash: [u8; 16] = [
            0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0,
            0x89, 0xc0,
        ];
        let sid = "S-1-5-21-1111-2222-3333-1001";
        let salt = [0xA5u8; 16];
        let rounds: u32 = 200;

        let pre_key = user_local_prekey(&nt_hash, sid).unwrap();
        let derived = dpapi_derive_key_sha512(&pre_key, &salt, 48, rounds);
        let aes_key: [u8; 32] = derived[..32].try_into().unwrap();
        let iv: [u8; 16] = derived[32..48].try_into().unwrap();

        // Cleartext layout: hmacSalt(16) || hmac(64) || padding || masterkey(64).
        // Make a 144-byte cleartext whose MK is the last 64 bytes and whose HMAC
        // matches the impacket verifier.
        let mk_bytes: [u8; 64] = [0xC3u8; 64];
        let hmac_salt: [u8; 16] = [0x77u8; 16];
        let mut k1 = HmacSha512::new_from_slice(&pre_key).unwrap();
        k1.update(&hmac_salt);
        let key2 = k1.finalize().into_bytes();
        let mut k2 = HmacSha512::new_from_slice(&key2).unwrap();
        k2.update(&mk_bytes);
        let stored_hmac = k2.finalize().into_bytes();
        let mut cleartext = Vec::with_capacity(144);
        cleartext.extend_from_slice(&hmac_salt);
        cleartext.extend_from_slice(&stored_hmac);  // 64 bytes
        cleartext.extend_from_slice(&mk_bytes);     // 64 bytes
        assert_eq!(cleartext.len(), 144);

        let cipher = aes_cbc_encrypt(&aes_key, &iv, &cleartext);
        let file = build_mk_file(
            2,
            "aaaabbbb-cccc-dddd-eeee-ffff00001111",
            2,
            &salt,
            rounds,
            CALG_SHA_512,
            CALG_AES_256,
            &cipher,
        );

        let mk = decrypt_local_user_masterkey(&file, &nt_hash, sid).expect("decrypt");
        assert_eq!(mk.len(), 64);
        assert_eq!(&mk[..], &mk_bytes[..]);
    }

    #[test]
    fn decrypt_system_aes_roundtrip() {
        use hmac::Mac;
        let machine_key: [u8; 20] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
        ];
        let salt = [0x5Au8; 16];
        let rounds: u32 = 200;

        let derived = dpapi_derive_key_sha512(&machine_key, &salt, 48, rounds);
        let aes_key: [u8; 32] = derived[..32].try_into().unwrap();
        let iv: [u8; 16] = derived[32..48].try_into().unwrap();

        let mk_bytes: [u8; 64] = [0x9Au8; 64];
        let hmac_salt: [u8; 16] = [0x3Bu8; 16];
        let mut k1 = HmacSha512::new_from_slice(&machine_key).unwrap();
        k1.update(&hmac_salt);
        let key2 = k1.finalize().into_bytes();
        let mut k2 = HmacSha512::new_from_slice(&key2).unwrap();
        k2.update(&mk_bytes);
        let stored_hmac = k2.finalize().into_bytes();
        let mut cleartext = Vec::with_capacity(144);
        cleartext.extend_from_slice(&hmac_salt);
        cleartext.extend_from_slice(&stored_hmac);
        cleartext.extend_from_slice(&mk_bytes);
        assert_eq!(cleartext.len(), 144);

        let cipher = aes_cbc_encrypt(&aes_key, &iv, &cleartext);
        let file = build_mk_file(
            2,
            "11112222-3333-4444-5555-666677778888",
            2,
            &salt,
            rounds,
            CALG_SHA_512,
            CALG_AES_256,
            &cipher,
        );

        let mk = decrypt_system_masterkey(&file, &machine_key).expect("decrypt");
        assert_eq!(mk.len(), 64);
        assert_eq!(&mk[..], &mk_bytes[..]);
    }

    #[test]
    fn test_parse_masterkey_v1() {
        // Construct a minimal v1 master key file
        let mut data = vec![0u8; 128 + 32 + 104]; // header + sub-header + ciphertext

        // Header
        data[0] = 2; // file version (always 2, even for v1 crypto)
        let guid = "aabbccdd-1122-3344-5566-778899aabbcc";
        for (i, ch) in guid.chars().enumerate() {
            let offset = 0x0C + i * 2;
            data[offset] = ch as u8;
            data[offset + 1] = 0;
        }
        // masterkey_len = 32 + 104 = 136
        data[0x60] = 136;

        // MasterKey section
        let mk_off = 0x80;
        data[mk_off] = 1; // section version
        for b in &mut data[mk_off + 4..mk_off + 20] {
            *b = 0xCC;
        }
        let rounds: u32 = 4000;
        data[mk_off + 0x14..mk_off + 0x18].copy_from_slice(&rounds.to_le_bytes());
        data[mk_off + 0x18..mk_off + 0x1C].copy_from_slice(&CALG_SHA1.to_le_bytes());
        data[mk_off + 0x1C..mk_off + 0x20].copy_from_slice(&CALG_3DES.to_le_bytes());
        for b in &mut data[mk_off + 0x20..mk_off + 0x20 + 104] {
            *b = 0xDD;
        }

        let result = parse_masterkey_file(&data, "Admin", "S-1-5-21-999-888-777-500", 0);
        assert!(result.is_some());
        let hash = result.unwrap();
        assert_eq!(hash.mode, 15300);
        assert!(hash.hash.starts_with("$DPAPImk$1*1*S-1-5-21-999-888-777-500*des3*sha1*4000*"));
    }
}
