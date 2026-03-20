//! LSA secrets extraction from the SECURITY registry hive.
//!
//! Decrypts LSA secrets (DPAPI keys, machine account passwords, cached domain
//! keys, service passwords) using the bootkey from the SYSTEM hive.
//! Supports both modern (AES-256-ECB, revision >= 0x00010006) and legacy
//! (RC4, older revisions) encryption schemes.

use aes::cipher::{BlockDecrypt, KeyInit};
use aes::Aes256;
use sha2::Digest;

use super::hashes::{decode_utf16le, md5_hash, rc4};
use super::hive::Hive;
use crate::error::{VmkatzError, Result};

/// A single LSA secret with its name, raw data, and parsed interpretation.
#[derive(Debug)]
pub struct LsaSecret {
    pub name: String,
    pub raw_data: Vec<u8>,
    pub parsed: LsaSecretType,
}

/// Parsed LSA secret types.
#[derive(Debug)]
pub enum LsaSecretType {
    /// DPAPI system keys (user + machine).
    DpapiSystem {
        user_key: [u8; 20],
        machine_key: [u8; 20],
    },
    /// DPAPI domain backup key — preferred key GUID pointer.
    DpapiBackupPreferred { guid: String },
    /// DPAPI domain backup key — RSA private key (can decrypt any domain user's master key).
    DpapiBackupKey {
        guid: String,
        version: u32,
        key_data: Vec<u8>,
        cert_data: Vec<u8>,
        pvk: Vec<u8>,
    },
    /// Machine account password (hex-encoded raw bytes).
    MachineAccount { password_hex: String },
    /// Default logon password (plaintext UTF-16LE decoded).
    DefaultPassword { password: String },
    /// Cached domain key (NL$KM).
    CachedDomainKey { key: Vec<u8> },
    /// Service account password (_SC_* secrets).
    ServicePassword { service: String, password: String },
    /// Unrecognized secret, shown as raw hex.
    Raw,
}

impl std::fmt::Display for LsaSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.parsed {
            LsaSecretType::DpapiSystem {
                user_key,
                machine_key,
            } => {
                write!(
                    f,
                    "  DPAPI_SYSTEM\n    user_key:    {}\n    machine_key: {}",
                    hex::encode(user_key),
                    hex::encode(machine_key)
                )
            }
            LsaSecretType::DpapiBackupPreferred { guid } => {
                write!(f, "  BCKUPKEY_P (Preferred Backup Key)\n    GUID: {}", guid)
            }
            LsaSecretType::DpapiBackupKey {
                guid,
                version,
                key_data,
                cert_data,
                pvk,
            } => {
                write!(
                    f,
                    "  BCKUPKEY (Domain DPAPI Backup Key)\n    GUID    : {}\n    Version : {}\n    Key     : {} bytes\n    Cert    : {} bytes\n    PVK     : {} bytes",
                    guid, version, key_data.len(), cert_data.len(), pvk.len()
                )
            }
            LsaSecretType::MachineAccount { password_hex } => {
                write!(f, "  $MACHINE.ACC\n    password: {}", password_hex)
            }
            LsaSecretType::DefaultPassword { password } => {
                write!(f, "  DefaultPassword\n    password: {}", password)
            }
            LsaSecretType::CachedDomainKey { key } => {
                write!(f, "  NL$KM\n    key: {}", hex::encode(key))
            }
            LsaSecretType::ServicePassword { service, password } => {
                write!(f, "  _SC_{}\n    password: {}", service, password)
            }
            LsaSecretType::Raw => {
                let hex_str = hex::encode(&self.raw_data);
                let display = if hex_str.len() > 128 {
                    format!("{}...", &hex_str[..128])
                } else {
                    hex_str
                };
                write!(f, "  {}\n    raw: {}", self.name, display)
            }
        }
    }
}

/// Extract LSA secrets from SECURITY hive data using the bootkey.
pub fn extract_lsa_secrets(security_data: &[u8], bootkey: &[u8; 16]) -> Result<Vec<LsaSecret>> {
    let hive = Hive::new(security_data)?;
    let root = hive.root_key()?;

    // Navigate to Policy key
    let policy = root.subkey(&hive, "Policy")?;

    // Check revision to determine modern vs legacy path
    let revision = match policy.subkey(&hive, "PolRevision") {
        Ok(rev_key) => {
            match rev_key.value(&hive, "") {
                Ok(data) if data.len() >= 4 => {
                    // Default (unnamed) value: first DWORD is minor, second is major
                    let val = crate::utils::read_u32_le(&data, 0).unwrap_or(0);
                    log::info!("SECURITY Policy revision: 0x{:08x}", val);
                    val
                }
                _ => {
                    log::info!("PolRevision value missing or too short, assuming legacy");
                    0
                }
            }
        }
        Err(_) => {
            log::info!("PolRevision key not found, assuming legacy");
            0
        }
    };

    // Determine if modern (Vista+) or legacy encryption
    let is_modern = revision >= 0x0001_0006;
    log::info!(
        "LSA encryption scheme: {}",
        if is_modern {
            "modern (AES)"
        } else {
            "legacy (RC4)"
        }
    );

    // Extract LSA key. Try modern first (PolEKList), fall back to legacy
    // (PolSecretEncryptionKey). Some Windows versions (e.g. Server 2003 R2 SP2)
    // report a modern revision but still use the legacy encryption scheme.
    let (lsa_key, is_modern) = if is_modern {
        match extract_lsa_key_modern(&hive, &policy, bootkey) {
            Ok(key) => (key, true),
            Err(e) => {
                log::info!("Modern LSA key extraction failed ({}), trying legacy fallback", e);
                (extract_lsa_key_legacy(&hive, &policy, bootkey)?, false)
            }
        }
    } else {
        (extract_lsa_key_legacy(&hive, &policy, bootkey)?, false)
    };
    log::info!("LSA key: {}", hex::encode(lsa_key));

    // Enumerate secrets
    let secrets_key = match policy.subkey(&hive, "Secrets") {
        Ok(k) => k,
        Err(_) => {
            log::warn!("Policy\\Secrets key not found");
            return Ok(Vec::new());
        }
    };

    let secret_subkeys = secrets_key.subkeys(&hive)?;
    let mut secrets = Vec::new();

    for secret_key in &secret_subkeys {
        let secret_name = secret_key.name().to_string();

        // Read CurrVal subkey's default value
        let curr_val = match secret_key.subkey(&hive, "CurrVal") {
            Ok(cv) => cv,
            Err(_) => {
                log::warn!("Secret '{}': no CurrVal subkey", secret_name);
                continue;
            }
        };

        let encrypted = match curr_val.value(&hive, "") {
            Ok(data) => data,
            Err(_) => {
                log::warn!("Secret '{}': no default value in CurrVal", secret_name);
                continue;
            }
        };

        if encrypted.is_empty() {
            log::warn!("Secret '{}': empty CurrVal", secret_name);
            continue;
        }

        let raw_data = if is_modern {
            match decrypt_secret_modern(&encrypted, &lsa_key) {
                Ok(data) => data,
                Err(e) => {
                    log::warn!("Secret '{}': decryption failed: {}", secret_name, e);
                    continue;
                }
            }
        } else {
            match decrypt_secret_legacy(&encrypted, &lsa_key) {
                Ok(data) => data,
                Err(e) => {
                    log::warn!("Secret '{}': decryption failed: {}", secret_name, e);
                    continue;
                }
            }
        };

        if raw_data.is_empty() {
            log::warn!("Secret '{}': decrypted to empty data", secret_name);
            continue;
        }

        let parsed = parse_secret(&secret_name, &raw_data);

        log::info!(
            "Secret '{}': {} bytes decrypted",
            secret_name,
            raw_data.len()
        );

        secrets.push(LsaSecret {
            name: secret_name,
            raw_data,
            parsed,
        });
    }

    Ok(secrets)
}

/// Extract LSA key using modern (AES-256-ECB) scheme from PolEKList.
///
/// Decrypted blob = LSA_SECRET_BLOB: Length(4) + Random(12) + Secret(Length).
/// Secret = inner LSA_SECRET: Version(4) + KeyID(16) + Algo(4) + Flags(4) + EncryptedData.
/// LSA key = EncryptedData[:32] = blob[44..76] (per impacket: parse Secret as LSA_SECRET).
fn extract_lsa_key_modern(
    hive: &Hive,
    policy: &super::hive::Key,
    bootkey: &[u8; 16],
) -> Result<[u8; 32]> {
    let ek_key = policy.subkey(hive, "PolEKList")?;
    let ek_data = ek_key.value(hive, "")?;

    if ek_data.len() < 28 + 32 {
        return Err(lsa_err("PolEKList value too short"));
    }

    // NT6_HARD_SECRET: 28-byte header + 32-byte salt ("lazyiv") + ciphertext
    let salt = &ek_data[28..60];
    let encrypted = &ek_data[60..];

    let decrypted = decrypt_aes_sha256(bootkey, salt, encrypted)?;

    // LSA_SECRET_BLOB: Length(4) + Random(12) + Secret(Length)
    if decrypted.len() < 16 {
        return Err(lsa_err("PolEKList decrypted blob too short"));
    }
    let blob_len = crate::utils::read_u32_le(&decrypted, 0).unwrap_or(0) as usize;
    log::debug!(
        "PolEKList decrypted ({} bytes, blob_len={}): {}",
        decrypted.len(),
        blob_len,
        hex::encode(&decrypted[..std::cmp::min(decrypted.len(), 160)])
    );

    // Secret at offset 16 is NT6_SYSTEM_KEYS (per mimikatz):
    //   unkType0(4) + CurrentKeyID(16) + unkType1(4) + nbKeys(4) = 28-byte header
    //   NT6_SYSTEM_KEY[0]: KeyId(16) + KeyType(4) + KeySize(4) + Key(KeySize)
    // LSA key = Key[0].Key = blob[16 + 28 + 16 + 4 + 4 .. +32] = blob[68..100]
    let keys_header = 16 + 28; // NT6_SYSTEM_KEYS header ends at 44
    let key_data_offset = keys_header + 16 + 4 + 4; // skip KeyId + KeyType + KeySize = 68
    if decrypted.len() >= key_data_offset + 32 {
        let key_size = crate::utils::read_u32_le(&decrypted, keys_header + 20).unwrap_or(0) as usize;
        if key_size == 32 && decrypted.len() >= key_data_offset + 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&decrypted[key_data_offset..key_data_offset + 32]);
            return Ok(key);
        }
    }

    // Fallback: try impacket-style offset (Secret[28..60])
    if decrypted.len() >= 16 + 28 + 32 {
        let mut key = [0u8; 32];
        key.copy_from_slice(&decrypted[44..76]);
        return Ok(key);
    }

    Err(lsa_err(&format!(
        "PolEKList: blob_len={}, decrypted_len={}",
        blob_len,
        decrypted.len()
    )))
}

/// Extract LSA key using legacy (RC4) scheme from PolSecretEncryptionKey.
fn extract_lsa_key_legacy(
    hive: &Hive,
    policy: &super::hive::Key,
    bootkey: &[u8; 16],
) -> Result<[u8; 32]> {
    let enc_key = policy.subkey(hive, "PolSecretEncryptionKey")?;
    let enc_data = enc_key.value(hive, "")?;

    if enc_data.len() < 76 {
        return Err(lsa_err("PolSecretEncryptionKey value too short"));
    }

    // Salt at [60..76], encrypted key at [12..60]
    let salt = &enc_data[60..76];
    let encrypted = &enc_data[12..60];

    // MD5 key derivation: 1000 iterations of (salt + bootkey)
    let mut md5_input = Vec::with_capacity(16 + 16 * 1000);
    for _ in 0..1000 {
        md5_input.extend_from_slice(salt);
        md5_input.extend_from_slice(bootkey);
    }
    let rc4_key = md5_hash(&md5_input);

    let decrypted = rc4(&rc4_key, encrypted);

    // LSA key is at [16..32] of decrypted result, pad to 32 bytes for uniform interface
    if decrypted.len() < 32 {
        return Err(lsa_err("Decrypted legacy LSA key too short"));
    }
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(&decrypted[16..32]);
    // Legacy key is only 16 bytes; zero-pad the rest
    Ok(key)
}

/// Decrypt a secret value using modern (AES-256-ECB) scheme.
fn decrypt_secret_modern(encrypted: &[u8], lsa_key: &[u8; 32]) -> Result<Vec<u8>> {
    // NT6_HARD_SECRET: 28-byte header + 32-byte salt + encrypted data (AES-256-ECB)
    if encrypted.len() < 28 + 32 {
        return Err(lsa_err("Secret value too short for modern decryption"));
    }

    let salt = &encrypted[28..60];
    let cipher_data = &encrypted[60..];

    if cipher_data.is_empty() {
        return Ok(Vec::new());
    }

    let decrypted = decrypt_aes_sha256(lsa_key, salt, cipher_data)?;

    // Parse LSA_SECRET_BLOB: Length(4) + random(12) + Secret(Length bytes)
    if decrypted.len() < 16 {
        return Ok(Vec::new());
    }

    let secret_len = crate::utils::read_u32_le(&decrypted, 0).unwrap_or(0) as usize;
    if secret_len == 0 {
        return Ok(Vec::new());
    }

    let start = 16; // After Length(4) + random(12)
    let end = start + secret_len;
    if end > decrypted.len() {
        // Return what we have
        Ok(decrypted[start..].to_vec())
    } else {
        Ok(decrypted[start..end].to_vec())
    }
}

/// Decrypt a secret value using legacy (RC4) scheme.
fn decrypt_secret_legacy(encrypted: &[u8], lsa_key: &[u8; 32]) -> Result<Vec<u8>> {
    // Legacy secret: first 4 bytes = length, then 4 bytes padding, then encrypted data
    if encrypted.len() < 16 {
        return Err(lsa_err("Secret value too short for legacy decryption"));
    }

    let secret_len = crate::utils::read_u32_le(encrypted, 0).unwrap_or(0) as usize;
    let cipher_data = &encrypted[12..]; // Skip length(4) + unk(4) + unk(4)

    // Derive RC4 key: MD5(lsa_key[0..16] + secret_len_le_bytes * padding)
    // Actually for legacy secrets: derive key from LSA key + salt
    // The legacy secret structure uses first 16 bytes of lsa_key
    let key_material = &lsa_key[..16];

    let mut md5_buf = Vec::new();
    for _ in 0..1000 {
        md5_buf.extend_from_slice(key_material);
    }
    let rc4_key = md5_hash(&md5_buf);

    let decrypted = rc4(&rc4_key, cipher_data);

    if secret_len > 0 && secret_len <= decrypted.len() {
        Ok(decrypted[..secret_len].to_vec())
    } else {
        Ok(decrypted)
    }
}

/// SHA-256 + AES-256-ECB decryption (modern LSA scheme).
/// Key derivation: SHA256(key_material + salt * 1000) → AES-256 key.
/// Mode: ECB (per mimikatz CRYPT_MODE_ECB, impacket per-block CBC reinit, pypykatz ECB).
/// The 32-byte "lazyiv" field is a KDF salt, NOT an AES IV.
fn decrypt_aes_sha256(key_material: &[u8], salt: &[u8], encrypted: &[u8]) -> Result<Vec<u8>> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(key_material);
    for _ in 0..1000 {
        hasher.update(salt);
    }
    let derived_key: [u8; 32] = hasher.finalize().into();

    aes256_ecb_decrypt(&derived_key, encrypted)
}

/// AES-256-ECB decryption (no IV, each block decrypted independently).
fn aes256_ecb_decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let cipher = Aes256::new(key.into());
    let mut buf = data.to_vec();
    // Pad to 16-byte boundary if needed
    let pad_len = (16 - (buf.len() % 16)) % 16;
    buf.extend(std::iter::repeat_n(0u8, pad_len));

    for chunk in buf.chunks_exact_mut(16) {
        let block = aes::Block::from_mut_slice(chunk);
        cipher.decrypt_block(block);
    }

    buf.truncate(data.len());
    Ok(buf)
}

/// Parse a decrypted secret by its name into a typed variant.
fn parse_secret(name: &str, data: &[u8]) -> LsaSecretType {
    if name.eq_ignore_ascii_case("DPAPI_SYSTEM") {
        // 44 bytes: version(4) + user_key(20) + machine_key(20)
        if data.len() >= 44 {
            let mut user_key = [0u8; 20];
            let mut machine_key = [0u8; 20];
            user_key.copy_from_slice(&data[4..24]);
            machine_key.copy_from_slice(&data[24..44]);
            return LsaSecretType::DpapiSystem {
                user_key,
                machine_key,
            };
        }
        log::warn!("DPAPI_SYSTEM: expected 44 bytes, got {}", data.len());
    }

    // DPAPI domain backup keys: BCKUPKEY_P (preferred GUID) and BCKUPKEY_{GUID} (RSA key)
    if name.eq_ignore_ascii_case("BCKUPKEY_P") || name.eq_ignore_ascii_case("BCKUPKEY_PREFERRED") {
        // 24 bytes: version(4) + reserved(4) + GUID(16)
        if data.len() >= 24 {
            let guid = format_guid(&data[8..24]);
            return LsaSecretType::DpapiBackupPreferred { guid };
        }
        // Some versions store just the GUID (16 bytes)
        if data.len() >= 16 {
            let guid = format_guid(&data[..16]);
            return LsaSecretType::DpapiBackupPreferred { guid };
        }
    }

    if let Some(key_guid) = name.strip_prefix("BCKUPKEY_") {
        // Skip if it's the "P" or "PREFERRED" variant (already handled above)
        if !key_guid.eq_ignore_ascii_case("P") && !key_guid.eq_ignore_ascii_case("PREFERRED") {
            return parse_bckupkey(key_guid, data);
        }
    }

    if name.eq_ignore_ascii_case("$MACHINE.ACC") {
        return LsaSecretType::MachineAccount {
            password_hex: hex::encode(data),
        };
    }

    if name.eq_ignore_ascii_case("DefaultPassword") {
        let password = decode_utf16le(data);
        return LsaSecretType::DefaultPassword { password };
    }

    if name.eq_ignore_ascii_case("NL$KM") || name.eq_ignore_ascii_case("_NL$KM_") {
        return LsaSecretType::CachedDomainKey { key: data.to_vec() };
    }

    if let Some(service_name) = name.strip_prefix("_SC_") {
        // GMSA managed passwords are binary blobs, not UTF-16LE text
        if service_name.starts_with("GMSA_") || service_name.starts_with("GMSA{") {
            return LsaSecretType::ServicePassword {
                service: service_name.to_string(),
                password: hex::encode(data),
            };
        }
        let password = decode_utf16le(data);
        return LsaSecretType::ServicePassword {
            service: service_name.to_string(),
            password,
        };
    }

    LsaSecretType::Raw
}

/// Format a 16-byte GUID as a standard string representation.
fn format_guid(data: &[u8]) -> String {
    if data.len() < 16 {
        return hex::encode(data);
    }
    // GUID binary layout: Data1(4 LE) + Data2(2 LE) + Data3(2 LE) + Data4(8 BE)
    let d1 = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let d2 = u16::from_le_bytes([data[4], data[5]]);
    let d3 = u16::from_le_bytes([data[6], data[7]]);
    format!(
        "{{{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
        d1, d2, d3, data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15]
    )
}

/// Parse a BCKUPKEY_{GUID} backup key secret.
///
/// Structure (version 2):
///   version(4) + key_length(4) + cert_length(4) + key_data(key_length) + cert_data(cert_length)
///
/// For version 1: raw PRIVATEKEYBLOB follows after version(4).
fn parse_bckupkey(guid_str: &str, data: &[u8]) -> LsaSecretType {
    if data.len() < 12 {
        return LsaSecretType::Raw;
    }

    let version = crate::utils::read_u32_le(data, 0).unwrap_or(0);

    match version {
        2 => {
            let key_len = crate::utils::read_u32_le(data, 4).unwrap_or(0) as usize;
            let cert_len = crate::utils::read_u32_le(data, 8).unwrap_or(0) as usize;

            if data.len() < 12 + key_len {
                return LsaSecretType::Raw;
            }

            let key_data = data[12..12 + key_len].to_vec();
            let cert_start = 12 + key_len;
            let cert_data = if cert_len > 0 && data.len() >= cert_start + cert_len {
                data[cert_start..cert_start + cert_len].to_vec()
            } else {
                Vec::new()
            };

            // Build PVK format: magic(4) + reserved(4) + keytype(4) + encrypted(4) +
            //                    cbEncryptData(4) + cbPvk(4) + pvk_data
            let pvk = build_pvk(&key_data);

            LsaSecretType::DpapiBackupKey {
                guid: guid_str.to_string(),
                version,
                key_data,
                cert_data,
                pvk,
            }
        }
        1 => {
            // Version 1: entire blob after version is the key material
            let key_data = data[4..].to_vec();
            let pvk = build_pvk(&key_data);

            LsaSecretType::DpapiBackupKey {
                guid: guid_str.to_string(),
                version,
                key_data,
                cert_data: Vec::new(),
                pvk,
            }
        }
        _ => LsaSecretType::Raw,
    }
}

/// Build a PVK (Private Key) file from raw RSA key data.
///
/// PVK format (Microsoft):
///   magic: 0xB0B5F11E (4 bytes LE)
///   reserved: 0 (4 bytes)
///   keytype: AT_KEYEXCHANGE=1 (4 bytes LE)
///   encrypted: 0 (4 bytes, not encrypted)
///   cbEncryptData: 0 (4 bytes)
///   cbPvk: key_data.len() (4 bytes LE)
///   pvk_data: raw key bytes
fn build_pvk(key_data: &[u8]) -> Vec<u8> {
    let mut pvk = Vec::with_capacity(24 + key_data.len());
    pvk.extend_from_slice(&0xB0B5_F11Eu32.to_le_bytes()); // magic
    pvk.extend_from_slice(&0u32.to_le_bytes()); // reserved
    pvk.extend_from_slice(&1u32.to_le_bytes()); // AT_KEYEXCHANGE
    pvk.extend_from_slice(&0u32.to_le_bytes()); // not encrypted
    pvk.extend_from_slice(&0u32.to_le_bytes()); // cbEncryptData
    pvk.extend_from_slice(&(key_data.len() as u32).to_le_bytes()); // cbPvk
    pvk.extend_from_slice(key_data);
    pvk
}

fn lsa_err(msg: &str) -> VmkatzError {
    VmkatzError::DecryptionError(format!("LSA: {}", msg))
}
