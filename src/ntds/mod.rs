//! Native NTDS.dit AD secrets extraction.
//!
//! Parses the ESE database (ntds.dit) directly to extract AD account
//! NTLM hashes without any external dependencies.
//!
//! Flow: ESE parse -> datatable rows -> PEK decrypt -> DES unwrap -> hashes

pub mod ese;

use crate::error::{VmkatzError, Result};
use ese::EseDb;
use crate::sam::hashes::{rc4, md5_hash, aes128_cbc_decrypt};

/// High-level NTDS context extracted from disk artifacts.
#[derive(Debug, Clone)]
pub struct NtdsContext {
    pub ntds_size: usize,
    pub boot_key: [u8; 16],
}

/// A single AD NTLM hash entry extracted from NTDS.
#[derive(Debug, Clone)]
pub struct AdHashEntry {
    pub username: String,
    pub rid: u32,
    pub lm_hash: [u8; 16],
    pub nt_hash: [u8; 16],
    pub is_history: bool,
    pub history_index: Option<u32>,
}

/// Build NTDS context from raw NTDS.dit + SYSTEM hive bytes.
pub fn build_context(ntds_data: &[u8], system_data: &[u8]) -> Result<NtdsContext> {
    if !is_ese_database(ntds_data) {
        return Err(VmkatzError::DecryptionError(
            "NTDS.dit does not look like a valid ESE database".to_string(),
        ));
    }

    let boot_key = crate::sam::bootkey::extract_bootkey(system_data)?;
    Ok(NtdsContext {
        ntds_size: ntds_data.len(),
        boot_key,
    })
}

/// Minimal ESE validity check for NTDS.dit.
fn is_ese_database(data: &[u8]) -> bool {
    if data.len() < 8 {
        return false;
    }
    data[4..8] == [0xEF, 0xCD, 0xAB, 0x89]
}

/// Extract AD NTLM hashes from NTDS + SYSTEM natively.
pub fn extract_ad_hashes(
    ntds_data: &[u8],
    system_data: &[u8],
    include_history: bool,
) -> Result<Vec<AdHashEntry>> {
    let ctx = build_context(ntds_data, system_data)?;
    let db = EseDb::open(ntds_data)?;

    // Log available tables for debugging
    let tables = db.table_names();
    log::info!("NTDS tables: {:?}", tables);

    // The main table is "datatable"
    let columns = db.columns("datatable").ok_or_else(|| {
        VmkatzError::DecryptionError("datatable not found in NTDS.dit".to_string())
    })?;

    log::info!("datatable has {} columns", columns.len());

    // Find relevant column names (AD attribute IDs)
    // The NTDS.dit datatable uses column names like:
    //   ATTm590045 = sAMAccountName
    //   ATTk589879 = unicodePwd (NT hash, encrypted)
    //   ATTk589914 = dBCSPwd (LM hash, encrypted)
    //   ATTr589970 = objectSid
    //   ATTj589832 = userAccountControl
    //   ATTk590689 = pekList (Password Encryption Key)
    //   ATTk589918 = ntPwdHistory
    //   ATTk589984 = lmPwdHistory

    // First pass: extract PEK (Password Encryption Key)
    let pek = extract_pek(&db, &ctx.boot_key)?;
    log::info!("PEK decrypted: {} bytes", pek.len());

    // Second pass: extract user hashes
    let mut entries = Vec::new();

    db.for_each_row("datatable", |read_col| {
        // Read sAMAccountName
        let username = match read_col("ATTm590045") {
            Some(data) => decode_ad_string(&data),
            None => return,
        };

        // Read objectSid to get RID
        let rid = match read_col("ATTr589970") {
            Some(data) => extract_rid_from_sid(&data),
            None => return,
        };

        let rid = match rid {
            Some(r) => r,
            None => return,
        };

        // Read userAccountControl to verify this is a user account
        let _uac = read_col("ATTj589832")
            .and_then(|d| crate::utils::read_u32_le(&d, 0))
            .unwrap_or(0);

        // Read encrypted NT hash (unicodePwd) and LM hash (dBCSPwd)
        let nt_raw = read_col("ATTk589879")
            .and_then(|data| decrypt_ad_hash(&data, &pek, rid).ok())
            .unwrap_or([0u8; 16]);

        let lm_raw = read_col("ATTk589914")
            .and_then(|data| decrypt_ad_hash(&data, &pek, rid).ok())
            .unwrap_or([0u8; 16]);

        let zero = [0u8; 16];

        // Win2016+ may store the NT hash in dBCSPwd while unicodePwd is empty.
        // When only one column has data, treat it as the NT hash.
        let (nt_hash, lm_hash) = if nt_raw != zero {
            (nt_raw, lm_raw)
        } else if lm_raw != zero {
            // unicodePwd is empty but dBCSPwd has data -> use it as NT hash
            (lm_raw, zero)
        } else {
            (zero, zero)
        };

        // Skip entries with no hashes at all
        if nt_hash == zero && lm_hash == zero {
            return;
        }

        entries.push(AdHashEntry {
            username: username.clone(),
            rid,
            lm_hash,
            nt_hash,
            is_history: false,
            history_index: None,
        });

        // Password history
        if include_history {
            if let Some(nt_hist_data) = read_col("ATTk589918") {
                if let Ok(hist) = decrypt_hash_history(&nt_hist_data, &pek, rid) {
                    for (i, h) in hist.iter().enumerate() {
                        entries.push(AdHashEntry {
                            username: username.clone(),
                            rid,
                            lm_hash: [0u8; 16],
                            nt_hash: *h,
                            is_history: true,
                            history_index: Some(i as u32),
                        });
                    }
                }
            }
            if let Some(lm_hist_data) = read_col("ATTk589984") {
                if let Ok(hist) = decrypt_hash_history(&lm_hist_data, &pek, rid) {
                    for (i, h) in hist.iter().enumerate() {
                        // Try to match with existing history entries
                        let target_idx = entries.iter().position(|e| {
                            e.username == username
                                && e.is_history
                                && e.history_index == Some(i as u32)
                        });
                        if let Some(idx) = target_idx {
                            entries[idx].lm_hash = *h;
                        } else {
                            entries.push(AdHashEntry {
                                username: username.clone(),
                                rid,
                                lm_hash: *h,
                                nt_hash: [0u8; 16],
                                is_history: true,
                                history_index: Some(i as u32),
                            });
                        }
                    }
                }
            }
        }
    })?;

    if entries.is_empty() {
        return Err(VmkatzError::DecryptionError(
            "No AD hashes found in NTDS.dit datatable".to_string(),
        ));
    }

    // Sort by RID
    entries.sort_by_key(|e| (e.rid, e.is_history, e.history_index));

    log::info!("Extracted {} AD hash entries", entries.len());
    Ok(entries)
}

/// Extract and decrypt the PEK (Password Encryption Key) from the datatable.
fn extract_pek(db: &EseDb<'_>, boot_key: &[u8; 16]) -> Result<Vec<u8>> {
    let mut pek_data: Option<Vec<u8>> = None;

    db.for_each_row("datatable", |read_col| {
        if pek_data.is_some() {
            return;
        }
        if let Some(data) = read_col("ATTk590689") {
            if data.len() > 16 {
                pek_data = Some(data);
            }
        }
    })?;

    let pek_encrypted = pek_data.ok_or_else(|| {
        VmkatzError::DecryptionError("PEK (ATTk590689) not found in datatable".to_string())
    })?;

    decrypt_pek(&pek_encrypted, boot_key)
}

/// Derive the RC4 key for PEK decryption: MD5(bootkey + key_salt * 1000).
/// Used by both PEK v1 and v2.
fn derive_pek_rc4_key(boot_key: &[u8; 16], key_salt: &[u8]) -> [u8; 16] {
    let mut md5_input = Vec::with_capacity(16 + key_salt.len() * 1000);
    md5_input.extend_from_slice(boot_key);
    for _ in 0..1000 {
        md5_input.extend_from_slice(key_salt);
    }
    md5_hash(&md5_input)
}

/// Decrypt the PEK blob using the bootkey.
///
/// PEK format v1 (RC4, Win2003): header(8) + key_salt(16) + encrypted(rest)
///   Decrypted layout: header(4) + key(16)
///
/// PEK format v2 (RC4, Vista+): header(8) + key_salt(16) + encrypted(rest)
///   Decrypted layout: header(4) + padding(32) + key(16)
///
/// PEK format v3 (AES, Win2016+): header(8) + salt(16) + encrypted(rest)
///   AES-128-CBC with bootkey as key and salt as IV
fn decrypt_pek(pek_blob: &[u8], boot_key: &[u8; 16]) -> Result<Vec<u8>> {
    if pek_blob.len() < 24 {
        return Err(VmkatzError::DecryptionError(
            "PEK blob too short".to_string(),
        ));
    }

    // Version at offset 0 (first 4 bytes)
    let version = crate::utils::read_u32_le(pek_blob, 0).unwrap_or(0);
    log::info!("PEK version: {}", version);

    match version {
        0x01 => {
            // PEK v1 (Win2003): RC4-based, smaller decrypted structure
            // Structure: version(4) + flags(4) + key_salt(16) + encrypted_pek(rest)
            // Min size: 24 (header+salt) + 20 (header(4) + key(16))
            if pek_blob.len() < 24 + 20 {
                return Err(VmkatzError::DecryptionError(
                    "PEK v1 blob too short".to_string(),
                ));
            }

            let key_salt = &pek_blob[8..24];
            let rc4_key = derive_pek_rc4_key(boot_key, key_salt);
            let decrypted = rc4(&rc4_key, &pek_blob[24..]);

            // v1 decrypted layout: header(4) + key(16)
            if decrypted.len() < 20 {
                return Err(VmkatzError::DecryptionError(
                    "Decrypted PEK v1 too short".to_string(),
                ));
            }

            // Skip 4-byte header, take 16-byte key
            Ok(decrypted[4..20].to_vec())
        }
        0x02 => {
            // PEK v2 (Vista+): RC4-based, larger decrypted structure
            // Structure: version(4) + flags(4) + key_salt(16) + encrypted_pek(rest)
            // Min size: 24 (header+salt) + 76 (header(4) + padding(32) + key(16) + extra(24))
            if pek_blob.len() < 24 + 76 {
                return Err(VmkatzError::DecryptionError(
                    "PEK v2 blob too short".to_string(),
                ));
            }

            let key_salt = &pek_blob[8..24];
            let rc4_key = derive_pek_rc4_key(boot_key, key_salt);
            let decrypted = rc4(&rc4_key, &pek_blob[24..]);

            // v2 decrypted layout: header(4) + padding(32) + key(16)
            if decrypted.len() < 52 {
                return Err(VmkatzError::DecryptionError(
                    "Decrypted PEK v2 too short".to_string(),
                ));
            }

            // Skip 36-byte header, take 16-byte key
            Ok(decrypted[36..52].to_vec())
        }
        0x03 => {
            // PEK v3: AES-256-CBC
            // Structure: version(4) + flags(4) + salt(16) + encrypted(rest)
            if pek_blob.len() < 24 + 32 {
                return Err(VmkatzError::DecryptionError(
                    "PEK v3 blob too short".to_string(),
                ));
            }

            let salt = &pek_blob[8..24];
            let encrypted = &pek_blob[24..];

            // AES key derived from bootkey
            // For PEK v3, the AES key IS the bootkey (zero-padded to 32 bytes for AES-256)
            // Actually it uses AES-128-CBC with the bootkey as key and salt as IV
            let decrypted = aes128_cbc_decrypt(boot_key, salt, encrypted)?;

            if decrypted.len() < 52 {
                return Err(VmkatzError::DecryptionError(
                    "Decrypted PEK v3 too short".to_string(),
                ));
            }

            Ok(decrypted[36..52].to_vec())
        }
        _ => Err(VmkatzError::DecryptionError(format!(
            "Unknown PEK version: {}",
            version
        ))),
    }
}

/// Decrypt an individual AD hash (NT or LM) using the PEK.
///
/// Hash blob format v1 (RC4):
///   version(4)=0x01 + padding(4) + salt(16) + encrypted_hash(16+)
///   RC4(MD5(pek + salt)) -> decrypt -> DES unwrap with RID
///
/// Hash blob format v2 (AES, pre-Win2016):
///   version(4)=0x02 + padding(4) + salt(16) + encrypted_hash(rest)
///   AES-128-CBC(pek, salt) -> decrypt -> DES unwrap with RID
///
/// Hash blob format v3 (AES, Win2016+):
///   version(4)=0x13 + padding(4) + salt(16) + data_len(4) + encrypted_hash(rest)
///   AES-128-CBC(pek, salt) -> decrypt -> DES unwrap with RID
fn decrypt_ad_hash(hash_blob: &[u8], pek: &[u8], rid: u32) -> Result<[u8; 16]> {
    if hash_blob.len() < 24 {
        return Ok([0u8; 16]); // Too short, treat as empty
    }

    let version = crate::utils::read_u32_le(hash_blob, 0).unwrap_or(0);

    let decrypted = match version {
        0x01 => {
            // RC4-based (legacy)
            if hash_blob.len() < 40 {
                return Ok([0u8; 16]);
            }
            let salt = &hash_blob[8..24];
            let encrypted = &hash_blob[24..];

            // RC4 key = MD5(PEK + salt)
            let mut md5_input = Vec::new();
            md5_input.extend_from_slice(pek);
            md5_input.extend_from_slice(salt);
            let rc4_key = md5_hash(&md5_input);

            rc4(&rc4_key, encrypted)
        }
        0x02 => {
            // AES-based (pre-Win2016)
            if hash_blob.len() < 40 {
                return Ok([0u8; 16]);
            }
            let salt = &hash_blob[8..24];
            let encrypted = &hash_blob[24..];

            aes128_cbc_decrypt(pek, salt, encrypted)?
        }
        0x13 => {
            // AES-based (Win2016+ TP4)
            // Structure: version(4) + padding(4) + salt(16) + data_len(4) + encrypted(rest)
            if hash_blob.len() < 32 {
                return Ok([0u8; 16]);
            }
            let salt = &hash_blob[8..24];
            // data_len at offset 24 tells us the plaintext length (usually 16)
            let encrypted = &hash_blob[28..];

            aes128_cbc_decrypt(pek, salt, encrypted)?
        }
        _ => {
            log::debug!("Unknown hash version: 0x{:08x}, blob_len={}", version, hash_blob.len());
            return Ok([0u8; 16]);
        }
    };

    if decrypted.len() < 16 {
        return Ok([0u8; 16]);
    }

    // DES unwrap with RID (same as SAM hash unwrapping)
    des_unwrap_hash(&decrypted[..16], rid)
}

/// Decrypt password history blob.
/// Decrypted data contains concatenated 16-byte hashes.
fn decrypt_hash_history(blob: &[u8], pek: &[u8], rid: u32) -> Result<Vec<[u8; 16]>> {
    if blob.len() < 24 {
        return Ok(Vec::new());
    }

    let version = crate::utils::read_u32_le(blob, 0).unwrap_or(0);

    let decrypted = match version {
        0x01 => {
            let salt = &blob[8..24];
            let encrypted = &blob[24..];
            let mut md5_input = Vec::new();
            md5_input.extend_from_slice(pek);
            md5_input.extend_from_slice(salt);
            let rc4_key = md5_hash(&md5_input);
            rc4(&rc4_key, encrypted)
        }
        0x02 => {
            let salt = &blob[8..24];
            let encrypted = &blob[24..];
            aes128_cbc_decrypt(pek, salt, encrypted)?
        }
        0x13 => {
            // Win2016+ AES: version(4) + padding(4) + salt(16) + data_len(4) + encrypted(rest)
            if blob.len() < 32 {
                return Ok(Vec::new());
            }
            let salt = &blob[8..24];
            let encrypted = &blob[28..];
            aes128_cbc_decrypt(pek, salt, encrypted)?
        }
        _ => return Ok(Vec::new()),
    };

    let mut hashes = Vec::new();
    let mut offset = 0;
    while offset + 16 <= decrypted.len() {
        let raw = &decrypted[offset..offset + 16];
        if let Ok(h) = des_unwrap_hash(raw, rid) {
            if h != [0u8; 16] {
                hashes.push(h);
            }
        }
        offset += 16;
    }

    Ok(hashes)
}

/// DES-ECB RID-based hash unwrapping (same algorithm as SAM).
fn aes_gcm_unwrap_hash(encrypted: &[u8], rid: u32) -> Result<[u8; 16]> {
fn des_unwrap_hash(encrypted: &[u8], rid: u32) -> Result<[u8; 16]> {
    use des::cipher::generic_array::GenericArray;
    use des::cipher::{BlockDecrypt, KeyInit};

    let rid_bytes = rid.to_le_bytes();

    let key1_src = [
        rid_bytes[0], rid_bytes[1], rid_bytes[2], rid_bytes[3],
        rid_bytes[0], rid_bytes[1], rid_bytes[2],
    ];
    let key2_src = [
        rid_bytes[3], rid_bytes[0], rid_bytes[1], rid_bytes[2],
        rid_bytes[3], rid_bytes[0], rid_bytes[1],
    ];

    let des_key1 = expand_des_key(&key1_src);
    let des_key2 = expand_des_key(&key2_src);

    let mut block1 = GenericArray::clone_from_slice(&encrypted[0..8]);
    let mut block2 = GenericArray::clone_from_slice(&encrypted[8..16]);

    let cipher1 = des::Des::new_from_slice(&des_key1)
        .map_err(|e| VmkatzError::DecryptionError(format!("DES key1: {}", e)))?;
    let cipher2 = des::Des::new_from_slice(&des_key2)
        .map_err(|e| VmkatzError::DecryptionError(format!("DES key2: {}", e)))?;

    cipher1.decrypt_block(&mut block1);
    cipher2.decrypt_block(&mut block2);

    let mut hash = [0u8; 16];
    hash[..8].copy_from_slice(&block1);
    hash[8..].copy_from_slice(&block2);
    Ok(hash)
}

/// Expand 7-byte key material to 8-byte DES key with odd parity.
///
/// DES uses 56-bit keys packed into 8 bytes (7 data bits + 1 parity bit each).
/// This distributes the 56 source bits into 8 key bytes, shifting each byte so
/// that bits 7..1 carry key material and bit 0 is set for odd parity.
fn expand_des_key(src: &[u8; 7]) -> [u8; 8] {
    // Spread 7 source bytes across 8 key bytes (7 data bits each)
    let mut key = [0u8; 8];
    key[0] = src[0] >> 1;
    key[1] = ((src[0] & 0x01) << 6) | (src[1] >> 2);
    key[2] = ((src[1] & 0x03) << 5) | (src[2] >> 3);
    key[3] = ((src[2] & 0x07) << 4) | (src[3] >> 4);
    key[4] = ((src[3] & 0x0F) << 3) | (src[4] >> 5);
    key[5] = ((src[4] & 0x1F) << 2) | (src[5] >> 6);
    key[6] = ((src[5] & 0x3F) << 1) | (src[6] >> 7);
    key[7] = src[6] & 0x7F;

    // Set odd parity on each byte (DES ignores bit 0, uses it for parity check)
    for b in &mut key {
        let mut val = *b << 1;
        let parity = (val.count_ones() + 1) & 1;
        val |= parity as u8;
        *b = val;
    }

    key
}

/// Decode an AD string (UTF-16LE typically).
fn decode_ad_string(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    // Try UTF-16LE first (most AD strings)
    if data.len() >= 2 && data.len().is_multiple_of(2) {
        let s = crate::utils::utf16le_decode(data);
        if !s.is_empty() && s.chars().all(|c| !c.is_control() || c == '\n' || c == '\r') {
            return s;
        }
    }
    // ASCII fallback
    String::from_utf8_lossy(data)
        .trim_end_matches('\0')
        .to_string()
}

/// Extract the RID (last sub-authority) from a Windows SID binary blob.
fn extract_rid_from_sid(sid: &[u8]) -> Option<u32> {
    // SID binary format:
    //   byte 0: revision (1)
    //   byte 1: sub-authority count
    //   bytes 2-7: identifier authority (6 bytes, big-endian)
    //   bytes 8+: sub-authorities (4 bytes each, little-endian per MS-DTYP 2.4.2)
    // RID is the last sub-authority
    if sid.len() < 8 {
        return None;
    }
    let sub_auth_count = sid[1] as usize;
    let expected_len = 8 + sub_auth_count * 4;
    if sid.len() < expected_len || sub_auth_count == 0 {
        return None;
    }
    let rid_offset = 8 + (sub_auth_count - 1) * 4;
    let rid_bytes: [u8; 4] = sid[rid_offset..rid_offset + 4].try_into().ok()?;

    // MS-DTYP 2.4.2 specifies LE sub-authorities, but some NTDS.dit databases
    // (e.g. GOAD lab environments) store the RID in big-endian.
    // RIDs are small sequential integers (500 for Administrator, 502 for krbtgt, etc.)
    // so min(LE, BE) always picks the correct interpretation: byte-swapping a small
    // integer yields a very large one, making min() select the right value.
    let rid_le = u32::from_le_bytes(rid_bytes);
    let rid_be = u32::from_be_bytes(rid_bytes);
    Some(rid_le.min(rid_be))
}
