//! SAM hash decryption: extracts NT/LM hashes from the SAM registry hive.
//!
//! Supports both AES (Windows 10+) and RC4 (legacy) encryption schemes,
//! plus DES-ECB RID-based unwrapping.

use aes::Aes128;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use des::cipher::generic_array::GenericArray;
use des::cipher::{BlockDecrypt, KeyInit};

use super::hive::Hive;
use super::SamEntry;
use crate::error::{VmkatzError, Result};

type Aes128CbcDec = cbc::Decryptor<Aes128>;

/// Extract all user hashes from SAM hive data using the given bootkey.
pub fn extract_hashes(sam_hive_data: &[u8], bootkey: &[u8; 16]) -> Result<Vec<SamEntry>> {
    let hive = Hive::new(sam_hive_data)?;
    let root = hive.root_key()?;

    let account = root
        .subkey(&hive, "SAM")?
        .subkey(&hive, "Domains")?
        .subkey(&hive, "Account")?;

    // Step 1: Derive hashed bootkey from Account\F value
    let f_value = account.value(&hive, "F")?;
    let hashed_bootkey = decrypt_hashed_bootkey(&f_value, bootkey)?;
    log::info!("Hashed bootkey: {}", hex::encode(hashed_bootkey));

    // Step 2: Enumerate users under Account\Users
    let users_key = account.subkey(&hive, "Users")?;
    let user_subkeys = users_key.subkeys(&hive)?;

    let mut entries = Vec::new();

    for user_key in &user_subkeys {
        let key_name = user_key.name();
        // Skip "Names" subkey
        if key_name.eq_ignore_ascii_case("Names") {
            continue;
        }

        // Parse RID from hex key name (e.g., "000001F4" = 500)
        let rid = match u32::from_str_radix(key_name, 16) {
            Ok(r) => r,
            Err(_) => {
                log::warn!("Skipping non-hex user key: {}", key_name);
                continue;
            }
        };

        let v_data = match user_key.value(&hive, "V") {
            Ok(v) => v,
            Err(e) => {
                log::warn!("RID {}: no V value: {}", rid, e);
                continue;
            }
        };

        // Read per-user F value for Account Control Bits (ACB flags at offset 0x38)
        let acb_flags = user_key.value(&hive, "F").ok()
            .filter(|f| f.len() >= 0x3C)
            .map(|f| u32::from_le_bytes([f[0x38], f[0x39], f[0x3A], f[0x3B]]))
            .unwrap_or(0);

        match extract_user_hashes(&v_data, &hashed_bootkey, rid, acb_flags) {
            Ok(entry) => {
                log::info!(
                    "RID {}: user={}, NT={}, flags=0x{:04x}{}",
                    rid,
                    entry.username,
                    hex::encode(entry.nt_hash),
                    entry.acb_flags,
                    if entry.is_disabled() { " [DISABLED]" } else { "" },
                );
                entries.push(entry);
            }
            Err(e) => {
                log::warn!("RID {}: hash extraction failed: {}", rid, e);
            }
        }
    }

    // Sort by RID for consistent output
    entries.sort_by_key(|e| e.rid);
    Ok(entries)
}

/// Decrypt the hashed bootkey from the SAM F value.
fn decrypt_hashed_bootkey(f: &[u8], bootkey: &[u8; 16]) -> Result<[u8; 16]> {
    if f.len() < 0xA0 {
        return Err(sam_err("F value too short"));
    }

    let revision = f[0x00];
    log::info!("SAM F revision: 0x{:02x}", revision);

    match revision {
        0x03 => {
            // AES (Windows 10+)
            let salt = &f[0x78..0x88];
            let encrypted = &f[0x88..0xA0]; // 24 bytes, use first 16
            let decrypted = aes128_cbc_decrypt(bootkey, salt, encrypted)?;
            let mut hbk = [0u8; 16];
            hbk.copy_from_slice(&decrypted[..16]);
            Ok(hbk)
        }
        0x02 => {
            // RC4 (legacy)
            let qwerty = b"!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0";
            let digits = b"0123456789012345678901234567890123456789\0";

            let mut md5_input = Vec::new();
            md5_input.extend_from_slice(&f[0x70..0x80]);
            md5_input.extend_from_slice(qwerty);
            md5_input.extend_from_slice(bootkey);
            md5_input.extend_from_slice(digits);

            let rc4_key = md5_hash(&md5_input);
            let decrypted = rc4(&rc4_key, &f[0x80..0xA0]);
            let mut hbk = [0u8; 16];
            hbk.copy_from_slice(&decrypted[..16]);
            Ok(hbk)
        }
        _ => Err(sam_err(&format!("Unknown F revision: 0x{:02x}", revision))),
    }
}

/// Extract username and hashes from a user's V value.
fn extract_user_hashes(v: &[u8], hashed_bootkey: &[u8; 16], rid: u32, acb_flags: u32) -> Result<SamEntry> {
    if v.len() < 0xCC {
        return Err(sam_err("V value too short"));
    }

    // Parse username from descriptor 1 (V+0x0C)
    let name_offset = (u32_le(v, 0x0C) as usize).saturating_add(0xCC);
    let name_length = u32_le(v, 0x10) as usize;
    let username = if name_offset.checked_add(name_length).is_some_and(|end| end <= v.len()) && name_length > 0 {
        decode_utf16le(&v[name_offset..name_offset + name_length])
    } else {
        format!("RID-{}", rid)
    };

    // Parse LM hash (desc[13] at V+0x9C)
    let lm_offset = (u32_le(v, 0x9C) as usize).saturating_add(0xCC);
    let lm_length = u32_le(v, 0xA0) as usize;
    let lm_hash = if lm_length >= 4 && lm_offset.checked_add(lm_length).is_some_and(|end| end <= v.len()) {
        decrypt_sam_hash(
            &v[lm_offset..lm_offset + lm_length],
            hashed_bootkey,
            rid,
            false,
        )?
    } else {
        [0u8; 16]
    };

    // Parse NT hash (desc[14] at V+0xA8)
    let nt_offset = (u32_le(v, 0xA8) as usize).saturating_add(0xCC);
    let nt_length = u32_le(v, 0xAC) as usize;
    let nt_hash = if nt_length >= 4 && nt_offset.checked_add(nt_length).is_some_and(|end| end <= v.len()) {
        decrypt_sam_hash(
            &v[nt_offset..nt_offset + nt_length],
            hashed_bootkey,
            rid,
            true,
        )?
    } else {
        [0u8; 16] // Empty hash
    };

    Ok(SamEntry {
        rid,
        username,
        nt_hash,
        lm_hash,
        acb_flags,
    })
}

/// Decrypt a single SAM hash (NT or LM) from its SAM_HASH structure.
fn decrypt_sam_hash(
    hash_data: &[u8],
    hashed_bootkey: &[u8; 16],
    rid: u32,
    is_nt: bool,
) -> Result<[u8; 16]> {
    if hash_data.len() < 4 {
        return Ok([0u8; 16]);
    }

    // SAM_HASH header: +0x00 u16 PekID, +0x02 u16 Revision
    let revision = u16::from_le_bytes(
        hash_data.get(2..4)
            .ok_or_else(|| sam_err("SAM_HASH header too short"))?
            .try_into()
            .map_err(|_| sam_err("SAM_HASH revision slice"))?,
    );

    let decrypted = match revision {
        0x02 => {
            // SAM_HASH_AES: header is 0x18 bytes (PekID + Revision + DataOffset + Salt[16]).
            // Encrypted hash data starts at +0x18. If total len <= 0x18, no hash stored.
            if hash_data.len() <= 0x18 {
                return Ok([0u8; 16]);
            }
            let salt = &hash_data[0x08..0x18];
            let encrypted = &hash_data[0x18..];
            let dec = aes128_cbc_decrypt(hashed_bootkey, salt, encrypted)?;
            if dec.len() < 16 {
                return Ok([0u8; 16]);
            }
            dec[..16].to_vec()
        }
        0x01 => {
            // RC4: encrypted at +0x04, 16 bytes
            if hash_data.len() < 0x14 {
                return Ok([0u8; 16]);
            }
            let encrypted = &hash_data[0x04..0x14];
            let suffix = if is_nt {
                b"NTPASSWORD\0" as &[u8]
            } else {
                b"LMPASSWORD\0" as &[u8]
            };
            let rid_bytes = rid.to_le_bytes();
            let mut md5_input = Vec::new();
            md5_input.extend_from_slice(hashed_bootkey);
            md5_input.extend_from_slice(&rid_bytes);
            md5_input.extend_from_slice(suffix);
            let rc4_key = md5_hash(&md5_input);
            rc4(&rc4_key, encrypted)
        }
        _ => {
            log::warn!("Unknown SAM_HASH revision: 0x{:04x}", revision);
            return Ok([0u8; 16]);
        }
    };

    if decrypted.len() < 16 {
        return Ok([0u8; 16]);
    }

    // DES-ECB RID unwrap
    des_unwrap_hash(&decrypted[..16], rid)
}

/// DES-ECB RID-based hash unwrapping.
fn des_unwrap_hash(encrypted: &[u8], rid: u32) -> Result<[u8; 16]> {
    let rid_bytes = rid.to_le_bytes();

    let key1_src = [
        rid_bytes[0],
        rid_bytes[1],
        rid_bytes[2],
        rid_bytes[3],
        rid_bytes[0],
        rid_bytes[1],
        rid_bytes[2],
    ];
    let key2_src = [
        rid_bytes[3],
        rid_bytes[0],
        rid_bytes[1],
        rid_bytes[2],
        rid_bytes[3],
        rid_bytes[0],
        rid_bytes[1],
    ];

    let des_key1 = expand_des_key(&key1_src);
    let des_key2 = expand_des_key(&key2_src);

    let mut block1 = GenericArray::clone_from_slice(&encrypted[0..8]);
    let mut block2 = GenericArray::clone_from_slice(&encrypted[8..16]);

    let cipher1 =
        des::Des::new_from_slice(&des_key1).map_err(|e| sam_err(&format!("DES key1: {}", e)))?;
    let cipher2 =
        des::Des::new_from_slice(&des_key2).map_err(|e| sam_err(&format!("DES key2: {}", e)))?;

    cipher1.decrypt_block(&mut block1);
    cipher2.decrypt_block(&mut block2);

    let mut hash = [0u8; 16];
    hash[..8].copy_from_slice(&block1);
    hash[8..].copy_from_slice(&block2);
    Ok(hash)
}

/// Expand 7-byte key source to 8-byte DES key with odd parity.
fn expand_des_key(src: &[u8; 7]) -> [u8; 8] {
    let mut key = [0u8; 8];
    key[0] = src[0] >> 1;
    key[1] = ((src[0] & 0x01) << 6) | (src[1] >> 2);
    key[2] = ((src[1] & 0x03) << 5) | (src[2] >> 3);
    key[3] = ((src[2] & 0x07) << 4) | (src[3] >> 4);
    key[4] = ((src[3] & 0x0F) << 3) | (src[4] >> 5);
    key[5] = ((src[4] & 0x1F) << 2) | (src[5] >> 6);
    key[6] = ((src[5] & 0x3F) << 1) | (src[6] >> 7);
    key[7] = src[6] & 0x7F;

    // Set odd parity
    for b in &mut key {
        let mut val = *b << 1;
        let parity = (val.count_ones() + 1) & 1;
        val |= parity as u8;
        *b = val;
    }

    key
}

/// AES-128-CBC decryption (no padding).
pub(crate) fn aes128_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let mut buf = data.to_vec();
    // Pad to 16-byte boundary if needed (with zeros for decryption)
    let pad_len = (16 - (buf.len() % 16)) % 16;
    buf.extend(std::iter::repeat_n(0u8, pad_len));

    let decryptor =
        Aes128CbcDec::new_from_slices(key, iv).map_err(|e| sam_err(&format!("AES init: {}", e)))?;
    decryptor
        .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf)
        .map_err(|e| sam_err(&format!("AES decrypt: {}", e)))?;

    // Trim back to original size
    buf.truncate(data.len());
    Ok(buf)
}

/// MD5 hash.
pub(crate) fn md5_hash(data: &[u8]) -> [u8; 16] {
    use md5::Digest;
    let result = md5::Md5::digest(data);
    let mut out = [0u8; 16];
    out.copy_from_slice(&result);
    out
}

/// RC4 stream cipher.
pub(crate) fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s: Vec<u8> = (0..=255u8).collect();
    let mut j: u8 = 0;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }
    let (mut i, mut j) = (0u8, 0u8);
    data.iter()
        .map(|&b| {
            i = i.wrapping_add(1);
            j = j.wrapping_add(s[i as usize]);
            s.swap(i as usize, j as usize);
            b ^ s[s[i as usize].wrapping_add(s[j as usize]) as usize]
        })
        .collect()
}

pub(crate) fn decode_utf16le(data: &[u8]) -> String {
    crate::utils::utf16le_decode(data)
}

fn u32_le(data: &[u8], offset: usize) -> u32 {
    data.get(offset..offset + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
        .unwrap_or(0)
}

fn sam_err(msg: &str) -> VmkatzError {
    VmkatzError::DecryptionError(format!("SAM: {}", msg))
}
