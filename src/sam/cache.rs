//! Domain Cached Credentials (DCC2 / MsCacheV2) extraction.
//!
//! Decrypts cached domain logon hashes from the SECURITY registry hive.
//! These are stored in `SECURITY\Cache\NL$n` values and encrypted with
//! the NL$KM key (an LSA secret). Output is hashcat mode 2100 format.

use super::hashes::{aes128_cbc_decrypt, decode_utf16le};
use super::hive::Hive;
use crate::error::{GovmemError, Result};

/// A single domain cached credential entry.
#[derive(Debug)]
pub struct CachedCredential {
    pub username: String,
    pub domain: String,
    pub dns_domain: String,
    pub dcc2_hash: [u8; 16],
    pub iteration_count: u32,
}

impl std::fmt::Display for CachedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // hashcat mode 2100 format
        write!(
            f,
            "  {}/{}:$DCC2${}#{}#{}",
            if self.dns_domain.is_empty() {
                &self.domain
            } else {
                &self.dns_domain
            },
            self.username,
            self.iteration_count,
            self.username.to_lowercase(),
            hex::encode(self.dcc2_hash),
        )
    }
}

/// Extract domain cached credentials from the SECURITY hive.
///
/// Requires the NL$KM key (64 bytes), which is extracted as an LSA secret.
pub fn extract_cached_credentials(
    security_data: &[u8],
    nlkm_key: &[u8],
) -> Result<Vec<CachedCredential>> {
    if nlkm_key.len() < 32 {
        return Err(GovmemError::DecryptionError(
            "NL$KM key too short (need at least 32 bytes)".to_string(),
        ));
    }

    let hive = Hive::new(security_data)?;
    let root = hive.root_key()?;

    // Navigate to Cache key
    let cache_key = match root.subkey(&hive, "Cache") {
        Ok(k) => k,
        Err(_) => {
            log::info!("SECURITY\\Cache key not found, no cached credentials");
            return Ok(Vec::new());
        }
    };

    // Read iteration count
    let iteration_count = match cache_key.subkey(&hive, "NL$IterationCount") {
        Ok(iter_key) => {
            match iter_key.value(&hive, "") {
                Ok(data) if data.len() >= 4 => {
                    let raw = u32::from_le_bytes(data[0..4].try_into().unwrap());
                    if raw > 10240 {
                        raw & 0xFFFF_FC00 // round down to nearest 1024
                    } else {
                        raw * 1024
                    }
                }
                _ => 10240,
            }
        }
        Err(_) => {
            // NL$IterationCount might be a value, not a subkey
            match cache_key.value(&hive, "NL$IterationCount") {
                Ok(data) if data.len() >= 4 => {
                    let raw = u32::from_le_bytes(data[0..4].try_into().unwrap());
                    if raw > 10240 {
                        raw & 0xFFFF_FC00
                    } else {
                        raw * 1024
                    }
                }
                _ => 10240,
            }
        }
    };

    log::info!("DCC2 iteration count: {}", iteration_count);

    // AES key = NL$KM[16..32]
    let aes_key = &nlkm_key[16..32];

    let mut credentials = Vec::new();

    // Try NL$1 through NL$50 (max configurable cache size)
    for i in 1..=50 {
        let value_name = format!("NL${}", i);

        let data = match cache_key.value(&hive, &value_name) {
            Ok(d) => d,
            Err(_) => break, // No more entries
        };

        // NL_RECORD header is 0x60 (96) bytes minimum
        if data.len() < 0x60 + 16 {
            continue;
        }

        // Parse NL_RECORD header
        let user_length = u16::from_le_bytes(data[0x00..0x02].try_into().unwrap()) as usize;
        let domain_name_length = u16::from_le_bytes(data[0x02..0x04].try_into().unwrap()) as usize;
        let dns_domain_length = u16::from_le_bytes(data[0x3C..0x3E].try_into().unwrap()) as usize;

        // IV at offset 0x40 (16 bytes)
        let iv = &data[0x40..0x50];

        // Check if entry is empty (IV is all zeros)
        if iv.iter().all(|&b| b == 0) {
            continue;
        }

        // Flags at 0x30
        let flags = u32::from_le_bytes(data[0x30..0x34].try_into().unwrap());
        if flags & 1 != 1 {
            continue; // not a valid/encrypted entry
        }

        // Encrypted data starts at 0x60
        let encrypted = &data[0x60..];
        if encrypted.len() < 0x48 + user_length {
            log::warn!(
                "NL${}: encrypted data too short ({} bytes)",
                i,
                encrypted.len()
            );
            continue;
        }

        // Decrypt with AES-128-CBC
        let plaintext = match aes128_cbc_decrypt(aes_key, iv, encrypted) {
            Ok(pt) => pt,
            Err(e) => {
                log::warn!("NL${}: decryption failed: {}", i, e);
                continue;
            }
        };

        if plaintext.len() < 0x48 + user_length {
            log::warn!("NL${}: decrypted data too short", i);
            continue;
        }

        // Extract DCC2 hash (first 16 bytes of decrypted data)
        let mut dcc2_hash = [0u8; 16];
        dcc2_hash.copy_from_slice(&plaintext[0..16]);

        // Check if hash is all zeros (empty entry)
        if dcc2_hash.iter().all(|&b| b == 0) {
            continue;
        }

        // Extract username at offset 0x48 (UTF-16LE)
        let username_end = 0x48 + user_length;
        let username = if username_end <= plaintext.len() {
            decode_utf16le(&plaintext[0x48..username_end])
        } else {
            continue;
        };

        // Extract domain name after username (with padding)
        let domain_offset = 0x48 + pad4(user_length);
        let domain = if domain_offset + domain_name_length <= plaintext.len() {
            decode_utf16le(&plaintext[domain_offset..domain_offset + domain_name_length])
        } else {
            String::new()
        };

        // Extract DNS domain name after domain (with padding)
        let dns_offset = domain_offset + pad4(domain_name_length);
        let dns_domain =
            if dns_domain_length > 0 && dns_offset + dns_domain_length <= plaintext.len() {
                decode_utf16le(&plaintext[dns_offset..dns_offset + dns_domain_length])
            } else {
                String::new()
            };

        log::info!(
            "NL${}: user={} domain={} dns={} hash={}",
            i,
            username,
            domain,
            dns_domain,
            hex::encode(dcc2_hash),
        );

        credentials.push(CachedCredential {
            username,
            domain,
            dns_domain,
            dcc2_hash,
            iteration_count,
        });
    }

    Ok(credentials)
}

/// Round up to DWORD alignment.
fn pad4(len: usize) -> usize {
    (len + 3) & !3
}
