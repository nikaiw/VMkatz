//! Output entry points and shared formatting helpers.

use super::args::Colors;

#[cfg(feature = "credman")]
mod credman;
mod dedup;
#[cfg(all(feature = "disk", feature = "dpapi"))]
mod dpapi;
mod exports;
#[cfg(feature = "ntds.dit")]
mod ntds;
#[cfg(feature = "sam")]
mod registry;
mod sessions;
mod text;

#[cfg(feature = "credman")]
pub(crate) use credman::{print_credman_csv, print_credman_text};
#[cfg(all(feature = "disk", feature = "dpapi"))]
pub(crate) use dpapi::{
    dedup_dpapi_hashes, print_dpapi_masterkey_csv, print_dpapi_masterkey_hashcat,
    print_dpapi_masterkey_text,
};
#[cfg(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv"
))]
pub(crate) use exports::export_bitlocker_fvek;
pub(crate) use exports::export_kerberos_tickets;
#[cfg(feature = "ntds.dit")]
pub(crate) use ntds::{
    print_ntds_brief, print_ntds_csv, print_ntds_hashcat, print_ntds_ntlm, print_ntds_text,
};
#[cfg(all(
    feature = "sam",
    any(
        feature = "vmware",
        feature = "vbox",
        feature = "qemu",
        feature = "hyperv"
    )
))]
pub(crate) use registry::print_registry_creds;
#[cfg(feature = "sam")]
pub(crate) use registry::{
    print_cached_credentials, print_dcc2_csv, print_dcc2_hashcat, print_disk_secrets,
    print_lsa_csv, print_lsa_secrets, print_sam_brief, print_sam_csv, print_sam_hashcat,
    print_sam_ntlm, print_sam_text,
};
pub(crate) use sessions::output_credentials;

/// Returns true if a provider should be shown given the --provider filter.
/// Empty filter = show all providers.
fn should_show(providers: &[String], name: &str) -> bool {
    providers.is_empty() || providers.iter().any(|p| p.eq_ignore_ascii_case(name))
}

// Blank hash detection

/// NT hash of empty password (NTLM(""))
const BLANK_NT_HEX: &str = "31d6cfe0d16ae931b73c59d7e0c089c0";
/// LM hash of empty password (`LanMan`(""))
/// Used as placeholder in pwdump format when LM hashing is disabled.
const BLANK_LM_HEX: &str = "aad3b435b51404eeaad3b435b51404ee";

const ZERO_HASH_16: [u8; 16] = [0u8; 16];

/// Prefix used by `decode_password_bytes` for binary (non-text) passwords.
/// Allows `fmt_password` to display raw hex without lossy UTF-16 re-encoding.
const RAW_HEX_PREFIX: &str = "\x00hex:";

/// Get the displayable password string, stripping internal raw-hex prefix if present.
fn display_password(password: &str) -> &str {
    password.strip_prefix(RAW_HEX_PREFIX).unwrap_or(password)
}

/// Format a hash with blank annotation and optional color.
fn fmt_hash(hash: &[u8], c: &Colors) -> String {
    let h = hex::encode(hash);
    if hash.iter().all(|&b| b == 0) {
        return format!("{}{}{}", c.dim, h, c.reset);
    }
    if h == BLANK_NT_HEX || h == BLANK_LM_HEX {
        return format!("{}{} (blank){}", c.dim, h, c.reset);
    }
    format!("{}{}{}", c.yellow, h, c.reset)
}

/// Format LM hash for pwdump output: zero → standard empty LM placeholder.
#[cfg(feature = "sam")]
fn fmt_lm_pwdump(hash: &[u8; 16]) -> String {
    if *hash == ZERO_HASH_16 {
        BLANK_LM_HEX.to_string()
    } else {
        hex::encode(hash)
    }
}

/// Format a password for display: if it contains non-printable/control characters
/// (typical of machine account random passwords), show as hex instead of garbled Unicode.
fn fmt_password(password: &str, c: &Colors) -> String {
    // Raw hex from decode_password_bytes (binary password that failed UTF-16 decode)
    if let Some(hex_str) = password.strip_prefix(RAW_HEX_PREFIX) {
        return format!("{}(hex) {}{}", c.dim, hex_str, c.reset);
    }
    let is_printable = password.chars().all(|ch| {
        !ch.is_control()
            && (ch.is_ascii_graphic() || ch.is_ascii_whitespace() || ch.is_alphanumeric())
    });
    if is_printable {
        format!("{}{}{}", c.red, password, c.reset)
    } else {
        // Non-printable but valid UTF-16 (e.g. CJK characters)
        let bytes: Vec<u8> = password.encode_utf16().flat_map(u16::to_le_bytes).collect();
        format!("{}(hex) {}{}", c.dim, hex::encode(&bytes), c.reset)
    }
}

/// DWM-N (domain "Window Manager") and UMFD-N ("Font Driver Host") virtual
/// accounts: their per-boot random password is noise, so cleartext is suppressed.
fn is_virtual_account(username: &str, domain: &str) -> bool {
    domain.eq_ignore_ascii_case("Window Manager")
        || domain.eq_ignore_ascii_case("Font Driver Host")
        || username.starts_with("DWM-")
        || username.starts_with("UMFD-")
}

fn csv_escape(s: &str) -> String {
    let sanitized: String = s
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .collect();
    if sanitized.contains(',') || sanitized.contains('"') || sanitized.contains('\n') {
        format!("\"{}\"", sanitized.replace('"', "\"\""))
    } else {
        sanitized
    }
}
