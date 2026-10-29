//! Output formatting (text/csv/ntlm/hashcat/brief) and export helpers
//! (DPAPI backup keys, Kerberos tickets, BitLocker FVEK).

use vmkatz::lsass::types::{Credential, KerberosKey};

use super::args::{Args, COLORS_OFF, Colors, get_colors};

/// Returns true if a provider should be shown given the --provider filter.
/// Empty filter = show all providers.
fn should_show(providers: &[String], name: &str) -> bool {
    providers.is_empty() || providers.iter().any(|p| p.eq_ignore_ascii_case(name))
}

// ---------------------------------------------------------------------------
// Blank hash detection
// ---------------------------------------------------------------------------

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

/// Print `DiskSecrets` (SAM + LSA + cached creds) using the current output format.
#[cfg(all(
    feature = "sam",
    any(
        feature = "vmware",
        feature = "vbox",
        feature = "qemu",
        feature = "hyperv"
    )
))]
pub(crate) fn print_disk_secrets(secrets: &vmkatz::sam::DiskSecrets, args: &Args) {
    let c = get_colors(args);

    match args.format.as_str() {
        "ntlm" => print_sam_ntlm(&secrets.sam_entries),
        "csv" => print_sam_csv(&secrets.sam_entries),
        "hashcat" => print_sam_hashcat(&secrets.sam_entries),
        "brief" => print_sam_brief(&secrets.sam_entries),
        _ => print_sam_text(&secrets.sam_entries, c),
    }

    if !secrets.lsa_secrets.is_empty() {
        match args.format.as_str() {
            "csv" => print_lsa_csv(&secrets.lsa_secrets),
            "hashcat" => {} // LSA secrets not applicable for hashcat
            _ => print_lsa_secrets(&secrets.lsa_secrets, c),
        }
    }

    export_dpapi_backup_keys(&secrets.lsa_secrets);

    if !secrets.cached_credentials.is_empty() {
        match args.format.as_str() {
            "csv" => print_dcc2_csv(&secrets.cached_credentials),
            "hashcat" => print_dcc2_hashcat(&secrets.cached_credentials),
            _ => print_cached_credentials(&secrets.cached_credentials, c),
        }
    }
}

#[cfg(feature = "ntds.dit")]
pub(crate) fn print_ntds_text(entries: &[vmkatz::ntds::AdHashEntry], c: &Colors) {
    println!("\n{}[+] AD NTLM Hashes:{}", c.green, c.reset);
    for entry in entries {
        let hist = if entry.is_history {
            match entry.history_index {
                Some(idx) => format!("history{idx}"),
                None => "history".to_string(),
            }
        } else {
            "current".to_string()
        };
        if entry.lm_hash == ZERO_HASH_16 {
            println!(
                "  RID: {:<6} {}{:<24}{} {:<10} NT:{}",
                entry.rid,
                c.bold,
                entry.username,
                c.reset,
                hist,
                fmt_hash(&entry.nt_hash, c),
            );
        } else {
            println!(
                "  RID: {:<6} {}{:<24}{} {:<10} NT:{}  LM:{}",
                entry.rid,
                c.bold,
                entry.username,
                c.reset,
                hist,
                fmt_hash(&entry.nt_hash, c),
                fmt_hash(&entry.lm_hash, c),
            );
        }
    }
}

#[cfg(feature = "ntds.dit")]
pub(crate) fn print_ntds_ntlm(entries: &[vmkatz::ntds::AdHashEntry]) {
    for entry in entries {
        let user: std::borrow::Cow<str> = if entry.is_history {
            match entry.history_index {
                Some(idx) => format!("{}_history{}", entry.username, idx).into(),
                None => format!("{}_history", entry.username).into(),
            }
        } else {
            (&*entry.username).into()
        };

        println!(
            "{}:{}:{}:{}:::",
            user,
            entry.rid,
            fmt_lm_pwdump(&entry.lm_hash),
            hex::encode(entry.nt_hash),
        );
    }
}

#[cfg(feature = "ntds.dit")]
pub(crate) fn print_ntds_csv(entries: &[vmkatz::ntds::AdHashEntry]) {
    println!("provider,username,domain,secret_type,secret,target");
    for entry in entries {
        let provider = if entry.is_history {
            let idx = entry.history_index.unwrap_or(0);
            format!("ntds_history_{idx}")
        } else {
            "ntds".to_string()
        };
        if entry.nt_hash != ZERO_HASH_16 {
            println!(
                "{},{},,nt_hash,{},{}",
                provider,
                csv_escape(&entry.username),
                hex::encode(entry.nt_hash),
                entry.rid
            );
        }
        if entry.lm_hash != ZERO_HASH_16 {
            println!(
                "{},{},,lm_hash,{},{}",
                provider,
                csv_escape(&entry.username),
                hex::encode(entry.lm_hash),
                entry.rid
            );
        }
    }
}

#[cfg(feature = "ntds.dit")]
pub(crate) fn print_ntds_hashcat(entries: &[vmkatz::ntds::AdHashEntry]) {
    let mut seen = std::collections::HashSet::new();
    for entry in entries {
        if entry.nt_hash != ZERO_HASH_16 && seen.insert((&entry.username, entry.nt_hash)) {
            println!("{}:{}", entry.username, hex::encode(entry.nt_hash));
        }
    }
}

#[cfg(feature = "ntds.dit")]
pub(crate) fn print_ntds_brief(entries: &[vmkatz::ntds::AdHashEntry]) {
    for entry in entries {
        if entry.nt_hash != ZERO_HASH_16 && !entry.is_history {
            println!("{}: {}", entry.username, hex::encode(entry.nt_hash));
        }
    }
}

#[cfg(feature = "sam")]
pub(crate) fn print_sam_text(entries: &[vmkatz::sam::SamEntry], c: &Colors) {
    println!("\n{}[+] SAM Hashes:{}", c.green, c.reset);
    for entry in entries {
        // Build status annotation
        let status = sam_status_label(entry, c);

        if entry.lm_hash == ZERO_HASH_16 {
            println!(
                "  RID: {:<5} {}{:<20}{}  NT:{}{}",
                entry.rid,
                c.bold,
                entry.username,
                c.reset,
                fmt_hash(&entry.nt_hash, c),
                status,
            );
        } else {
            println!(
                "  RID: {:<5} {}{:<20}{}  NT:{}  LM:{}{}",
                entry.rid,
                c.bold,
                entry.username,
                c.reset,
                fmt_hash(&entry.nt_hash, c),
                fmt_hash(&entry.lm_hash, c),
                status,
            );
        }
    }
}

/// Build a human-readable status label for a SAM entry.
#[cfg(feature = "sam")]
fn sam_status_label(entry: &vmkatz::sam::SamEntry, c: &Colors) -> String {
    let mut tags = Vec::new();
    if entry.is_disabled() {
        tags.push("DISABLED");
    }
    if entry.nt_hash == ZERO_HASH_16 {
        tags.push("NO PASSWORD");
    } else if hex::encode(entry.nt_hash) == BLANK_NT_HEX {
        tags.push("BLANK PASSWORD");
    }
    if tags.is_empty() {
        String::new()
    } else {
        format!("  {}({}){}", c.dim, tags.join(", "), c.reset)
    }
}

#[cfg(feature = "sam")]
pub(crate) fn print_sam_ntlm(entries: &[vmkatz::sam::SamEntry]) {
    for entry in entries {
        println!(
            "{}:{}:{}:{}:::",
            entry.username,
            entry.rid,
            fmt_lm_pwdump(&entry.lm_hash),
            hex::encode(entry.nt_hash),
        );
    }
}

#[cfg(feature = "sam")]
pub(crate) fn print_sam_csv(entries: &[vmkatz::sam::SamEntry]) {
    println!("provider,username,domain,secret_type,secret,target");
    for entry in entries {
        if entry.nt_hash != ZERO_HASH_16 {
            println!(
                "sam,{},,nt_hash,{},{}",
                csv_escape(&entry.username),
                hex::encode(entry.nt_hash),
                entry.rid
            );
        }
        if entry.lm_hash != ZERO_HASH_16 {
            println!(
                "sam,{},,lm_hash,{},{}",
                csv_escape(&entry.username),
                hex::encode(entry.lm_hash),
                entry.rid
            );
        }
    }
}

#[cfg(feature = "sam")]
pub(crate) fn print_sam_hashcat(entries: &[vmkatz::sam::SamEntry]) {
    for entry in entries {
        if entry.nt_hash != ZERO_HASH_16 {
            // hashcat mode 1000 (NTLM) with --username format
            println!("{}:{}", entry.username, hex::encode(entry.nt_hash));
        }
    }
}

#[cfg(feature = "sam")]
pub(crate) fn print_sam_brief(entries: &[vmkatz::sam::SamEntry]) {
    for entry in entries {
        if entry.nt_hash != ZERO_HASH_16 {
            println!("{}: {}", entry.username, hex::encode(entry.nt_hash));
        }
    }
}

#[cfg(feature = "sam")]
pub(crate) fn print_dcc2_csv(creds: &[vmkatz::sam::cache::CachedCredential]) {
    println!("provider,username,domain,secret_type,secret,target");
    for cred in creds {
        println!(
            "dcc2,{},{},dcc2_hash,$DCC2${}#{}#{},",
            csv_escape(&cred.username),
            csv_escape(if cred.dns_domain.is_empty() {
                &cred.domain
            } else {
                &cred.dns_domain
            }),
            cred.iteration_count,
            cred.username.to_lowercase(),
            hex::encode(cred.dcc2_hash),
        );
    }
}

#[cfg(feature = "sam")]
pub(crate) fn print_lsa_csv(secrets: &[vmkatz::sam::lsa::LsaSecret]) {
    println!("provider,username,domain,secret_type,secret,target");
    for secret in secrets {
        match &secret.parsed {
            vmkatz::sam::lsa::LsaSecretType::DpapiSystem {
                user_key,
                machine_key,
            } => {
                println!(
                    "lsa,,,dpapi_user_key,{},{}",
                    hex::encode(user_key),
                    csv_escape(&secret.name)
                );
                println!(
                    "lsa,,,dpapi_machine_key,{},{}",
                    hex::encode(machine_key),
                    csv_escape(&secret.name)
                );
            }
            vmkatz::sam::lsa::LsaSecretType::MachineAccount { password_hex } => {
                println!(
                    "lsa,,,machine_password,{},{}",
                    csv_escape(password_hex),
                    csv_escape(&secret.name)
                );
            }
            vmkatz::sam::lsa::LsaSecretType::DefaultPassword { password } => {
                println!(
                    "lsa,,,default_password,{},{}",
                    csv_escape(password),
                    csv_escape(&secret.name)
                );
            }
            vmkatz::sam::lsa::LsaSecretType::ServicePassword { service, password } => {
                println!(
                    "lsa,,,service_password,{},{}",
                    csv_escape(password),
                    csv_escape(service)
                );
            }
            vmkatz::sam::lsa::LsaSecretType::CachedDomainKey { key } => {
                println!(
                    "lsa,,,cached_domain_key,{},{}",
                    hex::encode(key),
                    csv_escape(&secret.name)
                );
            }
            vmkatz::sam::lsa::LsaSecretType::DpapiBackupPreferred { guid } => {
                println!(
                    "lsa,,,dpapi_backup_preferred,{},{}",
                    csv_escape(guid),
                    csv_escape(&secret.name)
                );
            }
            vmkatz::sam::lsa::LsaSecretType::DpapiBackupKey { guid, key_data, .. } => {
                println!(
                    "lsa,,,dpapi_backup_key,{},{}",
                    hex::encode(key_data),
                    csv_escape(guid)
                );
            }
            vmkatz::sam::lsa::LsaSecretType::Raw => {
                println!(
                    "lsa,,,raw,{},{}",
                    hex::encode(&secret.raw_data),
                    csv_escape(&secret.name)
                );
            }
        }
    }
}

/// Keep only the most recent DPAPI master key per (username, sid) unless `show_all` is set.
#[cfg(feature = "sam")]
pub(crate) fn dedup_dpapi_hashes(
    mut hashes: Vec<vmkatz::sam::dpapi_masterkey::DpapiMasterKeyHash>,
    show_all: bool,
) -> Vec<vmkatz::sam::dpapi_masterkey::DpapiMasterKeyHash> {
    if show_all || hashes.len() <= 1 {
        return hashes;
    }
    // Sort by (username, sid, modified DESC) so the most recent key comes first
    hashes.sort_by(|a, b| {
        a.username
            .cmp(&b.username)
            .then(a.sid.cmp(&b.sid))
            .then(b.modified.cmp(&a.modified))
    });
    let mut seen = std::collections::HashSet::new();
    hashes.retain(|h| seen.insert((h.username.clone(), h.sid.clone())));
    hashes
}

#[cfg(feature = "sam")]
pub(crate) fn print_dpapi_masterkey_csv(
    hashes: &[vmkatz::sam::dpapi_masterkey::DpapiMasterKeyHash],
) {
    println!("provider,username,domain,secret_type,secret,target");
    for h in hashes {
        println!(
            "dpapi_disk,{},{},masterkey_hash,{},{}",
            csv_escape(&h.username),
            csv_escape(&h.sid),
            csv_escape(&h.hash),
            csv_escape(&h.guid),
        );
    }
}

#[cfg(feature = "sam")]
pub(crate) fn print_dcc2_hashcat(creds: &[vmkatz::sam::cache::CachedCredential]) {
    for cred in creds {
        // hashcat mode 2100 (DCC2)
        println!(
            "$DCC2${}#{}#{}",
            cred.iteration_count,
            cred.username.to_lowercase(),
            hex::encode(cred.dcc2_hash),
        );
    }
}

#[cfg(feature = "sam")]
pub(crate) fn print_lsa_secrets(secrets: &[vmkatz::sam::lsa::LsaSecret], c: &Colors) {
    use vmkatz::sam::lsa::LsaSecretType;
    // Only show secrets with actionable parsed data.
    // Skip empty service passwords and unparsed raw blobs (L$TermServ*, SAC, SCM, etc.)
    let visible: Vec<_> = secrets
        .iter()
        .filter(|s| {
            !matches!(&s.parsed,
                LsaSecretType::ServicePassword { password, .. } if password.is_empty()
            ) && !matches!(&s.parsed, LsaSecretType::Raw)
        })
        .collect();
    if visible.is_empty() {
        return;
    }
    println!("\n{}[+] LSA Secrets:{}", c.green, c.reset);
    for secret in visible {
        println!("{secret}");
    }
}

#[cfg(feature = "sam")]
pub(crate) fn print_cached_credentials(creds: &[vmkatz::sam::cache::CachedCredential], c: &Colors) {
    println!(
        "\n{}[+] Domain Cached Credentials (DCC2):{}",
        c.green, c.reset
    );
    for cred in creds {
        println!("{cred}");
    }
}

#[cfg(feature = "sam")]
pub(crate) fn export_dpapi_backup_keys(secrets: &[vmkatz::sam::lsa::LsaSecret]) {
    for secret in secrets {
        if let vmkatz::sam::lsa::LsaSecretType::DpapiBackupKey { guid, pvk, .. } = &secret.parsed {
            if pvk.is_empty() {
                continue;
            }
            let filename = format!("ntds_capi_0_{guid}.pvk");
            match std::fs::write(&filename, pvk) {
                Ok(()) => {
                    eprintln!("[+] DPAPI backup key exported: {filename}");
                }
                Err(e) => {
                    log::warn!("Failed to write PVK file {filename}: {e}");
                }
            }
        }
    }
}

#[cfg(feature = "sam")]
pub(crate) fn print_dpapi_masterkey_text(
    hashes: &[vmkatz::sam::dpapi_masterkey::DpapiMasterKeyHash],
    c: &Colors,
) {
    use vmkatz::lsass::types::filetime_to_string;

    println!(
        "\n{}[+] DPAPI Master Key Files ({} found):{}",
        c.green,
        hashes.len(),
        c.reset
    );
    for h in hashes {
        println!("  User: {} ({})", h.username, h.sid);
        println!("    GUID    : {}", h.guid);
        if h.modified != 0 {
            println!("    Modified: {}", filetime_to_string(h.modified));
        }
        let mode_desc = match h.mode {
            15300 => "3DES/SHA1, local",
            15310 => "3DES/SHA1, domain",
            15900 => "AES256/SHA512, local",
            15910 => "AES256/SHA512, domain",
            _ => "unknown",
        };
        println!("    Hashcat : mode {} ({})", h.mode, mode_desc);
        println!("    Hash    : {}", h.hash);
    }
}

#[cfg(feature = "sam")]
pub(crate) fn print_dpapi_masterkey_hashcat(
    hashes: &[vmkatz::sam::dpapi_masterkey::DpapiMasterKeyHash],
) {
    for h in hashes {
        println!("{}", h.hash);
    }
}

/// Print bootkey + SAM hashes + LSA secrets recovered from a memory image (by the
/// signature carve or the CM hive-map walk). Returns true if anything was printed.
#[cfg(all(
    feature = "sam",
    any(
        feature = "vmware",
        feature = "vbox",
        feature = "qemu",
        feature = "hyperv"
    )
))]
pub(crate) fn print_registry_creds(
    creds: &vmkatz::sam::mem_hive::MemoryHiveCreds,
    args: &Args,
) -> bool {
    let c = get_colors(args);
    let Some(bootkey) = creds.bootkey else {
        return false;
    };
    if creds.sam_hashes.is_empty() && creds.lsa_secrets.is_empty() {
        return false;
    }
    eprintln!(
        "{}[+] Bootkey: {}{}",
        c.green,
        hex::encode(bootkey),
        c.reset
    );

    match args.format.as_str() {
        "ntlm" => print_sam_ntlm(&creds.sam_hashes),
        "csv" => print_sam_csv(&creds.sam_hashes),
        "hashcat" => print_sam_hashcat(&creds.sam_hashes),
        "brief" => print_sam_brief(&creds.sam_hashes),
        _ => print_sam_text(&creds.sam_hashes, c),
    }
    if !creds.lsa_secrets.is_empty() {
        match args.format.as_str() {
            "csv" => print_lsa_csv(&creds.lsa_secrets),
            "hashcat" => {}
            _ => print_lsa_secrets(&creds.lsa_secrets, c),
        }
        export_dpapi_backup_keys(&creds.lsa_secrets);
    }
    true
}

// ---------------------------------------------------------------------------
// Kerberos ticket export (--kirbi, --ccache)
// ---------------------------------------------------------------------------

/// Export Kerberos tickets from credentials if --kirbi or --ccache is set.
pub(crate) fn export_kerberos_tickets(credentials: &[Credential], args: &Args) {
    if args.kirbi.is_none() && args.ccache.is_none() {
        return;
    }

    // Collect all tickets with their context
    let mut all_tickets: Vec<(&vmkatz::lsass::types::KerberosTicket, &str, &str)> = Vec::new();
    for cred in credentials {
        if let Some(krb) = &cred.kerberos {
            for ticket in &krb.tickets {
                all_tickets.push((ticket, &krb.username, &krb.domain));
            }
        }
    }

    if all_tickets.is_empty() {
        eprintln!("[*] No Kerberos tickets to export");
        return;
    }

    // --kirbi: write individual .kirbi files
    if let Some(dir) = &args.kirbi {
        let dir_path = std::path::Path::new(dir);
        if !dir_path.exists() {
            if let Err(e) = std::fs::create_dir_all(dir_path) {
                eprintln!("[!] Failed to create kirbi directory {dir}: {e}");
                return;
            }
        }
        let mut count = 0;
        for (index, (ticket, username, _domain)) in all_tickets.iter().enumerate() {
            if ticket.kirbi.is_empty() {
                continue;
            }
            let svc = ticket.service_name.join("-");
            let filename = format!(
                "{}_{index:03}_{}_{}.kirbi",
                sanitize_filename(username),
                ticket.ticket_type,
                sanitize_filename(&svc)
            );
            let path = dir_path.join(&filename);
            match std::fs::write(&path, &ticket.kirbi) {
                Ok(()) => {
                    count += 1;
                    log::debug!("Wrote {}", path.display());
                }
                Err(e) => eprintln!("[!] Failed to write {}: {}", path.display(), e),
            }
        }
        eprintln!("[+] Exported {count} .kirbi ticket(s) to {dir}");
    }

    // --ccache: write all tickets into a single ccache file
    if let Some(ccache_path) = &args.ccache {
        let data = build_ccache(&all_tickets);
        match std::fs::write(ccache_path, &data) {
            Ok(()) => eprintln!(
                "[+] Exported {} ticket(s) to {} ({} bytes)",
                all_tickets.len(),
                ccache_path,
                data.len()
            ),
            Err(e) => eprintln!("[!] Failed to write {ccache_path}: {e}"),
        }
    }
}

/// Write dislocker-compatible FVEK files to disk.
#[cfg(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv"
))]
pub(crate) fn export_bitlocker_fvek(keys: &[vmkatz::lsass::bitlocker::BitLockerKey], dir: &str) {
    let dir_path = std::path::Path::new(dir);
    if !dir_path.exists() {
        if let Err(e) = std::fs::create_dir_all(dir_path) {
            eprintln!("[!] Failed to create FVEK directory {dir}: {e}");
            return;
        }
    }

    for (i, key) in keys.iter().enumerate() {
        let filename = format!("fvek_{i}.bin");
        let path = dir_path.join(&filename);
        let blob = key.to_dislocker_fvek();
        match std::fs::write(&path, &blob) {
            Ok(()) => eprintln!(
                "[+] Wrote {} ({}, {} bytes)",
                path.display(),
                key.cipher,
                blob.len()
            ),
            Err(e) => eprintln!("[!] Failed to write {}: {}", path.display(), e),
        }
    }
}

/// Sanitize a string for use in a filename.
fn sanitize_filename(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' | ' ' | '$' => '_',
            _ => c,
        })
        .collect()
}

/// Build a ccache (MIT Kerberos credential cache) file.
/// Format: v4 (0x0504), one default principal, N credentials.
fn build_ccache(tickets: &[(&vmkatz::lsass::types::KerberosTicket, &str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();

    // File format version: 0x0504 (v4)
    out.extend_from_slice(&[0x05, 0x04]);

    // Header tags (v4): 2-byte header length, then tag entries
    // We use a single empty header (length = 0)
    out.extend_from_slice(&0u16.to_be_bytes());

    // Default principal: use the first ticket's client
    if let Some((ticket, _username, _domain)) = tickets.first() {
        let realm = &ticket.domain_name;
        let client = &ticket.client_name;
        write_ccache_principal(&mut out, ticket.client_name_type as u32, realm, client);
    } else {
        // Empty principal
        write_ccache_principal(&mut out, 1, "", &[]);
    }

    // Credentials
    for (ticket, _username, _domain) in tickets {
        if ticket.ticket_blob.is_empty() {
            continue;
        }
        write_ccache_credential(&mut out, ticket);
    }

    out
}

/// Write a principal to ccache format.
/// Format: `name_type` (u32), `num_components` (u32), realm (`counted_octet_string`),
///         components[num] (`counted_octet_string` each)
fn write_ccache_principal(out: &mut Vec<u8>, name_type: u32, realm: &str, components: &[String]) {
    out.extend_from_slice(&name_type.to_be_bytes());
    out.extend_from_slice(&(components.len() as u32).to_be_bytes());
    // Realm
    write_ccache_string(out, realm);
    // Components
    for comp in components {
        write_ccache_string(out, comp);
    }
}

fn write_ccache_string(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

/// Write a single credential entry in ccache format.
fn write_ccache_credential(out: &mut Vec<u8>, ticket: &vmkatz::lsass::types::KerberosTicket) {
    // Client principal
    let client_realm = &ticket.domain_name;
    write_ccache_principal(
        out,
        ticket.client_name_type as u32,
        client_realm,
        &ticket.client_name,
    );

    // Server principal
    let server_realm = &ticket.target_domain_name;
    write_ccache_principal(
        out,
        ticket.service_name_type as u32,
        server_realm,
        &ticket.service_name,
    );

    // Keyblock: keytype (u16), etype (u16 = 0 for ccache v4), keylength (u16), keyvalue
    // ccache v4 uses: enc_type (u16), key_length (u32), key_data
    out.extend_from_slice(&(ticket.key_type as u16).to_be_bytes());
    out.extend_from_slice(&(ticket.session_key.len() as u32).to_be_bytes());
    out.extend_from_slice(&ticket.session_key);

    // Convert Windows FILETIME (100-ns ticks since 1601-01-01) to Unix timestamp
    // 10_000_000 = ticks per second, 11_644_473_600 = seconds between 1601 and 1970 epochs
    let to_unix = |ft: u64| -> u32 {
        if ft == 0 {
            return 0;
        }
        ((ft / 10_000_000).saturating_sub(11_644_473_600)) as u32
    };
    out.extend_from_slice(&to_unix(ticket.start_time).to_be_bytes()); // authtime
    out.extend_from_slice(&to_unix(ticket.start_time).to_be_bytes()); // starttime
    out.extend_from_slice(&to_unix(ticket.end_time).to_be_bytes()); // endtime
    out.extend_from_slice(&to_unix(ticket.renew_until).to_be_bytes()); // renew_till

    // is_skey: u8 (0)
    out.push(0);

    // ticket_flags: u32 (big-endian, already stored as big-endian in our struct)
    out.extend_from_slice(&ticket.ticket_flags.to_be_bytes());

    // Addresses: count (u32) = 0
    out.extend_from_slice(&0u32.to_be_bytes());

    // Authdata: count (u32) = 0
    out.extend_from_slice(&0u32.to_be_bytes());

    // A ccache stores the complete ASN.1 Ticket, not just its encrypted cipher.
    let ticket_der = vmkatz::lsass::build_ticket_der(ticket);
    out.extend_from_slice(&(ticket_der.len() as u32).to_be_bytes());
    out.extend_from_slice(&ticket_der);

    // Second ticket: length = 0
    out.extend_from_slice(&0u32.to_be_bytes());
}

/// Deduplicate credentials by (username, domain, `nt_hash`).
///
/// Sessions sharing the same identity and NT hash are merged into one entry,
/// moving data from duplicates into the first occurrence to avoid cloning.
fn dedup_credentials(credentials: &[Credential]) -> Vec<Credential> {
    // Dedup key: (username_lower, domain_lower, nt_hash)
    type DedupKey = (String, String, [u8; 16]);

    // Track which index is the "representative" for each (user, domain, nt_hash) group.
    // We build a map from group key → first index, and collect donor indices.
    let no_hash = [0xFFu8; 16]; // sentinel for sessions without MSV

    // First pass: identify groups and representative indices
    let mut repr_map: Vec<(usize, Vec<usize>)> = Vec::new(); // (repr_idx, donor_indices)
    let mut key_to_repr: Vec<(DedupKey, usize)> = Vec::new();

    for (i, cred) in credentials.iter().enumerate() {
        let nt = cred.msv.as_ref().map_or(no_hash, |m| m.nt_hash);
        let key = (
            cred.username.to_ascii_lowercase(),
            cred.domain.to_ascii_lowercase(),
            nt,
        );

        if let Some(pos) = key_to_repr.iter().position(|(k, _)| *k == key) {
            repr_map[key_to_repr[pos].1].1.push(i);
        } else {
            let repr_idx = repr_map.len();
            repr_map.push((i, Vec::new()));
            key_to_repr.push((key, repr_idx));
        }
    }

    // Second pass: build result by taking ownership where possible
    let mut result = Vec::with_capacity(repr_map.len());

    // We need to work with the original credentials; clone only the representative
    // and merge just the unique extras from donors (DPAPI, Kerberos, CredMan).
    for (repr_idx, donor_indices) in &repr_map {
        let base = &credentials[*repr_idx];

        // For single-entry groups (no donors), just clone the credential directly
        if donor_indices.is_empty() {
            result.push(Credential {
                luid: base.luid,
                username: base.username.clone(),
                domain: base.domain.clone(),
                logon_type: base.logon_type,
                session_id: base.session_id,
                logon_time: base.logon_time,
                logon_server: base.logon_server.clone(),
                sid: base.sid.clone(),
                msv: base.msv.clone(),
                wdigest: base
                    .wdigest
                    .as_ref()
                    .filter(|w| !w.password.is_empty())
                    .cloned(),
                kerberos: base.kerberos.clone(),
                tspkg: base
                    .tspkg
                    .as_ref()
                    .filter(|t| !t.password.is_empty())
                    .cloned(),
                dpapi: base.dpapi.clone(),
                credman: base.credman.clone(),
                ssp: base
                    .ssp
                    .as_ref()
                    .filter(|s| !s.password.is_empty())
                    .cloned(),
                livessp: base
                    .livessp
                    .as_ref()
                    .filter(|l| !l.password.is_empty())
                    .cloned(),
                cloudap: base.cloudap.clone(),
            });
            continue;
        }

        // Multi-entry group: merge unique extras from donors
        let mut merged = Credential {
            luid: base.luid,
            username: base.username.clone(),
            domain: base.domain.clone(),
            logon_type: base.logon_type,
            session_id: base.session_id,
            logon_time: base.logon_time,
            logon_server: base.logon_server.clone(),
            sid: base.sid.clone(),
            msv: base.msv.clone(),
            wdigest: base
                .wdigest
                .as_ref()
                .filter(|w| !w.password.is_empty())
                .cloned(),
            kerberos: base.kerberos.clone(),
            tspkg: base
                .tspkg
                .as_ref()
                .filter(|t| !t.password.is_empty())
                .cloned(),
            dpapi: base.dpapi.clone(),
            credman: base.credman.clone(),
            ssp: base
                .ssp
                .as_ref()
                .filter(|s| !s.password.is_empty())
                .cloned(),
            livessp: base
                .livessp
                .as_ref()
                .filter(|l| !l.password.is_empty())
                .cloned(),
            cloudap: base.cloudap.clone(),
        };

        for &idx in donor_indices {
            let donor = &credentials[idx];

            // Best metadata
            if donor.logon_time != 0
                && (merged.logon_time == 0 || donor.logon_time < merged.logon_time)
            {
                merged.logon_time = donor.logon_time;
            }
            if merged.sid.is_empty() && !donor.sid.is_empty() {
                merged.sid.clone_from(&donor.sid);
            }
            if merged.logon_server.is_empty() && !donor.logon_server.is_empty() {
                merged.logon_server.clone_from(&donor.logon_server);
            }

            // WDigest: keep first non-empty
            if merged.wdigest.is_none() {
                if let Some(wd) = donor.wdigest.as_ref().filter(|w| !w.password.is_empty()) {
                    merged.wdigest = Some(wd.clone());
                }
            }

            // Kerberos: merge unique keys, tickets, password
            if let Some(donor_krb) = &donor.kerberos {
                if let Some(merged_krb) = &mut merged.kerberos {
                    if merged_krb.password.is_empty() && !donor_krb.password.is_empty() {
                        merged_krb.password.clone_from(&donor_krb.password);
                    }
                    for key in &donor_krb.keys {
                        if merged_krb.keys.iter().all(|k| k.key != key.key) {
                            merged_krb.keys.push(KerberosKey {
                                etype: key.etype,
                                key: key.key.clone(),
                            });
                        }
                    }
                    for ticket in &donor_krb.tickets {
                        if merged_krb
                            .tickets
                            .iter()
                            .all(|t| t.service_name != ticket.service_name)
                        {
                            merged_krb.tickets.push(ticket.clone());
                        }
                    }
                } else {
                    merged.kerberos = Some(donor_krb.clone());
                }
            }

            // DPAPI: collect unique by GUID
            for dk in &donor.dpapi {
                if !merged.dpapi.iter().any(|d| d.guid == dk.guid) {
                    merged.dpapi.push(dk.clone());
                }
            }

            // CredMan: collect unique by target
            for cm in &donor.credman {
                if !merged.credman.iter().any(|c| c.target == cm.target) {
                    merged.credman.push(cm.clone());
                }
            }

            // TsPkg, SSP, LiveSSP, CloudAP: keep first non-empty
            if merged.tspkg.is_none() {
                merged.tspkg = donor
                    .tspkg
                    .as_ref()
                    .filter(|t| !t.password.is_empty())
                    .cloned();
            }
            if merged.ssp.is_none() {
                merged.ssp = donor
                    .ssp
                    .as_ref()
                    .filter(|s| !s.password.is_empty())
                    .cloned();
            }
            if merged.livessp.is_none() {
                merged.livessp = donor
                    .livessp
                    .as_ref()
                    .filter(|l| !l.password.is_empty())
                    .cloned();
            }
            if merged.cloudap.is_none() {
                merged.cloudap.clone_from(&donor.cloudap);
            }
        }

        result.push(merged);
    }

    result
}

fn print_text(
    credentials: &[Credential],
    c: &Colors,
    show_all: bool,
    verbose: bool,
    providers: &[String],
) {
    use vmkatz::lsass::types::{LUID_IUSR, LUID_LOCAL_SERVICE, LUID_NETWORK_SERVICE, LUID_SYSTEM};
    use vmkatz::lsass::types::{filetime_to_string, logon_type_name};

    let with_creds = credentials.iter().filter(|cr| cr.has_credentials()).count();
    let hidden = credentials.len() - with_creds;
    println!(
        "\n{}[+]{} {} logon session(s), {} with credentials{}:\n",
        c.green,
        c.reset,
        credentials.len(),
        with_creds,
        if !show_all && hidden > 0 {
            format!(" ({hidden} empty sessions hidden, use -a to show)")
        } else {
            String::new()
        },
    );
    for cred in credentials {
        if !show_all && !cred.has_credentials() {
            continue;
        }

        // LUID header
        let luid_label = match cred.luid {
            LUID_SYSTEM => " (SYSTEM)",
            LUID_NETWORK_SERVICE => " (NETWORK SERVICE)",
            LUID_LOCAL_SERVICE => " (LOCAL SERVICE)",
            LUID_IUSR => " (IUSER)",
            _ => "",
        };
        println!(
            "  {}LUID: 0x{:x}{}{}",
            c.bold, cred.luid, luid_label, c.reset
        );
        if cred.session_id != 0 || cred.logon_type != 0 {
            println!(
                "  Session: {} | LogonType: {}",
                cred.session_id,
                logon_type_name(cred.logon_type)
            );
        }
        if !cred.username.is_empty() {
            println!("  {}Username: {}{}", c.bold, cred.username, c.reset);
        }
        if !cred.domain.is_empty() {
            println!("  Domain: {}", cred.domain);
        }
        if !cred.logon_server.is_empty() {
            println!("  LogonServer: {}", cred.logon_server);
        }
        if cred.logon_time != 0 {
            println!("  LogonTime: {}", filetime_to_string(cred.logon_time));
        }
        if !cred.sid.is_empty() {
            println!("  SID: {}", cred.sid);
        }
        if !cred.has_credentials() {
            println!(
                "  {}(no credentials extracted - paged out){}",
                c.dim, c.reset
            );
            println!();
            continue;
        }
        if let Some(msv) = &cred.msv {
            if should_show(providers, "msv") {
                println!("  {}[MSV1_0]{}", c.cyan, c.reset);
                if msv.lm_hash != ZERO_HASH_16 {
                    println!("    LM Hash : {}", fmt_hash(&msv.lm_hash, c));
                }
                println!("    NT Hash : {}", fmt_hash(&msv.nt_hash, c));
                println!("    SHA1    : {}", fmt_hash(&msv.sha1_hash, c));
                // DPAPI protection key = SHA1(NT password) — same as SHA1 hash for local accounts.
                // Shown separately for mimikatz compatibility and offline DPAPI decryption workflows.
                println!("    DPAPI   : {}", fmt_hash(&msv.sha1_hash, c));
            }
        }
        if let Some(wd) = &cred.wdigest {
            if !wd.password.is_empty()
                && !cred.username.ends_with('$')
                && !is_virtual_account(&cred.username, &cred.domain)
                && should_show(providers, "wdigest")
            {
                println!("  {}[WDigest]{}", c.cyan, c.reset);
                println!("    Password: {}", fmt_password(&wd.password, c));
            }
        }
        if let Some(krb) = &cred.kerberos {
            if should_show(providers, "kerberos") {
                println!("  {}[Kerberos]{}", c.cyan, c.reset);
                // Skip machine account passwords (binary blobs, use keys instead)
                // and virtual-account random secrets.
                if !krb.password.is_empty()
                    && !cred.username.ends_with('$')
                    && !is_virtual_account(&cred.username, &cred.domain)
                {
                    println!("    Password: {}", fmt_password(&krb.password, c));
                }
                // Deduplicate keys by value — show each unique key once with primary etype
                let mut seen_keys: Vec<(&[u8], &str)> = Vec::new();
                for key in &krb.keys {
                    if !seen_keys.iter().any(|(k, _)| *k == key.key.as_slice()) {
                        seen_keys.push((&key.key, key.etype_name()));
                    }
                }
                for (key_bytes, etype_name) in &seen_keys {
                    println!("    {:11}: {}", etype_name, hex::encode(key_bytes));
                }
                for ticket in &krb.tickets {
                    println!(
                        "    [{}] {}",
                        ticket.ticket_type,
                        ticket.service_name.join("/")
                    );
                    println!("      Domain : {}", ticket.domain_name);
                    println!("      Client : {}", ticket.client_name.join("/"));
                    println!(
                        "      EncType: {} | KeyType: {}",
                        ticket.ticket_enc_type, ticket.key_type
                    );
                    println!("      Flags  : 0x{:08x}", ticket.ticket_flags);
                    println!("      Start  : {}", filetime_to_string(ticket.start_time));
                    println!("      End    : {}", filetime_to_string(ticket.end_time));
                    if verbose {
                        println!(
                            "      Kirbi  : {} bytes (base64: {})",
                            ticket.kirbi.len(),
                            vmkatz::lsass::base64_encode(&ticket.kirbi)
                        );
                    } else {
                        println!("      Kirbi  : {} bytes", ticket.kirbi.len());
                    }
                }
            }
        }
        if let Some(ts) = &cred.tspkg {
            if !ts.password.is_empty()
                && !is_virtual_account(&cred.username, &cred.domain)
                && should_show(providers, "tspkg")
            {
                println!("  {}[TsPkg]{}", c.cyan, c.reset);
                println!("    Password: {}", fmt_password(&ts.password, c));
            }
        }
        if should_show(providers, "dpapi") {
            for dk in &cred.dpapi {
                println!("  {}[DPAPI]{}", c.cyan, c.reset);
                println!("    GUID          : {}", dk.guid);
                println!(
                    "    MasterKey     : {}{}{}",
                    c.yellow,
                    hex::encode(&dk.key),
                    c.reset
                );
                println!(
                    "    SHA1 MasterKey: {}{}{}",
                    c.yellow,
                    hex::encode(dk.sha1_masterkey),
                    c.reset
                );
            }
        }
        if !cred.credman.is_empty() && should_show(providers, "credman") {
            println!("  {}[CredMan]{}", c.cyan, c.reset);
            for cm in &cred.credman {
                println!("    Target  : {}", cm.target);
                println!("    Username: {}", cm.username);
                println!("    Domain  : {}", cm.domain);
                println!("    Password: {}", fmt_password(&cm.password, c));
            }
        }
        if let Some(ssp) = &cred.ssp {
            if !ssp.password.is_empty() && should_show(providers, "ssp") {
                println!("  {}[SSP]{}", c.cyan, c.reset);
                println!("    Username: {}", ssp.username);
                println!("    Domain  : {}", ssp.domain);
                println!("    Password: {}", fmt_password(&ssp.password, c));
            }
        }
        if let Some(live) = &cred.livessp {
            if !live.password.is_empty() && should_show(providers, "livessp") {
                println!("  {}[LiveSSP]{}", c.cyan, c.reset);
                println!("    Username: {}", live.username);
                println!("    Domain  : {}", live.domain);
                println!("    Password: {}", fmt_password(&live.password, c));
            }
        }
        if let Some(cap) = &cred.cloudap {
            if should_show(providers, "cloudap") {
                println!("  {}[CloudAP]{}", c.cyan, c.reset);
                println!("    Username : {}", cap.username);
                println!("    Domain   : {}", cap.domain);
                if !cap.dpapi_key.is_empty() {
                    println!(
                        "    DPAPI Key: {}{}{}",
                        c.yellow,
                        hex::encode(&cap.dpapi_key),
                        c.reset
                    );
                }
                if !cap.prt.is_empty() {
                    println!("    PRT      : {}", cap.prt);
                }
            }
        }
        println!();
    }
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

fn print_csv(credentials: &[Credential], providers: &[String]) {
    println!("provider,username,domain,secret_type,secret,target");
    for cred in credentials.iter().filter(|c| c.has_credentials()) {
        let user = csv_escape(&cred.username);
        let dom = csv_escape(&cred.domain);

        if should_show(providers, "msv") {
            if let Some(msv) = &cred.msv {
                if msv.nt_hash != ZERO_HASH_16 {
                    println!("msv,{},{},nt_hash,{},", user, dom, hex::encode(msv.nt_hash));
                }
                if msv.lm_hash != ZERO_HASH_16 {
                    println!("msv,{},{},lm_hash,{},", user, dom, hex::encode(msv.lm_hash));
                }
                if msv.sha1_hash != [0u8; 20] {
                    println!("msv,{},{},sha1,{},", user, dom, hex::encode(msv.sha1_hash));
                }
            }
        }

        if should_show(providers, "wdigest") {
            if let Some(wd) = &cred.wdigest {
                if !wd.password.is_empty() {
                    println!(
                        "wdigest,{},{},password,{},",
                        user,
                        dom,
                        csv_escape(display_password(&wd.password))
                    );
                }
            }
        }

        if should_show(providers, "kerberos") {
            if let Some(krb) = &cred.kerberos {
                if !krb.password.is_empty() {
                    println!(
                        "kerberos,{},{},password,{},",
                        user,
                        dom,
                        csv_escape(display_password(&krb.password))
                    );
                }
                for key in &krb.keys {
                    println!(
                        "kerberos,{},{},{},{},",
                        user,
                        dom,
                        key.etype_name(),
                        hex::encode(&key.key)
                    );
                }
                for ticket in &krb.tickets {
                    let svc = ticket.service_name.join("/");
                    println!(
                        "kerberos,{},{},ticket_{},{},{}",
                        user,
                        dom,
                        ticket.ticket_type.to_string().to_ascii_lowercase(),
                        vmkatz::lsass::base64_encode(&ticket.kirbi),
                        csv_escape(&svc),
                    );
                }
            }
        }

        if should_show(providers, "tspkg") {
            if let Some(ts) = &cred.tspkg {
                if !ts.password.is_empty() {
                    println!(
                        "tspkg,{},{},password,{},",
                        user,
                        dom,
                        csv_escape(display_password(&ts.password))
                    );
                }
            }
        }

        if should_show(providers, "ssp") {
            if let Some(ssp) = &cred.ssp {
                if !ssp.password.is_empty() {
                    println!(
                        "ssp,{},{},password,{},",
                        csv_escape(&ssp.username),
                        csv_escape(&ssp.domain),
                        csv_escape(display_password(&ssp.password))
                    );
                }
            }
        }

        if should_show(providers, "livessp") {
            if let Some(live) = &cred.livessp {
                if !live.password.is_empty() {
                    println!(
                        "livessp,{},{},password,{},",
                        csv_escape(&live.username),
                        csv_escape(&live.domain),
                        csv_escape(display_password(&live.password))
                    );
                }
            }
        }

        if should_show(providers, "credman") {
            for cm in &cred.credman {
                if !cm.password.is_empty() {
                    println!(
                        "credman,{},{},password,{},{}",
                        csv_escape(&cm.username),
                        csv_escape(&cm.domain),
                        csv_escape(&cm.password),
                        csv_escape(&cm.target)
                    );
                }
            }
        }

        if should_show(providers, "dpapi") {
            for dk in &cred.dpapi {
                println!(
                    "dpapi,{},{},masterkey,{},{}",
                    user,
                    dom,
                    hex::encode(&dk.key),
                    csv_escape(&dk.guid)
                );
                println!(
                    "dpapi,{},{},sha1_masterkey,{},{}",
                    user,
                    dom,
                    hex::encode(dk.sha1_masterkey),
                    csv_escape(&dk.guid)
                );
            }
        }

        if should_show(providers, "cloudap") {
            if let Some(cap) = &cred.cloudap {
                if !cap.dpapi_key.is_empty() {
                    println!(
                        "cloudap,{},{},dpapi_key,{},",
                        csv_escape(&cap.username),
                        csv_escape(&cap.domain),
                        hex::encode(&cap.dpapi_key)
                    );
                }
                if !cap.prt.is_empty() {
                    println!(
                        "cloudap,{},{},prt,{},",
                        csv_escape(&cap.username),
                        csv_escape(&cap.domain),
                        csv_escape(&cap.prt)
                    );
                }
            }
        }
    }
}

/// Apply dedup (unless --all) and print credentials in the requested format.
pub(crate) fn output_credentials(credentials: &[Credential], args: &Args) {
    let deduped;
    let creds = if args.all {
        credentials
    } else {
        deduped = dedup_credentials(credentials);
        &deduped
    };

    let c = get_colors(args);
    match args.format.as_str() {
        "csv" => print_csv(creds, &args.provider),
        "ntlm" => print_ntlm(creds, &args.provider),
        "hashcat" => print_hashcat(creds, &args.provider),
        "brief" => print_brief(creds, &args.provider),
        _ => print_text(creds, c, args.all, args.verbose > 0, &args.provider),
    }
    report_extraction_summary(creds, &args.format);
}

/// Report a summary of extraction results to stderr.
///
/// For `ntlm`/`hashcat` formats, reports when zero hashes were found (so users can
/// distinguish success-with-no-hashes from tool failure). For `text`, provides counts.
fn report_extraction_summary(credentials: &[Credential], format: &str) {
    let with_hash = credentials
        .iter()
        .filter(|c| c.msv.as_ref().is_some_and(|m| m.nt_hash != ZERO_HASH_16))
        .count();
    let with_pw = credentials
        .iter()
        .filter(|c| {
            // Match the display filter — machine ($) and virtual-account cleartext
            // is suppressed, so don't count it.
            if is_virtual_account(&c.username, &c.domain) {
                return false;
            }
            let is_machine = c.username.ends_with('$');
            (!is_machine
                && (c.wdigest.as_ref().is_some_and(|w| !w.password.is_empty())
                    || c.kerberos.as_ref().is_some_and(|k| !k.password.is_empty())))
                || c.tspkg.as_ref().is_some_and(|t| !t.password.is_empty())
        })
        .count();

    if matches!(format, "ntlm" | "hashcat") && with_hash == 0 {
        eprintln!(
            "[*] No NTLM hashes found ({} sessions examined)",
            credentials.len()
        );
    } else if matches!(format, "text" | "brief") {
        eprintln!(
            "[*] {} sessions, {} NT hashes, {} plaintext passwords",
            credentials.len(),
            with_hash,
            with_pw
        );
    }
}

fn print_ntlm(credentials: &[Credential], providers: &[String]) {
    let mut seen = std::collections::HashSet::new();
    for cred in credentials.iter().filter(|c| c.has_credentials()) {
        if !should_show(providers, "msv") {
            continue;
        }
        if let Some(msv) = &cred.msv {
            let key = (cred.username.clone(), cred.domain.clone(), msv.nt_hash);
            if msv.nt_hash != ZERO_HASH_16 && seen.insert(key) {
                println!(
                    "{}\\{}:::{}:::",
                    cred.domain,
                    cred.username,
                    hex::encode(msv.nt_hash),
                );
            }
        }
    }
}

fn print_hashcat(credentials: &[Credential], providers: &[String]) {
    let mut seen = std::collections::HashSet::new();
    for cred in credentials.iter().filter(|c| c.has_credentials()) {
        if !should_show(providers, "msv") {
            continue;
        }
        // hashcat mode 1000 (NTLM) with --username format
        if let Some(msv) = &cred.msv {
            let key = (cred.username.clone(), cred.domain.clone(), msv.nt_hash);
            if msv.nt_hash != ZERO_HASH_16 && seen.insert(key) {
                println!(
                    "{}\\{}:{}",
                    cred.domain,
                    cred.username,
                    hex::encode(msv.nt_hash)
                );
            }
        }
    }
}

fn print_brief(credentials: &[Credential], providers: &[String]) {
    for cred in credentials.iter().filter(|c| c.has_credentials()) {
        let identity = if cred.domain.is_empty() {
            cred.username.clone()
        } else {
            format!("{}\\{}", cred.domain, cred.username)
        };
        let mut lines: Vec<String> = Vec::new();

        if should_show(providers, "msv") {
            if let Some(msv) = &cred.msv {
                if msv.nt_hash != ZERO_HASH_16 {
                    lines.push(format!("    NT      : {}", hex::encode(msv.nt_hash)));
                }
            }
        }
        if should_show(providers, "wdigest") {
            if let Some(wd) = &cred.wdigest {
                if !wd.password.is_empty() {
                    lines.push(format!(
                        "    WDigest : {}",
                        fmt_password(&wd.password, &COLORS_OFF)
                    ));
                }
            }
        }
        if should_show(providers, "kerberos") {
            if let Some(krb) = &cred.kerberos {
                if !krb.password.is_empty() {
                    lines.push(format!(
                        "    Kerberos: {}",
                        fmt_password(&krb.password, &COLORS_OFF)
                    ));
                }
            }
        }
        if should_show(providers, "tspkg") {
            if let Some(ts) = &cred.tspkg {
                if !ts.password.is_empty() {
                    lines.push(format!(
                        "    TsPkg   : {}",
                        fmt_password(&ts.password, &COLORS_OFF)
                    ));
                }
            }
        }
        if should_show(providers, "ssp") {
            if let Some(ssp) = &cred.ssp {
                if !ssp.password.is_empty() {
                    lines.push(format!(
                        "    SSP     : {}",
                        fmt_password(&ssp.password, &COLORS_OFF)
                    ));
                }
            }
        }
        if should_show(providers, "livessp") {
            if let Some(live) = &cred.livessp {
                if !live.password.is_empty() {
                    lines.push(format!(
                        "    LiveSSP : {}",
                        fmt_password(&live.password, &COLORS_OFF)
                    ));
                }
            }
        }
        if should_show(providers, "credman") {
            for cm in &cred.credman {
                if !cm.password.is_empty() {
                    lines.push(format!(
                        "    CredMan : {} ({})",
                        fmt_password(&cm.password, &COLORS_OFF),
                        cm.target
                    ));
                }
            }
        }

        if !lines.is_empty() {
            println!("  {identity}");
            for line in &lines {
                println!("{line}");
            }
            println!();
        }
    }
}

/// Print the Credential Manager section grouped by profile.
#[cfg(feature = "sam")]
pub(crate) fn print_credman_text(
    report: &vmkatz::sam::CredmanReport,
    c: &super::args::Colors,
    attributes: bool,
) {
    let has_vault = !report.vault.is_empty() || !report.vault_notes.is_empty();
    if report.entries.is_empty() && report.undecrypted.is_empty() && !has_vault {
        return;
    }
    if report.entries.is_empty() && report.undecrypted.is_empty() {
        print_vault_text(report, c);
        return;
    }
    println!("{}[+] Credential Manager{}", c.green, c.reset);
    let mut profiles: Vec<(&str, &str)> = Vec::new();
    for e in &report.entries {
        let k = (e.profile.as_str(), e.sid.as_str());
        if !profiles.contains(&k) {
            profiles.push(k);
        }
    }
    for (profile, sid) in profiles {
        let n = report
            .entries
            .iter()
            .filter(|e| e.profile == profile && e.sid == sid)
            .count();
        println!("  {}{profile}{} ({sid}) - {n} decrypted", c.cyan, c.reset);
        for e in report
            .entries
            .iter()
            .filter(|e| e.profile == profile && e.sid == sid)
        {
            println!("    Target   : {}", e.entry.target);
            println!("    User     : {}", e.entry.username);
            println!("    Password : {}", e.entry.password);
            if attributes {
                println!("    Attributes ({}):", e.attributes.len());
                for a in &e.attributes {
                    let shown: String = a.value_hex.chars().take(64).collect();
                    let more = if a.value_hex.len() > 64 {
                        "\u{2026}"
                    } else {
                        ""
                    };
                    println!(
                        "      {} = {shown}{more} [encrypted, offline decryption unsupported]",
                        a.keyword
                    );
                }
            }
            println!();
        }
    }
    if !report.undecrypted.is_empty() {
        println!(
            "  {}Undecrypted: {}{}",
            c.yellow,
            report.undecrypted.len(),
            c.reset
        );
        for u in &report.undecrypted {
            println!("    {} ({}): {} - {}", u.profile, u.sid, u.file, u.reason);
        }
    }
    if has_vault {
        print_vault_text(report, c);
    }
}

/// Print the Vault section grouped by profile + vault GUID.
#[cfg(feature = "sam")]
fn print_vault_text(report: &vmkatz::sam::CredmanReport, c: &super::args::Colors) {
    println!("{}[+] Vault{}", c.green, c.reset);
    let mut groups: Vec<(&str, &str)> = Vec::new();
    for v in &report.vault {
        let k = (v.profile.as_str(), v.vault_guid.as_str());
        if !groups.contains(&k) {
            groups.push(k);
        }
    }
    for (profile, guid) in groups {
        println!("  {}{profile}{} ({guid})", c.cyan, c.reset);
        for v in report
            .vault
            .iter()
            .filter(|v| v.profile == profile && v.vault_guid == guid)
        {
            println!("    Resource : {}", v.cred.resource);
            println!("    Identity : {}", v.cred.identity);
            println!("    Secret   : {}", v.cred.secret);
            println!();
        }
    }
    for n in &report.vault_notes {
        println!("  {}{n}{}", c.yellow, c.reset);
    }
}

/// CSV: `profile,sid,target,username,password`, one row per decrypted entry.
/// With `attributes`, a second `profile,sid,target,attr_keyword,attr_value_hex`
/// table follows (separate header) with one row per enumerated attribute.
#[cfg(feature = "sam")]
pub(crate) fn print_credman_csv(report: &vmkatz::sam::CredmanReport, attributes: bool) {
    println!("profile,sid,target,username,password");
    for e in &report.entries {
        println!(
            "{},{},{},{},{}",
            csv_escape(&e.profile),
            csv_escape(&e.sid),
            csv_escape(&e.entry.target),
            csv_escape(&e.entry.username),
            csv_escape(&e.entry.password),
        );
    }
    if attributes {
        println!("profile,sid,target,attr_keyword,attr_value_hex");
        for e in &report.entries {
            for a in &e.attributes {
                println!(
                    "{},{},{},{},{}",
                    csv_escape(&e.profile),
                    csv_escape(&e.sid),
                    csv_escape(&e.entry.target),
                    csv_escape(&a.keyword),
                    a.value_hex,
                );
            }
        }
    }
    if !report.vault.is_empty() {
        println!("profile,sid,vault_guid,resource,identity,secret");
        for v in &report.vault {
            println!(
                "{},{},{},{},{},{}",
                csv_escape(&v.profile),
                csv_escape(&v.sid),
                csv_escape(&v.vault_guid),
                csv_escape(&v.cred.resource),
                csv_escape(&v.cred.identity),
                csv_escape(&v.cred.secret),
            );
        }
    }
}
