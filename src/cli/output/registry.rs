//! SAM, LSA and cached domain credential output.

use super::exports::export_dpapi_backup_keys;
use super::{BLANK_NT_HEX, ZERO_HASH_16, csv_escape, fmt_hash, fmt_lm_pwdump};
use crate::cli::args::{Args, Colors, get_colors};

/// Print `DiskSecrets` (SAM + LSA + cached creds) using the current output format.
pub fn print_disk_secrets(secrets: &vmkatz::secrets::DiskSecrets, args: &Args) {
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

pub fn print_sam_text(entries: &[vmkatz::secrets::SamEntry], c: &Colors) {
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
fn sam_status_label(entry: &vmkatz::secrets::SamEntry, c: &Colors) -> String {
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

pub fn print_sam_ntlm(entries: &[vmkatz::secrets::SamEntry]) {
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

pub fn print_sam_csv(entries: &[vmkatz::secrets::SamEntry]) {
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

pub fn print_sam_hashcat(entries: &[vmkatz::secrets::SamEntry]) {
    for entry in entries {
        if entry.nt_hash != ZERO_HASH_16 {
            // hashcat mode 1000 (NTLM) with --username format
            println!("{}:{}", entry.username, hex::encode(entry.nt_hash));
        }
    }
}

pub fn print_sam_brief(entries: &[vmkatz::secrets::SamEntry]) {
    for entry in entries {
        if entry.nt_hash != ZERO_HASH_16 {
            println!("{}: {}", entry.username, hex::encode(entry.nt_hash));
        }
    }
}

pub fn print_dcc2_csv(creds: &[vmkatz::sam::cache::CachedCredential]) {
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

pub fn print_lsa_csv(secrets: &[vmkatz::sam::lsa::LsaSecret]) {
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

pub fn print_dcc2_hashcat(creds: &[vmkatz::sam::cache::CachedCredential]) {
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

pub fn print_lsa_secrets(secrets: &[vmkatz::sam::lsa::LsaSecret], c: &Colors) {
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

pub fn print_cached_credentials(creds: &[vmkatz::sam::cache::CachedCredential], c: &Colors) {
    println!(
        "\n{}[+] Domain Cached Credentials (DCC2):{}",
        c.green, c.reset
    );
    for cred in creds {
        println!("{cred}");
    }
}

/// Print bootkey + SAM hashes + LSA secrets recovered from a memory image (by the
/// signature carve or the CM hive-map walk). Returns true if anything was printed.
#[cfg(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv"
))]
pub fn print_registry_creds(creds: &vmkatz::sam::mem_hive::MemoryHiveCreds, args: &Args) -> bool {
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
