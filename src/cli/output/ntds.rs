//! NTDS account output, including domain prefixes and password history.

use super::{ZERO_HASH_16, csv_escape, fmt_hash, fmt_lm_pwdump};
use crate::cli::args::Colors;

fn ntds_domain<'a>(
    entry: &'a vmkatz::ntds::AdHashEntry,
    domain_override: Option<&'a str>,
) -> Option<&'a str> {
    domain_override
        .filter(|d| !d.is_empty())
        .or(entry.domain.as_deref())
}

fn ntds_username(entry: &vmkatz::ntds::AdHashEntry, domain_prefix: Option<&str>) -> String {
    if let Some(domain) = ntds_domain(entry, domain_prefix) {
        return format!("{domain}\\{}", entry.username);
    }
    entry.username.clone()
}

fn ntds_username_with_history(
    entry: &vmkatz::ntds::AdHashEntry,
    domain_prefix: Option<&str>,
) -> String {
    let base = ntds_username(entry, domain_prefix);
    if entry.is_history {
        return entry.history_index.map_or_else(
            || format!("{base}_history"),
            |idx| format!("{base}_history{idx}"),
        );
    }
    base
}

pub fn print_ntds_text(
    entries: &[vmkatz::ntds::AdHashEntry],
    c: &Colors,
    domain_prefix: Option<&str>,
) {
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
                ntds_username(entry, domain_prefix),
                c.reset,
                hist,
                fmt_hash(&entry.nt_hash, c),
            );
        } else {
            println!(
                "  RID: {:<6} {}{:<24}{} {:<10} NT:{}  LM:{}",
                entry.rid,
                c.bold,
                ntds_username(entry, domain_prefix),
                c.reset,
                hist,
                fmt_hash(&entry.nt_hash, c),
                fmt_hash(&entry.lm_hash, c),
            );
        }
    }
}

pub fn print_ntds_ntlm(entries: &[vmkatz::ntds::AdHashEntry], domain_prefix: Option<&str>) {
    for entry in entries {
        let user = ntds_username_with_history(entry, domain_prefix);

        println!(
            "{}:{}:{}:{}:::",
            user,
            entry.rid,
            fmt_lm_pwdump(&entry.lm_hash),
            hex::encode(entry.nt_hash),
        );
    }
}

pub fn print_ntds_csv(entries: &[vmkatz::ntds::AdHashEntry], domain_override: Option<&str>) {
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
                "{},{},{},nt_hash,{},{}",
                provider,
                csv_escape(&entry.username),
                csv_escape(ntds_domain(entry, domain_override).unwrap_or("")),
                hex::encode(entry.nt_hash),
                entry.rid
            );
        }
        if entry.lm_hash != ZERO_HASH_16 {
            println!(
                "{},{},{},lm_hash,{},{}",
                provider,
                csv_escape(&entry.username),
                csv_escape(ntds_domain(entry, domain_override).unwrap_or("")),
                hex::encode(entry.lm_hash),
                entry.rid
            );
        }
    }
}

pub fn print_ntds_hashcat(entries: &[vmkatz::ntds::AdHashEntry], domain_prefix: Option<&str>) {
    let mut seen = std::collections::HashSet::new();
    for entry in entries {
        let username = ntds_username_with_history(entry, domain_prefix);
        if entry.nt_hash != ZERO_HASH_16 && seen.insert((username.clone(), entry.nt_hash)) {
            println!("{}:{}", username, hex::encode(entry.nt_hash));
        }
    }
}

pub fn print_ntds_brief(entries: &[vmkatz::ntds::AdHashEntry], domain_prefix: Option<&str>) {
    for entry in entries {
        if entry.nt_hash != ZERO_HASH_16 {
            println!(
                "{}: {}",
                ntds_username_with_history(entry, domain_prefix),
                hex::encode(entry.nt_hash)
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> vmkatz::ntds::AdHashEntry {
        vmkatz::ntds::AdHashEntry {
            username: "alice".into(),
            domain: Some("corp.example".into()),
            rid: 1104,
            lm_hash: [0; 16],
            nt_hash: [1; 16],
            is_history: false,
            history_index: None,
        }
    }

    #[test]
    fn domain_prefix_supports_auto_and_override() {
        let e = entry();
        assert_eq!(ntds_username(&e, None), "corp.example\\alice");
        assert_eq!(ntds_username(&e, Some("CORP")), "CORP\\alice");
        let mut history = e;
        history.is_history = true;
        history.history_index = Some(2);
        assert_eq!(
            ntds_username_with_history(&history, Some("CORP")),
            "CORP\\alice_history2"
        );
    }
}
