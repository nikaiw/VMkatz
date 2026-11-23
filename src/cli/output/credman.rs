//! Credential Manager and Vault output grouped by profile.

use super::csv_escape;
use crate::cli::args::Colors;

/// Print the Credential Manager section grouped by profile.
pub fn print_credman_text(report: &vmkatz::credman::CredmanReport, c: &Colors, attributes: bool) {
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
fn print_vault_text(report: &vmkatz::credman::CredmanReport, c: &Colors) {
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

/// Print a single rectangular CSV stream for all CredMan/Vault record types.
pub fn print_credman_csv(report: &vmkatz::credman::CredmanReport, attributes: bool) {
    print!("{}", credman_csv_string(report, attributes));
}

fn credman_csv_string(report: &vmkatz::credman::CredmanReport, attributes: bool) -> String {
    let mut o = String::new();
    let header = [
        "record_type",
        "profile",
        "sid",
        "target",
        "username",
        "password",
        "attribute_keyword",
        "attribute_value_hex",
        "vault_guid",
        "resource",
        "identity",
        "secret",
        "file",
        "reason",
        "note",
    ];
    write_credman_csv_row(&mut o, &header);
    for e in &report.entries {
        let mut row = [""; 15];
        row[0] = "credential";
        row[1] = &e.profile;
        row[2] = &e.sid;
        row[3] = &e.entry.target;
        row[4] = &e.entry.username;
        row[5] = &e.entry.password;
        write_credman_csv_row(&mut o, &row);
    }
    if attributes {
        for e in &report.entries {
            for a in &e.attributes {
                let mut row = [""; 15];
                row[0] = "credential_attribute";
                row[1] = &e.profile;
                row[2] = &e.sid;
                row[3] = &e.entry.target;
                row[6] = &a.keyword;
                row[7] = &a.value_hex;
                write_credman_csv_row(&mut o, &row);
            }
        }
    }
    for v in &report.vault {
        let mut row = [""; 15];
        row[0] = "vault";
        row[1] = &v.profile;
        row[2] = &v.sid;
        row[8] = &v.vault_guid;
        row[9] = &v.cred.resource;
        row[10] = &v.cred.identity;
        row[11] = &v.cred.secret;
        write_credman_csv_row(&mut o, &row);
    }
    for u in &report.undecrypted {
        let mut row = [""; 15];
        row[0] = "undecrypted";
        row[1] = &u.profile;
        row[2] = &u.sid;
        row[12] = &u.file;
        row[13] = &u.reason;
        write_credman_csv_row(&mut o, &row);
    }
    for n in &report.vault_notes {
        let mut row = [""; 15];
        row[0] = "note";
        row[14] = n;
        write_credman_csv_row(&mut o, &row);
    }
    o
}

fn write_credman_csv_row(out: &mut String, fields: &[&str]) {
    for (index, field) in fields.iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        out.push_str(&csv_escape(field));
    }
    out.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_includes_undecrypted() {
        let mut r = vmkatz::credman::CredmanReport::default();
        r.undecrypted.push(vmkatz::credman::Undecrypted {
            profile: "bob".into(),
            sid: "S-1-5-21-1".into(),
            file: "C:\\x,y".into(),
            reason: "no key".into(),
        });
        r.vault_notes.push("bob\\G: keys=2 vcrd=0/1".into());
        let out = credman_csv_string(&r, false);
        let mut lines = out.lines();
        let header = lines.next().unwrap();
        assert_eq!(csv_field_count(header), 15);
        assert_eq!(lines.clone().count(), 2);
        for line in lines {
            assert_eq!(csv_field_count(line), 15, "{line}");
        }
        assert!(out.contains("undecrypted,bob,S-1-5-21-1,,,,,,,,,,\"C:\\x,y\",no key,"));
        assert!(out.contains("note,,,,,,,,,,,,,,bob\\G: keys=2 vcrd=0/1"));
    }

    fn csv_field_count(line: &str) -> usize {
        let mut fields = 1;
        let mut quoted = false;
        let mut chars = line.chars().peekable();
        while let Some(ch) = chars.next() {
            match ch {
                '"' if quoted && chars.peek() == Some(&'"') => {
                    chars.next();
                }
                '"' => quoted = !quoted,
                ',' if !quoted => fields += 1,
                _ => {}
            }
        }
        fields
    }
}
