//! Session output formats and extraction summaries.

use vmkatz::lsass::types::Credential;

use super::dedup::dedup_credentials;
use super::text::print_text;
use super::{
    ZERO_HASH_16, csv_escape, display_password, fmt_password, is_virtual_account, should_show,
};
use crate::cli::args::{Args, COLORS_OFF, get_colors};

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
pub fn output_credentials(credentials: &[Credential], args: &Args) {
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
