//! Human-readable session and provider output.

use vmkatz::lsass::types::{
    Credential, LUID_IUSR, LUID_LOCAL_SERVICE, LUID_NETWORK_SERVICE, LUID_SYSTEM,
    filetime_to_string, logon_type_name,
};

use super::{Colors, ZERO_HASH_16, fmt_hash, fmt_password, is_virtual_account, should_show};

pub(super) fn print_text(
    credentials: &[Credential],
    c: &Colors,
    show_all: bool,
    verbose: bool,
    providers: &[String],
) {
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

        print_session_header(cred, c);
        if !cred.has_credentials() {
            println!(
                "  {}(no credentials extracted - paged out){}",
                c.dim, c.reset
            );
            println!();
            continue;
        }
        print_providers(cred, c, verbose, providers);
        println!();
    }
}

fn print_session_header(cred: &Credential, c: &Colors) {
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
}

fn print_providers(cred: &Credential, c: &Colors, verbose: bool, providers: &[String]) {
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
    print_kerberos(cred, c, verbose, providers);
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
}

fn print_kerberos(cred: &Credential, c: &Colors, verbose: bool, providers: &[String]) {
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
}
