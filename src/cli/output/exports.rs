//! Kerberos tickets, BitLocker FVEKs and LSA backup key file exports.

use vmkatz::lsass::types::Credential;

use crate::cli::args::Args;

#[cfg(feature = "sam")]
pub(super) fn export_dpapi_backup_keys(secrets: &[vmkatz::sam::lsa::LsaSecret]) {
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

/// Export Kerberos tickets from credentials if --kirbi or --ccache is set.
pub fn export_kerberos_tickets(credentials: &[Credential], args: &Args) {
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
        match build_ccache(&all_tickets) {
            Ok(data) => match std::fs::write(ccache_path, &data) {
                Ok(()) => eprintln!(
                    "[+] Exported {} ticket(s) to {} ({} bytes)",
                    all_tickets.len(),
                    ccache_path,
                    data.len()
                ),
                Err(e) => eprintln!("[!] Failed to write {ccache_path}: {e}"),
            },
            Err(e) => eprintln!("[!] Failed to build ccache: {e}"),
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
pub fn export_bitlocker_fvek(keys: &[vmkatz::lsass::bitlocker::BitLockerKey], dir: &str) {
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
fn build_ccache(
    tickets: &[(&vmkatz::lsass::types::KerberosTicket, &str, &str)],
) -> Result<Vec<u8>, String> {
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
        write_ccache_principal(&mut out, ticket.client_name_type, realm, client)?;
    } else {
        // Empty principal
        write_ccache_principal(&mut out, 1, "", &[])?;
    }

    // Credentials
    for (ticket, _username, _domain) in tickets {
        if ticket.ticket_blob.is_empty() {
            continue;
        }
        write_ccache_credential(&mut out, ticket)?;
    }

    Ok(out)
}

/// Write a principal to ccache format.
/// Format: `name_type` (u32), `num_components` (u32), realm (`counted_octet_string`),
///         components[num] (`counted_octet_string` each)
fn write_ccache_principal(
    out: &mut Vec<u8>,
    name_type: i16,
    realm: &str,
    components: &[String],
) -> Result<(), String> {
    let name_type = u32::try_from(name_type)
        .map_err(|_| format!("Kerberos principal name type {name_type} is negative"))?;
    out.extend_from_slice(&name_type.to_be_bytes());
    write_ccache_len(out, components.len(), "principal component count")?;
    // Realm
    write_ccache_string(out, realm)?;
    // Components
    for comp in components {
        write_ccache_string(out, comp)?;
    }
    Ok(())
}

fn write_ccache_len(out: &mut Vec<u8>, len: usize, field: &str) -> Result<(), String> {
    let len = u32::try_from(len).map_err(|_| format!("{field} exceeds the ccache u32 limit"))?;
    out.extend_from_slice(&len.to_be_bytes());
    Ok(())
}

fn write_ccache_string(out: &mut Vec<u8>, s: &str) -> Result<(), String> {
    write_ccache_len(out, s.len(), "principal string length")?;
    out.extend_from_slice(s.as_bytes());
    Ok(())
}

/// Write a single credential entry in ccache format.
fn write_ccache_credential(
    out: &mut Vec<u8>,
    ticket: &vmkatz::lsass::types::KerberosTicket,
) -> Result<(), String> {
    // Client principal
    let client_realm = &ticket.domain_name;
    write_ccache_principal(
        out,
        ticket.client_name_type,
        client_realm,
        &ticket.client_name,
    )?;

    // Server principal
    let server_realm = &ticket.target_domain_name;
    write_ccache_principal(
        out,
        ticket.service_name_type,
        server_realm,
        &ticket.service_name,
    )?;

    // Keyblock: keytype (u16), etype (u16 = 0 for ccache v4), keylength (u16), keyvalue
    // ccache v4 uses: enc_type (u16), key_length (u32), key_data
    let key_type = u16::try_from(ticket.key_type).map_err(|_| {
        format!(
            "Kerberos key type {} exceeds ccache u16 limit",
            ticket.key_type
        )
    })?;
    out.extend_from_slice(&key_type.to_be_bytes());
    write_ccache_len(out, ticket.session_key.len(), "session key length")?;
    out.extend_from_slice(&ticket.session_key);

    // Convert Windows FILETIME (100-ns ticks since 1601-01-01) to Unix timestamp
    // 10_000_000 = ticks per second, 11_644_473_600 = seconds between 1601 and 1970 epochs
    let to_unix = |ft: u64| -> Result<u32, String> {
        if ft == 0 {
            return Ok(0);
        }
        let seconds = (ft / 10_000_000).saturating_sub(11_644_473_600);
        u32::try_from(seconds).map_err(|_| "Kerberos ticket time exceeds ccache u32 range".into())
    };
    out.extend_from_slice(&to_unix(ticket.start_time)?.to_be_bytes()); // authtime
    out.extend_from_slice(&to_unix(ticket.start_time)?.to_be_bytes()); // starttime
    out.extend_from_slice(&to_unix(ticket.end_time)?.to_be_bytes()); // endtime
    out.extend_from_slice(&to_unix(ticket.renew_until)?.to_be_bytes()); // renew_till

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
    write_ccache_len(out, ticket_der.len(), "ticket DER length")?;
    out.extend_from_slice(&ticket_der);

    // Second ticket: length = 0
    out.extend_from_slice(&0u32.to_be_bytes());
    Ok(())
}
