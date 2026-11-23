//! Offline Credential Manager orchestration and account/SID resolution.

use super::args::{Args, parse_dpapi_nthashes, parse_dpapi_passwords};
use super::output::{print_credman_csv, print_credman_text};

/// Supplied secrets resolved to a SID, or keyed by profile name for later binding.
struct ResolvedSecrets<T> {
    by_sid: Vec<(String, T)>,
    by_name: Vec<(String, T)>,
}

fn resolve_secret_sids<T>(
    specs: Vec<(String, T)>,
    machine_sid: Option<&str>,
    secrets: Option<&vmkatz::secrets::DiskSecrets>,
    hashes: &[vmkatz::dpapi::masterkey::DpapiMasterKeyHash],
    flag: &str,
) -> ResolvedSecrets<T> {
    let mut resolved = ResolvedSecrets {
        by_sid: Vec::new(),
        by_name: Vec::new(),
    };
    for (user, val) in specs {
        if user
            .get(..4)
            .is_some_and(|p| p.eq_ignore_ascii_case("S-1-"))
        {
            resolved.by_sid.push((user.to_ascii_uppercase(), val));
            continue;
        }
        let (domain, bare) = match user.rsplit_once('\\') {
            Some((d, n)) if !d.is_empty() && d != "." => (Some(d), n),
            Some((_, n)) => (None, n),
            None => (None, user.as_str()),
        };
        let sid = domain.map_or_else(
            || local_or_profile_sid(bare, machine_sid, secrets, hashes),
            |d| domain_profile_sid(d, bare, machine_sid, hashes),
        );
        if let Some(sid) = sid {
            resolved.by_sid.push((sid, val));
        } else {
            // Defer SID binding until the profile scan can resolve this name.
            log::info!("{flag}: {user:?} not resolved to a SID; will match by profile name");
            let key = domain.map_or_else(|| bare.to_string(), |d| format!("{d}\\{bare}"));
            resolved.by_name.push((key, val));
        }
    }
    resolved
}

/// SID for an unqualified (or `.\\`) account name: a profile of that name,
/// else the local SAM account.
fn local_or_profile_sid(
    bare: &str,
    machine_sid: Option<&str>,
    secrets: Option<&vmkatz::secrets::DiskSecrets>,
    hashes: &[vmkatz::dpapi::masterkey::DpapiMasterKeyHash],
) -> Option<String> {
    hashes
        .iter()
        .find(|h| h.username.eq_ignore_ascii_case(bare))
        .map(|h| h.sid.clone())
        .or_else(|| {
            let m = machine_sid?;
            secrets?
                .sam_entries
                .iter()
                .find(|e| e.username.eq_ignore_ascii_case(bare))
                .map(|e| format!("{m}-{}", e.rid))
        })
}

/// Match `DOMAIN\\name` to a `name` or `name.DOMAIN` profile outside the local SID domain.
/// Require the machine SID to avoid binding a domain secret to a local homonym.
fn domain_profile_sid(
    domain: &str,
    bare: &str,
    machine_sid: Option<&str>,
    hashes: &[vmkatz::dpapi::masterkey::DpapiMasterKeyHash],
) -> Option<String> {
    let m = machine_sid?;
    let qualified = format!("{bare}.{domain}");
    hashes
        .iter()
        .filter(|h| {
            h.username.eq_ignore_ascii_case(bare) || h.username.eq_ignore_ascii_case(&qualified)
        })
        .find(|h| {
            vmkatz::credman::machine_sid_from_user_sid(&h.sid)
                .is_some_and(|p| !p.eq_ignore_ascii_case(m))
        })
        .map(|h| h.sid.clone())
}

/// Prefer the SAM account-domain SID; otherwise infer it from a matching name and RID.
/// Inference can confuse local and domain accounts, so warn when used.
fn find_machine_sid(
    secrets: Option<&vmkatz::secrets::DiskSecrets>,
    hashes: &[vmkatz::dpapi::masterkey::DpapiMasterKeyHash],
) -> Option<String> {
    let secrets = secrets?;
    if let Some(m) = &secrets.machine_sid {
        return Some(m.clone());
    }
    let inferred = hashes.iter().find_map(|h| {
        let (prefix, rid) = h.sid.rsplit_once('-')?;
        let rid: u32 = rid.parse().ok()?;
        secrets
            .sam_entries
            .iter()
            .any(|e| e.rid == rid && e.username.eq_ignore_ascii_case(&h.username))
            .then(|| prefix.to_string())
    });
    if let Some(m) = &inferred {
        log::warn!("machine SID not found in SAM; inferred {m} from a profile (may be wrong)");
    }
    inferred
}

/// `--credman`: build the secret table from already-extracted SAM/LSA and sweep the disk.
pub(super) fn emit_credman<R: std::io::Read + std::io::Seek>(
    reader: &mut R,
    args: &Args,
    c: &super::args::Colors,
    secrets: Option<&vmkatz::secrets::DiskSecrets>,
    hashes: &[vmkatz::dpapi::masterkey::DpapiMasterKeyHash],
    ntds_by_name: &[(String, [u8; 16])],
) -> bool {
    let machine_sid = find_machine_sid(secrets, hashes);
    let nt_hashes = resolve_secret_sids(
        parse_dpapi_nthashes(&args.dpapi_nthash),
        machine_sid.as_deref(),
        secrets,
        hashes,
        "--dpapi-nthash",
    );
    let passwords = resolve_secret_sids(
        parse_dpapi_passwords(&args.dpapi_password),
        machine_sid.as_deref(),
        secrets,
        hashes,
        "--dpapi-password",
    );
    let empty = vmkatz::secrets::DiskSecrets::default();
    let mut table = vmkatz::credman::build_secret_table(
        secrets.unwrap_or(&empty),
        secrets.map_or(&[][..], |s| &s.lsa_secrets),
        machine_sid.as_deref(),
        &nt_hashes.by_sid,
        &passwords.by_sid,
    );
    // Try explicit hashes before this disk's NTDS hashes, retaining both:
    // a stale explicit credential must not hide a usable NTDS candidate.
    for (name, h) in nt_hashes.by_name {
        table
            .nt_by_name
            .entry(name.to_lowercase())
            .or_default()
            .push(h);
    }
    for (name, h) in ntds_by_name {
        table
            .nt_by_name
            .entry(name.to_lowercase())
            .or_default()
            .push(*h);
    }
    for (name, pw) in passwords.by_name {
        table
            .pw_by_name
            .entry(name.to_lowercase())
            .or_default()
            .push(pw);
    }
    match vmkatz::credman::extract_credman_from_reader_scoped(reader, args.partition, &table) {
        Ok(report) => {
            let found = !report.entries.is_empty()
                || !report.vault.is_empty()
                || !report.undecrypted.is_empty()
                || !report.vault_notes.is_empty();
            match args.format.as_str() {
                "csv" => print_credman_csv(&report, args.credman_attributes),
                "hashcat" => {}
                _ => print_credman_text(&report, c, args.credman_attributes),
            }
            found
        }
        Err(e) => {
            eprintln!("[!] Credential Manager extraction failed: {e}");
            false
        }
    }
}

#[cfg(test)]
mod secret_sid_tests {
    use super::resolve_secret_sids;
    use vmkatz::dpapi::masterkey::DpapiMasterKeyHash;
    use vmkatz::secrets::{DiskSecrets, SamEntry};

    fn mk_hash(user: &str, sid: &str) -> DpapiMasterKeyHash {
        DpapiMasterKeyHash {
            username: user.into(),
            sid: sid.into(),
            guid: String::new(),
            hash: String::new(),
            mode: 15900,
            modified: 0,
        }
    }

    #[test]
    fn resolved_and_deferred_secrets_keep_all_candidates() {
        let resolved = resolve_secret_sids(
            vec![
                ("LAB\\alice".into(), 1u8),
                ("s-1-5-21-9-9-9-500".into(), 2),
                ("LAB\\alice".into(), 3),
                ("bob".into(), 4),
            ],
            None,
            None,
            &[],
            "--dpapi-nthash",
        );
        assert_eq!(resolved.by_sid, [("S-1-5-21-9-9-9-500".into(), 2)]);
        assert_eq!(
            resolved.by_name,
            [
                ("LAB\\alice".into(), 1),
                ("LAB\\alice".into(), 3),
                ("bob".into(), 4)
            ]
        );
    }

    #[test]
    fn resolve_secret_sids_keeps_domain_prefix() {
        let machine = "S-1-5-21-1-2-3";
        let ds = DiskSecrets {
            sam_entries: vec![SamEntry {
                rid: 500,
                username: "Administrator".into(),
                nt_hash: [7u8; 16],
                lm_hash: [0u8; 16],
                acb_flags: 0,
            }],
            ..Default::default()
        };
        let local_only = [mk_hash("Administrator", "S-1-5-21-1-2-3-500")];
        // `LAB\Administrator` must not bind to the local MACHINE-500 SID.
        let resolved = resolve_secret_sids(
            vec![("LAB\\Administrator".to_string(), 1u8)],
            Some(machine),
            Some(&ds),
            &local_only,
            "--dpapi-nthash",
        );
        assert!(resolved.by_sid.is_empty(), "bound to {:?}", resolved.by_sid);
        assert_eq!(
            resolved.by_name,
            vec![("LAB\\Administrator".to_string(), 1u8)]
        );
        // With the domain profile present, it binds to the domain SID.
        let both = [
            mk_hash("Administrator", "S-1-5-21-1-2-3-500"),
            mk_hash("Administrator.LAB", "S-1-5-21-9-9-9-500"),
        ];
        let resolved = resolve_secret_sids(
            vec![("LAB\\Administrator".to_string(), 1u8)],
            Some(machine),
            Some(&ds),
            &both,
            "--dpapi-nthash",
        );
        assert_eq!(
            resolved.by_sid,
            vec![("S-1-5-21-9-9-9-500".to_string(), 1u8)]
        );
        // A bare name (or `.\name`) still resolves to the local SAM account.
        let resolved = resolve_secret_sids(
            vec![(".\\Administrator".to_string(), 1u8)],
            Some(machine),
            Some(&ds),
            &[],
            "--dpapi-nthash",
        );
        assert_eq!(
            resolved.by_sid,
            vec![("S-1-5-21-1-2-3-500".to_string(), 1u8)]
        );
        let resolved = resolve_secret_sids(
            vec![("s-1-5-21-9-9-9-500".to_string(), 2u8)],
            Some(machine),
            Some(&ds),
            &[],
            "--dpapi-nthash",
        );
        assert_eq!(
            resolved.by_sid,
            vec![("S-1-5-21-9-9-9-500".to_string(), 2u8)]
        );
    }
}
