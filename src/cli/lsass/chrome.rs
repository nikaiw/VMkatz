//! Combine optional browser scans with memory and disk keyrings.

use std::path::Path;

use vmkatz::memory::PhysicalMemory;

use crate::cli::args::{Args, parse_chrome_nthashes};

/// Add memory findings to the disk results; each record retains its source.
fn merge_findings(
    dst: &mut vmkatz::chrome::types::ChromeFindings,
    mut extra: vmkatz::chrome::types::ChromeFindings,
) {
    dst.passwords.append(&mut extra.passwords);
    dst.cookies.append(&mut extra.cookies);
    dst.autofill.append(&mut extra.autofill);
}

/// Combine memory and disk keyrings using one disk handle to avoid ESXi lock conflicts.
fn run_chrome_hybrid(
    disk_path: &Path,
    mem_keyring: &vmkatz::chrome::hybrid::HybridKeyring,
    extra_passwords: &[String],
    extra_nt_hashes: &[(String, [u8; 16])],
) -> anyhow::Result<vmkatz::chrome::runner::DiscoverySummary> {
    let mut disk = vmkatz::disk::open_disk(disk_path)?;
    #[cfg(feature = "sam")]
    let secrets = vmkatz::sam::extract_secrets_from_reader(&mut disk)?;
    #[cfg(not(feature = "sam"))]
    let secrets = vmkatz::secrets::DiskSecrets::default();
    let (disk_user_kr, disk_sys_kr) = vmkatz::chrome::runner::build_keyrings_from_reader(
        &mut disk,
        &secrets,
        extra_passwords,
        extra_nt_hashes,
    );
    let user_resolver = vmkatz::chrome::hybrid::ComposedResolver {
        primary: mem_keyring,
        fallback: &disk_user_kr,
    };
    Ok(vmkatz::chrome::runner::run_reader_with_keyring(
        &mut disk,
        &user_resolver,
        Some(&disk_sys_kr),
    )?)
}

/// Combine optional browser scans with the credentials recovered from this snapshot.
pub(super) fn run_chrome_for_snapshot<L: PhysicalMemory>(
    layer: &L,
    processes: &[vmkatz::windows::process::Process],
    credentials: &[vmkatz::lsass::types::Credential],
    args: &Args,
) {
    let pairs: Vec<(String, Vec<u8>)> = credentials
        .iter()
        .flat_map(|c| c.dpapi.iter())
        .map(|d| (d.guid.clone(), d.key.clone()))
        .collect();
    let mem_keyring = vmkatz::chrome::runner::keyring_from_pairs(pairs);

    // Recovered passwords may unlock disk masterkeys absent from the memory cache.
    let mut chrome_passwords: Vec<String> = args.chrome_password.clone();
    for c in credentials {
        let provider_pw = [
            c.wdigest.as_ref().map(|w| &w.password),
            c.kerberos.as_ref().map(|k| &k.password),
            c.tspkg.as_ref().map(|t| &t.password),
            c.ssp.as_ref().map(|s| &s.password),
            c.livessp.as_ref().map(|l| &l.password),
        ];
        for pw in provider_pw.into_iter().flatten() {
            if !pw.is_empty() {
                chrome_passwords.push(pw.clone());
            }
        }
        for cm in &c.credman {
            if !cm.password.is_empty() {
                chrome_passwords.push(cm.password.clone());
            }
        }
    }
    chrome_passwords.sort();
    chrome_passwords.dedup();

    // Include MSV hashes keyed by SID: domain users are absent from the local SAM.
    let mut chrome_nt_hashes: Vec<(String, [u8; 16])> = parse_chrome_nthashes(&args.chrome_nthash);
    for c in credentials {
        if let Some(msv) = &c.msv {
            if !c.sid.is_empty() && msv.nt_hash != [0u8; 16] {
                chrome_nt_hashes.push((c.sid.clone(), msv.nt_hash));
            }
        }
    }
    chrome_nt_hashes.sort();
    chrome_nt_hashes.dedup();

    // Memory heuristics are opt-in because they can produce false positives.
    let mem_findings = if args.chrome_process_scan {
        match vmkatz::chrome::process_scan::scan_chromium_processes(layer, processes) {
            Ok(f) => f,
            Err(e) => {
                log::warn!("chrome (in-process scan) failed: {e}");
                vmkatz::chrome::types::ChromeFindings::default()
            }
        }
    } else {
        vmkatz::chrome::types::ChromeFindings::default()
    };

    if let Some(disk_str) = args.disk.as_deref() {
        let disk_path = std::path::Path::new(disk_str);
        match run_chrome_hybrid(
            disk_path,
            &mem_keyring,
            &chrome_passwords,
            &chrome_nt_hashes,
        ) {
            Ok(mut summary) => {
                merge_findings(&mut summary.findings, mem_findings);
                let out = vmkatz::chrome::runner::render_summary(&summary, args.chrome_json);
                if !out.trim().is_empty() {
                    println!("{out}");
                }
            }
            Err(e) => log::warn!("chrome (hybrid) failed: {e}"),
        }
    } else {
        if !mem_findings.is_empty() {
            let summary = vmkatz::chrome::runner::DiscoverySummary {
                profiles: Vec::new(),
                findings: mem_findings,
            };
            let out = vmkatz::chrome::runner::render_summary(&summary, args.chrome_json);
            if !out.trim().is_empty() {
                println!("{out}");
            }
        }
        if !mem_keyring.is_empty() {
            log::info!(
                "[chrome] {} DPAPI MKs in memory but no --disk supplied; pass --disk <vmdk> to decrypt cookies/passwords from disk too",
                mem_keyring.len()
            );
        }
    }
}
