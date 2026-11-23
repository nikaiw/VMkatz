//! Extract from standalone registry hives and NTDS databases.

use std::path::Path;

use anyhow::Context;

use crate::cli::args::{Args, RawFileType, get_colors};
use crate::cli::output::{
    print_cached_credentials, print_dcc2_csv, print_dcc2_hashcat, print_lsa_csv, print_lsa_secrets,
    print_sam_brief, print_sam_csv, print_sam_hashcat, print_sam_ntlm, print_sam_text,
};
#[cfg(feature = "ntds.dit")]
use crate::cli::output::{
    print_ntds_brief, print_ntds_csv, print_ntds_hashcat, print_ntds_ntlm, print_ntds_text,
};

/// Extract AD hashes from raw NTDS.dit + SYSTEM hive files.
#[cfg(feature = "ntds.dit")]
pub fn run_raw_ntds(ntds_path: &Path, system_path: &Path, args: &Args) -> anyhow::Result<()> {
    let ntds_file = std::fs::File::open(ntds_path)
        .with_context(|| format!("Failed to read {}", ntds_path.display()))?;
    let system = std::fs::File::open(system_path)
        .with_context(|| format!("Failed to read {}", system_path.display()))?;
    let system_size = system.metadata()?.len();
    let boot_key = vmkatz::sam::bootkey::extract_bootkey_from_reader(system)
        .context("SYSTEM bootkey extraction failed")?;

    let (ctx, hashes) =
        vmkatz::ntds::extract_ad_hashes_with_bootkey(ntds_file, boot_key, args.ntds_history)
            .context("NTDS hash extraction failed")?;

    let c = get_colors(args);

    eprintln!("\n{}[+] NTDS (raw files):{}", c.green, c.reset);
    eprintln!(
        "  ntds.dit : {} ({} bytes)",
        ntds_path.display(),
        ctx.ntds_size
    );
    eprintln!(
        "  SYSTEM   : {} ({} bytes)",
        system_path.display(),
        system_size
    );
    eprintln!("  Bootkey  : {}", hex::encode(ctx.boot_key));
    eprintln!("  Hashes   : {}", hashes.len());

    match args.format.as_str() {
        "csv" => print_ntds_csv(&hashes, args.ntds_domain_prefix.as_deref()),
        "hashcat" => print_ntds_hashcat(&hashes, args.ntds_domain_prefix.as_deref()),
        "ntlm" => print_ntds_ntlm(&hashes, args.ntds_domain_prefix.as_deref()),
        "brief" => print_ntds_brief(&hashes, args.ntds_domain_prefix.as_deref()),
        _ => print_ntds_text(&hashes, c, args.ntds_domain_prefix.as_deref()),
    }

    Ok(())
}

/// Extract SAM/LSA/DCC2 from raw registry hive files.
/// Auto-detects which hive is SYSTEM (via bootkey extraction), SAM, and SECURITY.
pub fn run_raw_hives(
    hive_files: &[&(std::path::PathBuf, RawFileType)],
    args: &Args,
) -> anyhow::Result<()> {
    let hives: Vec<&Path> = hive_files.iter().map(|(path, _)| path.as_path()).collect();

    let mut system_idx = None;
    let mut bootkey = [0u8; 16];

    for (i, path) in hives.iter().enumerate() {
        let hive = open_registry_hive(path)?;
        if hive.root_key().is_ok_and(|key| {
            key.name().eq_ignore_ascii_case("SAM") || key.name().eq_ignore_ascii_case("SECURITY")
        }) {
            continue;
        }
        if let Some(key) =
            optional_registry_result(vmkatz::sam::bootkey::extract_bootkey_from_hive(&hive))?
        {
            log::info!(
                "SYSTEM hive: {} (bootkey: {})",
                path.display(),
                hex::encode(key)
            );
            system_idx = Some(i);
            bootkey = key;
            break;
        }
    }

    let system_idx = system_idx.context(
        "No SYSTEM hive found (could not extract bootkey from any of the provided files)",
    )?;

    let c = get_colors(args);
    eprintln!("\n{}[+] Raw hives:{}", c.green, c.reset);
    eprintln!(
        "  SYSTEM  : {} (bootkey: {})",
        hives[system_idx].display(),
        hex::encode(bootkey)
    );

    let mut sam_entries = Vec::new();
    let mut lsa_secrets = Vec::new();
    let mut cached_creds = Vec::new();

    for (i, path) in hives.iter().enumerate() {
        if i == system_idx {
            continue;
        }

        let hive = open_registry_hive(path)?;
        if let Some(entries) = optional_registry_result(
            vmkatz::sam::hashes::extract_hashes_from_hive(&hive, &bootkey),
        )? {
            if !entries.is_empty() {
                eprintln!(
                    "  SAM     : {} ({} accounts)",
                    path.display(),
                    entries.len()
                );
                sam_entries = entries;
                continue;
            }
        }

        if let Some(secrets) = optional_registry_result(
            vmkatz::sam::lsa::extract_lsa_secrets_from_hive(&hive, &bootkey),
        )? {
            if !secrets.is_empty() {
                eprintln!("  SECURITY: {} ({} secrets)", path.display(), secrets.len());
                lsa_secrets = secrets;

                if let Some(nlkm) = lsa_secrets.iter().find(|s| s.name == "NL$KM") {
                    if let Some(creds) = optional_registry_result(
                        vmkatz::sam::cache::extract_cached_credentials_from_hive(
                            &hive,
                            &nlkm.raw_data,
                        ),
                    )? {
                        cached_creds = creds;
                    }
                }
            }
        }
    }

    if sam_entries.is_empty() && lsa_secrets.is_empty() {
        anyhow::bail!("Could not extract SAM hashes or LSA secrets from the provided hives");
    }

    if !sam_entries.is_empty() {
        match args.format.as_str() {
            "ntlm" => print_sam_ntlm(&sam_entries),
            "csv" => print_sam_csv(&sam_entries),
            "hashcat" => print_sam_hashcat(&sam_entries),
            "brief" => print_sam_brief(&sam_entries),
            _ => print_sam_text(&sam_entries, c),
        }
    }

    if !lsa_secrets.is_empty() {
        match args.format.as_str() {
            "csv" => print_lsa_csv(&lsa_secrets),
            "hashcat" => {} // LSA secrets not applicable for hashcat
            _ => print_lsa_secrets(&lsa_secrets, c),
        }
    }

    if !cached_creds.is_empty() {
        match args.format.as_str() {
            "csv" => print_dcc2_csv(&cached_creds),
            "hashcat" => print_dcc2_hashcat(&cached_creds),
            _ => print_cached_credentials(&cached_creds, c),
        }
    }

    Ok(())
}

fn open_registry_hive(path: &Path) -> anyhow::Result<vmkatz::sam::hive::Hive<'static>> {
    let file =
        std::fs::File::open(path).with_context(|| format!("Failed to read {}", path.display()))?;
    Ok(vmkatz::sam::hive::Hive::from_reader(file)?)
}

fn optional_registry_result<T>(result: vmkatz::error::Result<T>) -> anyhow::Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error)
            if error.is_resource_limit() || matches!(error, vmkatz::error::VmkatzError::Io(_)) =>
        {
            Err(error.into())
        }
        Err(_) => Ok(None),
    }
}
