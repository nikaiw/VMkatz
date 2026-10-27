//! Disk-image, raw-file, Veeam, VMFS and VM-directory pipelines.

use std::path::Path;

use anyhow::Context;

#[cfg(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv"
))]
use vmkatz::lsass::finder::PagefileRef;

use super::args::Args;
#[cfg(feature = "veeam")]
use super::args::Colors;
#[cfg(feature = "chrome")]
use super::args::parse_chrome_nthashes;
#[cfg(feature = "sam")]
use super::args::{RawFileType, get_colors, parse_dpapi_nthashes};
#[cfg(all(
    feature = "sam",
    any(
        feature = "vmware",
        feature = "vbox",
        feature = "qemu",
        feature = "hyperv"
    )
))]
use super::lsass::extract_bitlocker_keys_from_snapshot;
#[cfg(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv"
))]
use super::lsass::run_lsass;
#[cfg(all(
    feature = "sam",
    any(
        feature = "vmware",
        feature = "vbox",
        feature = "qemu",
        feature = "hyperv"
    )
))]
use super::output::print_disk_secrets;
#[cfg(feature = "sam")]
use super::output::{
    dedup_dpapi_hashes, export_dpapi_backup_keys, print_cached_credentials, print_credman_csv,
    print_credman_text, print_dcc2_csv, print_dcc2_hashcat, print_dpapi_masterkey_csv,
    print_dpapi_masterkey_hashcat, print_dpapi_masterkey_text, print_lsa_csv, print_lsa_secrets,
    print_sam_brief, print_sam_csv, print_sam_hashcat, print_sam_ntlm, print_sam_text,
};
#[cfg(feature = "ntds.dit")]
use super::output::{
    print_ntds_brief, print_ntds_csv, print_ntds_hashcat, print_ntds_ntlm, print_ntds_text,
};

/// Format a byte count with binary units (B/KiB/MiB/GiB/TiB).
#[cfg(feature = "sam")]
fn human_size(bytes: u64) -> String {
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let units = ["KiB", "MiB", "GiB", "TiB"];
    let mut v = bytes as f64 / 1024.0;
    let mut i = 0;
    while v >= 1024.0 && i + 1 < units.len() {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1} {}", units[i])
}

/// One listing line: `<DIR>` marker or right-aligned size, then the name.
#[cfg(feature = "sam")]
fn format_entry(e: &vmkatz::fs::DirEntry) -> String {
    match e.kind {
        vmkatz::fs::EntryKind::Dir => format!("{:>10}  {}", "<DIR>", e.name),
        vmkatz::fs::EntryKind::File { size } => format!("{:>10}  {}", human_size(size), e.name),
    }
}

/// List `path` on each selected NTFS partition of `reader`.
#[cfg(feature = "sam")]
pub(crate) fn run_ls<R: std::io::Read + std::io::Seek>(
    reader: &mut R,
    path: &str,
    partition: Option<u64>,
) -> anyhow::Result<()> {
    use vmkatz::fs::{find_ntfs_partitions, is_bitlocker_partition, select_partition};
    use vmkatz::sam::{ListOutcome, list_path};

    let offsets = select_partition(find_ntfs_partitions(reader)?, partition)?;
    for off in offsets {
        if is_bitlocker_partition(reader, off) {
            println!("[partition @ {off:#x}, BitLocker] skipped: encrypted volume");
            continue;
        }
        let outcome = match list_path(reader, off, path) {
            Ok(o) => o,
            Err(e) => {
                println!("[partition @ {off:#x}] listing failed: {e}");
                continue;
            }
        };
        match outcome {
            ListOutcome::Listed { entries, degraded } => {
                let note = if degraded { " (degraded: MFTMirr)" } else { "" };
                println!("[partition @ {off:#x}, NTFS]{note}");
                if entries.is_empty() {
                    println!("(empty)");
                }
                for e in &entries {
                    println!("{}", format_entry(e));
                }
            }
            ListOutcome::PathNotFound => {
                println!("[partition @ {off:#x}, NTFS]");
                println!("path not found: {path}");
            }
            ListOutcome::PathUnresolvableDegraded => {
                println!("[partition @ {off:#x}, NTFS] (degraded: MFTMirr)");
                println!(
                    "path cannot be resolved: NTFS index unusable and fallback scan could not locate it: {path}"
                );
            }
        }
    }
    Ok(())
}

/// Quick check for MBR partition type 0x07 (NTFS/HPFS) in first sector.
#[cfg(feature = "vmfs")]
fn has_ntfs_partitions<R: std::io::Read + std::io::Seek>(reader: &mut R) -> bool {
    use std::io::SeekFrom;
    let pos = reader.stream_position().unwrap_or(0);
    let mut mbr = [0u8; 512];
    let ok = reader.seek(SeekFrom::Start(0)).is_ok() && reader.read_exact(&mut mbr).is_ok();
    let _ = reader.seek(SeekFrom::Start(pos));
    if !ok || mbr[510] != 0x55 || mbr[511] != 0xAA {
        return false;
    }
    // Check 4 MBR partition entries at 0x1BE, each 16 bytes, type byte at offset 4
    for i in 0..4 {
        let ptype = mbr[0x1BE + i * 16 + 4];
        if ptype == 0x07 || ptype == 0xEE {
            // 0x07 = NTFS, 0xEE = GPT (may contain NTFS)
            return true;
        }
    }
    false
}

/// List available VMFS-6 devices and their flat VMDKs.
#[cfg(feature = "vmfs")]
pub(crate) fn run_vmfs_list(device_filter: Option<&str>) {
    use vmkatz::disk::vmfs;

    let devices = vmfs::list_vmfs6_devices();
    if devices.is_empty() {
        eprintln!("[!] No VMFS-6 devices found in /dev/disks/");
        eprintln!("    (Are you running this on an ESXi host?)");
        return;
    }

    eprintln!("[+] VMFS-6 devices:");
    for dev in &devices {
        let label = if dev.label.is_empty() {
            "(unlabeled)".to_string()
        } else {
            dev.label.clone()
        };
        eprintln!("    {} — {}", dev.path.display(), label);
    }

    // If a specific device is given, or if there's only one, list its VMDKs
    let targets: Vec<_> = if let Some(filter) = device_filter {
        let filter_path = std::path::Path::new(filter);
        devices.iter().filter(|d| d.path == filter_path).collect()
    } else {
        devices.iter().collect()
    };

    for dev in &targets {
        let label = if dev.label.is_empty() {
            dev.path.display().to_string()
        } else {
            dev.label.clone()
        };
        match vmfs::list_vmfs6_vmdks(&dev.path) {
            Ok(vmdks) => {
                eprintln!("\n[+] {} — {} flat VMDKs:", label, vmdks.len());
                for (vm, vmdk) in &vmdks {
                    println!(
                        "--vmfs-device {} --vmdk '{}/{}'",
                        dev.path.display(),
                        vm,
                        vmdk
                    );
                }
            }
            Err(e) => {
                eprintln!("[!] {}: {}", dev.path.display(), e);
            }
        }
    }
}

/// Resolve `--dpapi-nthash` user specs (SID, SAM/profile name, or `DOMAIN\\name`) to SIDs.
fn resolve_nthash_sids(
    specs: Vec<(String, [u8; 16])>,
    machine_sid: Option<&str>,
    secrets: Option<&vmkatz::sam::DiskSecrets>,
    hashes: &[vmkatz::sam::dpapi_masterkey::DpapiMasterKeyHash],
) -> Vec<(String, [u8; 16])> {
    let mut out = Vec::new();
    for (user, nt) in specs {
        if user
            .get(..4)
            .is_some_and(|p| p.eq_ignore_ascii_case("S-1-"))
        {
            out.push((user, nt));
            continue;
        }
        let bare = user.rsplit_once('\\').map_or(user.as_str(), |(_, n)| n);
        let sid = hashes
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
            });
        if let Some(sid) = sid {
            out.push((sid, nt));
        } else {
            log::warn!("--dpapi-nthash: cannot resolve user {user:?} to a SID");
        }
    }
    out
}

/// Machine SID: the SID prefix of a profile whose RID and name match a SAM account.
fn find_machine_sid(
    secrets: Option<&vmkatz::sam::DiskSecrets>,
    hashes: &[vmkatz::sam::dpapi_masterkey::DpapiMasterKeyHash],
) -> Option<String> {
    let secrets = secrets?;
    hashes.iter().find_map(|h| {
        let (prefix, rid) = h.sid.rsplit_once('-')?;
        let rid: u32 = rid.parse().ok()?;
        secrets
            .sam_entries
            .iter()
            .any(|e| e.rid == rid && e.username.eq_ignore_ascii_case(&h.username))
            .then(|| prefix.to_string())
    })
}

/// `--credman`: build the secret table from already-extracted SAM/LSA and sweep the disk.
fn emit_credman<R: std::io::Read + std::io::Seek>(
    reader: &mut R,
    args: &Args,
    c: &super::args::Colors,
    secrets: Option<&vmkatz::sam::DiskSecrets>,
    hashes: &[vmkatz::sam::dpapi_masterkey::DpapiMasterKeyHash],
) {
    let machine_sid = find_machine_sid(secrets, hashes);
    let domain = resolve_nthash_sids(
        parse_dpapi_nthashes(&args.dpapi_nthash),
        machine_sid.as_deref(),
        secrets,
        hashes,
    );
    let empty = vmkatz::sam::DiskSecrets::default();
    let table = vmkatz::sam::build_secret_table(
        secrets.unwrap_or(&empty),
        secrets.map_or(&[][..], |s| &s.lsa_secrets),
        machine_sid.as_deref().unwrap_or(""),
        &domain,
    );
    match vmkatz::sam::extract_credman_from_reader_scoped(reader, args.partition, &table) {
        Ok(report) => match args.format.as_str() {
            "csv" => print_credman_csv(&report, args.credman_attributes),
            "hashcat" => {}
            _ => print_credman_text(&report, c, args.credman_attributes),
        },
        Err(e) => eprintln!("[!] Credential Manager extraction failed: {e}"),
    }
}

/// Print DPAPI master key hashes found on a VMFS-backed disk (same formats as `run_sam`).
fn vmfs_emit_dpapi<R: std::io::Read + std::io::Seek>(
    disk: &mut R,
    args: &Args,
    c: &super::args::Colors,
    secrets: Option<&vmkatz::sam::DiskSecrets>,
) {
    let hashes = vmkatz::sam::extract_dpapi_masterkeys_from_reader(disk, args.partition);
    let all_hashes = if args.credman {
        hashes.clone()
    } else {
        Vec::new()
    };
    let hashes = dedup_dpapi_hashes(hashes, args.all);
    if !hashes.is_empty() {
        match args.format.as_str() {
            "csv" => print_dpapi_masterkey_csv(&hashes),
            "hashcat" => print_dpapi_masterkey_hashcat(&hashes),
            _ => print_dpapi_masterkey_text(&hashes, c),
        }
    }
    if args.credman {
        emit_credman(disk, args, c, secrets, &all_hashes);
    }
}

/// NTDS extraction from a VMFS-backed disk; mirrors `run_ntds` (NTDS output, then DPAPI).
#[cfg(feature = "ntds.dit")]
fn vmfs_emit_ntds<R: std::io::Read + std::io::Seek>(
    disk: &mut R,
    args: &Args,
    c: &super::args::Colors,
) -> anyhow::Result<()> {
    let artifacts = vmkatz::sam::extract_ntds_artifacts_from_reader_scoped(disk, args.partition)
        .context("NTDS artifact extraction failed")?;
    let ctx = vmkatz::ntds::build_context(&artifacts.ntds_data, &artifacts.system_data)
        .context("NTDS context validation failed")?;
    let hashes = vmkatz::ntds::extract_ad_hashes(
        &artifacts.ntds_data,
        &artifacts.system_data,
        args.ntds_history,
    )
    .context("NTDS hash extraction failed")?;

    eprintln!("\n{}[+] NTDS Artifacts:{}", c.green, c.reset);
    eprintln!("  Partition offset : 0x{:x}", artifacts.partition_offset);
    eprintln!("  ntds.dit size    : {} bytes", ctx.ntds_size);
    eprintln!("  SYSTEM size      : {} bytes", artifacts.system_data.len());
    eprintln!("  Bootkey          : {}", hex::encode(ctx.boot_key));
    eprintln!("  Hashes extracted : {}", hashes.len());

    match args.format.as_str() {
        "csv" => print_ntds_csv(&hashes),
        "hashcat" => print_ntds_hashcat(&hashes),
        "ntlm" => print_ntds_ntlm(&hashes),
        "brief" => print_ntds_brief(&hashes),
        _ => print_ntds_text(&hashes, c),
    }

    vmfs_emit_dpapi(disk, args, c, None);
    Ok(())
}

#[cfg(feature = "vmfs")]
pub(crate) fn run_vmfs(
    device_path: &Path,
    vmdk_path: Option<&str>,
    args: &Args,
) -> anyhow::Result<()> {
    use vmkatz::disk::DiskImage;
    use vmkatz::disk::vmfs;

    let c = get_colors(args);

    if let Some(vmdk) = vmdk_path {
        // Single VMDK mode
        eprintln!(
            "{}[*] VMFS-6: Opening {} from {}{}",
            c.cyan,
            vmdk,
            device_path.display(),
            c.reset
        );
        let mut disk = vmfs::open_vmfs6_vmdk(device_path, vmdk)
            .map_err(|e| anyhow::anyhow!("VMFS open failed: {e}"))?;

        eprintln!(
            "{}[+] VMDK opened: {:.1} GB{}",
            c.green,
            disk.disk_size() as f64 / (1024.0 * 1024.0 * 1024.0),
            c.reset
        );

        if let Some(ref ls_path) = args.ls {
            return run_ls(&mut disk, ls_path, args.partition);
        }

        // NTDS replaces the plain SAM flow, as in the local-disk path.
        #[cfg(feature = "ntds.dit")]
        if args.ntds {
            return vmfs_emit_ntds(&mut disk, args, c);
        }

        // Extract secrets via the standard pipeline
        let mut disk_secrets: Option<vmkatz::sam::DiskSecrets> = None;
        match vmkatz::sam::extract_secrets_from_reader_scoped(&mut disk, args.partition) {
            Ok(secrets) => {
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
                        "hashcat" => {}
                        _ => print_lsa_secrets(&secrets.lsa_secrets, c),
                    }
                    export_dpapi_backup_keys(&secrets.lsa_secrets);
                }
                if !secrets.cached_credentials.is_empty() {
                    match args.format.as_str() {
                        "csv" => print_dcc2_csv(&secrets.cached_credentials),
                        "hashcat" => print_dcc2_hashcat(&secrets.cached_credentials),
                        _ => print_cached_credentials(&secrets.cached_credentials, c),
                    }
                }
                #[cfg(feature = "chrome")]
                if args.chrome {
                    let nt_hashes = parse_chrome_nthashes(&args.chrome_nthash);
                    match vmkatz::chrome::runner::run_reader(
                        &mut disk,
                        &secrets,
                        &args.chrome_password,
                        &nt_hashes,
                    ) {
                        Ok(summary) => {
                            let out =
                                vmkatz::chrome::runner::render_summary(&summary, args.chrome_json);
                            if !out.trim().is_empty() {
                                println!("{out}");
                            }
                        }
                        Err(e) => log::warn!("chrome (vmfs) failed: {e}"),
                    }
                }
                disk_secrets = Some(secrets);
            }
            Err(e) if args.partition.is_some() => return Err(e.into()),
            Err(e) => {
                eprintln!("[!] Extraction failed for {vmdk}: {e}");
            }
        }

        vmfs_emit_dpapi(&mut disk, args, c, disk_secrets.as_ref());
    } else {
        // A --partition offset is specific to one disk's partition table and is
        // meaningless across the many differently-laid-out VMDKs an auto-scan visits.
        // Require --vmdk so the offset applies to a single, explicit disk.
        if args.partition.is_some() {
            anyhow::bail!(
                "--partition requires --vmdk: a partition offset applies to one disk, not an \
                 auto-scan of all VMDKs. Select a disk with --vmdk (see --vmfs-list)."
            );
        }
        // Auto-scan mode: list all VMs and extract from each
        eprintln!(
            "{}[*] VMFS-6: Scanning all VMs on {}{}",
            c.cyan,
            device_path.display(),
            c.reset
        );

        let vmdks = vmfs::list_vmfs6_vmdks(device_path)
            .map_err(|e| anyhow::anyhow!("VMFS scan failed: {e}"))?;

        if vmdks.is_empty() {
            anyhow::bail!("No flat VMDKs found on VMFS-6 datastore");
        }

        eprintln!("[+] Found {} flat VMDKs:", vmdks.len());
        for (vm, vmdk) in &vmdks {
            eprintln!("    {vm}/{vmdk}");
        }

        for (vm_name, vmdk_name) in &vmdks {
            let vmdk_path = format!("{vm_name}/{vmdk_name}");
            eprintln!("\n{}[*] Processing: {}{}", c.cyan, vmdk_path, c.reset);

            match vmfs::open_vmfs6_vmdk(device_path, &vmdk_path) {
                Ok(mut disk) => {
                    // Quick check: skip VMDKs with no NTFS partitions (Linux/BSD VMs)
                    if !has_ntfs_partitions(&mut disk) {
                        eprintln!("[-] {vm_name}: no NTFS partitions, skipping");
                        continue;
                    }
                    if let Some(ref ls_path) = args.ls {
                        println!("=== {vmdk_path} ===");
                        if let Err(e) = run_ls(&mut disk, ls_path, args.partition) {
                            eprintln!("[!] {vm_name}: {e}");
                        }
                        continue;
                    }
                    #[cfg(feature = "ntds.dit")]
                    if args.ntds {
                        println!("=== {vmdk_path} ===");
                        if let Err(e) = vmfs_emit_ntds(&mut disk, args, c) {
                            eprintln!("[!] {vm_name}: {e:#}");
                        }
                        continue;
                    }
                    // Use NTFS-only extraction (no raw fallback scans) for batch mode
                    let mut disk_secrets: Option<vmkatz::sam::DiskSecrets> = None;
                    match vmkatz::sam::extract_secrets_ntfs_only_scoped(&mut disk, args.partition) {
                        Ok(secrets) => {
                            if !secrets.sam_entries.is_empty() {
                                eprintln!(
                                    "{}[+] {} — {} SAM hashes:{}",
                                    c.green,
                                    vm_name,
                                    secrets.sam_entries.len(),
                                    c.reset
                                );
                                match args.format.as_str() {
                                    "ntlm" => print_sam_ntlm(&secrets.sam_entries),
                                    "csv" => print_sam_csv(&secrets.sam_entries),
                                    "hashcat" => print_sam_hashcat(&secrets.sam_entries),
                                    "brief" => print_sam_brief(&secrets.sam_entries),
                                    _ => print_sam_text(&secrets.sam_entries, c),
                                }
                            }
                            if !secrets.lsa_secrets.is_empty() {
                                match args.format.as_str() {
                                    "csv" => print_lsa_csv(&secrets.lsa_secrets),
                                    "hashcat" => {}
                                    _ => print_lsa_secrets(&secrets.lsa_secrets, c),
                                }
                                export_dpapi_backup_keys(&secrets.lsa_secrets);
                            }
                            if !secrets.cached_credentials.is_empty() {
                                match args.format.as_str() {
                                    "csv" => print_dcc2_csv(&secrets.cached_credentials),
                                    "hashcat" => print_dcc2_hashcat(&secrets.cached_credentials),
                                    _ => print_cached_credentials(&secrets.cached_credentials, c),
                                }
                            }
                            disk_secrets = Some(secrets);
                        }
                        Err(e) => {
                            eprintln!("[!] {vm_name}: {e}");
                        }
                    }
                    vmfs_emit_dpapi(&mut disk, args, c, disk_secrets.as_ref());
                }
                Err(e) => {
                    eprintln!("[!] Failed to open {vmdk_path}: {e}");
                }
            }
        }
    }

    Ok(())
}

#[cfg(feature = "sam")]
pub(crate) fn run_sam(input_path: &Path, args: &Args) -> anyhow::Result<()> {
    #[cfg(feature = "ntds.dit")]
    {
        if args.ntds {
            return run_ntds(input_path, args);
        }
    }

    if args.verbose {
        eprintln!("[*] SAM hash extraction from: {}", input_path.display());
    }

    let c = get_colors(args);
    let mut found_anything = false;
    let mut disk_secrets: Option<vmkatz::sam::DiskSecrets> = None;

    // SAM/LSA extraction — non-fatal so DPAPI masterkey scan can still proceed
    match vmkatz::sam::extract_disk_secrets_scoped(input_path, args.partition) {
        Ok(secrets) => {
            found_anything = true;

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

            // Export DPAPI backup key PVK files when found
            export_dpapi_backup_keys(&secrets.lsa_secrets);

            if !secrets.cached_credentials.is_empty() {
                match args.format.as_str() {
                    "csv" => print_dcc2_csv(&secrets.cached_credentials),
                    "hashcat" => print_dcc2_hashcat(&secrets.cached_credentials),
                    _ => print_cached_credentials(&secrets.cached_credentials, c),
                }
            }
            disk_secrets = Some(secrets);
        }
        Err(e) if args.partition.is_some() => return Err(e.into()),
        Err(e) => {
            eprintln!("[!] SAM extraction failed: {e}");
        }
    }

    // Extract DPAPI master key hashes from user profiles (independent of SAM)
    let dpapi_hashes = vmkatz::sam::extract_dpapi_masterkeys_scoped(input_path, args.partition);
    let all_dpapi_hashes = if args.credman {
        dpapi_hashes.clone()
    } else {
        Vec::new()
    };
    let dpapi_hashes = dedup_dpapi_hashes(dpapi_hashes, args.all);
    if !dpapi_hashes.is_empty() {
        found_anything = true;
        match args.format.as_str() {
            "csv" => print_dpapi_masterkey_csv(&dpapi_hashes),
            "hashcat" => print_dpapi_masterkey_hashcat(&dpapi_hashes),
            _ => print_dpapi_masterkey_text(&dpapi_hashes, c),
        }
    }

    if args.credman {
        match vmkatz::disk::open_disk(input_path) {
            Ok(mut disk) => {
                emit_credman(&mut disk, args, c, disk_secrets.as_ref(), &all_dpapi_hashes);
            }
            Err(e) => eprintln!("[!] Credential Manager: cannot open disk: {e}"),
        }
    }

    #[cfg(feature = "chrome")]
    {
        if args.chrome {
            let chrome_nt_hashes = parse_chrome_nthashes(&args.chrome_nthash);
            match vmkatz::chrome::runner::run_disk_with_passwords(
                input_path,
                &args.chrome_password,
                &chrome_nt_hashes,
            ) {
                Ok(summary) => {
                    if !summary.profiles.is_empty() || !summary.findings.is_empty() {
                        found_anything = true;
                    }
                    let out = vmkatz::chrome::runner::render_summary(&summary, args.chrome_json);
                    if !out.trim().is_empty() {
                        println!("{out}");
                    }
                }
                Err(e) => log::warn!("chrome extraction failed: {e}"),
            }
        }
    }

    if !found_anything {
        anyhow::bail!("No SAM hashes or DPAPI master keys found on disk");
    }

    Ok(())
}

#[cfg(feature = "ntds.dit")]
fn run_ntds(input_path: &Path, args: &Args) -> anyhow::Result<()> {
    if args.verbose {
        eprintln!("[*] NTDS extraction from: {}", input_path.display());
    }

    let artifacts = vmkatz::sam::extract_ntds_artifacts_scoped(input_path, args.partition)
        .context("NTDS artifact extraction failed")?;
    let ctx = vmkatz::ntds::build_context(&artifacts.ntds_data, &artifacts.system_data)
        .context("NTDS context validation failed")?;
    let hashes = vmkatz::ntds::extract_ad_hashes(
        &artifacts.ntds_data,
        &artifacts.system_data,
        args.ntds_history,
    )
    .context("NTDS hash extraction failed")?;

    let c = get_colors(args);

    eprintln!("\n{}[+] NTDS Artifacts:{}", c.green, c.reset);
    eprintln!("  Partition offset : 0x{:x}", artifacts.partition_offset);
    eprintln!("  ntds.dit size    : {} bytes", ctx.ntds_size);
    eprintln!("  SYSTEM size      : {} bytes", artifacts.system_data.len());
    eprintln!("  Bootkey          : {}", hex::encode(ctx.boot_key));
    eprintln!("  Hashes extracted : {}", hashes.len());

    match args.format.as_str() {
        "csv" => print_ntds_csv(&hashes),
        "hashcat" => print_ntds_hashcat(&hashes),
        "ntlm" => print_ntds_ntlm(&hashes),
        "brief" => print_ntds_brief(&hashes),
        _ => print_ntds_text(&hashes, c),
    }

    // Also extract DPAPI master key hashes from user profiles on the same disk
    let dpapi_hashes = vmkatz::sam::extract_dpapi_masterkeys_scoped(input_path, args.partition);
    let dpapi_hashes = dedup_dpapi_hashes(dpapi_hashes, args.all);
    if !dpapi_hashes.is_empty() {
        match args.format.as_str() {
            "csv" => print_dpapi_masterkey_csv(&dpapi_hashes),
            "hashcat" => print_dpapi_masterkey_hashcat(&dpapi_hashes),
            _ => print_dpapi_masterkey_text(&dpapi_hashes, c),
        }
    }

    Ok(())
}

/// Run the credential pipeline over every disk image in a Veeam backup.
/// Images are read on demand — nothing is written to a temp file.
#[cfg(feature = "veeam")]
pub(crate) fn run_veeam(input_path: &Path, args: &Args) -> anyhow::Result<()> {
    use vmkatz::disk::DiskImage;

    let password = args.veeam_password.as_deref();

    // Inspection/extraction sub-modes (mirror vbktool's `list` / `extract`).
    if args.veeam_list {
        return run_veeam_list(input_path, password, args);
    }
    if let Some(name) = &args.veeam_extract {
        return run_veeam_extract(
            input_path,
            name,
            args.veeam_output.as_deref(),
            password,
            args,
        );
    }

    // Encrypted with no password: can't reconstruct — emit the Hashcat
    // target for cracking. With --veeam-password we fall through instead.
    if password.is_none()
        && vmkatz::veeam::inspect_encryption(input_path).is_ok_and(|e| e.encrypted)
    {
        return emit_veeam_hashcat(input_path);
    }

    let disks = vmkatz::veeam::list_disk_images(input_path, password)
        .context("failed to enumerate Veeam disk images")?;
    if disks.is_empty() {
        // Encryption is handled above, so an empty list means the backup holds
        // no Windows disk images (e.g. a Linux/agent backup or a wrong password).
        anyhow::bail!(
            "No Windows disk images in Veeam backup {}",
            input_path.display()
        );
    }

    let c = get_colors(args);
    eprintln!(
        "[+] Veeam backup: {} disk image(s) in {}",
        disks.len(),
        input_path.display()
    );

    let mut found_anything = false;
    for entry in &disks {
        let size_note = entry
            .size
            .map(|s| format!(" ({})", veeam_human_size(s)))
            .unwrap_or_default();
        eprintln!(
            "\n{}=== disk image: {}{}{}",
            c.green, entry.name, size_note, c.reset
        );

        let mut disk = match vmkatz::veeam::VbkDisk::open(input_path, &entry.path, password) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("[!] cannot open {}: {e}", entry.name);
                continue;
            }
        };
        log::info!("[veeam] {} = {} bytes", entry.name, disk.disk_size());

        // --ntds targets a DC's disk: extract AD hashes from NTDS.dit instead of
        // the local SAM/DPAPI pipeline.
        #[cfg(feature = "ntds.dit")]
        if args.ntds {
            match extract_ntds_from_reader(&mut disk, args, c) {
                Ok(found) => found_anything |= found,
                Err(e) => eprintln!("[!] NTDS extraction failed on {}: {e}", entry.name),
            }
            continue;
        }

        match extract_and_print_reader(&mut disk, args, c) {
            Ok(found) => found_anything |= found,
            Err(e) => eprintln!("[!] extraction failed on {}: {e}", entry.name),
        }
    }

    if !found_anything {
        anyhow::bail!("No SAM hashes or DPAPI master keys found in Veeam backup");
    }
    Ok(())
}

/// Print the encrypted backup's wrapped keyset as a Hashcat target
/// (`$vbk$*salt*iterations*verifier`, mode 31200) for offline cracking.
#[cfg(feature = "veeam")]
fn emit_veeam_hashcat(input_path: &Path) -> anyhow::Result<()> {
    let hashes = vmkatz::veeam::hashcat_hashes(input_path).with_context(|| {
        format!(
            "{} is encrypted but no Hashcat target could be built",
            input_path.display()
        )
    })?;
    eprintln!(
        "[+] Encrypted Veeam backup — {} Hashcat target(s), mode {}:",
        hashes.len(),
        vmkatz::veeam::HASHCAT_VEEAM_VBK_MODE
    );
    for h in &hashes {
        println!("{h}");
    }
    eprintln!(
        "[*] Crack with: hashcat -m {} <hash> <wordlist>, then re-run with --veeam-password",
        vmkatz::veeam::HASHCAT_VEEAM_VBK_MODE
    );
    Ok(())
}

/// Human-readable byte size (binary units), matching vbktool's list output.
#[cfg(feature = "veeam")]
fn veeam_human_size(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{bytes} {}", UNITS[0])
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

/// `--veeam-list`: print the backup catalogue (directories and stored files).
#[cfg(feature = "veeam")]
fn run_veeam_list(input_path: &Path, password: Option<&str>, args: &Args) -> anyhow::Result<()> {
    use vmkatz::veeam::StoredItemKind;
    let catalog = vmkatz::veeam::list_items_with_password(input_path, password)
        .context("failed to read Veeam catalogue")?;
    let c = get_colors(args);
    let (mut files, mut dirs, mut total) = (0u64, 0u64, 0u64);
    for item in &catalog.items {
        match item.kind {
            StoredItemKind::Directory => {
                dirs += 1;
                eprintln!("\n{}{}/{}", c.cyan, item.name, c.reset);
            }
            StoredItemKind::File => {
                files += 1;
                let sz = item.size.unwrap_or(0);
                total += sz;
                println!("  {:>11}  {}", veeam_human_size(sz), item.name);
            }
        }
    }
    eprintln!(
        "\n{files} file(s) · {dirs} director(ies) · {} total",
        veeam_human_size(total)
    );
    Ok(())
}

/// `--veeam-extract`: reconstruct one stored file to disk (never overwrites).
#[cfg(feature = "veeam")]
fn run_veeam_extract(
    input_path: &Path,
    name: &str,
    output: Option<&str>,
    password: Option<&str>,
    args: &Args,
) -> anyhow::Result<()> {
    // Default destination: the item's basename (after any catalogue path) in cwd.
    let default_name = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let dest = Path::new(output.unwrap_or(default_name));
    let report =
        vmkatz::veeam::extract_item_to_path_with_password(input_path, name, dest, password)
            .with_context(|| format!("failed to extract {name:?}"))?;
    let c = get_colors(args);
    eprintln!(
        "{}[+] Extracted {} → {}{}",
        c.green,
        report.name,
        dest.display(),
        c.reset
    );
    eprintln!(
        "    {} · {} blocks ({} sparse, {} compressed)",
        veeam_human_size(report.bytes_written),
        report.block_count,
        report.sparse_blocks,
        report.compressed_blocks
    );
    Ok(())
}

/// Extract and print SAM/LSA/DCC2, DPAPI, and (with `--chrome`) Chrome
/// secrets from one open disk reader — the reader-based twin of `run_sam`.
#[cfg(feature = "veeam")]
fn extract_and_print_reader<R: std::io::Read + std::io::Seek>(
    reader: &mut R,
    args: &Args,
    c: &Colors,
) -> anyhow::Result<bool> {
    use std::io::SeekFrom;
    let mut found_anything = false;

    reader.seek(SeekFrom::Start(0))?;
    // Only the chrome block below reads `secrets` after printing.
    #[cfg_attr(not(feature = "chrome"), expect(unused_variables))]
    let secrets = match vmkatz::sam::extract_secrets_from_reader(reader) {
        Ok(secrets) => {
            found_anything = true;
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
                    "hashcat" => {}
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
            secrets
        }
        Err(e) => {
            eprintln!("[!] SAM extraction failed: {e}");
            vmkatz::sam::DiskSecrets::default()
        }
    };

    // Chrome — independent of SAM success, like run_sam. Recovered secrets seed
    // keyring building; without them we still discover profiles and try
    // --chrome-password candidates.
    #[cfg(feature = "chrome")]
    if args.chrome {
        reader.seek(SeekFrom::Start(0))?;
        let nt_hashes = parse_chrome_nthashes(&args.chrome_nthash);
        match vmkatz::chrome::runner::run_reader(
            reader,
            &secrets,
            &args.chrome_password,
            &nt_hashes,
        ) {
            Ok(summary) => {
                if !summary.profiles.is_empty() || !summary.findings.is_empty() {
                    found_anything = true;
                }
                let out = vmkatz::chrome::runner::render_summary(&summary, args.chrome_json);
                if !out.trim().is_empty() {
                    println!("{out}");
                }
            }
            Err(e) => log::warn!("chrome extraction failed: {e}"),
        }
    }

    // DPAPI master key hashes (independent of SAM).
    reader.seek(SeekFrom::Start(0))?;
    let dpapi_hashes = vmkatz::sam::dpapi_masterkey::extract_from_disk(reader);
    let dpapi_hashes = dedup_dpapi_hashes(dpapi_hashes, args.all);
    if !dpapi_hashes.is_empty() {
        found_anything = true;
        match args.format.as_str() {
            "csv" => print_dpapi_masterkey_csv(&dpapi_hashes),
            "hashcat" => print_dpapi_masterkey_hashcat(&dpapi_hashes),
            _ => print_dpapi_masterkey_text(&dpapi_hashes, c),
        }
    }

    Ok(found_anything)
}

/// Extract AD hashes from a DC disk's NTDS.dit via a reader — the reader-based
/// twin of `run_ntds`. Returns whether any hashes were found.
#[cfg(all(feature = "veeam", feature = "ntds.dit"))]
fn extract_ntds_from_reader<R: std::io::Read + std::io::Seek>(
    reader: &mut R,
    args: &Args,
    c: &Colors,
) -> anyhow::Result<bool> {
    use std::io::SeekFrom;

    reader.seek(SeekFrom::Start(0))?;
    let artifacts = vmkatz::sam::extract_ntds_artifacts_from_reader(reader)
        .context("NTDS artifact extraction failed")?;
    let ctx = vmkatz::ntds::build_context(&artifacts.ntds_data, &artifacts.system_data)
        .context("NTDS context validation failed")?;
    let hashes = vmkatz::ntds::extract_ad_hashes(
        &artifacts.ntds_data,
        &artifacts.system_data,
        args.ntds_history,
    )
    .context("NTDS hash extraction failed")?;

    eprintln!("\n{}[+] NTDS Artifacts:{}", c.green, c.reset);
    eprintln!("  Partition offset : 0x{:x}", artifacts.partition_offset);
    eprintln!("  ntds.dit size    : {} bytes", ctx.ntds_size);
    eprintln!("  Hashes extracted : {}", hashes.len());

    match args.format.as_str() {
        "csv" => print_ntds_csv(&hashes),
        "hashcat" => print_ntds_hashcat(&hashes),
        "ntlm" => print_ntds_ntlm(&hashes),
        "brief" => print_ntds_brief(&hashes),
        _ => print_ntds_text(&hashes, c),
    }

    // DPAPI master key hashes from the same disk, as run_ntds does.
    reader.seek(SeekFrom::Start(0))?;
    let dpapi_hashes = dedup_dpapi_hashes(
        vmkatz::sam::dpapi_masterkey::extract_from_disk(reader),
        args.all,
    );
    if !dpapi_hashes.is_empty() {
        match args.format.as_str() {
            "csv" => print_dpapi_masterkey_csv(&dpapi_hashes),
            "hashcat" => print_dpapi_masterkey_hashcat(&dpapi_hashes),
            _ => print_dpapi_masterkey_text(&dpapi_hashes, c),
        }
    }

    Ok(!hashes.is_empty() || !dpapi_hashes.is_empty())
}

// ---------------------------------------------------------------------------
// Raw file modes (no disk image / VM snapshot needed)
// ---------------------------------------------------------------------------

/// Extract AD hashes from raw NTDS.dit + SYSTEM hive files.
#[cfg(feature = "ntds.dit")]
pub(crate) fn run_raw_ntds(
    ntds_path: &Path,
    system_path: &Path,
    args: &Args,
) -> anyhow::Result<()> {
    // Mapped, not read: a production NTDS.dit runs to tens of GB and the ESE
    // parser only ever borrows `&[u8]`, so there is nothing to gain from a heap
    // copy and an allocation abort to lose.
    let ntds_data = vmkatz::utils::FileBytes::open(ntds_path)
        .with_context(|| format!("Failed to read {}", ntds_path.display()))?;
    let system_data = std::fs::read(system_path)
        .with_context(|| format!("Failed to read {}", system_path.display()))?;

    let ctx = vmkatz::ntds::build_context(&ntds_data, &system_data)
        .context("NTDS context validation failed")?;
    let hashes = vmkatz::ntds::extract_ad_hashes(&ntds_data, &system_data, {
        #[cfg(feature = "ntds.dit")]
        {
            args.ntds_history
        }
        #[cfg(not(feature = "ntds.dit"))]
        {
            false
        }
    })
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
        system_data.len()
    );
    eprintln!("  Bootkey  : {}", hex::encode(ctx.boot_key));
    eprintln!("  Hashes   : {}", hashes.len());

    match args.format.as_str() {
        "csv" => print_ntds_csv(&hashes),
        "hashcat" => print_ntds_hashcat(&hashes),
        "ntlm" => print_ntds_ntlm(&hashes),
        "brief" => print_ntds_brief(&hashes),
        _ => print_ntds_text(&hashes, c),
    }

    Ok(())
}

/// Extract SAM/LSA/DCC2 from raw registry hive files.
/// Auto-detects which hive is SYSTEM (via bootkey extraction), SAM, and SECURITY.
#[cfg(feature = "sam")]
pub(crate) fn run_raw_hives(
    hive_files: &[&(std::path::PathBuf, RawFileType)],
    args: &Args,
) -> anyhow::Result<()> {
    // Read all hive files
    let hives: Vec<(&Path, Vec<u8>)> = hive_files
        .iter()
        .map(|(p, _)| {
            let data =
                std::fs::read(p).with_context(|| format!("Failed to read {}", p.display()))?;
            Ok((p.as_path(), data))
        })
        .collect::<anyhow::Result<_>>()?;

    // Identify SYSTEM hive by trying bootkey extraction on each
    let mut system_idx = None;
    let mut bootkey = [0u8; 16];

    for (i, (path, data)) in hives.iter().enumerate() {
        if let Ok(key) = vmkatz::sam::bootkey::extract_bootkey(data) {
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
        hives[system_idx].0.display(),
        hex::encode(bootkey)
    );

    let mut sam_entries = Vec::new();
    let mut lsa_secrets = Vec::new();
    let mut cached_creds = Vec::new();

    // Try SAM and SECURITY extraction on the other hives
    for (i, (path, data)) in hives.iter().enumerate() {
        if i == system_idx {
            continue;
        }

        // Try as SAM
        if let Ok(entries) = vmkatz::sam::hashes::extract_hashes(data, &bootkey) {
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

        // Try as SECURITY (LSA secrets + cached creds)
        if let Ok(secrets) = vmkatz::sam::lsa::extract_lsa_secrets(data, &bootkey) {
            if !secrets.is_empty() {
                eprintln!("  SECURITY: {} ({} secrets)", path.display(), secrets.len());
                lsa_secrets = secrets;

                if let Some(nlkm) = lsa_secrets.iter().find(|s| s.name == "NL$KM") {
                    if let Ok(creds) =
                        vmkatz::sam::cache::extract_cached_credentials(data, &nlkm.raw_data)
                    {
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

/// Classify a snapshot file by its hypervisor type based on extension.
fn snapshot_type_label(path: &Path) -> &'static str {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    match ext.to_ascii_lowercase().as_str() {
        "vmsn" | "vmss" | "vmem" => "VMware",
        "sav" => "VirtualBox",
        "elf" => "QEMU/KVM",
        "vmrs" | "bin" | "raw" => "Hyper-V",
        _ => "unknown",
    }
}

/// Classify a disk image file by its type based on extension.
fn disk_type_label(path: &Path) -> &'static str {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    match ext.to_ascii_lowercase().as_str() {
        "vmdk" => "VMDK",
        "vdi" => "VDI",
        "qcow2" | "qcow" => "QCOW2",
        "vhdx" => "VHDX",
        "vhd" => "VHD",
        _ => "disk",
    }
}

pub(crate) fn run_directory(dir: &Path, args: &Args) -> anyhow::Result<()> {
    let mut discovery =
        vmkatz::discover::discover_vm_files(dir).context("VM file discovery failed")?;

    // Apply --scan filter
    match args.scan.as_str() {
        "snapshot" => discovery.disk_files.clear(),
        "disk" => discovery.lsass_files.clear(),
        _ => {} // "all"
    }

    // Build typed file list for display
    if !discovery.lsass_files.is_empty() {
        for f in &discovery.lsass_files {
            let name = f.file_name().unwrap_or_default().to_string_lossy();
            eprintln!("[*] {} snapshot: {}", snapshot_type_label(f), name);
        }
    }
    if !discovery.disk_files.is_empty() {
        for f in &discovery.disk_files {
            let name = f.file_name().unwrap_or_default().to_string_lossy();
            eprintln!("[*] {} disk: {}", disk_type_label(f), name);
        }
    }

    if discovery.lsass_files.is_empty() && discovery.disk_files.is_empty() {
        if args.verbose {
            eprintln!("[!] No processable VM files found in {}", dir.display());
        }
        return Ok(());
    }

    #[cfg(any(
        feature = "vmware",
        feature = "vbox",
        feature = "qemu",
        feature = "hyperv"
    ))]
    {
        // Try to open pagefile.sys from the first available disk image
        #[cfg(feature = "sam")]
        let pagefile_reader = if discovery.lsass_files.is_empty() {
            None
        } else {
            discovery.disk_files.first().and_then(|d| {
                match vmkatz::paging::pagefile::PagefileReader::open(d) {
                    Ok(pf) => {
                        eprintln!(
                            "[+] Pagefile: {:.1} MB from {}",
                            pf.pagefile_size() as f64 / (1024.0 * 1024.0),
                            d.file_name().unwrap_or_default().to_string_lossy()
                        );
                        Some(pf)
                    }
                    Err(e) => {
                        log::info!("No pagefile from disk: {e}");
                        None
                    }
                }
            })
        };

        #[cfg(feature = "sam")]
        let pagefile: PagefileRef<'_> = pagefile_reader.as_ref();
        #[cfg(not(feature = "sam"))]
        let pagefile: PagefileRef<'_> = ();

        // Disk path for file-backed DLL resolution
        #[cfg(feature = "sam")]
        let disk_path: vmkatz::lsass::finder::DiskPathRef<'_> = discovery
            .disk_files
            .first()
            .map(std::path::PathBuf::as_path);
        #[cfg(not(feature = "sam"))]
        let disk_path: vmkatz::lsass::finder::DiskPathRef<'_> = ();

        for file in &discovery.lsass_files {
            let name = file.file_name().unwrap_or_default().to_string_lossy();
            eprintln!("\n[*] LSASS: {name}");
            if let Err(e) = run_lsass(file, args, pagefile, disk_path) {
                eprintln!("[!] {name}: {e}");
            }
        }
    }

    // Extract BitLocker FVEK keys from memory snapshots for transparent disk decryption.
    // This is done as a separate pass so we can pass keys to the SAM extraction phase.
    #[cfg(all(
        feature = "sam",
        any(
            feature = "vmware",
            feature = "vbox",
            feature = "qemu",
            feature = "hyperv"
        )
    ))]
    let bitlocker_keys: Vec<vmkatz::lsass::bitlocker::BitLockerKey> = {
        let mut keys = Vec::new();
        for file in &discovery.lsass_files {
            let snapshot_keys = extract_bitlocker_keys_from_snapshot(file);
            if !snapshot_keys.is_empty() {
                log::info!(
                    "BitLocker: {} FVEK candidate(s) from {}",
                    snapshot_keys.len(),
                    file.display()
                );
                keys.extend(snapshot_keys);
            }
        }
        // Deduplicate by FVEK content
        keys.sort_by(|a, b| a.fvek.cmp(&b.fvek));
        keys.dedup_by(|a, b| a.fvek == b.fvek && a.method == b.method);
        keys
    };

    #[cfg(feature = "sam")]
    for file in &discovery.disk_files {
        let name = file.file_name().unwrap_or_default().to_string_lossy();
        eprintln!("\n[*] SAM: {name}");
        // Try BitLocker-aware extraction if we have FVEK keys from memory
        #[cfg(any(
            feature = "vmware",
            feature = "vbox",
            feature = "qemu",
            feature = "hyperv"
        ))]
        if !bitlocker_keys.is_empty() {
            match vmkatz::sam::extract_disk_secrets_with_bitlocker(file, &bitlocker_keys) {
                Ok(secrets) => {
                    print_disk_secrets(&secrets, args);
                    continue;
                }
                Err(e) => {
                    log::info!("BitLocker-aware extraction failed for {name}: {e}");
                }
            }
        }
        if let Err(e) = run_sam(file, args) {
            eprintln!("[!] {name}: {e:#}");
        }
    }

    #[cfg(not(feature = "sam"))]
    if !discovery.disk_files.is_empty() {
        eprintln!(
            "[!] {} disk image(s) found but SAM support not compiled in (rebuild with --features sam)",
            discovery.disk_files.len()
        );
    }

    Ok(())
}

/// Recursively scan a directory tree for VM files and process each VM directory.
pub(crate) fn run_recursive(root: &Path, args: &Args) -> anyhow::Result<()> {
    let vm_dirs =
        vmkatz::discover::discover_vm_directories(root).context("Recursive VM discovery failed")?;

    if vm_dirs.is_empty() {
        eprintln!("[!] No VM directories found under {}", root.display());
        return Ok(());
    }

    eprintln!(
        "[*] Found {} VM director{} under {}",
        vm_dirs.len(),
        if vm_dirs.len() == 1 { "y" } else { "ies" },
        root.display()
    );

    let mut success = 0;
    let mut errors = 0;

    for dir in &vm_dirs {
        eprintln!("\n{}", "=".repeat(72));
        eprintln!("[*] Processing: {}", dir.display());
        match run_directory(dir, args) {
            Ok(()) => success += 1,
            Err(e) => {
                eprintln!("[!] {}: {:#}", dir.display(), e);
                errors += 1;
            }
        }
    }

    eprintln!("\n[*] Recursive scan complete: {success} processed, {errors} errors");
    Ok(())
}

#[cfg(all(test, feature = "sam"))]
mod ls_tests {
    use super::{format_entry, human_size};
    use vmkatz::fs::{DirEntry, EntryKind};

    #[test]
    fn human_size_units() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(4096), "4.0 KiB");
        assert_eq!(human_size(5 * 1024 * 1024 * 1024), "5.0 GiB");
    }

    #[test]
    fn format_entry_dir_vs_file() {
        let d = format_entry(&DirEntry {
            name: "Windows".into(),
            kind: EntryKind::Dir,
        });
        assert!(d.contains("<DIR>") && d.contains("Windows"));
        let f = format_entry(&DirEntry {
            name: "a.txt".into(),
            kind: EntryKind::File { size: 4096 },
        });
        assert!(f.contains("4.0 KiB") && f.contains("a.txt") && !f.contains("<DIR>"));
    }

    #[test]
    fn run_ls_lists_root_when_fixture_present() {
        let p = std::path::Path::new("/tmp/test.qcow2");
        if !p.exists() {
            eprintln!("SKIP run_ls_lists_root_when_fixture_present: /tmp/test.qcow2 absent");
            return;
        }
        let mut disk = vmkatz::disk::open_disk(p).unwrap();
        super::run_ls(&mut disk, "", None).unwrap();
    }
}
