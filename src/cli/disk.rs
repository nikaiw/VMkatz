//! Local disk commands and shared extraction helpers for disk-backed readers.

use std::path::Path;

#[cfg(any(
    feature = "ntds.dit",
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv"
))]
use anyhow::Context;
#[cfg(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv"
))]
use vmkatz::lsass::finder::PagefileRef;

#[cfg(any(feature = "vmfs", feature = "veeam"))]
use super::args::Colors;
use super::args::{Args, get_colors};
use super::credentials::emit_disk_extras;
#[cfg(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv"
))]
use super::lsass::run_lsass;
#[cfg(feature = "sam")]
use super::output::print_disk_secrets;
#[cfg(feature = "ntds.dit")]
use super::output::{
    print_ntds_brief, print_ntds_csv, print_ntds_hashcat, print_ntds_ntlm, print_ntds_text,
};

mod files;
#[cfg(feature = "sam")]
mod raw;
#[cfg(feature = "veeam")]
mod veeam;
#[cfg(feature = "vmfs")]
mod vmfs;

pub(crate) use files::{run_cp, run_ls};
#[cfg(feature = "sam")]
pub(crate) use raw::run_raw_hives;
#[cfg(feature = "ntds.dit")]
pub(crate) use raw::run_raw_ntds;
#[cfg(feature = "veeam")]
pub(crate) use veeam::run_veeam;
#[cfg(feature = "vmfs")]
pub(crate) use vmfs::{run_vmfs, run_vmfs_list};

pub(crate) fn run_disk(input_path: &Path, args: &Args) -> anyhow::Result<()> {
    #[cfg(feature = "ntds.dit")]
    if args.ntds || args.all {
        return run_ntds(input_path, args, &[]);
    }
    if !cfg!(any(feature = "sam", feature = "dpapi", feature = "chrome")) {
        anyhow::bail!(
            "No disk extraction feature enabled; use --ls or --cp, or build with sam, dpapi, credman or chrome"
        );
    }
    #[cfg(feature = "sam")]
    let secrets = match vmkatz::sam::extract_disk_secrets_scoped(input_path, args.partition) {
        Ok(secrets) => {
            print_disk_secrets(&secrets, args);
            Some(secrets)
        }
        Err(e) if args.partition.is_some() => return Err(e.into()),
        Err(e) => {
            eprintln!("[!] SAM extraction failed: {e}");
            None
        }
    };
    #[cfg(not(feature = "sam"))]
    let secrets: Option<vmkatz::secrets::DiskSecrets> = None;
    let mut disk = vmkatz::disk::open_disk(input_path)?;
    // Validate explicit offsets before optional scanners (which return empty on failure).
    if args.partition.is_some() {
        vmkatz::fs::select_partition(vmkatz::fs::find_ntfs_partitions(&mut disk)?, args.partition)?;
    }
    let found = emit_disk_extras(&mut disk, args, get_colors(args), secrets.as_ref(), &[]);
    if !found && secrets.is_none() {
        anyhow::bail!("No secrets found by the enabled disk extractors");
    }
    Ok(())
}

#[cfg(feature = "ntds.dit")]
pub(super) fn run_ntds(
    input_path: &Path,
    args: &Args,
    fvek_keys: &[vmkatz::lsass::bitlocker::BitLockerKey],
) -> anyhow::Result<()> {
    if args.verbose > 0 {
        eprintln!("[*] NTDS extraction from: {}", input_path.display());
    }

    let c = get_colors(args);
    let mut disk = vmkatz::disk::open_disk(input_path).context("Failed to open disk image")?;

    // Reuse local secrets for CredMan; --all also prints them.
    let local_secrets = if args.credman || args.all {
        let result = if fvek_keys.is_empty() {
            vmkatz::sam::extract_disk_secrets_scoped(input_path, args.partition)
        } else {
            vmkatz::sam::extract_disk_secrets_with_bitlocker_scoped(
                input_path,
                fvek_keys,
                args.partition,
            )
        };
        match result {
            Ok(secrets) => Some(secrets),
            Err(error) => {
                eprintln!("[!] SAM/LSA extraction failed: {error}");
                None
            }
        }
    } else {
        None
    };

    let result = read_ntds_stream(&mut disk, args, fvek_keys);
    let artifacts = match result {
        Ok(artifacts) => artifacts,
        Err(error) if args.all => {
            if let Some(secrets) = &local_secrets {
                print_disk_secrets(secrets, args);
            }
            eprintln!("[!] NTDS extraction skipped: {error}");
            let found = emit_disk_extras(&mut disk, args, c, local_secrets.as_ref(), &[]);
            if !found && local_secrets.is_none() {
                return Err(error).context("No secrets found by the enabled disk extractors");
            }
            return Ok(());
        }
        Err(error) => return Err(error).context("NTDS artifact extraction failed"),
    };
    if args.all {
        if let Some(secrets) = &local_secrets {
            print_disk_secrets(secrets, args);
        }
    }
    let (ctx, hashes) = artifacts.output.context("NTDS hash extraction failed")?;

    eprintln!("\n{}[+] NTDS Artifacts:{}", c.green, c.reset);
    eprintln!("  Partition offset : 0x{:x}", artifacts.partition_offset);
    eprintln!("  ntds.dit size    : {} bytes", ctx.ntds_size);
    eprintln!("  SYSTEM size      : {} bytes", artifacts.system_size);
    eprintln!("  Bootkey          : {}", hex::encode(ctx.boot_key));
    eprintln!("  Hashes extracted : {}", hashes.len());

    match args.format.as_str() {
        "csv" => print_ntds_csv(&hashes, args.ntds_domain_prefix.as_deref()),
        "hashcat" => print_ntds_hashcat(&hashes, args.ntds_domain_prefix.as_deref()),
        "ntlm" => print_ntds_ntlm(&hashes, args.ntds_domain_prefix.as_deref()),
        "brief" => print_ntds_brief(&hashes, args.ntds_domain_prefix.as_deref()),
        _ => print_ntds_text(&hashes, c, args.ntds_domain_prefix.as_deref()),
    }

    let ntds_by_name: Vec<_> = hashes
        .iter()
        .filter(|h| !h.is_history)
        .map(|h| (h.username.clone(), h.nt_hash))
        .collect();
    emit_disk_extras(&mut disk, args, c, local_secrets.as_ref(), &ntds_by_name);

    Ok(())
}

/// Extract LSASS from memory snapshots located beside an explicitly selected
/// standalone disk image. Directory mode already processes snapshots itself.
#[cfg(all(
    feature = "disk",
    any(
        feature = "vmware",
        feature = "vbox",
        feature = "qemu",
        feature = "hyperv"
    )
))]
pub(crate) fn run_associated_lsass_for_disk(input_path: &Path, args: &Args) -> anyhow::Result<()> {
    let vm_dir = input_path.parent().unwrap_or_else(|| Path::new("."));
    let discovery = vmkatz::discover::discover_vm_files(vm_dir)
        .context("Failed to discover snapshots beside the disk image")?;
    if discovery.lsass_files.is_empty() {
        if args.lsass {
            anyhow::bail!(
                "--lsass requested, but no supported memory snapshots were found beside {}",
                input_path.display()
            );
        }
        return Ok(());
    }

    let pagefile_reader = vmkatz::paging::pagefile::PagefileReader::open(input_path).ok();
    let pagefile: PagefileRef<'_> = pagefile_reader.as_ref();
    let disk_path = Some(input_path);
    for snapshot in &discovery.lsass_files {
        let name = snapshot.file_name().unwrap_or_default().to_string_lossy();
        eprintln!("\n[*] LSASS snapshot: {name}");
        if let Err(error) = run_lsass(snapshot, args, pagefile, disk_path) {
            eprintln!("[!] {name}: {error:#}");
        }
    }
    Ok(())
}

/// Run registry and optional disk extractors on an open reader.
#[cfg(any(feature = "vmfs", feature = "veeam"))]
fn extract_and_print_reader<R: std::io::Read + std::io::Seek>(
    reader: &mut R,
    args: &Args,
    c: &Colors,
    fvek_keys: &[vmkatz::lsass::bitlocker::BitLockerKey],
    ntfs_only: bool,
) -> anyhow::Result<bool> {
    reader.seek(std::io::SeekFrom::Start(0))?;
    #[cfg(feature = "sam")]
    let secrets = {
        let result = if !fvek_keys.is_empty() {
            vmkatz::sam::extract_disk_secrets_from_reader_with_bitlocker(
                reader,
                fvek_keys,
                args.partition,
            )
        } else if ntfs_only {
            vmkatz::sam::extract_secrets_ntfs_only_scoped(reader, args.partition)
        } else {
            vmkatz::sam::extract_secrets_from_reader_scoped(reader, args.partition)
        };
        match result {
            Ok(secrets) => {
                print_disk_secrets(&secrets, args);
                Some(secrets)
            }
            Err(e) if args.partition.is_some() => return Err(e.into()),
            Err(e) => {
                eprintln!("[!] SAM extraction failed: {e}");
                None
            }
        }
    };
    #[cfg(not(feature = "sam"))]
    let secrets: Option<vmkatz::secrets::DiskSecrets> = {
        let _ = (fvek_keys, ntfs_only);
        None
    };
    let found = emit_disk_extras(reader, args, c, secrets.as_ref(), &[]);
    Ok(found || secrets.is_some())
}

#[cfg(feature = "ntds.dit")]
type NtdsStreamOutput = vmkatz::sam::NtdsReadResult<
    vmkatz::error::Result<(vmkatz::ntds::NtdsContext, Vec<vmkatz::ntds::AdHashEntry>)>,
>;

#[cfg(feature = "ntds.dit")]
fn read_ntds_stream<R: std::io::Read + std::io::Seek>(
    disk: &mut R,
    args: &Args,
    fvek_keys: &[vmkatz::lsass::bitlocker::BitLockerKey],
) -> vmkatz::error::Result<NtdsStreamOutput> {
    vmkatz::sam::with_ntds_bootkey(disk, args.partition, fvek_keys, |reader, boot_key| {
        // Keep parser failures fatal even when --all skips absent disk artifacts.
        vmkatz::ntds::extract_ad_hashes_with_bootkey(reader, *boot_key, args.ntds_history)
    })
}
