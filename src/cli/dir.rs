//! VM-directory pipelines: auto-discover and process every VM file in a folder.

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
#[cfg(all(
    feature = "ntds.dit",
    any(
        feature = "vmware",
        feature = "vbox",
        feature = "qemu",
        feature = "hyperv"
    )
))]
use super::disk::run_ntds;
#[cfg(feature = "sam")]
use super::disk::run_sam;
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
        if args.verbose > 0 {
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
        #[cfg(all(
            feature = "ntds.dit",
            any(
                feature = "vmware",
                feature = "vbox",
                feature = "qemu",
                feature = "hyperv"
            )
        ))]
        if args.ntds || args.all {
            if let Err(e) = run_ntds(file, args, &bitlocker_keys) {
                eprintln!("[!] {name}: {e:#}");
            }
            continue;
        }
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
