//! Entry points for LSASS minidumps and memory snapshots.

use std::path::Path;

use anyhow::Context;
use vmkatz::lsass;
use vmkatz::lsass::finder::PagefileRef;

use super::args::Args;
use super::output::{export_kerberos_tickets, output_credentials};

#[cfg(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv"
))]
mod bitlocker;
#[cfg(all(
    feature = "chrome",
    any(
        feature = "vmware",
        feature = "vbox",
        feature = "qemu",
        feature = "hyperv"
    )
))]
mod chrome;
#[cfg(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv"
))]
mod pipeline;
#[cfg(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv"
))]
mod snapshot;

#[cfg(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv"
))]
use pipeline::run_with_layer;
#[cfg(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv"
))]
use snapshot::{SnapshotFormat, detect_snapshot_format};

#[cfg(all(
    feature = "sam",
    any(
        feature = "vmware",
        feature = "vbox",
        feature = "qemu",
        feature = "hyperv"
    )
))]
pub(crate) use bitlocker::extract_bitlocker_keys_from_snapshot;

/// Handle LSASS minidump files.
pub(crate) fn run_minidump(input_path: &Path, args: &Args) -> anyhow::Result<()> {
    if args.verbose > 0 {
        eprintln!("[*] Parsing LSASS minidump: {}", input_path.display());
    }

    let mdmp = vmkatz::minidump::Minidump::open(input_path).context("Failed to parse minidump")?;

    if args.verbose > 0 {
        eprintln!(
            "[+] Minidump: {} memory regions, {} modules, Windows {}.{} build {} ({:?})",
            mdmp.region_count(),
            mdmp.modules.len(),
            mdmp.major_version,
            mdmp.minor_version,
            mdmp.build_number,
            mdmp.arch,
        );
        for m in &mdmp.modules {
            eprintln!("    0x{:016x} ({:8} bytes) {}", m.base, m.size, m.base_name);
        }
    }

    let region_ranges = mdmp.region_ranges();
    let credentials = lsass::finder::extract_credentials_from_minidump(
        &mdmp,
        &mdmp.modules,
        mdmp.build_number,
        &region_ranges,
        mdmp.arch,
    )
    .context("Credential extraction from minidump failed")?;

    export_kerberos_tickets(&credentials, args);

    output_credentials(&credentials, args);

    Ok(())
}

pub(crate) fn run_lsass(
    input_path: &Path,
    args: &Args,
    pagefile: PagefileRef<'_>,
    disk_path: vmkatz::lsass::finder::DiskPathRef<'_>,
) -> anyhow::Result<()> {
    #[cfg(not(any(
        feature = "vmware",
        feature = "vbox",
        feature = "qemu",
        feature = "hyperv"
    )))]
    {
        let _ = (input_path, args, pagefile, disk_path);
        anyhow::bail!(
            "No hypervisor support compiled in (rebuild with --features vmware,vbox,qemu,hyperv)"
        );
    }

    #[cfg(any(
        feature = "vmware",
        feature = "vbox",
        feature = "qemu",
        feature = "hyperv"
    ))]
    {
        let verbose = args.verbose > 0 || args.list_processes;
        let ext = input_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        let format = detect_snapshot_format(input_path, ext, args.carve);

        match format {
            SnapshotFormat::VBox => {
                #[cfg(feature = "vbox")]
                {
                    run_with_layer(
                        || snapshot::vbox(input_path, verbose),
                        args,
                        verbose,
                        pagefile,
                        disk_path,
                    )
                }
                #[cfg(not(feature = "vbox"))]
                {
                    let _ = (pagefile, disk_path);
                    anyhow::bail!(
                        "VirtualBox .sav support not enabled (compile with --features vbox)"
                    )
                }
            }
            SnapshotFormat::QemuElf => {
                #[cfg(feature = "qemu")]
                {
                    run_with_layer(
                        || snapshot::qemu_elf(input_path, verbose),
                        args,
                        verbose,
                        pagefile,
                        disk_path,
                    )
                }
                #[cfg(not(feature = "qemu"))]
                {
                    let _ = (pagefile, disk_path);
                    anyhow::bail!("QEMU ELF support not enabled (compile with --features qemu)")
                }
            }
            #[cfg(feature = "qemu")]
            SnapshotFormat::QemuSavevm => run_with_layer(
                || snapshot::qemu_savevm(input_path, verbose),
                args,
                verbose,
                pagefile,
                disk_path,
            ),
            SnapshotFormat::HypervBin => {
                #[cfg(feature = "hyperv")]
                {
                    run_with_layer(
                        || snapshot::hyperv_bin(input_path, verbose),
                        args,
                        verbose,
                        pagefile,
                        disk_path,
                    )
                }
                #[cfg(not(feature = "hyperv"))]
                {
                    let _ = (pagefile, disk_path);
                    anyhow::bail!("Hyper-V support not enabled (compile with --features hyperv)")
                }
            }
            SnapshotFormat::HypervVmrs => {
                #[cfg(feature = "hyperv")]
                {
                    run_with_layer(
                        || snapshot::hyperv_vmrs(input_path, verbose),
                        args,
                        verbose,
                        pagefile,
                        disk_path,
                    )
                }
                #[cfg(not(feature = "hyperv"))]
                {
                    let _ = (pagefile, disk_path);
                    anyhow::bail!("Hyper-V support not enabled (compile with --features hyperv)")
                }
            }
            SnapshotFormat::Vmware => {
                #[cfg(feature = "vmware")]
                {
                    run_with_layer(
                        || snapshot::vmware(input_path, verbose),
                        args,
                        verbose,
                        pagefile,
                        disk_path,
                    )
                }
                #[cfg(not(feature = "vmware"))]
                {
                    let _ = (pagefile, disk_path);
                    anyhow::bail!(
                        "VMware .vmem/.vmsn support not enabled (compile with --features vmware)"
                    )
                }
            }
            SnapshotFormat::UnsupportedDisk => {
                let _ = (pagefile, disk_path);
                anyhow::bail!(
                    "{} is a disk image, not a memory snapshot. Use --sam for SAM hash extraction, \
                 or provide a memory snapshot (.vmsn, .vmem, .sav, .elf, .bin)",
                    input_path.display()
                )
            }
        }
    } // cfg(any hypervisor)
}
