//! Select the input pipeline without mixing it with argument parsing or logging.
//!
//! Precedence matters: VMFS commands and directories come first, then raw file
//! combinations, then a single backup, disk image, or memory snapshot.

use std::path::{Path, PathBuf};

use clap::Parser;

use super::args::{Args, RawFileType, detect_file_type};
use super::{dir, lsass};

pub fn run(args: &Args) -> anyhow::Result<()> {
    // VMFS commands identify their source through options, without a FILE argument.
    #[cfg(feature = "vmfs")]
    {
        if args.vmfs_list {
            super::disk::run_vmfs_list(args.vmfs_device.as_deref());
            return Ok(());
        }
        if let Some(device) = &args.vmfs_device {
            return super::disk::run_vmfs(Path::new(device), args.vmdk.as_deref(), args);
        }
    }

    let Some(first_input) = args.input_paths.first() else {
        if std::env::args_os().nth(1).is_some() {
            anyhow::bail!("No input file provided. Supply an input path; see --help for examples.");
        }
        Args::parse_from(["vmkatz", "--help"]);
        std::process::exit(0)
    };

    let path = Path::new(first_input);
    if args.input_paths.len() == 1 && path.is_dir() {
        return if args.recurse {
            dir::run_recursive(path, args)
        } else {
            dir::run_directory(path, args)
        };
    }

    run_files(args)
}

/// Recognize raw NTDS/SYSTEM and SAM/SYSTEM combinations before single-file modes.
fn run_files(args: &Args) -> anyhow::Result<()> {
    let files: Vec<(PathBuf, RawFileType)> = args
        .input_paths
        .iter()
        .map(|input| (PathBuf::from(input), detect_file_type(Path::new(input))))
        .collect();

    #[cfg(feature = "sam")]
    {
        let hives: Vec<_> = files
            .iter()
            .filter(|(_, kind)| *kind == RawFileType::RegistryHive)
            .collect();

        #[cfg(feature = "ntds.dit")]
        {
            let databases: Vec<_> = files
                .iter()
                .filter(|(_, kind)| *kind == RawFileType::EseDatabase)
                .collect();
            if databases.len() == 1 && !hives.is_empty() {
                return super::disk::run_raw_ntds(&databases[0].0, &hives[0].0, args);
            }
        }

        if hives.len() >= 2 {
            return super::disk::run_raw_hives(&hives, args);
        }
    }

    let [(path, kind)] = files.as_slice() else {
        anyhow::bail!(
            "Could not auto-detect file types. Provide either:\n  \
             vmkatz ntds.dit SYSTEM          (NTDS + SYSTEM hive)\n  \
             vmkatz SAM SYSTEM [SECURITY]    (raw registry hives)\n  \
             vmkatz snapshot.vmsn            (VM memory snapshot)\n  \
             vmkatz disk.vmdk               (virtual disk image)"
        );
    };
    run_single_file(path, *kind, args)
}

fn run_single_file(path: &Path, kind: RawFileType, args: &Args) -> anyhow::Result<()> {
    match kind {
        RawFileType::EseDatabase => {
            anyhow::bail!(
                "NTDS.dit detected but no SYSTEM hive provided.\n\
                 Usage: vmkatz ntds.dit SYSTEM"
            );
        }
        RawFileType::RegistryHive => {
            anyhow::bail!(
                "Registry hive detected but at least SAM + SYSTEM are required.\n\
                 Usage: vmkatz SAM SYSTEM [SECURITY]"
            );
        }
        RawFileType::Minidump => return lsass::run_minidump(path, args),
        RawFileType::Other => {}
    }

    // Backups contain disk images but need their own reader to access them.
    #[cfg(feature = "veeam")]
    if vmkatz::veeam::is_veeam_path(path) {
        return super::disk::run_veeam(path, args);
    }

    #[cfg(feature = "disk")]
    if is_disk_input(path, args) {
        return run_disk_input(path, args);
    }

    run_snapshot_input(path, args)
}

#[cfg(feature = "disk")]
fn is_disk_input(path: &Path, args: &Args) -> bool {
    let block_device = super::args::is_block_dev(path);
    // Proxmox can store QEMU savevm states on block devices. Their magic takes
    // precedence over both the device type and explicit disk-mode options.
    #[cfg(feature = "qemu")]
    if block_device && vmkatz::qemu::is_qemu_savevm(path) {
        return false;
    }

    let extension = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
    let disk_extension = ["vdi", "vmdk", "qcow2", "qcow", "vhdx", "vhd"]
        .iter()
        .any(|known| extension.eq_ignore_ascii_case(known));
    args.requests_disk_mode() || disk_extension || block_device
}

#[cfg(feature = "disk")]
fn run_disk_input(path: &Path, args: &Args) -> anyhow::Result<()> {
    if args.lsass || args.all {
        #[cfg(any(
            feature = "vmware",
            feature = "vbox",
            feature = "qemu",
            feature = "hyperv"
        ))]
        super::disk::run_associated_lsass_for_disk(path, args)?;
        #[cfg(not(any(
            feature = "vmware",
            feature = "vbox",
            feature = "qemu",
            feature = "hyperv"
        )))]
        if args.lsass {
            anyhow::bail!("--lsass requires a memory snapshot backend feature");
        }
    }

    // Clap guarantees two values for --cp. Copy keeps precedence over listing.
    if let Some(copy) = &args.cp {
        let mut disk = vmkatz::disk::open_disk(path)?;
        return super::disk::run_cp(&mut disk, &copy[0], &copy[1], args.partition);
    }
    if let Some(guest_path) = &args.ls {
        let mut disk = vmkatz::disk::open_disk(path)?;
        return super::disk::run_ls(&mut disk, guest_path, args.partition);
    }

    super::disk::run_disk(path, args)
}

fn run_snapshot_input(path: &Path, args: &Args) -> anyhow::Result<()> {
    #[cfg(feature = "disk")]
    {
        let disk_path = args.disk.as_deref();
        let pagefile = disk_path.and_then(|disk| {
            match vmkatz::paging::pagefile::PagefileReader::open(Path::new(disk)) {
                Ok(pagefile) => {
                    eprintln!(
                        "[+] Pagefile: {:.1} MB",
                        pagefile.pagefile_size() as f64 / (1024.0 * 1024.0),
                    );
                    Some(pagefile)
                }
                Err(error) => {
                    log::info!("No pagefile from {disk}: {error}");
                    None
                }
            }
        });
        lsass::run_lsass(path, args, pagefile.as_ref(), disk_path.map(Path::new))
    }
    #[cfg(not(feature = "disk"))]
    lsass::run_lsass(path, args, (), ())
}
