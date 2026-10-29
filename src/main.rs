#[cfg(not(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv",
    feature = "sam"
)))]
compile_error!(
    "At least one backend must be enabled: --features vmware, vbox, qemu, hyperv, and/or sam"
);

pub mod cli;

use std::path::Path;

use clap::Parser;

#[cfg(feature = "sam")]
use cli::is_block_dev;
#[cfg(feature = "ntds.dit")]
use cli::run_raw_ntds;
#[cfg(feature = "veeam")]
use cli::run_veeam;
use cli::{
    Args, RawFileType, detect_file_type, run_directory, run_lsass, run_minidump, run_recursive,
};
#[cfg(feature = "sam")]
use cli::{run_raw_hives, run_sam};
#[cfg(feature = "vmfs")]
use cli::{run_vmfs, run_vmfs_list};

/// Minimal logger (replaces `env_logger` — saves ~300KB from regex/jiff deps)
struct SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            eprintln!(
                "[{:<5} {}] {}",
                record.level(),
                record.target(),
                record.args()
            );
        }
    }

    fn flush(&self) {}
}

fn main() -> anyhow::Result<()> {
    // ESXi's BusyBox shell sets a 512KB stack limit (vs 8MB on standard Linux).
    // The deep call chain run_lsass → run_with_layer → find_system_process →
    // EPT scan + process walk + credential extraction overflows 512KB when
    // processing multiple large VM snapshots sequentially.
    // Spawn on a thread with the standard Linux 8MB stack to avoid this.
    const STACK_SIZE: usize = 8 * 1024 * 1024;
    let builder = std::thread::Builder::new().stack_size(STACK_SIZE);
    let handler = builder
        .spawn(vmkatz_main)
        .expect("failed to spawn main thread");
    handler.join().unwrap()
}

fn vmkatz_main() -> anyhow::Result<()> {
    // Show full help (not just error) when no arguments provided
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(e) if e.kind() == clap::error::ErrorKind::MissingRequiredArgument => {
            Args::parse_from(["vmkatz", "--help"]);
            unreachable!()
        }
        Err(e) => e.exit(),
    };
    let log_level = match args.verbose {
        0 => log::LevelFilter::Warn,
        1 => log::LevelFilter::Info,
        _ => log::LevelFilter::Debug,
    };
    log::set_logger(&SimpleLogger).unwrap();
    log::set_max_level(log_level);

    eprintln!("[*] vmkatz v{}", env!("CARGO_PKG_VERSION"));

    // VMFS-6 raw device mode: read flat VMDKs directly from SCSI device
    #[cfg(feature = "vmfs")]
    {
        if args.vmfs_list {
            run_vmfs_list(args.vmfs_device.as_deref());
            return Ok(());
        }
        if let Some(ref vmfs_device) = args.vmfs_device {
            return run_vmfs(Path::new(vmfs_device), args.vmdk.as_deref(), &args);
        }
    }

    if args.input_paths.is_empty() {
        Args::parse_from(["vmkatz", "--help"]);
        unreachable!()
    }

    let input_path = Path::new(&args.input_paths[0]);

    // Directory mode: auto-discover and process all VM files
    if args.input_paths.len() == 1 && input_path.is_dir() {
        if args.recurse {
            return run_recursive(input_path, &args);
        }
        return run_directory(input_path, &args);
    }

    // Multi-file mode or single raw file: classify by magic bytes
    let file_types: Vec<(std::path::PathBuf, RawFileType)> = args
        .input_paths
        .iter()
        .map(|p| (std::path::PathBuf::from(p), detect_file_type(Path::new(p))))
        .collect();

    // Classify files by type for raw file modes
    #[cfg(feature = "sam")]
    {
        let hive_files: Vec<_> = file_types
            .iter()
            .filter(|(_, t)| *t == RawFileType::RegistryHive)
            .collect();

        // Raw NTDS.dit + SYSTEM hive
        #[cfg(feature = "ntds.dit")]
        {
            let ese_files: Vec<_> = file_types
                .iter()
                .filter(|(_, t)| *t == RawFileType::EseDatabase)
                .collect();
            if ese_files.len() == 1 && !hive_files.is_empty() {
                return run_raw_ntds(&ese_files[0].0, &hive_files[0].0, &args);
            }
        }

        // Raw registry hives (SAM + SYSTEM [+ SECURITY])
        if hive_files.len() >= 2 {
            return run_raw_hives(&hive_files, &args);
        }
    }

    // Single raw file with helpful error messages
    if args.input_paths.len() == 1 {
        match file_types[0].1 {
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
            RawFileType::Minidump => {
                return run_minidump(input_path, &args);
            }
            RawFileType::Other => {} // fall through to existing logic
        }
    }

    // Existing single-file logic: disk images, VM snapshots, block devices
    if args.input_paths.len() != 1 {
        anyhow::bail!(
            "Could not auto-detect file types. Provide either:\n  \
             vmkatz ntds.dit SYSTEM          (NTDS + SYSTEM hive)\n  \
             vmkatz SAM SYSTEM [SECURITY]    (raw registry hives)\n  \
             vmkatz snapshot.vmsn            (VM memory snapshot)\n  \
             vmkatz disk.vmdk               (virtual disk image)"
        );
    }

    // Veeam backup containers: enumerate stored disk images and run the disk
    // credential pipeline on each (before SAM auto-detect, which can't open them).
    #[cfg(feature = "veeam")]
    {
        if vmkatz::veeam::is_veeam_path(input_path) {
            return run_veeam(input_path, &args);
        }
    }

    // Auto-detect SAM mode for disk images / block devices, or explicit --sam flag
    #[cfg(feature = "sam")]
    {
        let ext = input_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        let is_disk_ext = ext.eq_ignore_ascii_case("vdi")
            || ext.eq_ignore_ascii_case("vmdk")
            || ext.eq_ignore_ascii_case("qcow2")
            || ext.eq_ignore_ascii_case("qcow")
            || ext.eq_ignore_ascii_case("vhdx")
            || ext.eq_ignore_ascii_case("vhd");
        let is_block_device = is_block_dev(input_path);
        // Block devices may be QEMU savevm states (LVM snapshots on Proxmox) —
        // check magic before assuming SAM/disk mode.
        let is_memory_snapshot = is_block_device && {
            #[cfg(feature = "qemu")]
            {
                vmkatz::qemu::is_qemu_savevm(input_path)
            }
            #[cfg(not(feature = "qemu"))]
            {
                false
            }
        };
        #[cfg(feature = "ntds.dit")]
        let sam_mode =
            (args.sam || args.ntds || is_disk_ext || is_block_device) && !is_memory_snapshot;
        #[cfg(not(feature = "ntds.dit"))]
        let sam_mode = (args.sam || is_disk_ext || is_block_device) && !is_memory_snapshot;
        if sam_mode {
            if let Some(cp) = &args.cp {
                let mut disk = vmkatz::disk::open_disk(input_path)?;
                return cli::disk::run_cp(&mut disk, &cp[0], &cp[1], args.partition);
            }
            if let Some(ref ls_path) = args.ls {
                let mut disk = vmkatz::disk::open_disk(input_path)?;
                return cli::disk::run_ls(&mut disk, ls_path, args.partition);
            }
            return run_sam(input_path, &args);
        }
    }

    // LSASS credential extraction mode
    #[cfg(feature = "sam")]
    {
        let disk_path_str = args.disk.as_deref();
        let pagefile_reader = disk_path_str.and_then(|d| {
            match vmkatz::paging::pagefile::PagefileReader::open(Path::new(d)) {
                Ok(pf) => {
                    eprintln!(
                        "[+] Pagefile: {:.1} MB",
                        pf.pagefile_size() as f64 / (1024.0 * 1024.0),
                    );
                    Some(pf)
                }
                Err(e) => {
                    log::info!("No pagefile from {d}: {e}");
                    None
                }
            }
        });
        let disk_ref = disk_path_str.map(Path::new);
        run_lsass(input_path, &args, pagefile_reader.as_ref(), disk_ref)
    }
    #[cfg(not(feature = "sam"))]
    run_lsass(input_path, &args, (), ())
}
