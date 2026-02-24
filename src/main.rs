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

use std::path::Path;

use anyhow::Context;
use clap::Parser;

#[cfg(feature = "hyperv")]
use vmkatz::hyperv::HypervLayer;
#[cfg(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv"
))]
use vmkatz::lsass;
use vmkatz::lsass::finder::PagefileRef;
#[cfg(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv"
))]
use vmkatz::lsass::types::Credential;
#[cfg(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv"
))]
use vmkatz::memory::PhysicalMemory;
#[cfg(feature = "qemu")]
use vmkatz::qemu::QemuElfLayer;
#[cfg(feature = "vbox")]
use vmkatz::vbox::VBoxLayer;
#[cfg(feature = "vmware")]
use vmkatz::vmware::VmwareLayer;
// EPROCESS offsets auto-detected at runtime from ALL_EPROCESS_OFFSETS
#[cfg(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv"
))]
use vmkatz::windows::process;

#[derive(Parser, Debug)]
#[command(
    name = "vmkatz",
    version,
    about = "VM memory forensics - extract credentials from VMware/VirtualBox/QEMU/Hyper-V snapshots and disk images",
    long_about = "vmkatz extracts Windows credentials from virtual machine memory snapshots and disk images.\n\n\
        Supported inputs:\n  \
        - VMware snapshots (.vmsn + .vmem)\n  \
        - VirtualBox saved states (.sav)\n  \
        - QEMU/KVM/Proxmox ELF core dumps (.elf, from dump-guest-memory / virsh dump)\n  \
        - Hyper-V legacy saved states (.bin) and raw memory dumps (.raw, .dmp)\n  \
        - Disk images for SAM hashes (.vdi, .vmdk, .qcow2, .vhdx, .vhd)\n  \
        - VM directories (auto-discovers all files)\n\n\
        Target: Windows 7 SP1 through Windows 11 x64",
    after_help = "EXAMPLES:\n  \
        vmkatz snapshot.vmsn                        Extract LSASS credentials\n  \
        vmkatz --format ntlm snapshot.vmsn          Output as NTLM hashes\n  \
        vmkatz --disk disk.vmdk snapshot.vmsn       Resolve paged-out creds from disk\n  \
        vmkatz disk.vdi                             Extract SAM hashes + LSA secrets\n  \
        vmkatz /path/to/vm/directory/               Auto-discover and process all files\n  \
        vmkatz --list-processes snapshot.vmsn        List running processes only\n  \
        vmkatz --dump lsass snapshot.vmsn           Dump LSASS as minidump for pypykatz\n  \
        vmkatz --dump lsass -o out.dmp snap.vmsn    Dump with custom output filename\n  \
        vmkatz -v snapshot.vmsn                     Verbose output with process list"
)]
struct Args {
    /// Path to a snapshot, disk image, or VM directory
    #[arg(value_name = "FILE_OR_DIR")]
    input_path: String,

    /// Only list processes (skip credential extraction)
    #[arg(long, default_value_t = false)]
    list_processes: bool,

    /// Force SAM hash extraction mode (auto-detected for .vdi/.vmdk/.qcow2/.vhdx/.vhd)
    #[cfg(feature = "sam")]
    #[arg(long, default_value_t = false)]
    sam: bool,

    /// Try NTDS.dit extraction workflow (Windows/NTDS/ntds.dit + SYSTEM bootkey)
    #[cfg(feature = "ntds.dit")]
    #[arg(long, default_value_t = false)]
    ntds: bool,

    /// Include NTDS password history hashes (when available)
    #[cfg(feature = "ntds.dit")]
    #[arg(long, default_value_t = false)]
    ntds_history: bool,

    /// Disk image for pagefile.sys resolution (resolves paged-out memory from disk)
    #[cfg(feature = "sam")]
    #[arg(long, value_name = "DISK_IMAGE")]
    disk: Option<String>,

    /// Dump a process's virtual memory as minidump (.dmp) file
    #[arg(long, value_name = "PROCESS_NAME")]
    dump: Option<String>,

    /// Output file for --dump (default: <process>.dmp)
    #[arg(short, long, value_name = "FILE")]
    output: Option<String>,

    /// Windows build number for minidump header (default: 19045)
    #[arg(long, default_value_t = 19045, value_name = "NUMBER")]
    build: u32,

    /// Output format
    #[arg(long, default_value = "text", value_name = "FORMAT", value_parser = ["text", "csv", "ntlm", "hashcat"])]
    format: String,

    /// Verbose output (show memory regions, process list, etc.)
    #[arg(short, long, default_value_t = false)]
    verbose: bool,
}

fn main() -> anyhow::Result<()> {
    // Show full help (not just error) when no arguments provided
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(e) if e.kind() == clap::error::ErrorKind::MissingRequiredArgument => {
            Args::parse_from(["vmkatz", "--help"]);
            unreachable!()
        }
        Err(e) => e.exit(),
    };
    let log_level = if args.verbose { "info" } else { "warn" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level))
        .format_timestamp(None)
        .init();

    let input_path = Path::new(&args.input_path);

    // Directory mode: auto-discover and process all VM files
    if input_path.is_dir() {
        return run_directory(input_path, &args);
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
        #[cfg(feature = "ntds.dit")]
        let sam_mode = args.sam || args.ntds || is_disk_ext || is_block_device;
        #[cfg(not(feature = "ntds.dit"))]
        let sam_mode = args.sam || is_disk_ext || is_block_device;
        if sam_mode {
            return run_sam(input_path, &args);
        }
    }

    // LSASS credential extraction mode
    #[cfg(feature = "sam")]
    {
        let disk_path_str = args.disk.clone();
        let pagefile_reader =
            disk_path_str.as_ref().and_then(
                |d| match vmkatz::paging::pagefile::PagefileReader::open(Path::new(d)) {
                    Ok(pf) => {
                        println!(
                            "[+] Pagefile: {:.1} MB",
                            pf.pagefile_size() as f64 / (1024.0 * 1024.0),
                        );
                        Some(pf)
                    }
                    Err(e) => {
                        log::info!("No pagefile from {}: {}", d, e);
                        None
                    }
                },
            );
        let disk_ref = disk_path_str.as_ref().map(|d| Path::new(d.as_str()));
        run_lsass(input_path, &args, pagefile_reader.as_ref(), disk_ref)
    }
    #[cfg(not(feature = "sam"))]
    run_lsass(input_path, &args, Default::default(), Default::default())
}

#[cfg(feature = "sam")]
fn run_sam(input_path: &Path, args: &Args) -> anyhow::Result<()> {
    #[cfg(feature = "ntds.dit")]
    {
        if args.ntds {
            return run_ntds(input_path, args);
        }
    }

    if args.verbose {
        println!("[*] SAM hash extraction from: {}", input_path.display());
    }

    let secrets =
        vmkatz::sam::extract_disk_secrets(input_path).context("Disk secrets extraction failed")?;

    match args.format.as_str() {
        "ntlm" => print_sam_ntlm(&secrets.sam_entries),
        "csv" => print_sam_csv(&secrets.sam_entries),
        "hashcat" => print_sam_hashcat(&secrets.sam_entries),
        _ => print_sam_text(&secrets.sam_entries),
    }

    if !secrets.lsa_secrets.is_empty() && args.format != "hashcat" {
        print_lsa_secrets(&secrets.lsa_secrets);
    }

    if !secrets.cached_credentials.is_empty() {
        match args.format.as_str() {
            "hashcat" => print_dcc2_hashcat(&secrets.cached_credentials),
            _ => print_cached_credentials(&secrets.cached_credentials),
        }
    }

    Ok(())
}

#[cfg(feature = "ntds.dit")]
fn run_ntds(input_path: &Path, args: &Args) -> anyhow::Result<()> {
    if args.verbose {
        println!("[*] NTDS extraction from: {}", input_path.display());
    }

    let artifacts = vmkatz::sam::extract_ntds_artifacts(input_path)
        .context("NTDS artifact extraction failed")?;
    let ctx = vmkatz::sam::ntds::build_context(&artifacts.ntds_data, &artifacts.system_data)
        .context("NTDS context validation failed")?;
    let hashes = vmkatz::sam::ntds::extract_ad_hashes(
        &artifacts.ntds_data,
        &artifacts.system_data,
        args.ntds_history,
    )
    .context("NTDS hash extraction failed")?;

    println!("\n[+] NTDS Artifacts:");
    println!("  Partition offset : 0x{:x}", artifacts.partition_offset);
    println!("  ntds.dit size    : {} bytes", ctx.ntds_size);
    println!("  SYSTEM size      : {} bytes", artifacts.system_data.len());
    println!("  Bootkey          : {}", hex::encode(ctx.boot_key));
    println!("  Hashes extracted : {}", hashes.len());

    match args.format.as_str() {
        "csv" => print_ntds_csv(&hashes),
        "hashcat" => print_ntds_hashcat(&hashes),
        "ntlm" => print_ntds_ntlm(&hashes),
        _ => print_ntds_text(&hashes),
    }

    Ok(())
}

#[cfg(feature = "ntds.dit")]
fn print_ntds_text(entries: &[vmkatz::sam::ntds::AdHashEntry]) {
    println!("\n[+] AD NTLM Hashes:");
    for entry in entries {
        let hist = if entry.is_history {
            match entry.history_index {
                Some(idx) => format!("history{}", idx),
                None => "history".to_string(),
            }
        } else {
            "current".to_string()
        };
        println!(
            "  RID: {:<6} {:<24} {:<10} NT:{}  LM:{}",
            entry.rid,
            entry.username,
            hist,
            hex::encode(entry.nt_hash),
            hex::encode(entry.lm_hash),
        );
    }
}

#[cfg(feature = "ntds.dit")]
fn print_ntds_ntlm(entries: &[vmkatz::sam::ntds::AdHashEntry]) {
    for entry in entries {
        let user = if entry.is_history {
            match entry.history_index {
                Some(idx) => format!("{}_history{}", entry.username, idx),
                None => format!("{}_history", entry.username),
            }
        } else {
            entry.username.clone()
        };

        println!(
            "{}:{}:{}:{}:::",
            user,
            entry.rid,
            hex::encode(entry.lm_hash),
            hex::encode(entry.nt_hash),
        );
    }
}

#[cfg(feature = "ntds.dit")]
fn print_ntds_csv(entries: &[vmkatz::sam::ntds::AdHashEntry]) {
    println!("rid,username,is_history,history_index,nt_hash,lm_hash");
    for entry in entries {
        let history_index = entry
            .history_index
            .map(|v| v.to_string())
            .unwrap_or_default();
        println!(
            "{},{},{},{},{},{}",
            entry.rid,
            entry.username,
            entry.is_history,
            history_index,
            hex::encode(entry.nt_hash),
            hex::encode(entry.lm_hash),
        );
    }
}

#[cfg(feature = "ntds.dit")]
fn print_ntds_hashcat(entries: &[vmkatz::sam::ntds::AdHashEntry]) {
    let zero_hash = [0u8; 16];
    for entry in entries {
        if entry.nt_hash != zero_hash {
            println!("{}", hex::encode(entry.nt_hash));
        }
    }
}

#[cfg(feature = "sam")]
fn print_sam_text(entries: &[vmkatz::sam::SamEntry]) {
    println!("\n[+] SAM Hashes:");
    for entry in entries {
        println!(
            "  RID: {:<5} {:<20} NT:{}  LM:{}",
            entry.rid,
            entry.username,
            hex::encode(entry.nt_hash),
            hex::encode(entry.lm_hash),
        );
    }
}

#[cfg(feature = "sam")]
fn print_sam_ntlm(entries: &[vmkatz::sam::SamEntry]) {
    for entry in entries {
        println!(
            "{}:{}:{}:{}:::",
            entry.username,
            entry.rid,
            hex::encode(entry.lm_hash),
            hex::encode(entry.nt_hash),
        );
    }
}

#[cfg(feature = "sam")]
fn print_sam_csv(entries: &[vmkatz::sam::SamEntry]) {
    println!("rid,username,nt_hash,lm_hash");
    for entry in entries {
        println!(
            "{},{},{},{}",
            entry.rid,
            entry.username,
            hex::encode(entry.nt_hash),
            hex::encode(entry.lm_hash),
        );
    }
}

#[cfg(feature = "sam")]
fn print_sam_hashcat(entries: &[vmkatz::sam::SamEntry]) {
    let zero_hash = [0u8; 16];
    for entry in entries {
        if entry.nt_hash != zero_hash {
            // hashcat mode 1000 (NTLM)
            println!("{}", hex::encode(entry.nt_hash));
        }
    }
}

#[cfg(feature = "sam")]
fn print_dcc2_hashcat(creds: &[vmkatz::sam::cache::CachedCredential]) {
    for cred in creds {
        // hashcat mode 2100 (DCC2)
        println!(
            "$DCC2${}#{}#{}",
            cred.iteration_count,
            cred.username.to_lowercase(),
            hex::encode(cred.dcc2_hash),
        );
    }
}

#[cfg(feature = "sam")]
fn print_lsa_secrets(secrets: &[vmkatz::sam::lsa::LsaSecret]) {
    println!("\n[+] LSA Secrets:");
    for secret in secrets {
        println!("{}", secret);
    }
}

#[cfg(feature = "sam")]
fn print_cached_credentials(creds: &[vmkatz::sam::cache::CachedCredential]) {
    println!("\n[+] Domain Cached Credentials (DCC2):");
    for cred in creds {
        println!("{}", cred);
    }
}

fn run_directory(dir: &Path, args: &Args) -> anyhow::Result<()> {
    let discovery = vmkatz::discover::discover_vm_files(dir).context("VM file discovery failed")?;

    println!(
        "[*] Found {} LSASS snapshot(s), {} disk image(s) in: {}",
        discovery.lsass_files.len(),
        discovery.disk_files.len(),
        dir.display()
    );

    if discovery.lsass_files.is_empty() && discovery.disk_files.is_empty() {
        println!("[!] No processable VM files found in directory");
        return Ok(());
    }

    // Try to open pagefile.sys from the first available disk image
    #[cfg(feature = "sam")]
    let pagefile_reader = if !discovery.lsass_files.is_empty() {
        discovery.disk_files.first().and_then(|d| {
            match vmkatz::paging::pagefile::PagefileReader::open(d) {
                Ok(pf) => {
                    println!(
                        "[+] Pagefile: {:.1} MB from {}",
                        pf.pagefile_size() as f64 / (1024.0 * 1024.0),
                        d.file_name().unwrap_or_default().to_string_lossy()
                    );
                    Some(pf)
                }
                Err(e) => {
                    log::info!("No pagefile from disk: {}", e);
                    None
                }
            }
        })
    } else {
        None
    };

    #[cfg(feature = "sam")]
    let pagefile: PagefileRef<'_> = pagefile_reader.as_ref();
    #[cfg(not(feature = "sam"))]
    let pagefile: PagefileRef<'_> = Default::default();

    // Disk path for file-backed DLL resolution
    #[cfg(feature = "sam")]
    let disk_path: vmkatz::lsass::finder::DiskPathRef<'_> =
        discovery.disk_files.first().map(|p| p.as_path());
    #[cfg(not(feature = "sam"))]
    let disk_path: vmkatz::lsass::finder::DiskPathRef<'_> = Default::default();

    #[cfg(any(
        feature = "vmware",
        feature = "vbox",
        feature = "qemu",
        feature = "hyperv"
    ))]
    for file in &discovery.lsass_files {
        let name = file.file_name().unwrap_or_default().to_string_lossy();
        println!("\n[*] LSASS: {}", name);
        if let Err(e) = run_lsass(file, args, pagefile, disk_path) {
            eprintln!("[!] {}: {}", name, e);
        }
    }

    #[cfg(feature = "sam")]
    for file in &discovery.disk_files {
        let name = file.file_name().unwrap_or_default().to_string_lossy();
        println!("\n[*] SAM: {}", name);
        if let Err(e) = run_sam(file, args) {
            eprintln!("[!] {}: {:#}", name, e);
        }
    }

    #[cfg(not(feature = "sam"))]
    if !discovery.disk_files.is_empty() {
        eprintln!("[!] {} disk image(s) found but SAM support not compiled in (rebuild with --features sam)", discovery.disk_files.len());
    }

    Ok(())
}

fn run_lsass(
    input_path: &Path,
    args: &Args,
    pagefile: PagefileRef<'_>,
    disk_path: vmkatz::lsass::finder::DiskPathRef<'_>,
) -> anyhow::Result<()> {
    let verbose = args.verbose || args.list_processes;
    let ext = input_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    // Detect format by extension and magic bytes
    let format = detect_lsass_format(input_path, ext);

    match format {
        LsassFormat::VBox => {
            #[cfg(feature = "vbox")]
            {
                run_with_layer(
                    || {
                        if verbose {
                            println!(
                                "[*] Opening VirtualBox saved state: {}",
                                input_path.display()
                            );
                        }
                        let layer = VBoxLayer::open(input_path)
                            .context("Failed to open VirtualBox .sav file")?;
                        if verbose {
                            println!(
                                "[+] RAM: {} MB ({} pages mapped)",
                                layer.phys_size() / (1024 * 1024),
                                layer.page_count()
                            );
                        }
                        Ok(layer)
                    },
                    args,
                    verbose,
                    pagefile,
                    disk_path,
                )
            }
            #[cfg(not(feature = "vbox"))]
            {
                let _ = (pagefile, disk_path);
                anyhow::bail!("VirtualBox .sav support not enabled (compile with --features vbox)")
            }
        }
        LsassFormat::QemuElf => {
            #[cfg(feature = "qemu")]
            {
                run_with_layer(
                    || {
                        if verbose {
                            println!("[*] Opening QEMU ELF core dump: {}", input_path.display());
                        }
                        let layer = QemuElfLayer::open(input_path)
                            .context("Failed to open QEMU ELF core dump")?;
                        if verbose {
                            println!(
                                "[+] ELF: {} MB physical, {} PT_LOAD segments",
                                layer.phys_size() / (1024 * 1024),
                                layer.segment_count()
                            );
                        }
                        Ok(layer)
                    },
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
        LsassFormat::HypervBin => {
            #[cfg(feature = "hyperv")]
            {
                run_with_layer(
                    || {
                        if verbose {
                            println!("[*] Opening Hyper-V memory dump: {}", input_path.display());
                        }
                        let layer = HypervLayer::open(input_path)
                            .context("Failed to open Hyper-V .bin memory dump")?;
                        if verbose {
                            println!(
                                "[+] RAM: {} MB identity-mapped",
                                layer.phys_size() / (1024 * 1024)
                            );
                        }
                        Ok(layer)
                    },
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
        LsassFormat::Vmware => {
            #[cfg(feature = "vmware")]
            {
                run_with_layer(
                    || {
                        if verbose {
                            println!("[*] Opening VMware memory dump: {}", input_path.display());
                        }
                        let layer = VmwareLayer::open(input_path)
                            .context("Failed to open VMware memory dump")?;
                        if verbose {
                            println!("[+] VMEM mapped: {} MB", layer.phys_size() / (1024 * 1024));
                            println!("[+] Memory regions: {}", layer.regions.len());
                            for (i, region) in layer.regions.iter().enumerate() {
                                println!(
                                    "    Region {}: guest=0x{:x} vmem=0x{:x} pages=0x{:x} ({}MB)",
                                    i,
                                    region.guest_page_num,
                                    region.vmem_page_num,
                                    region.page_count,
                                    (region.page_count * 0x1000) / (1024 * 1024)
                                );
                            }
                        }
                        Ok(layer)
                    },
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
    }
}

/// Check if a path is a block device (Linux /dev/...).
fn is_block_dev(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        std::fs::metadata(path)
            .map(|m| m.file_type().is_block_device())
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

/// Format detection for LSASS memory snapshot files.
enum LsassFormat {
    VBox,
    QemuElf,
    HypervBin,
    Vmware,
}

/// Detect the memory snapshot format from extension and magic bytes.
fn detect_lsass_format(path: &Path, ext: &str) -> LsassFormat {
    // Extension-based detection first
    if ext.eq_ignore_ascii_case("sav") {
        return LsassFormat::VBox;
    }
    if ext.eq_ignore_ascii_case("elf") {
        return LsassFormat::QemuElf;
    }
    if ext.eq_ignore_ascii_case("bin") {
        // Could be Hyper-V .bin or a raw dump — check for ELF magic
        if has_elf_magic(path) {
            return LsassFormat::QemuElf;
        }
        return LsassFormat::HypervBin;
    }
    if ext.eq_ignore_ascii_case("raw") {
        // Raw memory dump — check for ELF magic (virsh dump can produce .raw)
        if has_elf_magic(path) {
            return LsassFormat::QemuElf;
        }
        return LsassFormat::HypervBin;
    }

    // For unknown extensions, try magic-based detection
    if has_elf_magic(path) {
        return LsassFormat::QemuElf;
    }

    // Default: VMware (.vmem, .vmsn, or anything else)
    LsassFormat::Vmware
}

/// Check if file starts with ELF magic bytes (reads only 4 bytes).
fn has_elf_magic(path: &Path) -> bool {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic).is_ok() && magic == [0x7f, b'E', b'L', b'F']
}

#[cfg(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv"
))]
fn run_with_layer<L: PhysicalMemory, F: FnOnce() -> anyhow::Result<L>>(
    make_layer: F,
    args: &Args,
    verbose: bool,
    pagefile: PagefileRef<'_>,
    disk_path: vmkatz::lsass::finder::DiskPathRef<'_>,
) -> anyhow::Result<()> {
    let layer = make_layer()?;

    // Find System process (auto-detect Windows version from EPROCESS layout)
    match process::find_system_process_auto(&layer) {
        Ok((system, eprocess_offsets)) => run_with_system(
            &layer,
            &system,
            &eprocess_offsets,
            args,
            verbose,
            pagefile,
            disk_path,
        ),
        Err(_) => {
            // EPT fallback: try to find nested hypervisor page tables (VBS/Hyper-V)
            log::info!("System process not found in L1 physical memory, trying EPT scan...");
            println!("[*] VBS detected: scanning for nested EPT...");

            let candidates = vmkatz::paging::ept::find_ept_candidates(&layer)
                .context("Failed to find System process (no EPT found — VBS not supported for this snapshot)")?;

            // Try each EPT candidate (ranked by non-zero translated pages)
            let mut last_err = None;
            for (i, candidate) in candidates.iter().enumerate() {
                println!(
                    "[*] Trying EPT #{} at L1=0x{:x} ({}/{} non-zero pages, {} PML4E)",
                    i + 1,
                    candidate.pml4_addr,
                    candidate.nonzero_pages,
                    candidate.total_sampled,
                    candidate.valid_pml4e,
                );

                let ept_layer = vmkatz::paging::ept::EptLayer::new(
                    &layer,
                    candidate.pml4_addr,
                    candidate.l2_size,
                );

                let mapped = ept_layer.mapped_page_count();
                println!(
                    "[*] EPT #{}: {} mapped pages ({} MB of L2 space)",
                    i + 1,
                    mapped,
                    mapped * 4 / 1024,
                );

                // Fast path: iterate only mapped pages for small EPTs.
                // For huge EPTs (hypervisor-level), use generic scan with precomputed binary search.
                let result = if mapped < 10_000_000 {
                    process::find_system_process_ept(&ept_layer, &layer).map_err(|e| e.into())
                } else {
                    process::find_system_process_auto(&ept_layer).map_err(|e| e.into())
                };

                match result {
                    Ok((system, eprocess_offsets)) => {
                        println!(
                            "[+] System found via EPT #{} at L2=0x{:x}, DTB=0x{:x}",
                            i + 1,
                            system.eprocess_phys,
                            system.dtb,
                        );
                        return run_with_system(
                            &ept_layer,
                            &system,
                            &eprocess_offsets,
                            args,
                            verbose,
                            pagefile,
                            disk_path,
                        );
                    }
                    Err(e) => {
                        log::info!("EPT #{} (L1=0x{:x}): {}", i + 1, candidate.pml4_addr, e);
                        last_err = Some(e);
                    }
                }
            }

            Err(last_err
                .unwrap_or_else(|| vmkatz::error::GovmemError::SystemProcessNotFound.into()))
        }
    }
}

#[cfg(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv"
))]
fn run_with_system<L: PhysicalMemory>(
    layer: &L,
    system: &vmkatz::windows::process::Process,
    eprocess_offsets: &vmkatz::windows::offsets::EprocessOffsets,
    args: &Args,
    verbose: bool,
    pagefile: PagefileRef<'_>,
    disk_path: vmkatz::lsass::finder::DiskPathRef<'_>,
) -> anyhow::Result<()> {
    // Enumerate all processes
    let processes = process::enumerate_processes(layer, system, eprocess_offsets)
        .context("Failed to enumerate processes")?;

    if verbose {
        println!("[+] Found {} processes:", processes.len());
        for p in &processes {
            println!(
                "    PID={:>6}  DTB=0x{:012x}  PEB=0x{:016x}  {}",
                p.pid, p.dtb, p.peb_vaddr, p.name
            );
        }
    }

    if args.list_processes {
        return Ok(());
    }

    // Process dump mode
    if let Some(ref dump_name) = args.dump {
        let target = find_process_by_name(&processes, dump_name)
            .ok_or_else(|| anyhow::anyhow!("Process '{}' not found in process list", dump_name))?;

        let default_output = format!("{}.dmp", dump_name.to_lowercase().trim_end_matches(".exe"));
        let output = args.output.as_deref().unwrap_or(&default_output);
        let output_path = std::path::Path::new(output);

        println!(
            "[*] Dumping {} (PID={}, DTB=0x{:x})...",
            target.name, target.pid, target.dtb
        );

        vmkatz::dump::dump_process(layer, target, args.build, output_path, pagefile, disk_path)?;

        let file_size = std::fs::metadata(output_path).map(|m| m.len()).unwrap_or(0);
        println!(
            "[+] Dumped {} → {} ({:.1} MB)",
            target.name,
            output,
            file_size as f64 / (1024.0 * 1024.0)
        );
        return Ok(());
    }

    // Find LSASS
    let lsass_proc = processes
        .iter()
        .find(|p| p.name.eq_ignore_ascii_case("lsass.exe"))
        .ok_or_else(|| anyhow::anyhow!("lsass.exe not found in process list"))?;

    if verbose {
        println!(
            "\n[+] LSASS: PID={}, DTB=0x{:x}, PEB=0x{:x}",
            lsass_proc.pid, lsass_proc.dtb, lsass_proc.peb_vaddr
        );
    }

    // Extract credentials
    let credentials =
        lsass::finder::extract_all_credentials(layer, lsass_proc, system.dtb, pagefile, disk_path)
            .context("Credential extraction failed")?;

    // Report pagefile resolution stats
    #[cfg(feature = "sam")]
    if let Some(pf) = pagefile {
        let resolved = pf.pages_resolved();
        if resolved > 0 {
            println!("[+] Pagefile: {} pages resolved from disk", resolved);
        }
    }

    match args.format.as_str() {
        "csv" => print_csv(&credentials),
        "ntlm" => print_ntlm(&credentials),
        "hashcat" => print_hashcat(&credentials),
        _ => print_text(&credentials),
    }

    Ok(())
}

#[cfg(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv"
))]
fn find_process_by_name<'a>(
    processes: &'a [vmkatz::windows::process::Process],
    name: &str,
) -> Option<&'a vmkatz::windows::process::Process> {
    // Try exact match (case-insensitive)
    processes
        .iter()
        .find(|p| p.name.eq_ignore_ascii_case(name))
        .or_else(|| {
            // Try with .exe appended
            let with_exe = format!("{}.exe", name);
            processes
                .iter()
                .find(|p| p.name.eq_ignore_ascii_case(&with_exe))
        })
}

#[cfg(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv"
))]
fn print_text(credentials: &[Credential]) {
    let with_creds = credentials.iter().filter(|c| c.has_credentials()).count();
    println!(
        "\n[+] {} logon session(s), {} with credentials:\n",
        credentials.len(),
        with_creds,
    );
    for cred in credentials {
        println!("{}", cred);
    }
}

#[cfg(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv"
))]
fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

#[cfg(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv"
))]
fn print_csv(credentials: &[Credential]) {
    println!("luid,username,domain,nt_hash,lm_hash,sha1_hash,wdigest_password,kerberos_password,tspkg_password");
    for cred in credentials.iter().filter(|c| c.has_credentials()) {
        let (nt, lm, sha1) = if let Some(msv) = &cred.msv {
            (
                hex::encode(msv.nt_hash),
                hex::encode(msv.lm_hash),
                hex::encode(msv.sha1_hash),
            )
        } else {
            (String::new(), String::new(), String::new())
        };
        let wdigest_pw = cred
            .wdigest
            .as_ref()
            .map(|w| w.password.as_str())
            .unwrap_or("");
        let kerb_pw = cred
            .kerberos
            .as_ref()
            .map(|k| k.password.as_str())
            .unwrap_or("");
        let tspkg_pw = cred
            .tspkg
            .as_ref()
            .map(|t| t.password.as_str())
            .unwrap_or("");

        println!(
            "0x{:x},{},{},{},{},{},{},{},{}",
            cred.luid,
            csv_escape(&cred.username),
            csv_escape(&cred.domain),
            nt,
            lm,
            sha1,
            csv_escape(wdigest_pw),
            csv_escape(kerb_pw),
            csv_escape(tspkg_pw),
        );
    }
}

#[cfg(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv"
))]
fn print_ntlm(credentials: &[Credential]) {
    let zero_hash = [0u8; 16];
    for cred in credentials.iter().filter(|c| c.has_credentials()) {
        if let Some(msv) = &cred.msv {
            if msv.nt_hash != zero_hash {
                println!(
                    "{}\\{}:::{}:::",
                    cred.domain,
                    cred.username,
                    hex::encode(msv.nt_hash),
                );
            }
        }
    }
}

#[cfg(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv"
))]
fn print_hashcat(credentials: &[Credential]) {
    let zero_hash = [0u8; 16];
    for cred in credentials.iter().filter(|c| c.has_credentials()) {
        // hashcat mode 1000 (NTLM)
        if let Some(msv) = &cred.msv {
            if msv.nt_hash != zero_hash {
                println!("{}", hex::encode(msv.nt_hash));
            }
        }
    }
}
