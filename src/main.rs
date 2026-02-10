#[cfg(not(any(feature = "vmware", feature = "vbox", feature = "sam")))]
compile_error!("At least one backend must be enabled: --features vmware, vbox, and/or sam");

use std::path::Path;

use anyhow::Context;
use clap::Parser;

#[cfg(any(feature = "vmware", feature = "vbox"))]
use vmkatz::lsass;
use vmkatz::lsass::finder::PagefileRef;
#[cfg(any(feature = "vmware", feature = "vbox"))]
use vmkatz::lsass::types::Credential;
#[cfg(any(feature = "vmware", feature = "vbox"))]
use vmkatz::memory::PhysicalMemory;
#[cfg(feature = "vbox")]
use vmkatz::vbox::VBoxLayer;
#[cfg(feature = "vmware")]
use vmkatz::vmware::VmwareLayer;
#[cfg(any(feature = "vmware", feature = "vbox"))]
// EPROCESS offsets auto-detected at runtime from ALL_EPROCESS_OFFSETS
#[cfg(any(feature = "vmware", feature = "vbox"))]
use vmkatz::windows::process;

#[derive(Parser, Debug)]
#[command(
    name = "vmkatz",
    version,
    about = "VM memory forensics - extract credentials from VMware/VirtualBox snapshots and disk images",
    long_about = "vmkatz extracts Windows credentials from virtual machine memory snapshots and disk images.\n\n\
        Supported inputs:\n  \
        - VMware snapshots (.vmsn + .vmem)\n  \
        - VirtualBox saved states (.sav)\n  \
        - Disk images for SAM hashes (.vdi, .vmdk, .qcow2)\n  \
        - VM directories (auto-discovers all files)\n\n\
        Target: Windows 10 x64 22H2 (build 19045)",
    after_help = "EXAMPLES:\n  \
        vmkatz snapshot.vmsn                        Extract LSASS credentials\n  \
        vmkatz --format ntlm snapshot.vmsn          Output as NTLM hashes\n  \
        vmkatz --disk disk.vmdk snapshot.vmsn       Resolve paged-out creds from disk\n  \
        vmkatz disk.vdi                             Extract SAM hashes + LSA secrets\n  \
        vmkatz /path/to/vm/directory/               Auto-discover and process all files\n  \
        vmkatz --list-processes snapshot.vmsn        List running processes only\n  \
        vmkatz -v snapshot.vmsn                     Verbose output with process list",
)]
struct Args {
    /// Path to a snapshot, disk image, or VM directory
    #[arg(value_name = "FILE_OR_DIR")]
    input_path: String,

    /// Only list processes (skip credential extraction)
    #[arg(long, default_value_t = false)]
    list_processes: bool,

    /// Force SAM hash extraction mode (auto-detected for .vdi/.vmdk/.qcow2)
    #[cfg(feature = "sam")]
    #[arg(long, default_value_t = false)]
    sam: bool,

    /// Disk image for pagefile.sys resolution (resolves paged-out memory from disk)
    #[cfg(feature = "sam")]
    #[arg(long, value_name = "DISK_IMAGE")]
    disk: Option<String>,

    /// Output format
    #[arg(long, default_value = "text", value_name = "FORMAT", value_parser = ["text", "csv", "ntlm"])]
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

    // Auto-detect SAM mode for disk images, or explicit --sam flag
    #[cfg(feature = "sam")]
    {
        let ext = input_path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let sam_mode = args.sam
            || ext.eq_ignore_ascii_case("vdi")
            || ext.eq_ignore_ascii_case("vmdk")
            || ext.eq_ignore_ascii_case("qcow2")
            || ext.eq_ignore_ascii_case("qcow");
        if sam_mode {
            return run_sam(input_path, &args);
        }
    }

    // LSASS credential extraction mode
    #[cfg(feature = "sam")]
    {
        let disk_path_str = args.disk.clone();
        let pagefile_reader = disk_path_str.as_ref().and_then(|d| {
            match vmkatz::paging::pagefile::PagefileReader::open(Path::new(d)) {
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
            }
        });
        let disk_ref = disk_path_str.as_ref().map(|d| Path::new(d.as_str()));
        return run_lsass(input_path, &args, pagefile_reader.as_ref(), disk_ref);
    }
    #[cfg(not(feature = "sam"))]
    run_lsass(input_path, &args, Default::default(), Default::default())
}

#[cfg(feature = "sam")]
fn run_sam(input_path: &Path, args: &Args) -> anyhow::Result<()> {
    if args.verbose {
        println!("[*] SAM hash extraction from: {}", input_path.display());
    }

    let secrets = vmkatz::sam::extract_disk_secrets(input_path)
        .context("Disk secrets extraction failed")?;

    match args.format.as_str() {
        "ntlm" => print_sam_ntlm(&secrets.sam_entries),
        "csv" => print_sam_csv(&secrets.sam_entries),
        _ => print_sam_text(&secrets.sam_entries),
    }

    if !secrets.lsa_secrets.is_empty() {
        print_lsa_secrets(&secrets.lsa_secrets);
    }

    Ok(())
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
fn print_lsa_secrets(secrets: &[vmkatz::sam::lsa::LsaSecret]) {
    println!("\n[+] LSA Secrets:");
    for secret in secrets {
        println!("{}", secret);
    }
}

fn run_directory(dir: &Path, args: &Args) -> anyhow::Result<()> {
    let discovery = vmkatz::discover::discover_vm_files(dir)
        .context("VM file discovery failed")?;

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

    #[cfg(any(feature = "vmware", feature = "vbox"))]
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

fn run_lsass(input_path: &Path, args: &Args, pagefile: PagefileRef<'_>, disk_path: vmkatz::lsass::finder::DiskPathRef<'_>) -> anyhow::Result<()> {
    let verbose = args.verbose || args.list_processes;
    let ext = input_path.extension().and_then(|e| e.to_str()).unwrap_or("");

    if ext.eq_ignore_ascii_case("sav") {
        #[cfg(feature = "vbox")]
        {
            run_with_layer(
                || {
                    if verbose {
                        println!("[*] Opening VirtualBox saved state: {}", input_path.display());
                    }
                    let layer = VBoxLayer::open(input_path)
                        .context("Failed to open VirtualBox .sav file")?;
                    if verbose {
                        println!("[+] RAM: {} MB ({} pages mapped)", layer.phys_size() / (1024 * 1024), layer.page_count());
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
    } else {
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
            anyhow::bail!("VMware .vmem/.vmsn support not enabled (compile with --features vmware)")
        }
    }
}

#[cfg(any(feature = "vmware", feature = "vbox"))]
fn run_with_layer<L: PhysicalMemory, F: FnOnce() -> anyhow::Result<L>>(
    make_layer: F,
    args: &Args,
    verbose: bool,
    pagefile: PagefileRef<'_>,
    disk_path: vmkatz::lsass::finder::DiskPathRef<'_>,
) -> anyhow::Result<()> {
    let layer = make_layer()?;

    // Find System process (auto-detect Windows version from EPROCESS layout)
    let (system, eprocess_offsets) = process::find_system_process_auto(&layer)
        .context("Failed to find System process")?;

    // Enumerate all processes
    let processes = process::enumerate_processes(&layer, &system, &eprocess_offsets)
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
        lsass::finder::extract_all_credentials(&layer, lsass_proc, system.dtb, pagefile, disk_path)
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
        _ => print_text(&credentials),
    }

    Ok(())
}

#[cfg(any(feature = "vmware", feature = "vbox"))]
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

#[cfg(any(feature = "vmware", feature = "vbox"))]
fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

#[cfg(any(feature = "vmware", feature = "vbox"))]
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

#[cfg(any(feature = "vmware", feature = "vbox"))]
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
