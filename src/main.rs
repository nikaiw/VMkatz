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
    long_about = "vmkatz extracts Windows credentials from virtual machine memory snapshots, disk images, and raw files.\n\n\
        Supported inputs:\n  \
        - VMware snapshots (.vmsn + .vmem)\n  \
        - VirtualBox saved states (.sav)\n  \
        - QEMU/KVM/Proxmox ELF core dumps (.elf, from dump-guest-memory / virsh dump)\n  \
        - Hyper-V legacy saved states (.bin) and raw memory dumps (.raw, .dmp)\n  \
        - Disk images for SAM hashes (.vdi, .vmdk, .qcow2, .vhdx, .vhd)\n  \
        - Raw registry hives (SAM + SYSTEM [+ SECURITY])\n  \
        - Raw NTDS.dit + SYSTEM hive\n  \
        - LSASS minidump (.dmp)\n  \
        - VM directories (auto-discovers all files)\n\n\
        Target: Windows 7 SP1 through Windows 11 x64",
    after_help = "EXAMPLES:\n  \
        vmkatz snapshot.vmsn                        Extract LSASS credentials\n  \
        vmkatz --format ntlm snapshot.vmsn          Output as NTLM hashes\n  \
        vmkatz --disk disk.vmdk snapshot.vmsn       Resolve paged-out creds from disk\n  \
        vmkatz disk.vdi                             Extract SAM hashes + LSA secrets\n  \
        vmkatz SAM SYSTEM                           Extract from raw registry hives\n  \
        vmkatz SAM SYSTEM SECURITY                  Full extraction with LSA + cached creds\n  \
        vmkatz ntds.dit SYSTEM                      Extract AD hashes from raw files\n  \
        vmkatz lsass.dmp                            Parse LSASS minidump\n  \
        vmkatz /path/to/vm/directory/               Auto-discover and process all files\n  \
        vmkatz --list-processes snapshot.vmsn        List running processes only\n  \
        vmkatz --dump lsass snapshot.vmsn           Dump LSASS as minidump for pypykatz\n  \
        vmkatz --dump lsass -o out.dmp snap.vmsn    Dump with custom output filename\n  \
        vmkatz -v snapshot.vmsn                     Verbose output with process list"
)]
struct Args {
    /// Path(s) to snapshot, disk image, raw hive/NTDS files, or VM directory
    #[arg(value_name = "FILE", num_args = 1..)]
    input_paths: Vec<String>,

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

    /// Color output (auto=detect terminal, always, never)
    #[arg(long, default_value = "auto", value_name = "WHEN", value_parser = ["auto", "always", "never"])]
    color: String,

    /// Export Kerberos tickets as .kirbi files to a directory
    #[arg(long, value_name = "DIR")]
    kirbi: Option<String>,

    /// Export Kerberos tickets as a single ccache file (MIT Kerberos format)
    #[arg(long, value_name = "FILE")]
    ccache: Option<String>,

    /// Verbose output (show memory regions, process list, etc.)
    #[arg(short, long, default_value_t = false)]
    verbose: bool,
}

// ---------------------------------------------------------------------------
// Terminal color support
// ---------------------------------------------------------------------------

/// ANSI color escape sequences (empty strings when disabled).
#[allow(dead_code)]
struct Colors {
    reset: &'static str,
    bold: &'static str,
    dim: &'static str,
    green: &'static str,
    yellow: &'static str,
    cyan: &'static str,
    red: &'static str,
}

const COLORS_ON: Colors = Colors {
    reset: "\x1b[0m",
    bold: "\x1b[1m",
    dim: "\x1b[2m",
    green: "\x1b[32m",
    yellow: "\x1b[33m",
    cyan: "\x1b[36m",
    red: "\x1b[31m",
};

const COLORS_OFF: Colors = Colors {
    reset: "",
    bold: "",
    dim: "",
    green: "",
    yellow: "",
    cyan: "",
    red: "",
};

fn get_colors(args: &Args) -> &'static Colors {
    use std::io::IsTerminal;
    match args.color.as_str() {
        "always" => &COLORS_ON,
        "never" => &COLORS_OFF,
        _ => {
            if std::io::stdout().is_terminal() {
                &COLORS_ON
            } else {
                &COLORS_OFF
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Blank hash detection
// ---------------------------------------------------------------------------

/// NT hash of empty password (NTLM(""))
const BLANK_NT_HEX: &str = "31d6cfe0d16ae931b73c59d7e0c089c0";
/// LM hash of empty password (LanMan(""))
/// Used as placeholder in pwdump format when LM hashing is disabled.
const BLANK_LM_HEX: &str = "aad3b435b51404eeaad3b435b51404ee";

const ZERO_HASH_16: [u8; 16] = [0u8; 16];

/// Format a hash with blank annotation and optional color.
fn fmt_hash(hash: &[u8], c: &Colors) -> String {
    let h = hex::encode(hash);
    if hash.iter().all(|&b| b == 0) {
        return format!("{}{}{}", c.dim, h, c.reset);
    }
    if h == BLANK_NT_HEX || h == BLANK_LM_HEX {
        return format!("{}{} (blank){}", c.dim, h, c.reset);
    }
    format!("{}{}{}", c.yellow, h, c.reset)
}

/// Format LM hash for pwdump output: zero → standard empty LM placeholder.
fn fmt_lm_pwdump(hash: &[u8; 16]) -> String {
    if *hash == ZERO_HASH_16 {
        BLANK_LM_HEX.to_string()
    } else {
        hex::encode(hash)
    }
}

// ---------------------------------------------------------------------------
// File type detection by magic bytes
// ---------------------------------------------------------------------------

/// File type detected from magic bytes at the start of the file.
#[derive(Debug, Clone, Copy, PartialEq)]
enum RawFileType {
    EseDatabase,   // NTDS.dit (0xEFCDAB89 at offset 4)
    RegistryHive,  // SAM/SYSTEM/SECURITY ("regf" at offset 0)
    Minidump,      // LSASS dump ("MDMP" at offset 0)
    Other,
}

fn detect_file_type(path: &Path) -> RawFileType {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(path) else {
        return RawFileType::Other;
    };
    let mut magic = [0u8; 8];
    if f.read_exact(&mut magic).is_err() {
        return RawFileType::Other;
    }
    if &magic[0..4] == b"regf" {
        return RawFileType::RegistryHive;
    }
    if magic[4..8] == [0xEF, 0xCD, 0xAB, 0x89] {
        return RawFileType::EseDatabase;
    }
    if &magic[0..4] == b"MDMP" {
        return RawFileType::Minidump;
    }
    RawFileType::Other
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

    let input_path = Path::new(&args.input_paths[0]);

    // Directory mode: auto-discover and process all VM files
    if args.input_paths.len() == 1 && input_path.is_dir() {
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
        let hive_files: Vec<_> = file_types.iter().filter(|(_, t)| *t == RawFileType::RegistryHive).collect();

        // Raw NTDS.dit + SYSTEM hive
        #[cfg(feature = "ntds.dit")]
        {
            let ese_files: Vec<_> = file_types.iter().filter(|(_, t)| *t == RawFileType::EseDatabase).collect();
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

    let c = get_colors(args);

    match args.format.as_str() {
        "ntlm" => print_sam_ntlm(&secrets.sam_entries),
        "csv" => print_sam_csv(&secrets.sam_entries),
        "hashcat" => print_sam_hashcat(&secrets.sam_entries),
        _ => print_sam_text(&secrets.sam_entries, c),
    }

    if !secrets.lsa_secrets.is_empty() && args.format != "hashcat" {
        print_lsa_secrets(&secrets.lsa_secrets, c);
    }

    if !secrets.cached_credentials.is_empty() {
        match args.format.as_str() {
            "hashcat" => print_dcc2_hashcat(&secrets.cached_credentials),
            _ => print_cached_credentials(&secrets.cached_credentials, c),
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
    let ctx = vmkatz::ntds::build_context(&artifacts.ntds_data, &artifacts.system_data)
        .context("NTDS context validation failed")?;
    let hashes = vmkatz::ntds::extract_ad_hashes(
        &artifacts.ntds_data,
        &artifacts.system_data,
        args.ntds_history,
    )
    .context("NTDS hash extraction failed")?;

    let c = get_colors(args);

    println!("\n{}[+] NTDS Artifacts:{}", c.green, c.reset);
    println!("  Partition offset : 0x{:x}", artifacts.partition_offset);
    println!("  ntds.dit size    : {} bytes", ctx.ntds_size);
    println!("  SYSTEM size      : {} bytes", artifacts.system_data.len());
    println!("  Bootkey          : {}", hex::encode(ctx.boot_key));
    println!("  Hashes extracted : {}", hashes.len());

    match args.format.as_str() {
        "csv" => print_ntds_csv(&hashes),
        "hashcat" => print_ntds_hashcat(&hashes),
        "ntlm" => print_ntds_ntlm(&hashes),
        _ => print_ntds_text(&hashes, c),
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Raw file modes (no disk image / VM snapshot needed)
// ---------------------------------------------------------------------------

/// Extract AD hashes from raw NTDS.dit + SYSTEM hive files.
#[cfg(feature = "ntds.dit")]
fn run_raw_ntds(ntds_path: &Path, system_path: &Path, args: &Args) -> anyhow::Result<()> {
    let ntds_data =
        std::fs::read(ntds_path).with_context(|| format!("Failed to read {}", ntds_path.display()))?;
    let system_data =
        std::fs::read(system_path).with_context(|| format!("Failed to read {}", system_path.display()))?;

    let ctx = vmkatz::ntds::build_context(&ntds_data, &system_data)
        .context("NTDS context validation failed")?;
    let hashes = vmkatz::ntds::extract_ad_hashes(
        &ntds_data,
        &system_data,
        {
            #[cfg(feature = "ntds.dit")]
            { args.ntds_history }
            #[cfg(not(feature = "ntds.dit"))]
            { false }
        },
    )
    .context("NTDS hash extraction failed")?;

    let c = get_colors(args);

    println!("\n{}[+] NTDS (raw files):{}", c.green, c.reset);
    println!("  ntds.dit : {} ({} bytes)", ntds_path.display(), ctx.ntds_size);
    println!("  SYSTEM   : {} ({} bytes)", system_path.display(), system_data.len());
    println!("  Bootkey  : {}", hex::encode(ctx.boot_key));
    println!("  Hashes   : {}", hashes.len());

    match args.format.as_str() {
        "csv" => print_ntds_csv(&hashes),
        "hashcat" => print_ntds_hashcat(&hashes),
        "ntlm" => print_ntds_ntlm(&hashes),
        _ => print_ntds_text(&hashes, c),
    }

    Ok(())
}

/// Extract SAM/LSA/DCC2 from raw registry hive files.
/// Auto-detects which hive is SYSTEM (via bootkey extraction), SAM, and SECURITY.
#[cfg(feature = "sam")]
fn run_raw_hives(
    hive_files: &[&(std::path::PathBuf, RawFileType)],
    args: &Args,
) -> anyhow::Result<()> {
    // Read all hive files
    let hives: Vec<(&Path, Vec<u8>)> = hive_files
        .iter()
        .map(|(p, _)| {
            let data = std::fs::read(p)
                .with_context(|| format!("Failed to read {}", p.display()))?;
            Ok((p.as_path(), data))
        })
        .collect::<anyhow::Result<_>>()?;

    // Identify SYSTEM hive by trying bootkey extraction on each
    let mut system_idx = None;
    let mut bootkey = [0u8; 16];

    for (i, (path, data)) in hives.iter().enumerate() {
        if let Ok(key) = vmkatz::sam::bootkey::extract_bootkey(data) {
            log::info!("SYSTEM hive: {} (bootkey: {})", path.display(), hex::encode(key));
            system_idx = Some(i);
            bootkey = key;
            break;
        }
    }

    let system_idx = system_idx.context(
        "No SYSTEM hive found (could not extract bootkey from any of the provided files)"
    )?;

    let c = get_colors(args);
    println!("\n{}[+] Raw hives:{}", c.green, c.reset);
    println!("  SYSTEM  : {} (bootkey: {})", hives[system_idx].0.display(), hex::encode(bootkey));

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
                println!("  SAM     : {} ({} accounts)", path.display(), entries.len());
                sam_entries = entries;
                continue;
            }
        }

        // Try as SECURITY (LSA secrets + cached creds)
        if let Ok(secrets) = vmkatz::sam::lsa::extract_lsa_secrets(data, &bootkey) {
            if !secrets.is_empty() {
                println!("  SECURITY: {} ({} secrets)", path.display(), secrets.len());
                let nlkm_key = secrets.iter().find_map(|s| {
                    if s.name == "NL$KM" {
                        Some(s.raw_data.clone())
                    } else {
                        None
                    }
                });
                lsa_secrets = secrets;

                if let Some(ref nlkm) = nlkm_key {
                    if let Ok(creds) = vmkatz::sam::cache::extract_cached_credentials(data, nlkm) {
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
            _ => print_sam_text(&sam_entries, c),
        }
    }

    if !lsa_secrets.is_empty() && args.format != "hashcat" {
        print_lsa_secrets(&lsa_secrets, c);
    }

    if !cached_creds.is_empty() {
        match args.format.as_str() {
            "hashcat" => print_dcc2_hashcat(&cached_creds),
            _ => print_cached_credentials(&cached_creds, c),
        }
    }

    Ok(())
}

/// Handle LSASS minidump files.
fn run_minidump(_input_path: &Path, _args: &Args) -> anyhow::Result<()> {
    anyhow::bail!(
        "LSASS minidump parsing is not yet implemented.\n\
         Workaround: use pypykatz to parse the minidump:\n  \
         pypykatz minidump lsass.dmp"
    );
}

#[cfg(feature = "ntds.dit")]
fn print_ntds_text(entries: &[vmkatz::ntds::AdHashEntry], c: &Colors) {
    println!("\n{}[+] AD NTLM Hashes:{}", c.green, c.reset);
    for entry in entries {
        let hist = if entry.is_history {
            match entry.history_index {
                Some(idx) => format!("history{}", idx),
                None => "history".to_string(),
            }
        } else {
            "current".to_string()
        };
        if entry.lm_hash != ZERO_HASH_16 {
            println!(
                "  RID: {:<6} {}{:<24}{} {:<10} NT:{}  LM:{}",
                entry.rid, c.bold, entry.username, c.reset, hist,
                fmt_hash(&entry.nt_hash, c),
                fmt_hash(&entry.lm_hash, c),
            );
        } else {
            println!(
                "  RID: {:<6} {}{:<24}{} {:<10} NT:{}",
                entry.rid, c.bold, entry.username, c.reset, hist,
                fmt_hash(&entry.nt_hash, c),
            );
        }
    }
}

#[cfg(feature = "ntds.dit")]
fn print_ntds_ntlm(entries: &[vmkatz::ntds::AdHashEntry]) {
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
            fmt_lm_pwdump(&entry.lm_hash),
            hex::encode(entry.nt_hash),
        );
    }
}

#[cfg(feature = "ntds.dit")]
fn print_ntds_csv(entries: &[vmkatz::ntds::AdHashEntry]) {
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
            fmt_lm_pwdump(&entry.lm_hash),
        );
    }
}

#[cfg(feature = "ntds.dit")]
fn print_ntds_hashcat(entries: &[vmkatz::ntds::AdHashEntry]) {
    let zero_hash = [0u8; 16];
    for entry in entries {
        if entry.nt_hash != zero_hash {
            println!("{}", hex::encode(entry.nt_hash));
        }
    }
}

#[cfg(feature = "sam")]
fn print_sam_text(entries: &[vmkatz::sam::SamEntry], c: &Colors) {
    println!("\n{}[+] SAM Hashes:{}", c.green, c.reset);
    for entry in entries {
        if entry.lm_hash != ZERO_HASH_16 {
            println!(
                "  RID: {:<5} {}{:<20}{}  NT:{}  LM:{}",
                entry.rid, c.bold, entry.username, c.reset,
                fmt_hash(&entry.nt_hash, c),
                fmt_hash(&entry.lm_hash, c),
            );
        } else {
            println!(
                "  RID: {:<5} {}{:<20}{}  NT:{}",
                entry.rid, c.bold, entry.username, c.reset,
                fmt_hash(&entry.nt_hash, c),
            );
        }
    }
}

#[cfg(feature = "sam")]
fn print_sam_ntlm(entries: &[vmkatz::sam::SamEntry]) {
    for entry in entries {
        println!(
            "{}:{}:{}:{}:::",
            entry.username,
            entry.rid,
            fmt_lm_pwdump(&entry.lm_hash),
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
            fmt_lm_pwdump(&entry.lm_hash),
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
fn print_lsa_secrets(secrets: &[vmkatz::sam::lsa::LsaSecret], c: &Colors) {
    println!("\n{}[+] LSA Secrets:{}", c.green, c.reset);
    for secret in secrets {
        println!("{}", secret);
    }
}

#[cfg(feature = "sam")]
fn print_cached_credentials(creds: &[vmkatz::sam::cache::CachedCredential], c: &Colors) {
    println!("\n{}[+] Domain Cached Credentials (DCC2):{}", c.green, c.reset);
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

    #[cfg(any(
        feature = "vmware",
        feature = "vbox",
        feature = "qemu",
        feature = "hyperv"
    ))]
    {
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

        for file in &discovery.lsass_files {
            let name = file.file_name().unwrap_or_default().to_string_lossy();
            println!("\n[*] LSASS: {}", name);
            if let Err(e) = run_lsass(file, args, pagefile, disk_path) {
                eprintln!("[!] {}: {}", name, e);
            }
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
    #[cfg(not(any(
        feature = "vmware",
        feature = "vbox",
        feature = "qemu",
        feature = "hyperv"
    )))]
    {
        let _ = (input_path, args, pagefile, disk_path);
        anyhow::bail!("No hypervisor support compiled in (rebuild with --features vmware,vbox,qemu,hyperv)");
    }

    #[cfg(any(
        feature = "vmware",
        feature = "vbox",
        feature = "qemu",
        feature = "hyperv"
    ))]
    {
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
    } // cfg(any hypervisor)
}

/// Check if a path is a block device (Linux /dev/...).
#[cfg(feature = "sam")]
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
#[cfg(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv"
))]
enum LsassFormat {
    VBox,
    QemuElf,
    HypervBin,
    Vmware,
}

/// Detect the memory snapshot format from extension and magic bytes.
#[cfg(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv"
))]
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
#[cfg(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv"
))]
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

    // Export Kerberos tickets if requested
    export_kerberos_tickets(&credentials, args);

    let c = get_colors(args);
    match args.format.as_str() {
        "csv" => print_csv(&credentials),
        "ntlm" => print_ntlm(&credentials),
        "hashcat" => print_hashcat(&credentials),
        _ => print_text(&credentials, c),
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

// ---------------------------------------------------------------------------
// Kerberos ticket export (--kirbi, --ccache)
// ---------------------------------------------------------------------------

/// Export Kerberos tickets from credentials if --kirbi or --ccache is set.
fn export_kerberos_tickets(credentials: &[Credential], args: &Args) {
    if args.kirbi.is_none() && args.ccache.is_none() {
        return;
    }

    // Collect all tickets with their context
    let mut all_tickets: Vec<(&vmkatz::lsass::types::KerberosTicket, &str, &str)> = Vec::new();
    for cred in credentials {
        if let Some(krb) = &cred.kerberos {
            for ticket in &krb.tickets {
                all_tickets.push((ticket, &krb.username, &krb.domain));
            }
        }
    }

    if all_tickets.is_empty() {
        println!("[*] No Kerberos tickets to export");
        return;
    }

    // --kirbi: write individual .kirbi files
    if let Some(dir) = &args.kirbi {
        let dir_path = std::path::Path::new(dir);
        if !dir_path.exists() {
            if let Err(e) = std::fs::create_dir_all(dir_path) {
                eprintln!("[!] Failed to create kirbi directory {}: {}", dir, e);
                return;
            }
        }
        let mut count = 0;
        for (ticket, username, _domain) in &all_tickets {
            if ticket.kirbi.is_empty() {
                continue;
            }
            let svc = ticket.service_name.join("-");
            let filename = format!(
                "{}_{}_{}.kirbi",
                sanitize_filename(username),
                ticket.ticket_type,
                sanitize_filename(&svc)
            );
            let path = dir_path.join(&filename);
            match std::fs::write(&path, &ticket.kirbi) {
                Ok(_) => {
                    count += 1;
                    log::debug!("Wrote {}", path.display());
                }
                Err(e) => eprintln!("[!] Failed to write {}: {}", path.display(), e),
            }
        }
        println!("[+] Exported {} .kirbi ticket(s) to {}", count, dir);
    }

    // --ccache: write all tickets into a single ccache file
    if let Some(ccache_path) = &args.ccache {
        let data = build_ccache(&all_tickets);
        match std::fs::write(ccache_path, &data) {
            Ok(_) => println!(
                "[+] Exported {} ticket(s) to {} ({} bytes)",
                all_tickets.len(),
                ccache_path,
                data.len()
            ),
            Err(e) => eprintln!("[!] Failed to write {}: {}", ccache_path, e),
        }
    }
}

/// Sanitize a string for use in a filename.
fn sanitize_filename(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' | ' ' | '$' => '_',
            _ => c,
        })
        .collect()
}

/// Build a ccache (MIT Kerberos credential cache) file.
/// Format: v4 (0x0504), one default principal, N credentials.
fn build_ccache(
    tickets: &[(&vmkatz::lsass::types::KerberosTicket, &str, &str)],
) -> Vec<u8> {
    let mut out = Vec::new();

    // File format version: 0x0504 (v4)
    out.extend_from_slice(&[0x05, 0x04]);

    // Header tags (v4): 2-byte header length, then tag entries
    // We use a single empty header (length = 0)
    out.extend_from_slice(&0u16.to_be_bytes());

    // Default principal: use the first ticket's client
    if let Some((ticket, _username, _domain)) = tickets.first() {
        let realm = &ticket.domain_name;
        let client = &ticket.client_name;
        write_ccache_principal(&mut out, ticket.client_name_type as u32, realm, client);
    } else {
        // Empty principal
        write_ccache_principal(&mut out, 1, "", &[]);
    }

    // Credentials
    for (ticket, _username, _domain) in tickets {
        if ticket.ticket_blob.is_empty() {
            continue;
        }
        write_ccache_credential(&mut out, ticket);
    }

    out
}

/// Write a principal to ccache format.
/// Format: name_type (u32), num_components (u32), realm (counted_octet_string),
///         components[num] (counted_octet_string each)
fn write_ccache_principal(out: &mut Vec<u8>, name_type: u32, realm: &str, components: &[String]) {
    out.extend_from_slice(&name_type.to_be_bytes());
    out.extend_from_slice(&(components.len() as u32).to_be_bytes());
    // Realm
    write_ccache_string(out, realm);
    // Components
    for comp in components {
        write_ccache_string(out, comp);
    }
}

fn write_ccache_string(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

/// Write a single credential entry in ccache format.
fn write_ccache_credential(out: &mut Vec<u8>, ticket: &vmkatz::lsass::types::KerberosTicket) {
    // Client principal
    let client_realm = &ticket.domain_name;
    write_ccache_principal(out, ticket.client_name_type as u32, client_realm, &ticket.client_name);

    // Server principal
    let server_realm = &ticket.target_domain_name;
    write_ccache_principal(out, ticket.service_name_type as u32, server_realm, &ticket.service_name);

    // Keyblock: keytype (u16), etype (u16 = 0 for ccache v4), keylength (u16), keyvalue
    // ccache v4 uses: enc_type (u16), key_length (u32), key_data
    out.extend_from_slice(&(ticket.key_type as u16).to_be_bytes());
    out.extend_from_slice(&(ticket.session_key.len() as u32).to_be_bytes());
    out.extend_from_slice(&ticket.session_key);

    // Times: authtime, starttime, endtime, renew_till (each u32, unix timestamp)
    let to_unix = |ft: u64| -> u32 {
        if ft == 0 {
            return 0;
        }
        ((ft / 10_000_000).saturating_sub(11_644_473_600)) as u32
    };
    out.extend_from_slice(&to_unix(ticket.start_time).to_be_bytes()); // authtime
    out.extend_from_slice(&to_unix(ticket.start_time).to_be_bytes()); // starttime
    out.extend_from_slice(&to_unix(ticket.end_time).to_be_bytes()); // endtime
    out.extend_from_slice(&to_unix(ticket.renew_until).to_be_bytes()); // renew_till

    // is_skey: u8 (0)
    out.push(0);

    // ticket_flags: u32 (big-endian, already stored as big-endian in our struct)
    out.extend_from_slice(&ticket.ticket_flags.to_be_bytes());

    // Addresses: count (u32) = 0
    out.extend_from_slice(&0u32.to_be_bytes());

    // Authdata: count (u32) = 0
    out.extend_from_slice(&0u32.to_be_bytes());

    // Ticket (the actual encrypted ticket blob)
    out.extend_from_slice(&(ticket.ticket_blob.len() as u32).to_be_bytes());
    out.extend_from_slice(&ticket.ticket_blob);

    // Second ticket: length = 0
    out.extend_from_slice(&0u32.to_be_bytes());
}

#[cfg(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv"
))]
fn print_text(credentials: &[Credential], c: &Colors) {
    use vmkatz::lsass::types::{filetime_to_string, logon_type_name};

    let with_creds = credentials.iter().filter(|cr| cr.has_credentials()).count();
    println!(
        "\n{}[+]{} {} logon session(s), {} with credentials:\n",
        c.green, c.reset, credentials.len(), with_creds,
    );
    for cred in credentials {
        // LUID header
        let luid_label = match cred.luid {
            0x3e7 => " (SYSTEM)",
            0x3e4 => " (NETWORK SERVICE)",
            0x3e5 => " (LOCAL SERVICE)",
            0x3e3 => " (IUSER)",
            _ => "",
        };
        println!("  {}LUID: 0x{:x}{}{}", c.bold, cred.luid, luid_label, c.reset);
        if cred.session_id != 0 || cred.logon_type != 0 {
            println!(
                "  Session: {} | LogonType: {}",
                cred.session_id,
                logon_type_name(cred.logon_type)
            );
        }
        println!("  {}Username: {}{}", c.bold, cred.username, c.reset);
        println!("  Domain: {}", cred.domain);
        if !cred.logon_server.is_empty() {
            println!("  LogonServer: {}", cred.logon_server);
        }
        if cred.logon_time != 0 {
            println!("  LogonTime: {}", filetime_to_string(cred.logon_time));
        }
        if !cred.sid.is_empty() {
            println!("  SID: {}", cred.sid);
        }
        if !cred.has_credentials() {
            println!("  {}(no credentials extracted - paged out){}", c.dim, c.reset);
            println!();
            continue;
        }
        if let Some(msv) = &cred.msv {
            println!("  {}[MSV1_0]{}", c.cyan, c.reset);
            if msv.lm_hash != ZERO_HASH_16 {
                println!("    LM Hash : {}", fmt_hash(&msv.lm_hash, c));
            }
            println!("    NT Hash : {}", fmt_hash(&msv.nt_hash, c));
            println!("    SHA1    : {}", fmt_hash(&msv.sha1_hash, c));
        }
        if let Some(wd) = &cred.wdigest {
            if !wd.password.is_empty() {
                println!("  {}[WDigest]{}", c.cyan, c.reset);
                println!("    Password: {}{}{}", c.red, wd.password, c.reset);
            }
        }
        if let Some(krb) = &cred.kerberos {
            println!("  {}[Kerberos]{}", c.cyan, c.reset);
            if !krb.password.is_empty() {
                println!("    Password: {}{}{}", c.red, krb.password, c.reset);
            }
            for key in &krb.keys {
                println!(
                    "    {:11}: {}",
                    key.etype_name(),
                    hex::encode(&key.key)
                );
            }
            for ticket in &krb.tickets {
                println!(
                    "    [{}] {}",
                    ticket.ticket_type,
                    ticket.service_name.join("/")
                );
                println!("      Domain : {}", ticket.domain_name);
                println!("      Client : {}", ticket.client_name.join("/"));
                println!(
                    "      EncType: {} | KeyType: {}",
                    ticket.ticket_enc_type, ticket.key_type
                );
                println!("      Flags  : 0x{:08x}", ticket.ticket_flags);
                println!("      Start  : {}", filetime_to_string(ticket.start_time));
                println!("      End    : {}", filetime_to_string(ticket.end_time));
                println!(
                    "      Kirbi  : {} bytes (base64: {})",
                    ticket.kirbi.len(),
                    vmkatz::lsass::base64_encode(&ticket.kirbi)
                );
            }
        }
        if let Some(ts) = &cred.tspkg {
            if !ts.password.is_empty() {
                println!("  {}[TsPkg]{}", c.cyan, c.reset);
                println!("    Password: {}{}{}", c.red, ts.password, c.reset);
            }
        }
        for dk in &cred.dpapi {
            println!("  {}[DPAPI]{}", c.cyan, c.reset);
            println!("    GUID          : {}", dk.guid);
            println!("    MasterKey     : {}{}{}", c.yellow, hex::encode(&dk.key), c.reset);
            println!("    SHA1 MasterKey: {}{}{}", c.yellow, hex::encode(dk.sha1_masterkey), c.reset);
        }
        if !cred.credman.is_empty() {
            println!("  {}[CredMan]{}", c.cyan, c.reset);
            for cm in &cred.credman {
                println!("    Target  : {}", cm.target);
                println!("    Username: {}", cm.username);
                println!("    Domain  : {}", cm.domain);
                println!("    Password: {}{}{}", c.red, cm.password, c.reset);
            }
        }
        if let Some(ssp) = &cred.ssp {
            if !ssp.password.is_empty() {
                println!("  {}[SSP]{}", c.cyan, c.reset);
                println!("    Username: {}", ssp.username);
                println!("    Domain  : {}", ssp.domain);
                println!("    Password: {}{}{}", c.red, ssp.password, c.reset);
            }
        }
        if let Some(live) = &cred.livessp {
            if !live.password.is_empty() {
                println!("  {}[LiveSSP]{}", c.cyan, c.reset);
                println!("    Username: {}", live.username);
                println!("    Domain  : {}", live.domain);
                println!("    Password: {}{}{}", c.red, live.password, c.reset);
            }
        }
        if let Some(cap) = &cred.cloudap {
            println!("  {}[CloudAP]{}", c.cyan, c.reset);
            println!("    Username : {}", cap.username);
            println!("    Domain   : {}", cap.domain);
            if !cap.dpapi_key.is_empty() {
                println!("    DPAPI Key: {}{}{}", c.yellow, hex::encode(&cap.dpapi_key), c.reset);
            }
            if !cap.prt.is_empty() {
                println!("    PRT      : {}", cap.prt);
            }
        }
        println!();
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
                fmt_lm_pwdump(&msv.lm_hash),
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
