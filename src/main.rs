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

/// Minimal logger (replaces env_logger — saves ~300KB from regex/jiff deps)
struct SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            eprintln!("[{:<5} {}] {}", record.level(), record.target(), record.args());
        }
    }

    fn flush(&self) {}
}

#[cfg(feature = "hyperv")]
use vmkatz::hyperv::HypervLayer;
use vmkatz::lsass;
use vmkatz::lsass::finder::PagefileRef;
use vmkatz::lsass::types::{Credential, KerberosKey};
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
        vmkatz -r /vmfs/volumes/datastore/           Recursively scan all VM directories\n  \
        vmkatz --list-processes snapshot.vmsn        List running processes only\n  \
        vmkatz --dump lsass snapshot.vmsn           Dump LSASS as minidump for pypykatz\n  \
        vmkatz --dump lsass -o out.dmp snap.vmsn    Dump with custom output filename\n  \
        vmkatz --carve partial_dump.raw              Carve from partial/raw memory\n  \
        vmkatz -v snapshot.vmsn                     Verbose output with process list"
)]
struct Args {
    /// Path(s) to snapshot, disk image, raw hive/NTDS files, or VM directory
    #[arg(value_name = "FILE", num_args = 0..)]
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
    #[cfg(feature = "dump")]
    #[arg(long, value_name = "PROCESS_NAME")]
    dump: Option<String>,

    /// Output file for --dump (default: <process>.dmp)
    #[cfg(feature = "dump")]
    #[arg(short, long, value_name = "FILE")]
    output: Option<String>,

    /// Windows build number for minidump header (default: 19045)
    #[cfg(feature = "dump")]
    #[arg(long, default_value_t = 19045, value_name = "NUMBER")]
    build: u32,

    /// Output format
    #[arg(long, default_value = "text", value_name = "FORMAT", value_parser = ["text", "csv", "ntlm", "hashcat", "brief"])]
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

    /// Show all logon sessions (disables deduplication and shows empty sessions)
    #[arg(short, long, default_value_t = false)]
    all: bool,

    /// Enable nested EPT scanning (for VBS/Credential Guard VMs)
    #[arg(long, default_value_t = false)]
    ept: bool,

    /// Recursively scan directory for VM snapshot and disk image files
    #[arg(short, long, default_value_t = false)]
    recurse: bool,

    /// Filter file types in directory/recursive mode (all, snapshot, disk)
    #[arg(long, default_value = "all", value_name = "TYPE", value_parser = ["all", "snapshot", "disk"])]
    scan: String,

    /// Filter output to specific providers (comma-separated: msv,wdigest,kerberos,tspkg,dpapi,ssp,livessp,credman,cloudap)
    #[arg(long, value_delimiter = ',', value_name = "LIST")]
    provider: Vec<String>,

    /// Carve credentials from partial/truncated/raw memory files
    #[cfg(feature = "carve")]
    #[arg(long, default_value_t = false)]
    carve: bool,

    /// VMFS-6 raw SCSI device for reading flat VMDKs through VMFS locks
    #[cfg(feature = "vmfs")]
    #[arg(long, value_name = "DEVICE")]
    vmfs_device: Option<String>,

    /// Flat VMDK path within the VMFS datastore (e.g., "VM-Name/VM-Name-flat.vmdk")
    #[cfg(feature = "vmfs")]
    #[arg(long, value_name = "PATH")]
    vmdk: Option<String>,

    /// List VMFS-6 devices and available flat VMDKs, then exit
    #[cfg(feature = "vmfs")]
    #[arg(long)]
    vmfs_list: bool,
}

impl Args {
    /// Whether carve mode is enabled (always false when feature is disabled).
    #[allow(dead_code)]
    fn carve(&self) -> bool {
        #[cfg(feature = "carve")]
        { self.carve }
        #[cfg(not(feature = "carve"))]
        { false }
    }
}

/// Returns true if a provider should be shown given the --provider filter.
/// Empty filter = show all providers.
fn should_show(providers: &[String], name: &str) -> bool {
    providers.is_empty() || providers.iter().any(|p| p.eq_ignore_ascii_case(name))
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

/// Prefix used by decode_password_bytes for binary (non-text) passwords.
/// Allows fmt_password to display raw hex without lossy UTF-16 re-encoding.
const RAW_HEX_PREFIX: &str = "\x00hex:";

/// Get the displayable password string, stripping internal raw-hex prefix if present.
fn display_password(password: &str) -> &str {
    password.strip_prefix(RAW_HEX_PREFIX).unwrap_or(password)
}

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
#[cfg(feature = "sam")]
fn fmt_lm_pwdump(hash: &[u8; 16]) -> String {
    if *hash == ZERO_HASH_16 {
        BLANK_LM_HEX.to_string()
    } else {
        hex::encode(hash)
    }
}

/// Format a password for display: if it contains non-printable/control characters
/// (typical of machine account random passwords), show as hex instead of garbled Unicode.
fn fmt_password(password: &str, c: &Colors) -> String {
    // Raw hex from decode_password_bytes (binary password that failed UTF-16 decode)
    if let Some(hex_str) = password.strip_prefix(RAW_HEX_PREFIX) {
        return format!("{}(hex) {}{}", c.dim, hex_str, c.reset);
    }
    let is_printable = password.chars().all(|ch| {
        !ch.is_control() && (ch.is_ascii_graphic() || ch.is_ascii_whitespace() || ch.is_alphanumeric())
    });
    if is_printable {
        format!("{}{}{}", c.red, password, c.reset)
    } else {
        // Non-printable but valid UTF-16 (e.g. CJK characters)
        let bytes: Vec<u8> = password.encode_utf16().flat_map(|w| w.to_le_bytes()).collect();
        format!("{}(hex) {}{}", c.dim, hex::encode(&bytes), c.reset)
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
    let log_level = if args.verbose {
        log::LevelFilter::Info
    } else {
        log::LevelFilter::Warn
    };
    log::set_logger(&SimpleLogger).unwrap();
    log::set_max_level(log_level);

    eprintln!("[*] vmkatz v{}", env!("CARGO_PKG_VERSION"));

    // VMFS-6 raw device mode: read flat VMDKs directly from SCSI device
    #[cfg(feature = "vmfs")]
    {
        if args.vmfs_list {
            return run_vmfs_list(args.vmfs_device.as_deref());
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
        let disk_path_str = args.disk.as_deref();
        let pagefile_reader =
            disk_path_str.and_then(
                |d| match vmkatz::paging::pagefile::PagefileReader::open(Path::new(d)) {
                    Ok(pf) => {
                        eprintln!(
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
        let disk_ref = disk_path_str.map(Path::new);
        run_lsass(input_path, &args, pagefile_reader.as_ref(), disk_ref)
    }
    #[cfg(not(feature = "sam"))]
    run_lsass(input_path, &args, (), ())
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
fn run_vmfs_list(device_filter: Option<&str>) -> anyhow::Result<()> {
    use vmkatz::disk::vmfs;

    let devices = vmfs::list_vmfs6_devices();
    if devices.is_empty() {
        eprintln!("[!] No VMFS-6 devices found in /dev/disks/");
        eprintln!("    (Are you running this on an ESXi host?)");
        return Ok(());
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
        devices
            .iter()
            .filter(|d| d.path == filter_path)
            .collect()
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
                    println!("--vmfs-device {} --vmdk '{}/{}'", dev.path.display(), vm, vmdk);
                }
            }
            Err(e) => {
                eprintln!("[!] {}: {}", dev.path.display(), e);
            }
        }
    }

    Ok(())
}

#[cfg(feature = "vmfs")]
fn run_vmfs(device_path: &Path, vmdk_path: Option<&str>, args: &Args) -> anyhow::Result<()> {
    use vmkatz::disk::vmfs;
    use vmkatz::disk::DiskImage;

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
            .map_err(|e| anyhow::anyhow!("VMFS open failed: {}", e))?;

        eprintln!(
            "{}[+] VMDK opened: {:.1} GB{}",
            c.green,
            disk.disk_size() as f64 / (1024.0 * 1024.0 * 1024.0),
            c.reset
        );

        // Extract secrets via the standard pipeline
        match vmkatz::sam::extract_secrets_from_reader(&mut disk) {
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
            }
            Err(e) => {
                eprintln!("[!] Extraction failed for {}: {}", vmdk, e);
            }
        }
    } else {
        // Auto-scan mode: list all VMs and extract from each
        eprintln!(
            "{}[*] VMFS-6: Scanning all VMs on {}{}",
            c.cyan,
            device_path.display(),
            c.reset
        );

        let vmdks = vmfs::list_vmfs6_vmdks(device_path)
            .map_err(|e| anyhow::anyhow!("VMFS scan failed: {}", e))?;

        if vmdks.is_empty() {
            anyhow::bail!("No flat VMDKs found on VMFS-6 datastore");
        }

        eprintln!("[+] Found {} flat VMDKs:", vmdks.len());
        for (vm, vmdk) in &vmdks {
            eprintln!("    {}/{}", vm, vmdk);
        }

        for (vm_name, vmdk_name) in &vmdks {
            let vmdk_path = format!("{}/{}", vm_name, vmdk_name);
            eprintln!(
                "\n{}[*] Processing: {}{}",
                c.cyan, vmdk_path, c.reset
            );

            match vmfs::open_vmfs6_vmdk(device_path, &vmdk_path) {
                Ok(mut disk) => {
                    // Quick check: skip VMDKs with no NTFS partitions (Linux/BSD VMs)
                    if !has_ntfs_partitions(&mut disk) {
                        eprintln!("[-] {}: no NTFS partitions, skipping", vm_name);
                        continue;
                    }
                    // Use NTFS-only extraction (no raw fallback scans) for batch mode
                    match vmkatz::sam::extract_secrets_ntfs_only(&mut disk) {
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
                        }
                        Err(e) => {
                            eprintln!("[!] {}: {}", vm_name, e);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[!] Failed to open {}: {}", vmdk_path, e);
                }
            }
        }
    }

    Ok(())
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
        eprintln!("[*] SAM hash extraction from: {}", input_path.display());
    }

    let c = get_colors(args);
    let mut found_anything = false;

    // SAM/LSA extraction — non-fatal so DPAPI masterkey scan can still proceed
    match vmkatz::sam::extract_disk_secrets(input_path) {
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
        }
        Err(e) => {
            eprintln!("[!] SAM extraction failed: {}", e);
        }
    }

    // Extract DPAPI master key hashes from user profiles (independent of SAM)
    let dpapi_hashes = vmkatz::sam::extract_dpapi_masterkeys(input_path);
    if !dpapi_hashes.is_empty() {
        found_anything = true;
        match args.format.as_str() {
            "csv" => print_dpapi_masterkey_csv(&dpapi_hashes),
            "hashcat" => print_dpapi_masterkey_hashcat(&dpapi_hashes),
            _ => print_dpapi_masterkey_text(&dpapi_hashes, c),
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
    let dpapi_hashes = vmkatz::sam::extract_dpapi_masterkeys(input_path);
    if !dpapi_hashes.is_empty() {
        match args.format.as_str() {
            "csv" => print_dpapi_masterkey_csv(&dpapi_hashes),
            "hashcat" => print_dpapi_masterkey_hashcat(&dpapi_hashes),
            _ => print_dpapi_masterkey_text(&dpapi_hashes, c),
        }
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

    eprintln!("\n{}[+] NTDS (raw files):{}", c.green, c.reset);
    eprintln!("  ntds.dit : {} ({} bytes)", ntds_path.display(), ctx.ntds_size);
    eprintln!("  SYSTEM   : {} ({} bytes)", system_path.display(), system_data.len());
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
    eprintln!("\n{}[+] Raw hives:{}", c.green, c.reset);
    eprintln!("  SYSTEM  : {} (bootkey: {})", hives[system_idx].0.display(), hex::encode(bootkey));

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
                eprintln!("  SAM     : {} ({} accounts)", path.display(), entries.len());
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
                    if let Ok(creds) = vmkatz::sam::cache::extract_cached_credentials(data, &nlkm.raw_data) {
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

/// Handle LSASS minidump files.
fn run_minidump(input_path: &Path, args: &Args) -> anyhow::Result<()> {
    if args.verbose {
        eprintln!("[*] Parsing LSASS minidump: {}", input_path.display());
    }

    let mdmp = vmkatz::minidump::Minidump::open(input_path)
        .context("Failed to parse minidump")?;

    if args.verbose {
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

    // Export Kerberos tickets if requested
    export_kerberos_tickets(&credentials, args);

    output_credentials(&credentials, args);

    Ok(())
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
        let user: std::borrow::Cow<str> = if entry.is_history {
            match entry.history_index {
                Some(idx) => format!("{}_history{}", entry.username, idx).into(),
                None => format!("{}_history", entry.username).into(),
            }
        } else {
            (&*entry.username).into()
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
    println!("provider,username,domain,secret_type,secret,target");
    for entry in entries {
        let provider = if entry.is_history {
            let idx = entry.history_index.unwrap_or(0);
            format!("ntds_history_{}", idx)
        } else {
            "ntds".to_string()
        };
        if entry.nt_hash != ZERO_HASH_16 {
            println!("{},{},,nt_hash,{},{}", provider, csv_escape(&entry.username), hex::encode(entry.nt_hash), entry.rid);
        }
        if entry.lm_hash != ZERO_HASH_16 {
            println!("{},{},,lm_hash,{},{}", provider, csv_escape(&entry.username), hex::encode(entry.lm_hash), entry.rid);
        }
    }
}

#[cfg(feature = "ntds.dit")]
fn print_ntds_hashcat(entries: &[vmkatz::ntds::AdHashEntry]) {
    let mut seen = std::collections::HashSet::new();
    for entry in entries {
        if entry.nt_hash != ZERO_HASH_16 && seen.insert((&entry.username, entry.nt_hash)) {
            println!("{}:{}", entry.username, hex::encode(entry.nt_hash));
        }
    }
}

#[cfg(feature = "ntds.dit")]
fn print_ntds_brief(entries: &[vmkatz::ntds::AdHashEntry]) {
    for entry in entries {
        if entry.nt_hash != ZERO_HASH_16 && !entry.is_history {
            println!("{}: {}", entry.username, hex::encode(entry.nt_hash));
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
    println!("provider,username,domain,secret_type,secret,target");
    for entry in entries {
        if entry.nt_hash != ZERO_HASH_16 {
            println!("sam,{},,nt_hash,{},{}", csv_escape(&entry.username), hex::encode(entry.nt_hash), entry.rid);
        }
        if entry.lm_hash != ZERO_HASH_16 {
            println!("sam,{},,lm_hash,{},{}", csv_escape(&entry.username), hex::encode(entry.lm_hash), entry.rid);
        }
    }
}

#[cfg(feature = "sam")]
fn print_sam_hashcat(entries: &[vmkatz::sam::SamEntry]) {
    for entry in entries {
        if entry.nt_hash != ZERO_HASH_16 {
            // hashcat mode 1000 (NTLM) with --username format
            println!("{}:{}", entry.username, hex::encode(entry.nt_hash));
        }
    }
}

#[cfg(feature = "sam")]
fn print_sam_brief(entries: &[vmkatz::sam::SamEntry]) {
    for entry in entries {
        if entry.nt_hash != ZERO_HASH_16 {
            println!("{}: {}", entry.username, hex::encode(entry.nt_hash));
        }
    }
}

#[cfg(feature = "sam")]
fn print_dcc2_csv(creds: &[vmkatz::sam::cache::CachedCredential]) {
    println!("provider,username,domain,secret_type,secret,target");
    for cred in creds {
        println!(
            "dcc2,{},{},dcc2_hash,$DCC2${}#{}#{},",
            csv_escape(&cred.username),
            csv_escape(if cred.dns_domain.is_empty() { &cred.domain } else { &cred.dns_domain }),
            cred.iteration_count,
            cred.username.to_lowercase(),
            hex::encode(cred.dcc2_hash),
        );
    }
}

#[cfg(feature = "sam")]
fn print_lsa_csv(secrets: &[vmkatz::sam::lsa::LsaSecret]) {
    println!("provider,username,domain,secret_type,secret,target");
    for secret in secrets {
        match &secret.parsed {
            vmkatz::sam::lsa::LsaSecretType::DpapiSystem { user_key, machine_key } => {
                println!("lsa,,,dpapi_user_key,{},{}", hex::encode(user_key), csv_escape(&secret.name));
                println!("lsa,,,dpapi_machine_key,{},{}", hex::encode(machine_key), csv_escape(&secret.name));
            }
            vmkatz::sam::lsa::LsaSecretType::MachineAccount { password_hex } => {
                println!("lsa,,,machine_password,{},{}", csv_escape(password_hex), csv_escape(&secret.name));
            }
            vmkatz::sam::lsa::LsaSecretType::DefaultPassword { password } => {
                println!("lsa,,,default_password,{},{}", csv_escape(password), csv_escape(&secret.name));
            }
            vmkatz::sam::lsa::LsaSecretType::ServicePassword { service, password } => {
                println!("lsa,,,service_password,{},{}", csv_escape(password), csv_escape(service));
            }
            vmkatz::sam::lsa::LsaSecretType::CachedDomainKey { key } => {
                println!("lsa,,,cached_domain_key,{},{}", hex::encode(key), csv_escape(&secret.name));
            }
            vmkatz::sam::lsa::LsaSecretType::DpapiBackupPreferred { guid } => {
                println!("lsa,,,dpapi_backup_preferred,{},{}", csv_escape(guid), csv_escape(&secret.name));
            }
            vmkatz::sam::lsa::LsaSecretType::DpapiBackupKey { guid, key_data, .. } => {
                println!("lsa,,,dpapi_backup_key,{},{}", hex::encode(key_data), csv_escape(guid));
            }
            vmkatz::sam::lsa::LsaSecretType::Raw => {
                println!("lsa,,,raw,{},{}", hex::encode(&secret.raw_data), csv_escape(&secret.name));
            }
        }
    }
}

#[cfg(feature = "sam")]
fn print_dpapi_masterkey_csv(hashes: &[vmkatz::sam::dpapi_masterkey::DpapiMasterKeyHash]) {
    println!("provider,username,domain,secret_type,secret,target");
    for h in hashes {
        println!(
            "dpapi_disk,{},{},masterkey_hash,{},{}",
            csv_escape(&h.username),
            csv_escape(&h.sid),
            csv_escape(&h.hash),
            csv_escape(&h.guid),
        );
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

#[cfg(feature = "sam")]
fn export_dpapi_backup_keys(secrets: &[vmkatz::sam::lsa::LsaSecret]) {
    for secret in secrets {
        if let vmkatz::sam::lsa::LsaSecretType::DpapiBackupKey {
            guid, pvk, ..
        } = &secret.parsed
        {
            if pvk.is_empty() {
                continue;
            }
            let filename = format!("ntds_capi_0_{}.pvk", guid);
            match std::fs::write(&filename, pvk) {
                Ok(_) => {
                    eprintln!("[+] DPAPI backup key exported: {}", filename);
                }
                Err(e) => {
                    log::warn!("Failed to write PVK file {}: {}", filename, e);
                }
            }
        }
    }
}

#[cfg(feature = "sam")]
fn print_dpapi_masterkey_text(
    hashes: &[vmkatz::sam::dpapi_masterkey::DpapiMasterKeyHash],
    c: &Colors,
) {
    println!(
        "\n{}[+] DPAPI Master Key Files ({} found):{}",
        c.green,
        hashes.len(),
        c.reset
    );
    for h in hashes {
        println!("  User: {} ({})", h.username, h.sid);
        println!("    GUID    : {}", h.guid);
        println!("    Hashcat : mode {} ({})", h.mode, if h.mode == 15300 { "3DES/SHA1" } else { "AES256/SHA512" });
        println!("    Hash    : {}", h.hash);
    }
}

#[cfg(feature = "sam")]
fn print_dpapi_masterkey_hashcat(hashes: &[vmkatz::sam::dpapi_masterkey::DpapiMasterKeyHash]) {
    for h in hashes {
        println!("{}", h.hash);
    }
}

/// Classify a snapshot file by its hypervisor type based on extension.
fn snapshot_type_label(path: &Path) -> &'static str {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
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
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    match ext.to_ascii_lowercase().as_str() {
        "vmdk" => "VMDK",
        "vdi" => "VDI",
        "qcow2" | "qcow" => "QCOW2",
        "vhdx" => "VHDX",
        "vhd" => "VHD",
        _ => "disk",
    }
}

fn run_directory(dir: &Path, args: &Args) -> anyhow::Result<()> {
    let mut discovery = vmkatz::discover::discover_vm_files(dir).context("VM file discovery failed")?;

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
        let pagefile_reader = if !discovery.lsass_files.is_empty() {
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
        let pagefile: PagefileRef<'_> = ();

        // Disk path for file-backed DLL resolution
        #[cfg(feature = "sam")]
        let disk_path: vmkatz::lsass::finder::DiskPathRef<'_> =
            discovery.disk_files.first().map(|p| p.as_path());
        #[cfg(not(feature = "sam"))]
        let disk_path: vmkatz::lsass::finder::DiskPathRef<'_> = ();

        for file in &discovery.lsass_files {
            let name = file.file_name().unwrap_or_default().to_string_lossy();
            eprintln!("\n[*] LSASS: {}", name);
            if let Err(e) = run_lsass(file, args, pagefile, disk_path) {
                eprintln!("[!] {}: {}", name, e);
            }
        }
    }

    #[cfg(feature = "sam")]
    for file in &discovery.disk_files {
        let name = file.file_name().unwrap_or_default().to_string_lossy();
        eprintln!("\n[*] SAM: {}", name);
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

/// Recursively scan a directory tree for VM files and process each VM directory.
fn run_recursive(root: &Path, args: &Args) -> anyhow::Result<()> {
    let vm_dirs = vmkatz::discover::discover_vm_directories(root)
        .context("Recursive VM discovery failed")?;

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
        eprintln!(
            "\n{}",
            "=".repeat(72)
        );
        eprintln!("[*] Processing: {}", dir.display());
        match run_directory(dir, args) {
            Ok(()) => success += 1,
            Err(e) => {
                eprintln!("[!] {}: {:#}", dir.display(), e);
                errors += 1;
            }
        }
    }

    eprintln!(
        "\n[*] Recursive scan complete: {} processed, {} errors",
        success, errors
    );
    Ok(())
}

#[allow(clippy::let_unit_value, clippy::unit_arg)]
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
    let format = detect_lsass_format(input_path, ext, args.carve());

    match format {
        LsassFormat::VBox => {
            #[cfg(feature = "vbox")]
            {
                run_with_layer(
                    || {
                        if verbose {
                            eprintln!(
                                "[*] Opening VirtualBox saved state: {}",
                                input_path.display()
                            );
                        }
                        let layer = VBoxLayer::open(input_path)
                            .context("Failed to open VirtualBox .sav file")?;
                        if verbose {
                            eprintln!(
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
                            eprintln!("[*] Opening QEMU ELF core dump: {}", input_path.display());
                        }
                        let layer = QemuElfLayer::open(input_path)
                            .context("Failed to open QEMU ELF core dump")?;
                        if verbose {
                            eprintln!(
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
        LsassFormat::QemuSavevm => {
            #[cfg(feature = "qemu")]
            {
                run_with_layer(
                    || {
                        if verbose {
                            eprintln!("[*] Opening QEMU savevm state: {}", input_path.display());
                        }
                        let layer = vmkatz::qemu::QemuSavevmLayer::open(input_path)
                            .context("Failed to open QEMU savevm state")?;
                        if verbose {
                            eprintln!(
                                "[+] QEMU savevm: {} MB physical memory",
                                layer.phys_size() / (1024 * 1024),
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
                anyhow::bail!("QEMU savevm support not enabled (compile with --features qemu)")
            }
        }
        LsassFormat::HypervBin => {
            #[cfg(feature = "hyperv")]
            {
                run_with_layer(
                    || {
                        if verbose {
                            eprintln!("[*] Opening Hyper-V memory dump: {}", input_path.display());
                        }
                        let layer = HypervLayer::open(input_path)
                            .context("Failed to open Hyper-V .bin memory dump")?;
                        if verbose {
                            eprintln!(
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
        LsassFormat::HypervVmrs => {
            #[cfg(feature = "hyperv")]
            {
                run_with_layer(
                    || {
                        if verbose {
                            eprintln!("[*] Opening Hyper-V VMRS saved state: {}", input_path.display());
                        }
                        let layer = vmkatz::hyperv::VmrsLayer::open(input_path)
                            .context("Failed to open VMRS saved state")?;
                        if verbose {
                            eprintln!(
                                "[+] VMRS: {} MB guest physical memory",
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
                            eprintln!("[*] Opening VMware memory dump: {}", input_path.display());
                        }
                        let layer = VmwareLayer::open(input_path)
                            .context("Failed to open VMware memory dump")?;
                        if verbose {
                            eprintln!("[+] VMEM mapped: {} MB", layer.phys_size() / (1024 * 1024));
                            eprintln!("[+] Memory regions: {}", layer.regions.len());
                            for (i, region) in layer.regions.iter().enumerate() {
                                eprintln!(
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
        LsassFormat::UnsupportedDisk => {
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
    QemuSavevm,
    HypervBin,
    HypervVmrs,
    Vmware,
    UnsupportedDisk,
}

/// Detect the memory snapshot format from extension and magic bytes.
#[cfg(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv"
))]
fn detect_lsass_format(path: &Path, ext: &str, carve: bool) -> LsassFormat {
    // Extension-based detection first
    if ext.eq_ignore_ascii_case("sav") {
        return LsassFormat::VBox;
    }
    if ext.eq_ignore_ascii_case("elf") {
        return LsassFormat::QemuElf;
    }
    if ext.eq_ignore_ascii_case("vmrs") {
        return LsassFormat::HypervVmrs;
    }
    if ext.eq_ignore_ascii_case("bin") {
        // Could be Hyper-V .bin, QEMU savevm, or a raw dump — check magic
        #[cfg(feature = "qemu")]
        if vmkatz::qemu::is_qemu_savevm(path) {
            return LsassFormat::QemuSavevm;
        }
        if has_elf_magic(path) {
            return LsassFormat::QemuElf;
        }
        #[cfg(feature = "hyperv")]
        if vmkatz::hyperv::is_vmrs_file(path) {
            return LsassFormat::HypervVmrs;
        }
        return LsassFormat::HypervBin;
    }
    if ext.eq_ignore_ascii_case("raw") {
        // Raw memory dump — check for QEVM/ELF magic
        #[cfg(feature = "qemu")]
        if vmkatz::qemu::is_qemu_savevm(path) {
            return LsassFormat::QemuSavevm;
        }
        if has_elf_magic(path) {
            return LsassFormat::QemuElf;
        }
        return LsassFormat::HypervBin;
    }

    // For unknown extensions, try magic-based detection
    #[cfg(feature = "qemu")]
    if vmkatz::qemu::is_qemu_savevm(path) {
        return LsassFormat::QemuSavevm;
    }
    if has_elf_magic(path) {
        return LsassFormat::QemuElf;
    }

    // Known VMware extensions always use VMware format
    if ext.eq_ignore_ascii_case("vmem")
        || ext.eq_ignore_ascii_case("vmsn")
        || ext.eq_ignore_ascii_case("vmss")
    {
        return LsassFormat::Vmware;
    }

    // Reject disk image extensions — these should never reach LSASS extraction
    if ext.eq_ignore_ascii_case("vmdk")
        || ext.eq_ignore_ascii_case("vdi")
        || ext.eq_ignore_ascii_case("qcow2")
        || ext.eq_ignore_ascii_case("qcow")
        || ext.eq_ignore_ascii_case("vhdx")
        || ext.eq_ignore_ascii_case("vhd")
    {
        return LsassFormat::UnsupportedDisk;
    }

    // In carve mode, truly unknown files default to identity-mapped raw (HypervBin)
    if carve {
        return LsassFormat::HypervBin;
    }

    // Default: VMware (anything else)
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

#[cfg(all(
    feature = "carve",
    any(
        feature = "vmware",
        feature = "vbox",
        feature = "qemu",
        feature = "hyperv"
    )
))]
fn run_carve<L: PhysicalMemory>(
    layer: &L,
    args: &Args,
    pagefile: PagefileRef<'_>,
    disk_path: lsass::finder::DiskPathRef<'_>,
) -> anyhow::Result<()> {
    let credentials = lsass::carve::carve_credentials(layer, pagefile, disk_path);

    if credentials.is_empty() {
        anyhow::bail!("Carve mode: no credentials found");
    }

    output_credentials(&credentials, args);

    Ok(())
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

    // -- Phase 1: Direct L1 scan for System process --
    let t_system = std::time::Instant::now();
    match process::find_system_process_auto(&layer) {
        Ok((system, eprocess_offsets)) => {
            eprintln!("[*] System discovery: {:?}", t_system.elapsed());
            run_with_system(
                &layer,
                &system,
                &eprocess_offsets,
                args,
                verbose,
                pagefile,
                disk_path,
            )
        }
        #[cfg(feature = "carve")]
        Err(_) if !args.ept && args.carve => {
            eprintln!("[*] System process not found — falling back to carve mode");
            run_carve(&layer, args, pagefile, disk_path)
        }
        Err(_) if !args.ept => {
            anyhow::bail!("System process not found in physical memory (EPT scan disabled, use --ept to enable)");
        }
        #[cfg(feature = "carve")]
        Err(_) if args.carve && layer.is_truncated() => {
            // Truncated file + carve mode: skip expensive EPT scanning.
            // EPT is almost certainly wrong (the System process is just in the truncated
            // part). Go straight to L1 carve.
            eprintln!("[*] lsass.exe not found in process list — falling back to carve mode");
            run_carve(&layer, args, pagefile, disk_path)
        }
        Err(_) => {
            eprintln!("[*] System discovery (L1, not found): {:?}", t_system.elapsed());
            // -- Phase 2: EPT candidate scan (VBS/Hyper-V nested paging) --
            log::info!("System process not found in L1 physical memory, trying EPT scan...");
            eprintln!("[*] System process not found in L1 memory — trying nested EPT (VBS/Hyper-V)...");

            let t_ept = std::time::Instant::now();
            let candidates = vmkatz::paging::ept::find_ept_candidates(&layer)
                .context("Failed to find System process in physical memory (no valid EPT found)")?;
            eprintln!("[*] EPT candidate scan: {:?}", t_ept.elapsed());

            // Try each EPT candidate (ranked by non-zero translated pages).
            // Limit to 5 attempts — if System isn't in the top candidates, it's likely
            // not a Windows VM or VBS isn't active.
            const MAX_EPT_ATTEMPTS: usize = 5;
            let mut last_err = None;
            for (i, candidate) in candidates.iter().take(MAX_EPT_ATTEMPTS).enumerate() {
                eprintln!(
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

                // Skip EPTs that were aborted (too many mapped pages = hypervisor-level)
                if ept_layer.is_aborted() {
                    eprintln!(
                        "[*] EPT #{}: skipped (>{} mapped pages — hypervisor-level EPT)",
                        i + 1,
                        ept_layer.mapped_page_count(),
                    );
                    continue;
                }

                let mapped = ept_layer.mapped_page_count();
                // Skip EPTs too large for the page-by-page scan (>4M pages = ~16 GB)
                if mapped > 4_000_000 {
                    eprintln!(
                        "[*] EPT #{}: skipped ({} mapped pages — too large to scan)",
                        i + 1,
                        mapped,
                    );
                    continue;
                }
                eprintln!(
                    "[*] EPT #{}: {} mapped pages ({} MB of L2 space)",
                    i + 1,
                    mapped,
                    mapped * 4 / 1024,
                );

                // Single-pass scan: iterates mapped pages once, tries all offsets at each match.
                let result = process::find_system_process_ept(&ept_layer, &layer)
                    .map_err(|e| -> anyhow::Error { e.into() });

                match result {
                    Ok((system, eprocess_offsets)) => {
                        eprintln!(
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

            // -- Phase 3: Carve mode on EPT layers --
            #[cfg(feature = "carve")]
            if args.carve {
                eprintln!("[*] EPT System scan failed — trying carve mode on EPT layers...");

                // Try carve on each viable EPT layer (guest memory is behind EPT)
                for (i, candidate) in candidates.iter().take(MAX_EPT_ATTEMPTS).enumerate() {
                    let ept_layer = vmkatz::paging::ept::EptLayer::new(
                        &layer,
                        candidate.pml4_addr,
                        candidate.l2_size,
                    );
                    if ept_layer.is_aborted() {
                        continue;
                    }
                    let mapped = ept_layer.mapped_page_count();
                    if !(100..=4_000_000).contains(&mapped) {
                        continue;
                    }
                    eprintln!(
                        "[*] Carve: trying EPT #{} ({} mapped pages, {} MB)",
                        i + 1,
                        mapped,
                        mapped * 4 / 1024,
                    );
                    match run_carve(&ept_layer, args, pagefile, disk_path) {
                        Ok(()) => return Ok(()),
                        Err(e) => {
                            log::info!("Carve EPT #{}: {}", i + 1, e);
                        }
                    }
                }

                // -- Phase 4: Carve L1 directly (non-VBS VMs) --
                eprintln!("[*] Carve: falling back to L1 physical memory");
                return run_carve(&layer, args, pagefile, disk_path);
            }

            Err(last_err
                .unwrap_or_else(|| vmkatz::error::VmkatzError::SystemProcessNotFound.into()))
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
    let t_enum = std::time::Instant::now();
    let processes = process::enumerate_processes(layer, system, eprocess_offsets)
        .context("Failed to enumerate processes")?;
    eprintln!("[*] Process enumeration: {:?}", t_enum.elapsed());

    if verbose {
        eprintln!("[+] Found {} processes:", processes.len());
        for p in &processes {
            eprintln!(
                "    PID={:>6}  DTB=0x{:012x}  PEB=0x{:016x}  {}",
                p.pid, p.dtb, p.peb_vaddr, p.name
            );
        }
    }

    if args.list_processes {
        return Ok(());
    }

    // Process dump mode
    #[cfg(feature = "dump")]
    if let Some(ref dump_name) = args.dump {
        let target = find_process_by_name(&processes, dump_name)
            .ok_or_else(|| anyhow::anyhow!("Process '{}' not found in process list", dump_name))?;

        let default_output = format!("{}.dmp", dump_name.to_lowercase().trim_end_matches(".exe"));
        let output = args.output.as_deref().unwrap_or(&default_output);
        let output_path = std::path::Path::new(output);

        eprintln!(
            "[*] Dumping {} (PID={}, DTB=0x{:x})...",
            target.name, target.pid, target.dtb
        );

        vmkatz::dump::dump_process(layer, target, args.build, output_path, pagefile, disk_path)?;

        let file_size = std::fs::metadata(output_path).map(|m| m.len()).unwrap_or(0);
        eprintln!(
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
        .find(|p| p.name.eq_ignore_ascii_case("lsass.exe"));

    #[cfg(feature = "carve")]
    if lsass_proc.is_none() && args.carve {
        eprintln!("[*] lsass.exe not found in process list — falling back to carve mode");
        return run_carve(layer, args, pagefile, disk_path);
    }
    let lsass_proc =
        lsass_proc.ok_or_else(|| anyhow::anyhow!("lsass.exe not found in process list"))?;

    if verbose {
        eprintln!(
            "\n[+] LSASS: PID={}, DTB=0x{:x}, PEB=0x{:x}",
            lsass_proc.pid, lsass_proc.dtb, lsass_proc.peb_vaddr
        );
    }

    // Extract credentials (bitness-aware: dispatches to Vista+ or pre-Vista path)
    let t_creds = std::time::Instant::now();
    let credentials = match lsass::finder::extract_all_credentials_auto(
        layer,
        lsass_proc,
        system.dtb,
        eprocess_offsets,
        pagefile,
        disk_path,
    ) {
        Ok(c) => c,
        #[cfg(feature = "carve")]
        Err(e) if args.carve => {
            eprintln!(
                "[*] Credential extraction failed ({}) — falling back to carve mode",
                e
            );
            return run_carve(layer, args, pagefile, disk_path);
        }
        Err(e) => return Err(e).context("Credential extraction failed"),
    };
    eprintln!("[*] Credential extraction: {:?}", t_creds.elapsed());

    // Report pagefile resolution stats
    #[cfg(feature = "sam")]
    if let Some(pf) = pagefile {
        let resolved = pf.pages_resolved();
        if resolved > 0 {
            eprintln!("[+] Pagefile: {} pages resolved from disk", resolved);
        }
    }

    // Export Kerberos tickets if requested
    export_kerberos_tickets(&credentials, args);

    output_credentials(&credentials, args);

    Ok(())
}

#[cfg(all(
    feature = "dump",
    any(
        feature = "vmware",
        feature = "vbox",
        feature = "qemu",
        feature = "hyperv"
    )
))]
fn find_process_by_name<'a>(
    processes: &'a [vmkatz::windows::process::Process],
    name: &str,
) -> Option<&'a vmkatz::windows::process::Process> {
    // Single-pass: check both exact and .exe-appended match
    let mut exe_match = None;
    for p in processes {
        if p.name.eq_ignore_ascii_case(name) {
            return Some(p);
        }
        if exe_match.is_none()
            && p.name.len() == name.len() + 4
            && p.name[..name.len()].eq_ignore_ascii_case(name)
            && p.name[name.len()..].eq_ignore_ascii_case(".exe")
        {
            exe_match = Some(p);
        }
    }
    exe_match
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
        eprintln!("[*] No Kerberos tickets to export");
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
        eprintln!("[+] Exported {} .kirbi ticket(s) to {}", count, dir);
    }

    // --ccache: write all tickets into a single ccache file
    if let Some(ccache_path) = &args.ccache {
        let data = build_ccache(&all_tickets);
        match std::fs::write(ccache_path, &data) {
            Ok(_) => eprintln!(
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

    // Convert Windows FILETIME (100-ns ticks since 1601-01-01) to Unix timestamp
    // 10_000_000 = ticks per second, 11_644_473_600 = seconds between 1601 and 1970 epochs
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

/// Deduplicate credentials by (username, domain, nt_hash).
///
/// Sessions sharing the same identity and NT hash are merged into one entry,
/// moving data from duplicates into the first occurrence to avoid cloning.
fn dedup_credentials(credentials: &[Credential]) -> Vec<Credential> {
    // Track which index is the "representative" for each (user, domain, nt_hash) group.
    // We build a map from group key → first index, and collect donor indices.
    let no_hash = [0xFFu8; 16]; // sentinel for sessions without MSV

    // Dedup key: (username_lower, domain_lower, nt_hash)
    type DedupKey = (String, String, [u8; 16]);

    // First pass: identify groups and representative indices
    let mut repr_map: Vec<(usize, Vec<usize>)> = Vec::new(); // (repr_idx, donor_indices)
    let mut key_to_repr: Vec<(DedupKey, usize)> = Vec::new();

    for (i, cred) in credentials.iter().enumerate() {
        let nt = cred.msv.as_ref().map(|m| m.nt_hash).unwrap_or(no_hash);
        let key = (
            cred.username.to_ascii_lowercase(),
            cred.domain.to_ascii_lowercase(),
            nt,
        );

        if let Some(pos) = key_to_repr.iter().position(|(k, _)| *k == key) {
            repr_map[key_to_repr[pos].1].1.push(i);
        } else {
            let repr_idx = repr_map.len();
            repr_map.push((i, Vec::new()));
            key_to_repr.push((key, repr_idx));
        }
    }

    // Second pass: build result by taking ownership where possible
    let mut result = Vec::with_capacity(repr_map.len());

    // We need to work with the original credentials; clone only the representative
    // and merge just the unique extras from donors (DPAPI, Kerberos, CredMan).
    for (repr_idx, donor_indices) in &repr_map {
        let base = &credentials[*repr_idx];

        // For single-entry groups (no donors), just clone the credential directly
        if donor_indices.is_empty() {
            result.push(Credential {
                luid: base.luid,
                username: base.username.clone(),
                domain: base.domain.clone(),
                logon_type: base.logon_type,
                session_id: base.session_id,
                logon_time: base.logon_time,
                logon_server: base.logon_server.clone(),
                sid: base.sid.clone(),
                msv: base.msv.clone(),
                wdigest: base.wdigest.as_ref().filter(|w| !w.password.is_empty()).cloned(),
                kerberos: base.kerberos.as_ref().cloned(),
                tspkg: base.tspkg.as_ref().filter(|t| !t.password.is_empty()).cloned(),
                dpapi: base.dpapi.clone(),
                credman: base.credman.clone(),
                ssp: base.ssp.as_ref().filter(|s| !s.password.is_empty()).cloned(),
                livessp: base.livessp.as_ref().filter(|l| !l.password.is_empty()).cloned(),
                cloudap: base.cloudap.as_ref().cloned(),
            });
            continue;
        }

        // Multi-entry group: merge unique extras from donors
        let mut merged = Credential {
            luid: base.luid,
            username: base.username.clone(),
            domain: base.domain.clone(),
            logon_type: base.logon_type,
            session_id: base.session_id,
            logon_time: base.logon_time,
            logon_server: base.logon_server.clone(),
            sid: base.sid.clone(),
            msv: base.msv.clone(),
            wdigest: base.wdigest.as_ref().filter(|w| !w.password.is_empty()).cloned(),
            kerberos: base.kerberos.as_ref().cloned(),
            tspkg: base.tspkg.as_ref().filter(|t| !t.password.is_empty()).cloned(),
            dpapi: base.dpapi.clone(),
            credman: base.credman.clone(),
            ssp: base.ssp.as_ref().filter(|s| !s.password.is_empty()).cloned(),
            livessp: base.livessp.as_ref().filter(|l| !l.password.is_empty()).cloned(),
            cloudap: base.cloudap.as_ref().cloned(),
        };

        for &idx in donor_indices {
            let donor = &credentials[idx];

            // Best metadata
            if donor.logon_time != 0 && (merged.logon_time == 0 || donor.logon_time < merged.logon_time) {
                merged.logon_time = donor.logon_time;
            }
            if merged.sid.is_empty() && !donor.sid.is_empty() {
                merged.sid.clone_from(&donor.sid);
            }
            if merged.logon_server.is_empty() && !donor.logon_server.is_empty() {
                merged.logon_server.clone_from(&donor.logon_server);
            }

            // WDigest: keep first non-empty
            if merged.wdigest.is_none() {
                if let Some(wd) = donor.wdigest.as_ref().filter(|w| !w.password.is_empty()) {
                    merged.wdigest = Some(wd.clone());
                }
            }

            // Kerberos: merge unique keys, tickets, password
            if let Some(donor_krb) = &donor.kerberos {
                if let Some(merged_krb) = &mut merged.kerberos {
                    if merged_krb.password.is_empty() && !donor_krb.password.is_empty() {
                        merged_krb.password.clone_from(&donor_krb.password);
                    }
                    for key in &donor_krb.keys {
                        if merged_krb.keys.iter().all(|k| k.key != key.key) {
                            merged_krb.keys.push(KerberosKey { etype: key.etype, key: key.key.clone() });
                        }
                    }
                    for ticket in &donor_krb.tickets {
                        if merged_krb.tickets.iter().all(|t| t.service_name != ticket.service_name) {
                            merged_krb.tickets.push(ticket.clone());
                        }
                    }
                } else {
                    merged.kerberos = Some(donor_krb.clone());
                }
            }

            // DPAPI: collect unique by GUID
            for dk in &donor.dpapi {
                if !merged.dpapi.iter().any(|d| d.guid == dk.guid) {
                    merged.dpapi.push(dk.clone());
                }
            }

            // CredMan: collect unique by target
            for cm in &donor.credman {
                if !merged.credman.iter().any(|c| c.target == cm.target) {
                    merged.credman.push(cm.clone());
                }
            }

            // TsPkg, SSP, LiveSSP, CloudAP: keep first non-empty
            if merged.tspkg.is_none() {
                merged.tspkg = donor.tspkg.as_ref().filter(|t| !t.password.is_empty()).cloned();
            }
            if merged.ssp.is_none() {
                merged.ssp = donor.ssp.as_ref().filter(|s| !s.password.is_empty()).cloned();
            }
            if merged.livessp.is_none() {
                merged.livessp = donor.livessp.as_ref().filter(|l| !l.password.is_empty()).cloned();
            }
            if merged.cloudap.is_none() {
                merged.cloudap = donor.cloudap.as_ref().cloned();
            }
        }

        result.push(merged);
    }

    result
}

fn print_text(credentials: &[Credential], c: &Colors, show_all: bool, verbose: bool, providers: &[String]) {
    use vmkatz::lsass::types::{filetime_to_string, logon_type_name};

    let with_creds = credentials.iter().filter(|cr| cr.has_credentials()).count();
    let hidden = credentials.len() - with_creds;
    println!(
        "\n{}[+]{} {} logon session(s), {} with credentials{}:\n",
        c.green, c.reset, credentials.len(), with_creds,
        if !show_all && hidden > 0 {
            format!(" ({} empty sessions hidden, use -a to show)", hidden)
        } else {
            String::new()
        },
    );
    for cred in credentials {
        if !show_all && !cred.has_credentials() {
            continue;
        }

        // LUID header
        use vmkatz::lsass::types::{LUID_SYSTEM, LUID_NETWORK_SERVICE, LUID_LOCAL_SERVICE, LUID_IUSR};
        let luid_label = match cred.luid {
            LUID_SYSTEM => " (SYSTEM)",
            LUID_NETWORK_SERVICE => " (NETWORK SERVICE)",
            LUID_LOCAL_SERVICE => " (LOCAL SERVICE)",
            LUID_IUSR => " (IUSER)",
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
        if !cred.username.is_empty() {
            println!("  {}Username: {}{}", c.bold, cred.username, c.reset);
        }
        if !cred.domain.is_empty() {
            println!("  Domain: {}", cred.domain);
        }
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
            if should_show(providers, "msv") {
                println!("  {}[MSV1_0]{}", c.cyan, c.reset);
                if msv.lm_hash != ZERO_HASH_16 {
                    println!("    LM Hash : {}", fmt_hash(&msv.lm_hash, c));
                }
                println!("    NT Hash : {}", fmt_hash(&msv.nt_hash, c));
                println!("    SHA1    : {}", fmt_hash(&msv.sha1_hash, c));
                // DPAPI protection key = SHA1(NT password) — same as SHA1 hash for local accounts.
                // Shown separately for mimikatz compatibility and offline DPAPI decryption workflows.
                println!("    DPAPI   : {}", fmt_hash(&msv.sha1_hash, c));
            }
        }
        if let Some(wd) = &cred.wdigest {
            if !wd.password.is_empty() && !cred.username.ends_with('$') && should_show(providers, "wdigest") {
                println!("  {}[WDigest]{}", c.cyan, c.reset);
                println!("    Password: {}", fmt_password(&wd.password, c));
            }
        }
        if let Some(krb) = &cred.kerberos {
            if should_show(providers, "kerberos") {
                println!("  {}[Kerberos]{}", c.cyan, c.reset);
                // Skip machine account passwords (binary blobs, use keys instead)
                if !krb.password.is_empty() && !cred.username.ends_with('$') {
                    println!("    Password: {}", fmt_password(&krb.password, c));
                }
                // Deduplicate keys by value — show each unique key once with primary etype
                let mut seen_keys: Vec<(&[u8], &str)> = Vec::new();
                for key in &krb.keys {
                    if !seen_keys.iter().any(|(k, _)| *k == key.key.as_slice()) {
                        seen_keys.push((&key.key, key.etype_name()));
                    }
                }
                for (key_bytes, etype_name) in &seen_keys {
                    println!(
                        "    {:11}: {}",
                        etype_name,
                        hex::encode(key_bytes)
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
                    if verbose {
                        println!(
                            "      Kirbi  : {} bytes (base64: {})",
                            ticket.kirbi.len(),
                            vmkatz::lsass::base64_encode(&ticket.kirbi)
                        );
                    } else {
                        println!("      Kirbi  : {} bytes", ticket.kirbi.len());
                    }
                }
            }
        }
        if let Some(ts) = &cred.tspkg {
            if !ts.password.is_empty() && should_show(providers, "tspkg") {
                println!("  {}[TsPkg]{}", c.cyan, c.reset);
                println!("    Password: {}", fmt_password(&ts.password, c));
            }
        }
        if should_show(providers, "dpapi") {
            for dk in &cred.dpapi {
                println!("  {}[DPAPI]{}", c.cyan, c.reset);
                println!("    GUID          : {}", dk.guid);
                println!("    MasterKey     : {}{}{}", c.yellow, hex::encode(&dk.key), c.reset);
                println!("    SHA1 MasterKey: {}{}{}", c.yellow, hex::encode(dk.sha1_masterkey), c.reset);
            }
        }
        if !cred.credman.is_empty() && should_show(providers, "credman") {
            println!("  {}[CredMan]{}", c.cyan, c.reset);
            for cm in &cred.credman {
                println!("    Target  : {}", cm.target);
                println!("    Username: {}", cm.username);
                println!("    Domain  : {}", cm.domain);
                println!("    Password: {}", fmt_password(&cm.password, c));
            }
        }
        if let Some(ssp) = &cred.ssp {
            if !ssp.password.is_empty() && should_show(providers, "ssp") {
                println!("  {}[SSP]{}", c.cyan, c.reset);
                println!("    Username: {}", ssp.username);
                println!("    Domain  : {}", ssp.domain);
                println!("    Password: {}", fmt_password(&ssp.password, c));
            }
        }
        if let Some(live) = &cred.livessp {
            if !live.password.is_empty() && should_show(providers, "livessp") {
                println!("  {}[LiveSSP]{}", c.cyan, c.reset);
                println!("    Username: {}", live.username);
                println!("    Domain  : {}", live.domain);
                println!("    Password: {}", fmt_password(&live.password, c));
            }
        }
        if let Some(cap) = &cred.cloudap {
            if should_show(providers, "cloudap") {
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
        }
        println!();
    }
}

fn csv_escape(s: &str) -> String {
    let sanitized: String = s.chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .collect();
    if sanitized.contains(',') || sanitized.contains('"') || sanitized.contains('\n') {
        format!("\"{}\"", sanitized.replace('"', "\"\""))
    } else {
        sanitized
    }
}

fn print_csv(credentials: &[Credential], providers: &[String]) {
    println!("provider,username,domain,secret_type,secret,target");
    for cred in credentials.iter().filter(|c| c.has_credentials()) {
        let user = csv_escape(&cred.username);
        let dom = csv_escape(&cred.domain);

        if should_show(providers, "msv") {
            if let Some(msv) = &cred.msv {
                if msv.nt_hash != ZERO_HASH_16 {
                    println!("msv,{},{},nt_hash,{},", user, dom, hex::encode(msv.nt_hash));
                }
                if msv.lm_hash != ZERO_HASH_16 {
                    println!("msv,{},{},lm_hash,{},", user, dom, hex::encode(msv.lm_hash));
                }
                if msv.sha1_hash != [0u8; 20] {
                    println!("msv,{},{},sha1,{},", user, dom, hex::encode(msv.sha1_hash));
                }
            }
        }

        if should_show(providers, "wdigest") {
            if let Some(wd) = &cred.wdigest {
                if !wd.password.is_empty() {
                    println!("wdigest,{},{},password,{},", user, dom, csv_escape(display_password(&wd.password)));
                }
            }
        }

        if should_show(providers, "kerberos") {
            if let Some(krb) = &cred.kerberos {
                if !krb.password.is_empty() {
                    println!("kerberos,{},{},password,{},", user, dom, csv_escape(display_password(&krb.password)));
                }
                for key in &krb.keys {
                    println!(
                        "kerberos,{},{},{},{},",
                        user, dom, key.etype_name(), hex::encode(&key.key)
                    );
                }
                for ticket in &krb.tickets {
                    let svc = ticket.service_name.join("/");
                    println!(
                        "kerberos,{},{},ticket_{},{},{}",
                        user, dom,
                        ticket.ticket_type.to_string().to_ascii_lowercase(),
                        vmkatz::lsass::base64_encode(&ticket.kirbi),
                        csv_escape(&svc),
                    );
                }
            }
        }

        if should_show(providers, "tspkg") {
            if let Some(ts) = &cred.tspkg {
                if !ts.password.is_empty() {
                    println!("tspkg,{},{},password,{},", user, dom, csv_escape(display_password(&ts.password)));
                }
            }
        }

        if should_show(providers, "ssp") {
            if let Some(ssp) = &cred.ssp {
                if !ssp.password.is_empty() {
                    println!(
                        "ssp,{},{},password,{},",
                        csv_escape(&ssp.username), csv_escape(&ssp.domain),
                        csv_escape(display_password(&ssp.password))
                    );
                }
            }
        }

        if should_show(providers, "livessp") {
            if let Some(live) = &cred.livessp {
                if !live.password.is_empty() {
                    println!(
                        "livessp,{},{},password,{},",
                        csv_escape(&live.username), csv_escape(&live.domain),
                        csv_escape(display_password(&live.password))
                    );
                }
            }
        }

        if should_show(providers, "credman") {
            for cm in &cred.credman {
                if !cm.password.is_empty() {
                    println!(
                        "credman,{},{},password,{},{}",
                        csv_escape(&cm.username), csv_escape(&cm.domain),
                        csv_escape(&cm.password), csv_escape(&cm.target)
                    );
                }
            }
        }

        if should_show(providers, "dpapi") {
            for dk in &cred.dpapi {
                println!(
                    "dpapi,{},{},masterkey,{},{}",
                    user, dom, hex::encode(&dk.key), csv_escape(&dk.guid)
                );
                println!(
                    "dpapi,{},{},sha1_masterkey,{},{}",
                    user, dom, hex::encode(dk.sha1_masterkey), csv_escape(&dk.guid)
                );
            }
        }

        if should_show(providers, "cloudap") {
            if let Some(cap) = &cred.cloudap {
                if !cap.dpapi_key.is_empty() {
                    println!(
                        "cloudap,{},{},dpapi_key,{},",
                        csv_escape(&cap.username), csv_escape(&cap.domain),
                        hex::encode(&cap.dpapi_key)
                    );
                }
                if !cap.prt.is_empty() {
                    println!(
                        "cloudap,{},{},prt,{},",
                        csv_escape(&cap.username), csv_escape(&cap.domain),
                        csv_escape(&cap.prt)
                    );
                }
            }
        }
    }
}

/// Apply dedup (unless --all) and print credentials in the requested format.
fn output_credentials(credentials: &[Credential], args: &Args) {
    let deduped;
    let creds = if args.all {
        credentials
    } else {
        deduped = dedup_credentials(credentials);
        &deduped
    };

    let c = get_colors(args);
    match args.format.as_str() {
        "csv" => print_csv(creds, &args.provider),
        "ntlm" => print_ntlm(creds, &args.provider),
        "hashcat" => print_hashcat(creds, &args.provider),
        "brief" => print_brief(creds, &args.provider),
        _ => print_text(creds, c, args.all, args.verbose, &args.provider),
    }
    report_extraction_summary(creds, &args.format);
}

/// Report a summary of extraction results to stderr.
///
/// For `ntlm`/`hashcat` formats, reports when zero hashes were found (so users can
/// distinguish success-with-no-hashes from tool failure). For `text`, provides counts.
fn report_extraction_summary(credentials: &[Credential], format: &str) {
    let with_hash = credentials
        .iter()
        .filter(|c| {
            c.msv
                .as_ref()
                .is_some_and(|m| m.nt_hash != ZERO_HASH_16)
        })
        .count();
    let with_pw = credentials
        .iter()
        .filter(|c| {
            // Don't count machine account passwords (binary blobs, not useful)
            let is_machine = c.username.ends_with('$');
            (!is_machine
                && (c.wdigest.as_ref().is_some_and(|w| !w.password.is_empty())
                    || c.kerberos.as_ref().is_some_and(|k| !k.password.is_empty())))
                || c.tspkg.as_ref().is_some_and(|t| !t.password.is_empty())
        })
        .count();

    if matches!(format, "ntlm" | "hashcat") && with_hash == 0 {
        eprintln!(
            "[*] No NTLM hashes found ({} sessions examined)",
            credentials.len()
        );
    } else if matches!(format, "text" | "brief") {
        eprintln!(
            "[*] {} sessions, {} NT hashes, {} plaintext passwords",
            credentials.len(),
            with_hash,
            with_pw
        );
    }
}

fn print_ntlm(credentials: &[Credential], providers: &[String]) {
    let mut seen = std::collections::HashSet::new();
    for cred in credentials.iter().filter(|c| c.has_credentials()) {
        if !should_show(providers, "msv") {
            continue;
        }
        if let Some(msv) = &cred.msv {
            let key = (cred.username.clone(), cred.domain.clone(), msv.nt_hash);
            if msv.nt_hash != ZERO_HASH_16 && seen.insert(key) {
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

fn print_hashcat(credentials: &[Credential], providers: &[String]) {
    let mut seen = std::collections::HashSet::new();
    for cred in credentials.iter().filter(|c| c.has_credentials()) {
        if !should_show(providers, "msv") {
            continue;
        }
        // hashcat mode 1000 (NTLM) with --username format
        if let Some(msv) = &cred.msv {
            let key = (cred.username.clone(), cred.domain.clone(), msv.nt_hash);
            if msv.nt_hash != ZERO_HASH_16 && seen.insert(key) {
                println!("{}\\{}:{}", cred.domain, cred.username, hex::encode(msv.nt_hash));
            }
        }
    }
}

fn print_brief(credentials: &[Credential], providers: &[String]) {
    for cred in credentials.iter().filter(|c| c.has_credentials()) {
        let identity = if cred.domain.is_empty() {
            cred.username.clone()
        } else {
            format!("{}\\{}", cred.domain, cred.username)
        };
        let mut lines: Vec<String> = Vec::new();

        if should_show(providers, "msv") {
            if let Some(msv) = &cred.msv {
                if msv.nt_hash != ZERO_HASH_16 {
                    lines.push(format!("    NT      : {}", hex::encode(msv.nt_hash)));
                }
            }
        }
        if should_show(providers, "wdigest") {
            if let Some(wd) = &cred.wdigest {
                if !wd.password.is_empty() {
                    lines.push(format!("    WDigest : {}", fmt_password(&wd.password, &COLORS_OFF)));
                }
            }
        }
        if should_show(providers, "kerberos") {
            if let Some(krb) = &cred.kerberos {
                if !krb.password.is_empty() {
                    lines.push(format!("    Kerberos: {}", fmt_password(&krb.password, &COLORS_OFF)));
                }
            }
        }
        if should_show(providers, "tspkg") {
            if let Some(ts) = &cred.tspkg {
                if !ts.password.is_empty() {
                    lines.push(format!("    TsPkg   : {}", fmt_password(&ts.password, &COLORS_OFF)));
                }
            }
        }
        if should_show(providers, "ssp") {
            if let Some(ssp) = &cred.ssp {
                if !ssp.password.is_empty() {
                    lines.push(format!("    SSP     : {}", fmt_password(&ssp.password, &COLORS_OFF)));
                }
            }
        }
        if should_show(providers, "livessp") {
            if let Some(live) = &cred.livessp {
                if !live.password.is_empty() {
                    lines.push(format!("    LiveSSP : {}", fmt_password(&live.password, &COLORS_OFF)));
                }
            }
        }
        if should_show(providers, "credman") {
            for cm in &cred.credman {
                if !cm.password.is_empty() {
                    lines.push(format!("    CredMan : {} ({})", fmt_password(&cm.password, &COLORS_OFF), cm.target));
                }
            }
        }

        if !lines.is_empty() {
            println!("  {}", identity);
            for line in &lines {
                println!("{}", line);
            }
            println!();
        }
    }
}
