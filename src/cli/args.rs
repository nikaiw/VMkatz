//! Command-line arguments, terminal colours and input-file classification.

use std::path::Path;

use clap::Parser;

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
        vmkatz --chrome disk.vmdk                    Discover browser profiles (build with --features chrome)\n  \
        vmkatz -v snapshot.vmsn                     Verbose output with process list"
)]
pub(crate) struct Args {
    /// Path(s) to snapshot, disk image, raw hive/NTDS files, or VM directory
    #[arg(value_name = "FILE", num_args = 0..)]
    pub(crate) input_paths: Vec<String>,

    /// Only list processes (skip credential extraction)
    #[arg(long, default_value_t = false)]
    pub(crate) list_processes: bool,

    /// Force SAM hash extraction mode (auto-detected for .vdi/.vmdk/.qcow2/.vhdx/.vhd)
    #[cfg(feature = "sam")]
    #[arg(long, default_value_t = false)]
    pub(crate) sam: bool,

    /// Try NTDS.dit extraction workflow (Windows/NTDS/ntds.dit + SYSTEM bootkey)
    #[cfg(feature = "ntds.dit")]
    #[arg(long, default_value_t = false)]
    pub(crate) ntds: bool,

    /// Include NTDS password history hashes (when available)
    #[cfg(feature = "ntds.dit")]
    #[arg(long, default_value_t = false)]
    pub(crate) ntds_history: bool,

    /// Disk image for pagefile.sys resolution (resolves paged-out memory from disk)
    #[cfg(feature = "sam")]
    #[arg(long, value_name = "DISK_IMAGE")]
    pub(crate) disk: Option<String>,

    /// Dump a process's virtual memory as minidump (.dmp) file
    #[cfg(feature = "dump")]
    #[arg(long, value_name = "PROCESS_NAME")]
    pub(crate) dump: Option<String>,

    /// Output file for --dump (default: <process>.dmp)
    #[cfg(feature = "dump")]
    #[arg(short, long, value_name = "FILE")]
    pub(crate) output: Option<String>,

    /// Windows build number for minidump header (default: 19045)
    #[cfg(feature = "dump")]
    #[arg(long, default_value_t = 19045, value_name = "NUMBER")]
    pub(crate) build: u32,

    /// Output format
    #[arg(long, default_value = "text", value_name = "FORMAT", value_parser = ["text", "csv", "ntlm", "hashcat", "brief"])]
    pub(crate) format: String,

    /// Color output (auto=detect terminal, always, never)
    #[arg(long, default_value = "auto", value_name = "WHEN", value_parser = ["auto", "always", "never"])]
    pub(crate) color: String,

    /// Export Kerberos tickets as .kirbi files to a directory
    #[arg(long, value_name = "DIR")]
    pub(crate) kirbi: Option<String>,

    /// Export Kerberos tickets as a single ccache file (MIT Kerberos format)
    #[arg(long, value_name = "FILE")]
    pub(crate) ccache: Option<String>,

    /// Export `BitLocker` FVEK keys as dislocker-compatible .fvek files to a directory
    #[arg(long, value_name = "DIR")]
    pub(crate) bitlocker_fvek: Option<String>,

    /// Verbose output (show memory regions, process list, etc.)
    #[arg(short, long, default_value_t = false)]
    pub(crate) verbose: bool,

    /// Show all logon sessions (disables deduplication and shows empty sessions)
    #[arg(short, long, default_value_t = false)]
    pub(crate) all: bool,

    /// Enable nested EPT scanning (for VBS/Credential Guard VMs)
    #[arg(long, default_value_t = false)]
    pub(crate) ept: bool,

    /// Recursively scan directory for VM snapshot and disk image files
    #[arg(short, long, default_value_t = false)]
    pub(crate) recurse: bool,

    /// Filter file types in directory/recursive mode (all, snapshot, disk)
    #[arg(long, default_value = "all", value_name = "TYPE", value_parser = ["all", "snapshot", "disk"])]
    pub(crate) scan: String,

    /// Filter output to specific providers (comma-separated: msv,wdigest,kerberos,tspkg,dpapi,ssp,livessp,credman,cloudap)
    #[arg(long, value_delimiter = ',', value_name = "LIST")]
    pub(crate) provider: Vec<String>,

    /// Carve credentials from partial/truncated/raw memory files
    #[cfg(feature = "carve")]
    #[arg(long, default_value_t = false)]
    pub(crate) carve: bool,

    /// Extract browser secrets (Chromium + Firefox). Requires --features chrome at build time.
    #[arg(long, default_value_t = false)]
    pub(crate) chrome: bool,

    /// Emit chrome findings as JSON instead of pretty text.
    #[arg(long, default_value_t = false)]
    pub(crate) chrome_json: bool,

    /// Extra password candidate to try when decrypting user DPAPI masterkey
    /// files (repeatable). Useful when the password isn't in LSA — e.g. you
    /// got it from cracking, pivoting, or just know it's a vuln-lab default.
    #[arg(long, value_name = "PASSWORD")]
    pub(crate) chrome_password: Vec<String>,

    /// NT hash for DPAPI masterkey decrypt (repeatable). Bare hex tries all
    /// users; `SID:HEX` targets one. For domain users not in the local SAM.
    #[arg(long, value_name = "[SID:]HEX")]
    pub(crate) chrome_nthash: Vec<String>,

    /// Also scan running chrome.exe / msedge.exe / brave.exe process memory
    /// for cookies and saved passwords (ChromeKatz-style). Uses heuristic
    /// pattern matching, so the disk-side decrypt is more reliable; this
    /// flag is best used when the disk path is unavailable or when you want
    /// in-flight values that haven't been persisted yet (e.g. Edge's recent
    /// memory-resident password disclosures).
    #[arg(long, default_value_t = false)]
    pub(crate) chrome_process_scan: bool,

    /// VMFS-6 raw SCSI device for reading flat VMDKs through VMFS locks
    #[cfg(feature = "vmfs")]
    #[arg(long, value_name = "DEVICE")]
    pub(crate) vmfs_device: Option<String>,

    /// Flat VMDK path within the VMFS datastore (e.g., "VM-Name/VM-Name-flat.vmdk")
    #[cfg(feature = "vmfs")]
    #[arg(long, value_name = "PATH")]
    pub(crate) vmdk: Option<String>,

    /// List VMFS-6 devices and available flat VMDKs, then exit
    #[cfg(feature = "vmfs")]
    #[arg(long)]
    pub(crate) vmfs_list: bool,

    /// Skip carving SAM/SYSTEM/SECURITY registry hives from physical memory. By
    /// default that carve runs first on a memory snapshot (local NT hashes + LSA
    /// secrets, no page tables — works under Credential Guard) and, when it finds
    /// credentials, is the whole result; this flag disables it and goes straight to
    /// the LSASS-cache pipeline.
    #[cfg(feature = "sam")]
    #[arg(long, default_value_t = false)]
    pub(crate) no_mem_registry: bool,

    /// Password for an encrypted Veeam backup (VBK/VIB/VRB). Not needed for
    /// unencrypted backups.
    #[cfg(feature = "veeam")]
    #[arg(long, value_name = "PASSWORD")]
    pub(crate) veeam_password: Option<String>,

    /// List the catalogue (stored VMs/files) of a Veeam backup, then exit.
    #[cfg(feature = "veeam")]
    #[arg(long)]
    pub(crate) veeam_list: bool,

    /// Reconstruct one stored file from a Veeam backup by exact catalogue name
    /// or stable path (e.g. a NTDS.dit or a registry hive), then exit.
    #[cfg(feature = "veeam")]
    #[arg(long, value_name = "NAME")]
    pub(crate) veeam_extract: Option<String>,

    /// Destination path for --veeam-extract (default: the item's basename in the
    /// current directory). Never overwrites an existing file.
    #[cfg(feature = "veeam")]
    #[arg(long, value_name = "PATH")]
    pub(crate) veeam_output: Option<String>,
}

impl Args {
    /// Whether carve mode is enabled (always false when feature is disabled).
    pub(crate) const fn carve(&self) -> bool {
        #[cfg(feature = "carve")]
        {
            self.carve
        }
        #[cfg(not(feature = "carve"))]
        {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Terminal color support
// ---------------------------------------------------------------------------

/// ANSI color escape sequences (empty strings when disabled).
pub(crate) struct Colors {
    pub(crate) reset: &'static str,
    pub(crate) bold: &'static str,
    pub(crate) dim: &'static str,
    pub(crate) green: &'static str,
    pub(crate) yellow: &'static str,
    pub(crate) cyan: &'static str,
    pub(crate) red: &'static str,
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

pub(crate) const COLORS_OFF: Colors = Colors {
    reset: "",
    bold: "",
    dim: "",
    green: "",
    yellow: "",
    cyan: "",
    red: "",
};

pub(crate) fn get_colors(args: &Args) -> &'static Colors {
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
// File type detection by magic bytes
// ---------------------------------------------------------------------------

/// File type detected from magic bytes at the start of the file.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum RawFileType {
    EseDatabase,  // NTDS.dit (0xEFCDAB89 at offset 4)
    RegistryHive, // SAM/SYSTEM/SECURITY ("regf" at offset 0)
    Minidump,     // LSASS dump ("MDMP" at offset 0)
    Other,
}

pub(crate) fn detect_file_type(path: &Path) -> RawFileType {
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

/// Check if a path is a block device (Linux /dev/...).
#[cfg(feature = "sam")]
// Windows: the unix branch is cfg'd out, leaving a trivially-const `false`.
#[cfg_attr(not(unix), allow(clippy::missing_const_for_fn))]
pub(crate) fn is_block_dev(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        std::fs::metadata(path).is_ok_and(|m| m.file_type().is_block_device())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

/// Parse `--chrome-nthash` specs into `(SID, 16-byte NT hash)` pairs.
/// Accepts `SID:HEX` (targeted) or bare `HEX` (tried against all users).
#[cfg(feature = "chrome")]
pub(crate) fn parse_chrome_nthashes(specs: &[String]) -> Vec<(String, [u8; 16])> {
    let mut out: Vec<(String, [u8; 16])> = Vec::new();
    for spec in specs {
        let (sid, hex_str) = match spec.split_once(':') {
            Some((s, h)) => (s, h),
            None => ("", spec.as_str()),
        };
        let Ok(bytes) = hex::decode(hex_str.trim()) else {
            log::warn!("--chrome-nthash: invalid hex in {spec:?}");
            continue;
        };
        let Ok(nt_hash) = <[u8; 16]>::try_from(bytes.as_slice()) else {
            log::warn!("--chrome-nthash: NT hash must be 16 bytes in {spec:?}");
            continue;
        };
        out.push((sid.to_string(), nt_hash));
    }
    out
}
