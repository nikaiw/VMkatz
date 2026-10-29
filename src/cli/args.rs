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
        vmkatz --credman disk.vmdk                   Decrypt Windows Credential Manager (offline)\n  \
        vmkatz --credman --credman-attributes disk.vmdk   Also enumerate credential attributes (encrypted values; offline decryption unsupported)\n  \
        vmkatz --credman --dpapi-password vmkz:P@ss disk.vmdk   Supply a local user's password (needed to open their masterkey)\n  \
        vmkatz --ls disk.vmdk                       List root of each NTFS partition\n  \
        vmkatz --ls='\\Windows\\System32\\config' disk.vmdk   List a directory (read-only)\n  \
        vmkatz --partition 0x100000 disk.vmdk       Restrict to one partition (byte offset)\n  \
        vmkatz --vmfs-device /dev/sdb --vmdk 'DC01/DC01-flat.vmdk' --ls   List from VMFS\n  \
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

    /// List a directory on the NTFS partition(s) of a disk image (default: root)
    #[cfg(feature = "sam")]
    #[arg(long, value_name = "PATH", num_args = 0..=1, default_missing_value = "", require_equals = true)]
    pub(crate) ls: Option<String>,

    /// Restrict --ls and extraction to the NTFS partition at this byte offset (decimal or 0x hex)
    #[cfg(feature = "sam")]
    #[arg(long, value_name = "OFFSET", value_parser = parse_offset)]
    pub(crate) partition: Option<u64>,

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
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub(crate) verbose: u8,

    /// Show all logon sessions (disables deduplication and shows empty sessions).
    /// On a disk/VMDK, also extract every secret type (SAM/LSA/DCC2 + NTDS + DPAPI).
    #[arg(short, long, default_value_t = false)]
    pub(crate) all: bool,

    /// Copy a file out of the disk image's NTFS to a local path, e.g.
    /// --cp '\Windows\NTDS\ntds.dit' ./ntds.dit (disk images and VMFS --vmdk; honours --partition)
    #[arg(long, num_args = 2, value_names = ["SRC", "DST"])]
    pub(crate) cp: Option<Vec<String>>,

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

    /// Extract Credential Manager entries from disk images by decrypting
    /// on-disk DPAPI masterkeys with SAM/LSA secrets.
    #[arg(long, default_value_t = false)]
    pub(crate) credman: bool,

    /// With `--credman`: enumerate CREDENTIAL attributes and show each
    /// attribute's encrypted value as hex (offline decryption of entropy-bound
    /// WindowsLive/SSO blobs is not supported).
    #[arg(long, default_value_t = false)]
    pub(crate) credman_attributes: bool,

    /// `USER:HEX` NT hash for `--credman` (repeatable). USER is a SID, a
    /// SAM/profile name, or `DOMAIN\\name`. For domain users not in the local SAM.
    #[arg(long, value_name = "USER:HEX")]
    pub(crate) dpapi_nthash: Vec<String>,

    /// `USER:PASSWORD` cleartext password for `--credman` (repeatable). USER is a
    /// SID, a SAM/profile name, or `DOMAIN\\name`. Required for LOCAL accounts:
    /// their masterkey derives from the password, not the NT hash. Everything
    /// after the first `:` is the password. Note: visible in the process list.
    #[arg(long, value_name = "USER:PASSWORD")]
    pub(crate) dpapi_password: Vec<String>,

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

    /// Skip registry hive (SAM/SYSTEM/SECURITY) recovery from memory entirely:
    /// neither the CM hive-map walk nor the --registry-carve fallback runs.
    #[cfg(feature = "sam")]
    #[arg(long, default_value_t = false)]
    pub(crate) no_mem_registry: bool,

    /// Fall back to a full physical-memory signature scan for SAM/SYSTEM/SECURITY
    /// when the CM hive-map walk finds nothing or cannot run (slow, up to ~3 GB RSS).
    #[cfg(feature = "sam")]
    #[arg(long, default_value_t = false)]
    pub(crate) registry_carve: bool,

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
    #[cfg(any(
        feature = "vmware",
        feature = "vbox",
        feature = "qemu",
        feature = "hyperv"
    ))]
    #[cfg_attr(not(feature = "carve"), expect(clippy::unused_self))]
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

/// Parse a byte offset given as decimal or `0x`-prefixed hex.
#[cfg(feature = "sam")]
pub(crate) fn parse_offset(s: &str) -> Result<u64, String> {
    let t = s.trim();
    let r = match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(h, 16),
        None => t.parse::<u64>(),
    };
    r.map_err(|e| format!("invalid offset '{s}': {e}"))
}

#[cfg(all(test, feature = "sam"))]
mod offset_tests {
    use super::parse_offset;

    #[test]
    fn parse_offset_hex_and_decimal() {
        assert_eq!(parse_offset("0x100000"), Ok(1048576));
        assert_eq!(parse_offset("1048576"), Ok(1048576));
        assert!(parse_offset("zzz").is_err());
    }
}

/// Parse `--dpapi-nthash` specs into `(USER, 16-byte NT hash)` pairs.
/// Requires `USER:HEX`; malformed entries are skipped with a warning.
#[cfg(feature = "sam")]
pub(crate) fn parse_dpapi_passwords(specs: &[String]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for spec in specs {
        // Split on the FIRST colon: a password may itself contain colons.
        let Some((user, pw)) = spec.split_once(':') else {
            log::warn!("--dpapi-password: expected USER:PASSWORD in {spec:?}");
            continue;
        };
        if pw.is_empty() {
            log::warn!("--dpapi-password: empty password in {spec:?}");
            continue;
        }
        out.push((user.trim().to_string(), pw.to_string()));
    }
    out
}

pub(crate) fn parse_dpapi_nthashes(specs: &[String]) -> Vec<(String, [u8; 16])> {
    let mut out: Vec<(String, [u8; 16])> = Vec::new();
    for spec in specs {
        let Some((user, hex_str)) = spec.rsplit_once(':') else {
            log::warn!("--dpapi-nthash: expected USER:HEX in {spec:?}");
            continue;
        };
        let Ok(bytes) = hex::decode(hex_str.trim()) else {
            log::warn!("--dpapi-nthash: invalid hex in {spec:?}");
            continue;
        };
        let Ok(nt_hash) = <[u8; 16]>::try_from(bytes.as_slice()) else {
            log::warn!("--dpapi-nthash: NT hash must be 16 bytes in {spec:?}");
            continue;
        };
        out.push((user.trim().to_string(), nt_hash));
    }
    out
}

#[cfg(all(test, feature = "sam"))]
mod dpapi_nthash_tests {
    use super::parse_dpapi_nthashes;

    #[test]
    fn parses_user_hash_pairs() {
        let v = parse_dpapi_nthashes(&["LAB\\jdoe:00112233445566778899aabbccddeeff".into()]);
        assert_eq!(v[0].0, "LAB\\jdoe");
        assert_eq!(v[0].1[0], 0x00);
        assert_eq!(v[0].1[15], 0xff);
    }
}
