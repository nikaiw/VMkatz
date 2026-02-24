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

A single static binary, ~5 MB. Drop it on the ESXi host, the Proxmox node, or the NAS. Point it at a `.vmsn`, `.vmdk`, or an entire VM folder. Walk away with credentials, not disk images.

## What It Extracts

### From memory snapshots (LSASS)
All 9 SSP credential providers that mimikatz implements:

| Provider | Data | Notes |
| --- | --- | --- |
| MSV1_0 | NT/LM hashes, SHA1 | Physical-scan fallback for paged entries |
| WDigest | Plaintext passwords | Linked-list walk + `.data` fallback |
| Kerberos | Passwords, tickets (`.kirbi`) | AVL tree walk, often paged in VM snapshots |
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
- **NTDS.dit**: Full Active Directory hash extraction from domain controller disks (feature-gated)

## Supported Inputs

| Format | Extensions | Source |
| --- | --- | --- |
| VMware snapshots | `.vmsn` + `.vmem` | Workstation, ESXi |
| VirtualBox saved states | `.sav` | VirtualBox |
| QEMU/KVM ELF core dumps | `.elf` | `virsh dump`, `dump-guest-memory` |
| Hyper-V memory dumps | `.bin`, `.raw`, `.dmp` | Legacy saved states, raw dumps |
| VMware virtual disks | `.vmdk` (sparse + flat) | Workstation, ESXi |
| VirtualBox virtual disks | `.vdi` | VirtualBox |
| QEMU/KVM virtual disks | `.qcow2` | QEMU, Proxmox |
| Hyper-V virtual disks | `.vhdx`, `.vhd` | Hyper-V |
| LVM block devices | `/dev/...` | Proxmox LVM-thin, raw LVs |
| VM directories | any folder | Auto-discovers all processable files |

**Target OS**: Windows 7 SP1 through Windows Server 2025 x64 (auto-detected).

## Quick Start

```bash
# Build (default features: all hypervisors + disk support)
cargo build --release

# Extract LSASS credentials from a VMware snapshot
./vmkatz snapshot.vmsn

# Same, with pagefile resolution for paged-out creds
./vmkatz --disk disk.vmdk snapshot.vmsn

# Extract SAM/LSA/DCC2 from a virtual disk (auto-detected)
./vmkatz disk.vmdk

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
```

## Output Formats

| Format | Flag | Description |
| --- | --- | --- |
| `text` | `--format text` (default) | Full credential dump with session metadata |
| `ntlm` | `--format ntlm` | `DOMAIN\user:::hash:::` pwdump format |
| `hashcat` | `--format hashcat` | Raw hashes: mode 1000 (NTLM), mode 2100 (DCC2) |
| `csv` | `--format csv` | Machine-readable, all fields |

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
    LM Hash : 00000000000000000000000000000000
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

# Upload (~5 MB)
scp target/x86_64-unknown-linux-musl/release/vmkatz root@esxi:/tmp/

# On ESXi 8.0+, allow non-VIB binaries (requires once)
esxcli system settings advanced set -o /User/execInstalledOnly -i 0

# Extract from a live VM snapshot
/tmp/vmkatz /vmfs/volumes/datastore1/MyVM/MyVM-Snapshot1.vmsn

# Extract SAM from a powered-off VM disk
/tmp/vmkatz /vmfs/volumes/datastore1/MyVM/MyVM-flat.vmdk
```

## Build Features

VMkatz is modular. Features can be enabled/disabled at compile time:

| Feature | Description | Default |
| --- | --- | --- |
| `vmware` | VMware `.vmsn`/`.vmem` snapshot support | Yes |
| `vbox` | VirtualBox `.sav` saved-state support | Yes |
| `qemu` | QEMU/KVM ELF core dump support | Yes |
| `hyperv` | Hyper-V `.bin`/`.raw` dump support | Yes |
| `sam` | Disk extraction (SAM/LSA/DCC2) and disk format handlers | Yes |
| `ntds.dit` | NTDS.dit AD extraction (`--ntds`, `--ntds-history`). Requires `sam` | No |

```bash
# Default build (all hypervisors + disk)
cargo build --release

# Add NTDS support
cargo build --release --features "ntds.dit"

# Memory-only build (no disk handling, smaller binary)
cargo build --release --no-default-features --features "vmware vbox qemu hyperv"

# Disk-only build with NTDS
cargo build --release --no-default-features --features "sam ntds.dit"
```

## Tested Targets

Tested across 7 Windows versions and 4 hypervisors.

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
| Proxmox 8 | Windows Server 2025 x64 | SAM / LSA (LVM block device) | PASS | Template VM |

### Known limitations
- **VBS / Credential Guard**: VMs with Virtualization-Based Security enabled use nested Hyper-V page tables. The VMEM captured by ESXi is 99% zero pages because the actual kernel memory is behind Hyper-V's SLAT. An EPT walker is implemented but cannot yet recover credentials from these VMs. SAM extraction from the virtual disk still works when the VM is powered off.
- **Kerberos**: Kerberos credentials are frequently paged out in VM snapshots. The provider reports `paged` but the data is legitimately absent from RAM. Pagefile resolution (`--disk`) can recover some entries.
- **x86 (32-bit) guests**: Not supported. Only x64 Windows is targeted.

## How It Works

1. **Layer**: Opens the VM snapshot format and exposes guest physical memory as a flat address space. Each hypervisor format (VMware regions, VBox page map, QEMU ELF segments, Hyper-V identity map) is abstracted behind a common `PhysicalMemory` trait.

2. **Process discovery**: Scans physical memory for EPROCESS structures using signature matching (`System\0` at ImageFileName offset) with auto-detection across 6 known offset tables (Win7 through Win11 24H2).

3. **Page table walking**: Translates virtual addresses to physical using the kernel DTB (CR3) with full 4-level page table support. Handles large pages (2MB/1GB), PCID bits, and pagefile fault resolution.

4. **LSASS extraction**: Locates `lsass.exe`, maps its virtual address space, finds DLLs (`lsass.dll`, `msv1_0.dll`, `wdigest.dll`, `kerberos.dll`, etc.) via PEB/LDR enumeration, resolves crypto keys via pattern matching on `.text`/`.data` sections, and decrypts credentials in-memory using 3DES-CBC or AES-CBC (auto-detected by buffer alignment).

5. **Disk extraction**: Parses the virtual disk container (sparse VMDK, VDI, QCOW2, VHDX, VHD), finds the Windows partition (MBR/GPT), walks NTFS MFT to locate `SAM`, `SYSTEM`, `SECURITY` hives, and decrypts hashes using the boot key.
