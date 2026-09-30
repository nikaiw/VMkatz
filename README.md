# VMkatz

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Build](https://github.com/nikaiw/VMkatz/actions/workflows/release.yml/badge.svg)](https://github.com/nikaiw/VMkatz/actions/workflows/release.yml)
[![CI](https://github.com/nikaiw/VMkatz/actions/workflows/clippy.yml/badge.svg)](https://github.com/nikaiw/VMkatz/actions/workflows/clippy.yml)
[![Platform](https://img.shields.io/badge/platform-linux%20|%20windows%20|%20macos%20|%20esxi-lightgrey)]()

You are three weeks into a red team engagement. You land on a NAS attached to the virtualization cluster — hundreds of gigabytes of `.vmdk`, `.vmsn`, `.sav` sitting right there. But your link does 200 KB/s. Exfiltrating a single 100 GB disk would take **six days**.

VMkatz exists because you shouldn't have to exfiltrate what you can read in place. It extracts Windows credentials directly from VM files — memory snapshots, virtual disks, Veeam backups: NTLM hashes, Kerberos tickets, DPAPI master keys, LSA secrets, NTDS.dit, BitLocker keys, browser secrets.

Single static binary, ~3 MB. Drop it on the ESXi host, the Proxmox node, or the NAS. Point it at a VM folder and walk away with credentials, not disk images.

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

# Output as hashcat-ready hashes
./vmkatz --format hashcat snapshot.vmsn

# Export Kerberos tickets
./vmkatz --kirbi snapshot.vmsn        # .kirbi files
./vmkatz --ccache snapshot.vmsn       # .ccache file

# Export BitLocker FVEK for dislocker
./vmkatz --bitlocker-fvek /tmp/keys snapshot.vmsn

# Recursively scan all VMs under a path
./vmkatz -r /vmfs/volumes/datastore1/

# Parse LSASS minidump
./vmkatz lsass.dmp

# Extract from Hyper-V saved state
./vmkatz guest.vmrs

# Extract from Veeam backup (build with --features veeam)
./vmkatz backup.vbk
./vmkatz --veeam-list backup.vbk               # List disk images
./vmkatz --veeam-extract backup.vbk            # Extract raw disk
```

## Output Formats

| Format | Flag | Description |
| --- | --- | --- |
| `text` | `--format text` (default) | Full credential dump with session metadata |
| `brief` | `--format brief` | Compact one-line-per-credential summary |
| `ntlm` | `--format ntlm` | `DOMAIN\user:::hash:::` pwdump format |
| `hashcat` | `--format hashcat` | Raw hashes: mode 1000 (NTLM), 2100 (DCC2), 15300/15900 (DPAPI) |
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

VMkatz is modular. Features can be enabled/disabled at compile time:

| Feature | Description | Default |
| --- | --- | --- |
| `vmware` | VMware `.vmsn`/`.vmem` snapshot support | Yes |
| `vbox` | VirtualBox `.sav` saved-state support | Yes |
| `qemu` | QEMU/KVM ELF core dumps + Proxmox savevm | Yes |
| `hyperv` | Hyper-V `.vmrs`/`.bin`/`.raw` dump support | Yes |
| `sam` | Disk extraction (SAM/LSA/DCC2) + disk format handlers | Yes |
| `ntds.dit` | NTDS.dit AD extraction. Requires `sam` | Yes |
| `carve` | Degraded extraction from partial/truncated memory | Yes |
| `dump` | Process memory dump as minidump | Yes |
| `vmfs` | VMFS-5/6 raw parser for ESXi SCSI devices. Requires `sam` | Yes |
| `chrome` | Browser secrets extraction (Chromium + Firefox). Requires `sam` | No |
| `veeam` | Veeam VBK/VIB/VRB backup support. Requires `sam` | No |

```bash
cargo build --release                                              # Full build
cargo build --release --no-default-features --features vmware      # VMware only
cargo build --release --no-default-features --features "sam ntds.dit"  # Disk only
cargo build --release --features chrome                            # Add chrome module
cargo build --release --features veeam                             # Add Veeam backup support
```

## Browser secrets (experimental)

The optional `chrome` module extracts saved passwords, cookies, and autofill
from Chromium-family browsers (Chrome, Edge, Brave, Vivaldi, Opera) via
offline DPAPI decryption. Build with `--features chrome`, enable with `--chrome`.

Supports Chrome v10 (`os_crypt.encrypted_key`) and v20 App-Bound Encryption
(Chrome ≥127). Works from disk, memory+disk (hybrid), or both combined.

```bash
./vmkatz --chrome disk.vmdk                              # Disk-only
./vmkatz --chrome --chrome-password vagrant disk.vmdk    # With extra password
./vmkatz --chrome --disk disk.vmdk snapshot.vmsn         # Hybrid mem+disk
./vmkatz --chrome --chrome-json disk.vmdk                # JSON output
```

For domain users (whose credentials aren't in the local SAM), use
`--chrome-password` with a known plaintext or `--chrome-nthash` with an NT
hash to unlock their browser secrets.

## Documentation

- [ESXi deployment, VIB bypass, VMFS raw access](docs/esxi.md)
- [Example output](docs/examples.md)
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
