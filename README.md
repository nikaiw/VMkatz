# VMkatz

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Build](https://github.com/nikaiw/VMkatz/actions/workflows/release.yml/badge.svg)](https://github.com/nikaiw/VMkatz/actions/workflows/release.yml)
[![CI](https://github.com/nikaiw/VMkatz/actions/workflows/clippy.yml/badge.svg)](https://github.com/nikaiw/VMkatz/actions/workflows/clippy.yml)
[![Platform](https://img.shields.io/badge/platform-linux%20|%20windows%20|%20macos%20|%20esxi-lightgrey)]()

## Too Big to Steal

You are three weeks into a red team engagement. Your traffic crawls through a VPN, then bounces across four SOCKS proxies chained through compromised jump boxes before it touches the target network. Every packet takes the scenic route.

After days of lateral movement you land on a NAS attached to the virtualization cluster and the directory listing hits different: rows upon rows of `.vmdk`, `.vmsn`, `.sav`. Hundreds of gigabytes of virtual machines - domain controllers, admin workstations, the crown jewels - sitting right there.

But your link wheezes at 200 KB/s. Pulling a single 100 GB disk image would take **six days**, and every hour of sustained exfil is another chance the SOC spots the anomaly, burns your tunnel, and the whole chain collapses.

VMkatz exists because you shouldn't have to exfiltrate what you can read in place. It extracts Windows secrets - NTLM hashes, DPAPI master keys, Kerberos tickets, cached domain credentials, LSA secrets, NTDS.dit, BitLocker keys - directly from VM memory snapshots and virtual disks, **on the NAS, the hypervisor, wherever the VM files are**.

A single static binary, ~3 MB. Drop it on the ESXi host, the Proxmox node, or the NAS. Point it at a `.vmsn`, `.vmdk`, or an entire VM folder. Walk away with credentials, not disk images.

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
| Hyper-V saved states | `.vmrs` | Hyper-V 2016+ | Untested |
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

```bash
cargo build --release                                              # Full build
cargo build --release --no-default-features --features vmware      # VMware only
cargo build --release --no-default-features --features "sam ntds.dit"  # Disk only
cargo build --release --features chrome                            # Add chrome module
```

## Browser secrets (optional)

The optional `chrome` module extracts saved passwords, cookies, and autofill
entries from Chromium-family browsers (Chrome, Edge, Brave, Vivaldi, Opera)
and Firefox. It is gated by the `chrome` Cargo feature at build time and the
`--chrome` runtime flag, and depends on the `sam` feature for NTFS + DPAPI
primitives. Four extraction vectors are supported:

- **Disk-only DPAPI chain** — given a disk image, the module walks each
  user's `Protect` directory, decrypts every masterkey file (Win10+
  password-derived chain; legacy NT-hash chain for domain users), pulls
  `DPAPI_SYSTEM` from `SECURITY` for the SYSTEM-context MKs, then decrypts
  each Chromium SQLite artifact end-to-end. Both Chrome v10
  (`os_crypt.encrypted_key`) and v20 App-Bound Encryption (Chrome ≥127,
  `app_bound_encrypted_key`) are handled.
- **Hybrid (memory + disk)** — when a memory snapshot is also supplied, the
  cleartext masterkeys extracted from LSASS are merged with the disk-side
  keyring via `ComposedResolver`. This unlocks profiles whose user password
  isn't in LSA secrets, and recovers v20 keys that depend on
  SYSTEM-context-user MKs which only the elevation service can produce.
- **In-process memory scan** (`--chrome-process-scan`, opt-in) — walks every
  chrome.exe / msedge.exe / brave.exe in the snapshot, dumps each process's
  mapped userland through the page-table walker, and runs heuristic
  pattern matchers for `https://` URLs followed by username/password pairs
  and ASCII cookie domains. ChromeKatz-style; this is the lever that
  recovers what's *in flight* in browser memory — including the plaintext
  passwords Edge ≤ 147 holds in memory for the whole session ([Rønning,
  April 2026](https://www.threatlocker.com/blog/microsoft-edge-is-keeping-your-passwords-in-plaintext-memory-heres-what-that-actually-means)).
  Results are heuristic and noisy; the disk-side path remains the
  high-fidelity reference. The precise per-Chrome-version `CookieMonster`
  locator (next iteration) will replace the heuristic with structured
  extraction; `src/chrome/cookie_monster.rs` already carries the matching
  `CanonicalCookie` struct layouts.
- **Memory-only** — limited; without disk access the encrypted SQLite files
  are unreadable, so this path is mostly useful for pivoting MKs to a later
  disk-mode run.

Use `--chrome-password <pw>` (repeatable) to inject extra password candidates
when the user's plaintext isn't in LSA (cracked offline, pivoted, known lab
default). The v20 ABE static keys are auto-extracted from the install's
`elevation_service.exe` PE; a Chrome 135 fallback ships in-tree so older
binaries still decrypt.

```bash
# Disk-only: full decrypt where the user pwd is in LSA secrets
./vmkatz --chrome disk.vmdk

# Disk-only with extra password candidates
./vmkatz --chrome --chrome-password vagrant disk.vmdk

# Hybrid mem+disk: best yield for v20 ABE cookies
./vmkatz --chrome --disk disk.vmdk snapshot.vmsn

# Hybrid + ChromeKatz-style in-process scan of chrome.exe / msedge.exe
./vmkatz --chrome --chrome-process-scan --disk disk.vmdk snapshot.vmsn

# Structured output for tooling
./vmkatz --chrome --chrome-json disk.vmdk
```

Status: Chromium decrypt (v10 + v20) is complete and validated on Win10,
Win11 22H2/24H2/25H2, Win Server 2019/2022/2025. Firefox NSS plaintext
decrypt is a scaffold — profile discovery works, but plaintext requires an
NSS link that is not yet wired through.

What we deliberately do *not* implement: the live `IElevator` COM-interface
abuse and the debugger-based App-Bound Encryption bypasses (VoidStealer,
xaitax/Chrome-App-Bound-Encryption-Decryption). Both require a live
execution context inside a running Windows host; vmkatz is an offline
forensic tool, so we work the other side of the same problem — disk DPAPI
chain + memory snapshot reads.

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
- [**ChromeKatz**](https://github.com/Meckazin/ChromeKatz) by Meckazin -- the inspiration for the chrome module's in-process scan. The `CanonicalCookie` struct layouts in `src/chrome/cookie_monster.rs` (Chrome 124 / Chrome 130 / Edge / Edge 130, with the ProcessBoundString cookie value variant) are ported from `CookieKatz/Memory.h`; the upcoming per-version locator signature will replace our current heuristic scan.
- [**Chrome-App-Bound-Encryption-Decryption**](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) by xaitax -- reference for the Chrome ≥ 127 v20 App-Bound Encryption format. Our offline implementation works disk-side via `elevation_service.exe` PE pattern-scanning rather than the live syscall-based reflective hollowing the project uses, but the format/version notes were invaluable cross-references.
- [**DonPAPI**](https://github.com/login-securite/DonPAPI) and [**dploot**](https://github.com/zblurx/dploot) -- DPAPI remote dumping tools; surveyed for the masterkey decryption chain order and the LSA-context-vs-machine-context `DPAPI_SYSTEM` halves used per `Protect\S-1-5-18\` subdirectory.
