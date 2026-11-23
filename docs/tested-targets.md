# Tested Targets

Tested across 7 Windows versions and 5 hypervisors/platforms.

| Hypervisor | Guest OS | Artifact | Result | Notes |
| --- | --- | --- | --- | --- |
| VMware Workstation | Windows 10 22H2 x64 | LSASS (`.vmsn`) | PASS | 3 snapshots |
| VMware Workstation | Windows 10 22H2 x64 | LSASS + pagefile (`.vmsn` + `.vmdk`) | PASS | Resolves paged-out credentials |
| VMware Workstation | Windows 10 22H2 x64 | SAM / LSA / DCC2 (`.vmdk`) | PASS | |
| VMware Workstation | Windows 10 22H2 x64 | Folder mode | PASS | Auto-discovers `.vmsn` + `.vmdk` |
| VMware Workstation | Windows 10 22H2 x64 | Chrome v10 + v20 ABE (hybrid) | PASS | 83 cookies + 1 password |
| Proxmox 8 | Windows 11 25H2 x64 | Chrome v20 ABE (hybrid LVM + QEMU dump) | PASS | 15 cookies, IV recovery triggered |
| Proxmox 8 | Windows 11 24H2 x64 | Chrome v20 ABE (hybrid LVM + QEMU dump) | PASS | 52 cookies per VM (fleet) |
| ESXi 8.0 | Windows 11 24H2 x64 | Chrome v20 ABE (disk-only flat `.vmdk`) | PASS | 18 / 29 cookies on Acronis / RedTeam workstations |
| ESXi 8.0 | Windows 11 24H2 x64 | Chrome v20 ABE (hybrid archived `.vmsn` + base) | PASS | 6-8 cookies on archived snapshots |
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
| Proxmox 8 | Windows Server 2019 x64 | NTDS.dit (LVM block device) | PASS | 3 DCs, 8KB pages |
| Proxmox 8 | Windows Server 2025 x64 | SAM / LSA (LVM block device) | PASS | |
| Proxmox 8 | Windows Server 2025 x64 | NTDS.dit (LVM block device) | PASS | 32KB pages, native ESE parsing |
| Proxmox 8 | Windows 11 x64 | SAM / LSA (LVM block device) | PASS | Live VM |
| Proxmox 8 | Windows Server 2025 x64 | LSASS (QEMU savevm) | PASS | Kerberos + DPAPI extracted |
| Proxmox 8 | Windows 11 x64 | LSASS (QEMU savevm) | PASS | CloudAP + DPAPI extracted |
| ESXi 6.7 | Windows 10 x64 | LSASS (`.vmsn` + `.vmem`) | PASS | 2 NT hashes + plaintext |
| ESXi 6.7 | Windows Server 2016 x64 | LSASS (embedded `.vmsn`) | PASS | Memory embedded in `.vmsn` |
| ESXi 6.7 | Windows Server 2016 x64 | SAM / LSA / DCC2 (embedded `.vmsn`) | PASS | |
| ESXi 8.0 | Windows Server 2012 x64 | SAM / LSA / DCC2 (VMFS-6 raw) | PASS | Running VM, file locks bypassed |
| ESXi 8.0 | Windows Server 2016 x64 | SAM / LSA / DCC2 (VMFS-6 raw) | PASS | Running VM |
| ESXi 8.0 | Windows Server 2019 x64 | SAM / LSA / DCC2 (VMFS-6 raw) | PASS | Running VM |
| ESXi 8.0 | Windows 11 x64 | SAM (VMFS-6 raw) | PASS | Running VM |
| Hyper-V | Windows Server 2012 R2 x64 | SAM / LSA / DCC2 (`.vhdx`) | PASS | |
| Hyper-V | Windows Server 2003 R2 x64 | SAM / LSA (`.vhdx`) | PASS | |

## 1.6.0-dev.1 validation (2026-11-23)

The default x86_64 musl build from Rust 1.99.1 was exercised on ESXi 8.0.2 and Proxmox VE 9.1.1, using existing disks and captures without changing VM state.

| Host | Checks | Result |
| --- | --- | --- |
| ESXi, VMFS-5 dense sub-blocks | Enumerate VMDKs, list/copy NTFS files, SAM, NTDS | PASS; 20 VMDKs found, 12 NTDS accounts |
| ESXi, archived Windows 7 snapshot | LSASS from embedded `.vmsn` memory | PASS |
| Proxmox, live Server 2025 LVM disk | List/copy NTFS files, refuse overwrite, SAM, NTDS | PASS; 54 NTDS accounts |
| Proxmox, Server 2016 / Windows x86 / Windows 11 captures | LSASS from raw memory | PASS; CSV output identical to published dev commit `2d8c2a6` (1.5.2) |

Explicit VMFS selections without an NTFS/BitLocker volume fail promptly, including the Linux test disk. Tests enforce timeouts and sample memory with a 1 GiB stop threshold. Proxmox peak RSS stayed below 100 MiB; ESXi's largest sampled memory accounting value was about 529 MiB (not an RSS measurement). No test hit either threshold.

This host run does not validate a real 8 TiB image or revalidate VirtualBox, Hyper-V and QEMU savevm captures. Synthetic large-image and malformed-input cases remain covered by the local test suite; these results are not a global memory bound.

After the Rust 1.100.0 update, the same two hosts ran the default musl binary against a synthetic NTFS disk. Both listed the fixture, copied its contents byte for byte and refused to overwrite the destination. With the same features and target, the executable measured 3,945,736 bytes at `opt-level="z"` and 4,289,800 bytes at `"s"`. The earlier Rust 1.99.1 executable measured 3,953,920 bytes.

## Known limitations

- **VBS / Credential Guard**: VMs with Virtualization-Based Security enabled use nested Hyper-V page tables. The VMEM captured by ESXi is 99% zero pages because the actual kernel memory is behind Hyper-V's SLAT. An EPT walker is implemented but cannot yet recover credentials from these VMs. SAM extraction from the virtual disk still works.
- **Kerberos**: Kerberos credentials are frequently paged out in VM snapshots. The provider reports `paged` but the data is legitimately absent from RAM. Pagefile resolution (`--disk`) can recover some entries. Ticket carving can find orphaned tickets from freed sessions.
- **Hyper-V**: Modern `.vmrs` saved states (Hyper-V 2016+) are supported via a native parser reverse-engineered from `vmsavedstatedumpprovider.dll` — no Microsoft DLL needed. Legacy `.bin`/`.raw` dumps are also supported via identity-mapped reading. VHDX disk extraction tested on Windows Server 2003 R2 and 2012 R2.
- **QEMU/Proxmox savevm**: RAM pages from dirty-tracking iterations are captured; non-dirty pages return zeros. MSV credentials are often `(paged)` but Kerberos keys and DPAPI master keys are typically available. MMIO gap remapping assumes q35+UEFI layout (`below_4g=0x80000000`).
- **BitLocker and VMFS memory**: BitLocker-encrypted partitions are detected. VM-directory mode and ESXi VMFS mode can extract supported AES-XTS FVEKs from memory snapshots associated with the VM directory and try them for SAM and NTDS extraction. On ESXi, VMFS association requires the mounted datastore to be visible under `/vmfs/volumes` with a unique VM folder match. Add `--lsass` to explicitly extract LSASS secrets from those associated snapshots; pagefile resolution is not available in this path. `--bitlocker-fvek` exports keys recovered from a memory snapshot; it is not an input option. Standalone disk mode does not associate a memory snapshot or accept an external FVEK. CBC/Diffuser decryption is not implemented.
- **x86 (32-bit) guests**: Supported with PAE paging (default since Vista). Covers WinXP SP3 through Win10 x86. Pre-Vista (XP/2003) extracts MSV/DPAPI only; Vista+ x86 extracts all 9 SSP providers. Non-PAE 32-bit (rare, XP-only) is not supported.
