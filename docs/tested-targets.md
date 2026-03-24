# Tested Targets

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

## Known limitations

- **VBS / Credential Guard**: VMs with Virtualization-Based Security enabled use nested Hyper-V page tables. The VMEM captured by ESXi is 99% zero pages because the actual kernel memory is behind Hyper-V's SLAT. An EPT walker is implemented but cannot yet recover credentials from these VMs. SAM extraction from the virtual disk still works.
- **Kerberos**: Kerberos credentials are frequently paged out in VM snapshots. The provider reports `paged` but the data is legitimately absent from RAM. Pagefile resolution (`--disk`) can recover some entries. Ticket carving can find orphaned tickets from freed sessions.
- **Hyper-V**: Modern `.vmrs` saved states (Hyper-V 2016+) are supported via a native parser reverse-engineered from `vmsavedstatedumpprovider.dll` — no Microsoft DLL needed. Legacy `.bin`/`.raw` dumps are also supported via identity-mapped reading. VHDX disk extraction tested on Windows Server 2003 R2 and 2012 R2.
- **QEMU/Proxmox savevm**: RAM pages from dirty-tracking iterations are captured; non-dirty pages return zeros. MSV credentials are often `(paged)` but Kerberos keys and DPAPI master keys are typically available. MMIO gap remapping assumes q35+UEFI layout (`below_4g=0x80000000`).
- **BitLocker**: BitLocker-encrypted partitions are detected. When a memory snapshot is available, vmkatz extracts the FVEK from memory and decrypts the volume transparently. Without a snapshot, use `--bitlocker-fvek` to provide a key file.
- **x86 (32-bit) guests**: Supported with PAE paging (default since Vista). Covers WinXP SP3 through Win10 x86. Pre-Vista (XP/2003) extracts MSV/DPAPI only; Vista+ x86 extracts all 9 SSP providers. Non-PAE 32-bit (rare, XP-only) is not supported.
