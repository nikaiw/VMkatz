# Architecture

## How It Works

1. **Layer**: Opens the VM snapshot format and exposes guest physical memory as a flat address space. Each hypervisor format (VMware regions, VBox page map, QEMU ELF segments, QEMU savevm page stream with MMIO gap remapping, Hyper-V identity map, Hyper-V VMRS key-value store with LZNT1 decompression) is abstracted behind a common `PhysicalMemory` trait.

2. **Process discovery**: Scans physical memory for EPROCESS structures using signature matching (`System\0` at ImageFileName offset) with auto-detection across 18 known offset tables (WinXP SP3 through Win11 24H2, x86 PAE + x64).

3. **Page table walking**: Translates virtual addresses to physical using the kernel DTB (CR3). Supports 4-level x64 page tables and 3-level PAE (pre-Vista x86). TLB cache (256-entry direct-mapped), large pages (2MB/1GB), PCID bits, and pagefile fault resolution.

4. **LSASS extraction**: Locates `lsass.exe`, maps its virtual address space, finds DLLs (`lsasrv.dll`, `msv1_0.dll`, `wdigest.dll`, `kerberos.dll`, `dpapisrv.dll`, etc.) via PEB/LDR enumeration, resolves crypto keys via pattern matching on `.text`/`.data` sections, and decrypts credentials in-memory using 3DES-CBC, AES-CBC, AES-CFB, DES-X-CBC, or RC4 (auto-detected by buffer alignment and OS version). Also works on LSASS minidumps (`.dmp`).

5. **Disk extraction**: Parses the virtual disk container (sparse VMDK, VDI, QCOW2, VHDX, VHD, LVM block devices), finds the Windows partition (MBR/GPT), detects BitLocker-encrypted volumes (`-FVE-FS-` signature), walks NTFS MFT to locate `SAM`, `SYSTEM`, `SECURITY` hives, and decrypts hashes using the boot key. Supports both modern (AES, Vista+) and legacy (DES-ECB/RC4, XP/2003) LSA secret encryption. On ESXi, a native VMFS-5/6 parser reads flat VMDKs directly from raw SCSI devices, bypassing filesystem locks on running VMs.

6. **NTDS extraction**: For domain controllers (`--ntds`), locates `NTDS.dit` and the `SYSTEM` hive on disk, then parses the ESE (JET Blue) database natively. Traverses B+ trees to read the `datatable`, extracts the PEK (Password Encryption Key) using the bootkey, and decrypts NT/LM hashes for every AD account. Supports both 8KB pages (Windows Server 2019 and earlier) and 32KB large pages (Windows Server 2025), as well as RC4 (legacy), AES pre-Win2016, and AES Win2016+ (v0x13) hash blob formats.

## Module Layout

```
src/
├── main.rs              CLI dispatch, format detection, output formatting
├── lib.rs               Crate root — feature-gated module declarations
├── error.rs             VmkatzError type
├── utils.rs             Endian helpers, hex, UTF-16LE decode, mmap helpers
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
│   ├── kerberos.rs      Kerberos provider (tickets, passwords, ticket carving)
│   ├── tspkg.rs         TsPkg provider (RDP plaintext)
│   ├── dpapi.rs         DPAPI provider (master key cache)
│   ├── ssp.rs           SSP provider (plaintext credentials)
│   ├── livessp.rs       LiveSSP provider (plaintext, rare post-Win8)
│   ├── credman.rs       Credential Manager (stored credentials)
│   ├── cloudap.rs       CloudAP provider (Azure AD tokens)
│   ├── bitlocker.rs     BitLocker FVEK extraction from memory (pool tag scan)
│   └── carve.rs         [feature: carve] Degraded extraction for partial memory
├── dump.rs              [feature: dump] Process memory → minidump writer
├── vmware/              [feature: vmware] VMware .vmsn/.vmem/.vmss layer
├── vbox/                [feature: vbox] VirtualBox .sav layer
├── qemu/                [feature: qemu] QEMU ELF core dump + Proxmox savevm layer
├── hyperv/              [feature: hyperv] Hyper-V .vmrs/.bin/.raw layer (native VMRS parser)
├── sam/                 [feature: sam] SAM/LSA/DCC2 + DPAPI + disk format handlers
│   ├── mod.rs           Orchestration, disk extraction entry point
│   ├── hive.rs          Windows registry hive parser (regf format)
│   ├── bootkey.rs       Bootkey extraction from SYSTEM hive
│   ├── hashes.rs        SAM hash decryption (AES-CBC, RC4, MD5, DES)
│   ├── lsa.rs           LSA secrets decryption (DPAPI system keys, service passwords)
│   ├── cache.rs         Cached domain credentials (DCC2)
│   ├── dpapi_masterkey.rs  DPAPI master key file parser (hashcat 15300/15900)
│   ├── aes_xts.rs       AES-XTS sector decryption (for BitLocker)
│   ├── bitlocker_decrypt.rs  BitLocker transparent decrypting Read+Seek wrapper
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
│   └── vmfs.rs          [feature: vmfs] VMFS-5/6 raw parser (LVM → SFD → FDC → FD → data)
└── ntds/                [feature: ntds.dit] NTDS.dit ESE database parser
    ├── mod.rs           PEK decryption, hash extraction pipeline
    └── ese.rs           JET Blue database primitives (pages, B+ trees, columns)
```
