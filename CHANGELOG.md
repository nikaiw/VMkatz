# Changelog

## Unreleased

### New Features
- **`--credman`** — offline Windows Credential Manager extraction. Decrypts the on-disk `Credentials` store (including saved RDP/TERMSRV credentials) from a disk image by recovering DPAPI masterkeys: local users via their SAM NT hash, SYSTEM via `DPAPI_SYSTEM` (no extra input), and domain users via `--dpapi-nthash USER:HASH` (repeatable). Prints target, login and password. The Vault store (`Policy.vpol` / `*.vcrd`) is planned for a follow-up

## v1.5.2

A large bug-fix roll-up since v1.5.1 (~70 commits). The VMFS highlights below head
the release: a block-resolution bug that made thick-provisioned / GPT Windows VMs
read the wrong data over VMFS and silently extract **nothing** is fixed, VMFS mode
reaches parity with the local-disk path (NTDS + DPAPI), partition detection handles
GPT, and an NTDS column mix-up that mislabeled NT hashes is corrected (validated on
real ESXi 8.0.2). The release also rolls up extensive earlier dev fixes across LSASS
credential extraction — Kerberos, MSV, WDigest, credman and EPROCESS/x86 layout
offsets for many Windows builds — plus QEMU/Hyper-V handling; see the full commit
list in the release notes.

### New Features
- **`--ls[=PATH]`** — read-only NTFS directory listing. Without a path, lists the root of every NTFS partition on the target; with a path given in equals form (e.g. `--ls='\Windows\System32'`) lists that directory. Works on local disk images and VMFS (`--vmfs-device [--vmdk]`), and falls back to an MFTMirr scan when the directory index is unreadable
- **`--partition <OFFSET>`** — restrict any operation to a single partition by byte offset (hex `0x...` or decimal, as shown in logs and `--ls` headers)

### Fixes
- **VMFS reader — Large File Block resolution (critical)** — a single LFB spans many file blocks (e.g. 512 × 1 MB), but every file block in an LFB was mapped to the LFB's base, so any data past the first block read the wrong bytes. On thick-provisioned / GPT Windows VMDKs the NTFS volume sits mid-LFB, so the volume read as boot code: `find_ntfs_partitions` saw no NTFS and **all** extraction (SAM/LSA/NTDS/DPAPI/Chrome) silently returned nothing. Each file block now gets its intra-LFB offset
- **GPT partition detection** — `find_ntfs_partitions` now parses GPT (not just MBR), accepting a partition only when a valid NTFS VBR is present, so modern UEFI/GPT Windows VMs are handled
- **NTDS NT/LM columns swapped** — the AD hash extractor read `unicodePwd`/`dBCSPwd` from the wrong attribute IDs, emitting the real NT hash under the LM label (and zero under NT). Now `unicodePwd`=`ATTk589914` (NT), `dBCSPwd`=`ATTk589879` (LM)
- **VMFS parity — NTDS + DPAPI** — `--vmfs-device … --ntds` now extracts domain hashes (previously SAM/LSA only), and VMFS runs now also emit DPAPI master-key hashes. VMFS mode now matches the local-disk path
- **DPAPI master keys scoped by `--partition`** — a reader-based extractor honors `--partition` consistently across SAM/NTDS/DPAPI, on both the local-disk and VMFS paths
- **`--ls` robustness** — bad `--partition` offset is fatal with the available offsets listed; a per-partition failure no longer aborts the whole sweep; `--partition` requires `--vmdk` in VMFS mode (an offset is specific to one disk)
- **MFTMirr fallback scope** — a clean `NTFS entry not found` no longer triggers the MFTMirr scan: partitions without `\Windows` (WinRE/OEM/System Reserved) are reported and skipped without a wasted MFT scan. The fallback only runs when the directory index itself could not be enumerated (I/O or parse errors)
- **NTDS via MFTMirr fallback** — `--ntds` now falls back to the MFTMirr scan on degraded disks (incomplete VMDKs, live block devices): `ntds.dit` is matched by name plus its `\Windows\NTDS` parent chain, and content-validated via the ESE magic when parent records are unreadable
- **CI** — the Windows cross-check's `apt`/wine install no longer hangs the pipeline (noninteractive, retries, per-request timeout, 20-minute job cap)

## v1.5.1

### Fixes
- **Process enumeration regression** — `EPROCESS.DirectoryTableBase` is no longer required to be page-aligned in its raw form. Win10 guests carry `0x002` in the low bits on every process, so the alignment check introduced in v1.5.0 rejected the whole list and left only System: LSASS extraction failed with "lsass.exe not found in process list". All three DTB validation sites now share one predicate that masks before checking
- **Allocation bounds** — a PE `virtual_size` reached `vec![0u8; len]` unvalidated at ~20 call sites; one guard in the shared `read_*_bytes` covers them all. Same for the VMRS key-table block size and the NTFS record size
- **Full-RAM sweeps** — swept windows are dropped as they are consumed, keeping RSS at one window instead of the whole image
- **Windows portability** — drop-behind used `madvise(DONTNEED)` with no Windows equivalent, so the documented RSS bound was a no-op there; `VirtualUnlock` evicts the same pages. The host-memory query read `/proc/meminfo` only, which disabled the oversize warning

### Performance
- NTDS.dit and LSASS minidumps are mapped instead of read into memory

## v1.5.0

### New Features
- **Hyper-V VMRS** — native credential extraction from Hyper-V saved states (XPRESS decompression, GPA remapping across MMIO gap). First open-source native VMRS parser
- **Veeam backups** — SAM/LSA/DCC2/DPAPI/NTDS/Chrome extraction directly from VBK/VIB/VRB archives (`--features veeam`), plus Hashcat mode 31200 for encrypted backups, `--veeam-list` and `--veeam-extract` commands
- **Chrome v20 ABE v3** — decrypt Chrome 154+ App-Bound Encryption using CNG-KSP machine keys from `%ProgramData%\Microsoft\Crypto\Keys`
- **Domain-user DPAPI** — masterkey derivation via PBKDF2 "key3" and legacy 3DES/SHA1 chains; `--chrome-nthash` flag for cracked hashes
- **CM hive-map registry recovery** — recover SAM/SECURITY from memory via `_HHIVE`/`_HMAP` structures, O(hive) instead of O(RAM)
- **Memory registry carving** — carve SAM/SYSTEM/SECURITY hives from physical RAM (`--mem-registry`)
- **Kerberos on Server 2025 / Win11 24H2** (build 26100) and Server 2019 (build 17763) — per-build logon-session table locators
- **Parallel DPAPI masterkey decrypt** across cores

### Performance
- CM hive-map is now the primary registry recovery path (~10x less memory than signature carve)
- VMRS LRU block cache replaces FIFO — ~28% faster scans at same memory budget
- VMRS registry-carve warm cache capped to prevent OOM on large guests
- Mmap drop-behind bounds RSS on ESXi scans (16 GB → 0.3 GB peak on 16 GB dump)
- DPAPI: parse masterkey section once per file, NT-hash pre-keys before PBKDF2 sweep

### Fixes
- **Disk parsers hardened**: QCOW2 zero-flag over backing + bounded chain depth, VMDK warn-once on masked reads, VDI BLOCK_ZERO + zero block_size rejection, VHDX chunk bitmap index + mandatory parent, VHD mandatory parent for differencing disks
- **QEMU savevm**: zero page now overrides earlier data in iterative migration
- **NTDS.dit**: dBCSPwd column kept as LM hash per AD schema (was wrongly relabeled as NT)
- **NTFS**: resilient read logs exact zero-filled byte count
- **cm_hive**: scored stride calibration fixes 50% mapping on Win7
- **Veeam**: chunk-cache for byte-by-byte NTFS reads, sparse-tail underflow, NTFS truncation guard
- **LSASS**: bounded MSV/WDigest reads, IV recovery from .data fallback
- Parser allocation and loop bounds hardened against crafted images
