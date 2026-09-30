# Changelog

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
