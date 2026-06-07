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

## Chrome module (optional)

Extracts browser secrets (passwords, cookies, autofill) from Chromium-family
browsers (Chrome, Edge, Brave, Vivaldi, Opera) and Firefox. Gated by the
`chrome` Cargo feature (not in the default set) and the `--chrome` runtime
flag; depends on `sam` for NTFS and DPAPI primitives.

```
src/chrome/
├── runner.rs         CLI orchestration: disk-only / hybrid / reader-based entrypoints
├── profile.rs        NTFS-walking profile + artifact discovery
├── disk.rs           per-profile SQLite decrypt + key derivation orchestrator
├── local_state.rs    parse Chrome/Edge "Local State" JSON for encrypted_key + ABE blob
├── dpapi_decrypt.rs  DPAPI blob parser + AES-256-CBC / HMAC-SHA512 primitive
├── abe.rs            v20 App-Bound Encryption chain (two DPAPI layers + flag-keyed AES-GCM)
├── abe_keys.rs       auto-extract Chrome ABE static keys from elevation_service.exe
├── blob.rs           shared blob-shape helpers (v10 DPAPI prefix, v20 APPB header)
├── memory.rs         memory-side pattern + key-ring helpers
├── hybrid.rs         ComposedResolver: mem keyring → disk keyring fallback
├── heuristic.rs      candidate-validation heuristics (SQLite shape, key-byte sanity,
│                     plus the in-process URL/cookie scanners gated by TLD allowlist)
├── process_scan.rs   ChromeKatz-style in-process scanner: enumerate chromium PIDs,
│                     dump each mapped region via the page-walk enumerator, run
│                     heuristic password/cookie matchers, tag findings with
│                     ChromeSource::Memory { pid, process }
├── cookie_monster.rs CanonicalCookie struct layouts (Chrome 124/130/130-PB, Edge 130
│                     and Edge 130-PB), OptimizedString reader, RB-tree walker;
│                     waiting for the per-version locator signature
├── firefox.rs        Firefox profile discovery (NSS decrypt is a scaffold)
├── sqlite/           minimal embedded SQLite reader (no rusqlite dep)
├── output.rs         pretty + JSON renderers
└── types.rs          Browser/Profile/Finding domain types

src/paging/regions.rs    page-walk top-down enumerator of mapped userland regions
                         (chrome feature only); used by process_scan to feed pattern
                         matchers without brute-forcing the 128 TiB address space
```

The chain stitches three layers:

- **DPAPI masterkey decryption** — for user MKs, `sam::dpapi_masterkey` runs
  the Win10+ password-derived chain (PBKDF2-SHA512 with Microsoft's
  XOR-feedback variant) over every plaintext in LSA secrets plus the
  caller-supplied `--chrome-password` list. For SYSTEM-context MKs, both
  halves of `DPAPI_SYSTEM` are read from `SECURITY` and applied to the
  matching subdirectory of `Protect\S-1-5-18\` (machine half for `\User\`,
  user half for the root).
- **Chrome v10** — the `os_crypt.encrypted_key` field in `Local State` is a
  DPAPI blob whose plaintext is the per-install AES-256-GCM key used to
  decrypt every row in `Login Data`/`Cookies`/`Web Data` whose value starts
  with `v10`.
- **Chrome v20 (App-Bound Encryption, Chrome ≥127)** — `app_bound_encrypted_key`
  is wrapped three times: user-context DPAPI blob → SYSTEM-context DPAPI
  blob → a flag-byte-driven AES-256-GCM envelope. The flag selects which
  static key (auto-extracted from the install's `elevation_service.exe` PE
  via pattern scan; Chrome 135 fallback ships in-tree) unwraps the final
  32-byte v20 key. Cookies whose ciphertext starts with `v20` use this key
  with the same AES-GCM scheme.

When hybrid mode is used (`--disk` + memory snapshot), `unwrap_app_bound_with_resolvers`
collects every candidate MK for each layer's GUID across both the
mem-extracted (LSASS DPAPI cache) and disk-extracted keyrings, then picks
the one whose decrypted output validates against the expected layer shape.
This is defensive: `decrypt_blob` has no HMAC verify, so wrong MKs silently
produce garbage that is only caught by the next layer's parse.

### In-process discovery (opt-in)

The `--chrome-process-scan` flag walks every running `chrome.exe` /
`msedge.exe` / `brave.exe` / `vivaldi.exe` / `opera.exe` in the snapshot
through `paging::regions::enumerate_user_regions` (page-table top-down
traversal of the canonical low half) and reads each region via
`ProcessMemory`. Currently it emits one info-level log line per process
("PID/image/MiB mapped") and a discovery total; no entries are written
into `ChromeFindings`.

The flag previously merged heuristic password / cookie hits from
`heuristic::scan_heap_for_passwords` / `_cookies` into the disk-side
findings. That path was retired because chrome process memory is filled
with minified-JavaScript string tables and chrome.dll auth-flow
constants that look syntactically identical to cookie or credential
bytes once isolated from their structural context. On VMware Win10 with
Edge browsing live the heuristic emitted ~99k "cookies" — top hosts
included real domains the user had visited (americanexpress.com,
youtube.com, apartments.com) but individual rows were dominated by
UUID-prefixed hostnames, JS-token cookie names (`typeof`,
`viz.mojom.GpuHostMessageHeader`) and minified-JS values
(`Symbol&&Symbol.`, `||void 0===t||t`). Every filter tightening pass
either still leaked thousands of false positives or rejected real
cookies too — so the honest choice is to ship discovery only and let
the next iteration replace it with structured walking.

The struct layouts in `cookie_monster.rs` (`CanonicalCookieChrome`,
`CanonicalCookieChrome130`, `CanonicalCookieEdge130`, plus the
`ProcessBoundString` variants for Chrome 130+ in-memory cookie value
encryption) are ready for the per-Chrome-version `CookieMonster` locator
signature: pattern-match the destructor in chrome.dll, resolve the
vtable from the resulting code address, scan the heap for objects whose
first qword equals that vtable, walk the `std::map` red-black tree from
the resulting CookieMonster. Until that signature work lands, the disk
DPAPI chain remains the high-fidelity reference and the only
structurally-reliable extractor.

See [`docs/plans/2026-06-05-chrome-module-design.md`](plans/2026-06-05-chrome-module-design.md)
for the full design spec.
