# Architecture

## Reading Guide

Start at [main.rs](../src/main.rs), which calls `cli::run`, re-exported from
[cli/dispatch.rs](../src/cli/dispatch.rs). The CLI selects workflows and formats
results; the library modules implement disk/memory access and artifact processing.
For example, `cli/disk/vmfs.rs` handles command options, while `disk/vmfs.rs` reads
the datastore. Likewise, `cli/credman.rs`, `credman/` and `cli/output/credman.rs`
handle orchestration, processing and formatting respectively.

| Task | Start here | Follow into |
|---|---|---|
| Options and input routing | [cli/args.rs](../src/cli/args.rs), [cli/dispatch.rs](../src/cli/dispatch.rs) | The selected `cli/disk.rs`, `cli/lsass.rs` or `cli/dir.rs` handler |
| NTFS listing or copy | [cli/disk/files.rs](../src/cli/disk/files.rs) | [fs/partition.rs](../src/fs/partition.rs), then [fs/listing.rs](../src/fs/listing.rs) for listing or [fs/ntfs.rs](../src/fs/ntfs.rs) for copying |
| Memory snapshots | [cli/lsass.rs](../src/cli/lsass.rs) | [snapshot.rs](../src/cli/lsass/snapshot.rs) selects and opens the format; [pipeline.rs](../src/cli/lsass/pipeline.rs) coordinates discovery and processing |
| VMFS datastore access | [cli/disk/vmfs.rs](../src/cli/disk/vmfs.rs) | [disk/vmfs.rs](../src/disk/vmfs.rs), with the volume's I/O methods kept together |
| Degraded NTFS recovery | [fs/ntfs_fallback.rs](../src/fs/ntfs_fallback.rs) | [mft.rs](../src/fs/ntfs_fallback/mft.rs) for scans, [records.rs](../src/fs/ntfs_fallback/records.rs) for decoding, [data.rs](../src/fs/ntfs_fallback/data.rs) for file reads |
| Output formatting | [cli/output.rs](../src/cli/output.rs) | The formatter for the result source in [cli/output/](../src/cli/output/); session text and deduplication have their own modules |

For disk allocation caches, see [disk/table.rs](../src/disk/table.rs) and
[disk/vmdk/directory.rs](../src/disk/vmdk/directory.rs). Automatic recovery budgets
live in [fs/recovery.rs](../src/fs/recovery.rs); snapshot page-index limits live in
[memory/page_index.rs](../src/memory/page_index.rs).

## How It Works

1. **Layer**: Opens the VM snapshot format and exposes guest physical memory as a flat address space. Each hypervisor format (VMware regions, VBox page map, QEMU ELF segments, QEMU savevm page stream with MMIO gap remapping, Hyper-V identity map, Hyper-V VMRS key-value store with XPRESS decompression) is abstracted behind a common `PhysicalMemory` trait.

2. **Process discovery**: Scans physical memory for EPROCESS structures using signature matching (`System\0` at ImageFileName offset) with auto-detection across 18 known offset tables (WinXP SP3 through Win11 24H2, x86 PAE + x64).

3. **Page table walking**: Translates virtual addresses to physical using the kernel DTB (CR3). Supports 4-level x64 page tables and 3-level PAE (pre-Vista x86). TLB cache (256-entry direct-mapped), large pages (2MB/1GB), PCID bits, and pagefile fault resolution.

4. **LSASS extraction**: Locates `lsass.exe`, maps its virtual address space, finds DLLs (`lsasrv.dll`, `msv1_0.dll`, `wdigest.dll`, `kerberos.dll`, `dpapisrv.dll`, etc.) via PEB/LDR enumeration, resolves crypto keys via pattern matching on `.text`/`.data` sections, and decrypts credentials in-memory using 3DES-CBC, AES-CBC, AES-CFB, DES-X-CBC, or RC4 (auto-detected by buffer alignment and OS version). Also works on LSASS minidumps (`.dmp`).

5. **Disk extraction**: Parses the virtual disk container (sparse VMDK, VDI, QCOW2, VHDX, VHD, LVM block devices), finds the Windows partition (MBR/GPT), detects BitLocker-encrypted volumes (`-FVE-FS-` signature), walks NTFS MFT to locate `SAM`, `SYSTEM`, `SECURITY` hives, and decrypts hashes using the boot key. Supports both modern (AES, Vista+) and legacy (DES-ECB/RC4, XP/2003) LSA secret encryption. On ESXi, a native VMFS-5/6 parser reads flat VMDKs directly from raw SCSI devices, bypassing filesystem locks on running VMs.

6. **NTDS extraction**: For domain controllers (`--ntds`), locates `NTDS.dit` and the `SYSTEM` hive on disk, then parses the ESE (JET Blue) database natively. Traverses B+ trees to read the `datatable`, extracts the PEK (Password Encryption Key) using the bootkey, and decrypts NT/LM hashes for every AD account. Supports both 8KB pages (Windows Server 2019 and earlier) and 32KB large pages (Windows Server 2025), as well as RC4 (legacy), AES pre-Win2016, and AES Win2016+ (v0x13) hash blob formats.

## Module Layout

This is a selective map of entry points and implementation boundaries. A parent
such as `cli/output.rs` declares private modules from `cli/output/` and exposes
their entry points; use the reading guide above to follow a specific operation.

```
src/
├── main.rs              Argument parsing, logging and worker thread setup
├── cli/
│   ├── args.rs          Options, feature availability and raw-file classification
│   ├── dispatch.rs      Input routing: VMFS, directory, raw files, disk or snapshot
│   ├── dir.rs           Directory and recursive processing
│   ├── disk.rs          Local disk commands and shared reader extraction
│   ├── disk/
│   │   ├── files.rs     NTFS listing and file copy commands
│   │   ├── raw.rs       Standalone registry hive and NTDS commands
│   │   ├── vmfs.rs      VMFS datastore commands and snapshot association
│   │   └── veeam.rs     Backup listing, reconstruction and disk processing
│   ├── lsass.rs         Snapshot and minidump command entry points
│   ├── lsass/
│   │   ├── snapshot.rs  Format detection, opening and layout diagnostics
│   │   ├── pipeline.rs  System discovery, EPT/carve fallbacks and memory extraction
│   │   ├── chrome.rs    Optional memory/disk browser workflow
│   │   └── bitlocker.rs FVEK discovery and export
│   ├── credentials.rs   Optional disk consumers: DPAPI, CredMan and browsers
│   ├── credman.rs       Credential Manager command orchestration
│   ├── output.rs        Output entry points and shared formatting helpers
│   └── output/
│       ├── sessions.rs  Session formats and extraction summaries
│       ├── dedup.rs     Session grouping, normalization and provider merging
│       ├── text.rs      Session headings and human-readable provider output
│       ├── registry.rs  SAM, LSA and cached domain credential output
│       ├── ntds.rs      AD account and password history output
│       ├── dpapi.rs     Disk master key selection and output
│       ├── credman.rs   Credential Manager and Vault output
│       └── exports.rs   Kerberos, BitLocker and LSA backup key file exports
├── lib.rs               Crate root — feature-gated module declarations
├── error.rs             VmkatzError type
├── utils.rs             Endian helpers, hex, UTF-16LE decode, mmap helpers
├── memory/
│   ├── reader.rs        PhysicalMemory and VirtualMemory traits
│   └── page_index.rs    Bounded run-based snapshot page mappings
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
│   ├── savevm.rs        File opening, header validation and physical reads
│   └── savevm/stream.rs RAM migration records and page-index construction
├── hyperv/              [feature: hyperv] Hyper-V .vmrs/.bin/.raw layer (native VMRS parser)
│   ├── vmrs.rs          VMRS metadata, memory layout and physical reads
│   └── vmrs/
│       ├── metadata.rs  Bounded KeyTable traversal and RAM job enumeration
│       ├── compression.rs XPRESS decoding and RAM block framing
│       ├── scan.rs      Parallel RAM scan and sequential fallback signaling
│       └── budget.rs    Shared worker/cache memory budget
├── secrets.rs           Shared result records; no registry or DPAPI implementation
├── dpapi/               [feature: dpapi] Blobs, masterkeys, CREDHIST; optional disk adapter
├── credman/             [feature: credman] Offline Credentials/Vault consumers
├── fs/                  [feature: disk] NTFS, partitions, listing and bounded MFT recovery
│   ├── partition.rs    Partition discovery and selection
│   ├── listing.rs      Healthy directory index lookup, then degraded MFT fallback
│   ├── ntfs.rs         Partition reader, NTFS navigation, bounded reads and file copy
│   ├── ntfs/stream.rs  Resilient read/seek adapter for registry recovery
│   ├── ntfs_fallback.rs Degraded listing and file recovery entry points
│   ├── ntfs_fallback/
│   │   ├── records.rs  Boot parameters, data runs and FILE attributes
│   │   ├── mft.rs      MFTMirr bootstrap, traversal and target-file search
│   │   ├── data.rs     Bounded file reads and attribute-list extensions
│   │   └── tests.rs    Synthetic volumes and recovery regressions
│   └── recovery.rs     Shared scan, file-size and candidate limits
├── sam/                 [feature: sam] Registry SAM/LSA/DCC2 extraction
│   ├── mod.rs           Orchestration, disk extraction entry point
│   ├── hive.rs          Windows registry hive parser (regf format)
│   ├── bootkey.rs       Bootkey extraction from SYSTEM hive
│   ├── hashes.rs        SAM hash decryption (AES-CBC, RC4, MD5, DES)
│   ├── lsa.rs           LSA secrets decryption (DPAPI system keys, service passwords)
│   ├── cache.rs         Cached domain credentials (DCC2)
│   ├── ntfs_reader.rs   Streaming NTDS and registry reads, bounded recovery
│   ├── disk_fallbacks.rs Fallback hive search for non-standard layouts
│   └── vmdk_scan.rs     Bounded grain recovery: candidates, contiguous hives, fragments
├── disk/                [feature: disk] Virtual disk formats + BitLocker sector reader
│   ├── mod.rs          Format dispatch, DiskImage trait and shared I/O bounds
│   ├── table.rs        Bounded on-demand allocation-table cache
│   ├── vmdk.rs          VMware sparse/flat VMDK
│   ├── vmdk/directory.rs Bounded grain-directory access and cache
│   ├── vdi.rs           VirtualBox VDI (+ differencing chain)
│   ├── qcow2.rs         QEMU QCOW2 (+ backing files)
│   ├── vhd.rs           Hyper-V VHD (legacy)
│   ├── vhdx.rs          Hyper-V VHDX
│   ├── raw.rs           Raw/block device passthrough
│   ├── bitlocker_decrypt.rs Transparent sector-decryption reader
│   ├── vmfs.rs          [feature: vmfs] Public API and complete volume I/O workflow
│   └── vmfs/
│       ├── lvm.rs       Logical-to-physical extent mapping
│       ├── metadata.rs  Superblock, resource metadata and file descriptors
│       └── tests.rs     Directory, block mapping and descriptor-boundary regressions
├── veeam/               [feature: veeam] Veeam backup access
│   ├── disk.rs          Native adapter exposing backup images as disks
│   └── upstream/        Imported vbktool implementation
└── ntds/                [feature: ntds.dit] NTDS.dit ESE database parser
    ├── mod.rs           PEK decryption, hash extraction pipeline
    └── ese.rs           JET Blue database primitives (pages, B+ trees, columns)
```

To follow a command, start at `cli::dispatch::run`. It checks VMFS options
and directories first, then recognizes raw file combinations. For a single
file, it selects the minidump, backup, disk or snapshot handler. Disk handlers
process `--cp` before `--ls`, followed by extraction. `Args::requests_disk_mode`
lists the options that force disk processing; `--chrome` also supports snapshots
and therefore does not force that choice.

`cli/disk.rs` keeps local-image processing and shared reader helpers. Its private
submodules implement NTFS file operations, raw registry/NTDS input, VMFS and Veeam
commands. Raw, VMFS and Veeam modules are gated by `sam`, `vmfs` and `veeam`;
their entry points remain available through `cli::disk` re-exports.

`cli/lsass.rs` is the parent module; `cli/lsass/` holds its private submodules.
`snapshot` selects and opens the memory layer, then `pipeline` discovers System
and runs the memory extraction stages. Chrome and BitLocker workflows have their
own modules. These submodules require at least one backend; format selection and
optional stages retain their individual feature gates.

`cli/output.rs` exposes the output entry points and shared formatting helpers.
Its private modules group formatters by data source and keep file exports separate.
Registry, NTDS and CredMan output follow their respective features; disk master key
output requires both `disk` and `dpapi`. LSA backup key export stays under `sam`,
without requiring the `dpapi` feature.

`disk/vmfs.rs` starts with the public API and flat-VMDK reader, followed by a single
`Vmfs6Volume` implementation. Bootstrap, resource reads, block resolution and
directory traversal stay together because they share the same volume state and
call each other. LVM mapping and metadata decoding remain separate; the reader's
unit tests are grouped in `vmfs/tests.rs`.

`fs/ntfs_fallback.rs` keeps the degraded listing and recovery entry points.
`records` decodes on-disk structures, `mft` handles bootstrap and both listing and
target-file scans, and `data` reads file contents. Target-file search and `data`
require `sam` or unit tests; disk-only listing remains available. Both search passes
share one `ScanBudget`, with limits centralized in `fs/recovery.rs`.

Veeam's imported implementation lives under `veeam/upstream/`, with its lint
exceptions scoped to that module. The native `veeam/disk.rs` adapter uses the
normal crate lint policy. Public Veeam module paths are preserved by re-exports
in `veeam/mod.rs`.

## Chrome module (optional)

Extracts browser secrets (passwords, cookies, autofill) from Chromium-family
browsers (Chrome, Edge, Brave, Vivaldi, Opera) and Firefox. Gated by the
`chrome` Cargo feature (not in the default set) and the `--chrome` runtime
flag; depends on `disk` and `dpapi`. SAM/LSA are optional secret sources; a build
without `sam` can use explicit passwords/hashes or LSASS keys in hybrid mode.

```
src/chrome/
├── runner.rs         CLI orchestration: disk-only / hybrid / reader-based entrypoints
├── profile.rs        NTFS-walking profile + artifact discovery
├── disk.rs           per-profile SQLite decrypt + key derivation orchestrator
├── local_state.rs    parse Chrome/Edge "Local State" JSON for encrypted_key + ABE blob
├── dpapi_decrypt.rs  Compatibility re-export of dpapi::blob primitives
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

- **DPAPI masterkey decryption** — for user MKs, `dpapi::masterkey` runs
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

For the implemented browser workflows, start at [chrome/runner.rs](../src/chrome/runner.rs).
