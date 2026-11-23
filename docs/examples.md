# Example Output

## LSASS extraction (default text)
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
    NT Hash : bbf7d1528afa8b0fdd40a5b2531bbb6d
    SHA1    : 6ed12f1e60b17cfff120d753029314748b58aa05
    DPAPI   : 6ed12f1e60b17cfff120d753029314748b58aa05
```

## Hashcat mode
```
$ vmkatz --format hashcat snapshot.vmsn
[*] Providers: MSV(ok) WDigest(ok) ...
bbf7d1528afa8b0fdd40a5b2531bbb6d
```

## NTDS.dit extraction
```
$ vmkatz --ntds dc-disk.qcow2

[+] NTDS Artifacts:
  Partition offset : 0x100000
  ntds.dit size    : 20971520 bytes
  SYSTEM size      : 14155776 bytes
  Bootkey          : 9ae365ba5244457bfc2a26187a28346a
  Hashes extracted : 18

[+] AD NTLM Hashes:
  RID: 500    Administrator            current    NT:c66d72021a2d4744409969a581a1705e
  RID: 502    krbtgt                   current    NT:9c238cafb7b4447e5f701c71dbdcf636
  RID: 1000   vagrant                  current    NT:e02bc503339d51f71d913c245d35b50b
  ...
```

Usernames are prefixed by default when the account SID matches a domain SID
from the domain root and LDAP `crossRef` in `ntds.dit`. Accounts whose domain
cannot be matched unambiguously remain unprefixed. Include password history with:

```bash
vmkatz --ntds --ntds-history dc-disk.qcow2
```

An explicit prefix (for example the NetBIOS name) overrides the NTDS mapping:

```bash
vmkatz --ntds --ntds-domain-prefix CORP dc-disk.qcow2
```

## Proxmox disk of a running VM

On a Proxmox host, vmkatz accepts the VM's active LVM block device directly;
the VM does not need to be stopped. The device is opened for reading, and
vmkatz does not change the LV or block-device read/write state:

```bash
vmkatz --credman /dev/pve/vm-102-disk-0
vmkatz --ntds --credman /dev/pve/vm-110-disk-1
```

The first command scans local SAM/LSA and Credential Manager data. The second
also parses NTDS and supplies its account hashes to the DPAPI masterkey
resolver. A running guest can update files during the scan, so the result is
not an atomic point-in-time image; use a Proxmox snapshot when consistency is
required.

## Listing and copying disk files

```sh
vmkatz --ls '\Windows\System32\config' disk.vmdk
vmkatz --cp '\Windows\NTDS\ntds.dit' ./ntds.dit disk.vmdk
```

`--cp` and the `extract_file ... get` helper stream the NTFS data with a 64 KiB
copy buffer, including files larger than 2 GiB. The destination must not already
exist; files and symlinks are never overwritten. A read/write error or premature
end of the NTFS stream fails the copy and removes its incomplete output. These
copy operations do not use the NTFS registry-recovery zero-fill fallback; the
underlying disk-format readers retain their own sparse/damaged-image behaviour.

## Large disks and damaged NTFS volumes

Disk extraction requires an NTFS or BitLocker volume signature in the boot
sector. A Linux-only MBR/GPT disk is rejected without scanning its contents;
VMFS enumeration skips it before opening associated memory snapshots. A readable
NTFS index reporting a missing Windows path does not trigger raw recovery.

Snapshot parent chains are limited to 64 parent levels across VMDK, VDI, VHD,
VHDX and QCOW2. A longer chain or cycle is rejected instead of recursing without
a limit.

Sparse VMDK grain directories are read on demand through **four 4 KiB windows
per snapshot level** (16 KiB of cached data), shared across that level's extents.
The windows are allocated on first use and replaced in FIFO order. Opening an
8 TiB disk does not load its entire grain directory into RAM. Truncated directory ranges are
rejected before reading; parent paths and locator metadata fields are limited
to **1 MiB each**. These limits cover disk metadata, not all extraction buffers.

VDI, VHD, VHDX and QCOW2 allocation tables are also read on demand, through
sixteen 4 KiB windows (**64 KiB of cached table data per disk in a parent chain**).
QCOW2 L1 and L2 tables share that cache, including images with 16 MiB clusters.
Table ranges are checked before use; neither table size nor virtual disk capacity
causes a full-table allocation. These readers use ordinary file I/O and do not
require `mmap`.

Automatic recovery has fixed limits:

- Whole-disk regf/hbin and VMDK grain recovery is disabled above **1 GiB of
  virtual capacity**, including sparse images. Normal NTFS lookup still works
  on larger disks.
- An MFT fallback scan visits at most **64 MiB or 65,536 records** per invocation,
  shared across retries and path components for directory listings. It checks
  a **30-second deadline** between batches. Failed reads count toward the budget.
- Recovered files and the scattered-hive block collection are capped at
  **64 MiB** each; listing and VMDK signature collections are capped at
  **65,536 candidates**. These are recovery limits, not a process-wide RAM limit.
- Exceeding a budget reports `Recovery stopped`; an incomplete directory scan
  is not reported as an empty or successful listing. A recovered NTDS database
  larger than 64 MiB is refused; normal NTFS file reads use their existing limits.

These bounds reduce automatic recovery work but can leave files unrecovered on
damaged images, especially when the boot sector itself is missing. They do not
throttle storage traffic or interrupt a kernel read blocked on storage. Use a
consistent copy and external resource limits when analysing production data.

Hyper-V VMRS retains at most **128 MiB of RAM-block data** in its cache, reduced
when the host reports less available memory. Parallel scans share that budget
between retained blocks, decompression buffers and the stacks of at most eight
workers. The old cache is released before scanning; warming it never raises its
limit. Metadata has separate bounds: **262,144 object entries**, a **32 MiB**
key budget (including estimated allocation overhead), **4 KiB** key paths,
**64** nested tables and **1,000,000** traversal steps. KeyTables use a **64 KiB**
read buffer; their declared size no longer causes a complete allocation.
Parallel jobs are generated on demand, including sparse high block indices.
Sweep buffers and callback allocations are outside the RAM-cache budget.

VirtualBox `.sav` reads guest RAM on demand; it does not keep a decompressed
copy or write one to a temporary file. Its LZF cache holds at most **16 records**
(**255 KiB** each), plus a transient compressed record of at most **2 MiB**.
Logical-to-file checkpoints use at most **1 MiB**; spacing starts at **8 MiB**
and widens for very large streams. Random reads may scan intervening record
headers and decompress a cache miss; sequential reads reuse the current record.
SSM strings are limited to **1 MiB**.

VirtualBox and QEMU savevm group consecutive page mappings into runs with a
constant offset stride. Their index is limited to **131,072 runs** (under
**16 MiB** on 64-bit targets), with space reserved for splitting updates.
This bounds fragmentation rather than guest RAM size: very fragmented snapshots
can return a metadata-budget error. QEMU also limits RAM-block declarations to
**65,536**. It still requires a whole-file virtual `mmap` for stream parsing;
its virtual address reservation is not covered by the index budget. Existing
pread fallbacks for other readers, including older ESXi hosts, are preserved.

NTDS extraction reads ESE pages directly from NTFS, including sparse/fragmented
files and BitLocker readers. Raw NTDS files use the same seekable reader; neither
path requires `mmap` or a complete database buffer. The page cache retains at
most **512 KiB**. Visited-page bitmaps allocate only reached ranges, with an
**8 MiB** limit per traversal; pending page pointers are capped at **4 MiB**.
Catalog records and each resolved long value have **16 MiB** payload limits.

SAM, SYSTEM and SECURITY are read sequentially through **64 KiB windows**,
with at most **512 KiB cached per hive**. Their combined file size is no longer
limited to 128 MiB on normal NTFS or raw-file CLI paths. NTDS keeps only the
bootkey after processing SYSTEM. The registry parser bounds individual cell/value
reads and retained subkey enumeration at **16 MiB**, and list traversal at
**65,536 lists**. Disconnected SYSTEM-cell recovery stops after **64 MiB** of
scan range, **1,048,576 attempts**, or **30 seconds**; normal indexed lookups
can reach cells anywhere in a large hive.

Generic complete NTFS reads remain capped at **128 MiB per file**. For NTDS,
use `with_ntds_bootkey` to stream both NTDS and SYSTEM. Its `output` result
carries SYSTEM/parser errors separately from filesystem lookup failures. `NtdsContext::ntds_size`
and `NtdsReadResult::system_size` use `u64`. `--cp` remains streamed.
The buffered `extract_ntds_artifacts*` and `with_ntds_artifacts` APIs and
`NtdsArtifacts` have been removed in favour of `with_ntds_bootkey`.
DLL page recovery reads only PE headers and retained sections, sharing a
**128 MiB** section budget across modules instead of loading complete DLLs.

Browser databases and WAL files still use buffered reads, limited to **128 MiB
per file**; a resource refusal is reported as an error, not an absent profile.
Several profiles can retain multiple buffers. The optional Veeam `diskfs`
library interface buffers files up to **512 MiB** and rejects larger files;
the CLI uses `VbkDisk` with the generic NTFS streaming readers instead.

These hive readers need no file-backed `mmap`, including on older ESXi hosts.
The existing `pread` fallback remains available to other readers. Minidumps
still need contiguous bytes and can use substantial RAM when mapping fails.
Extracted results and other consumers may retain their own buffers: these are
component limits, not a process-wide memory guarantee.

## Pagefile resolution
```
$ vmkatz --disk disk.vmdk snapshot.vmsn
[+] Pagefile: 320.0 MB
[*] Providers: MSV(ok) WDigest(ok) ...
[+] File-backed: 12540 DLL pages resolved from disk
[+] Pagefile: 2274 pages resolved from disk
```

Memory snapshots only capture physical RAM. Credentials that were paged to disk at snapshot time appear as `(paged out)`. The `--disk` flag reads pagefile.sys from the VM's virtual disk to resolve these.

In **directory mode**, this happens automatically: VMkatz discovers both the snapshot and the disk image, and resolves paged memory without manual flags.

## Browser secrets (`--chrome`)

Requires a build with `--features chrome`. Decrypts saved passwords, cookies
and autofill from Chromium-family browsers (Chrome, Edge, Brave, Vivaldi,
Opera). Firefox profile discovery works; Firefox NSS plaintext decrypt is
a scaffold.

### Disk-only

When the user's plaintext password is in LSA secrets (auto-logon /
service account / cached), no extra args needed:

```
$ vmkatz --chrome disk.vmdk
[Chrome] user/Default (Edge)
  artifacts: local_state=54644 login_data=57344 cookies=77824 web_data=262144
  path: Users\user\AppData\Local\Microsoft\Edge\User Data\Default

[+] Chrome findings: 1 password, 18 cookies, 0 autofill
  www.example.com  user@example.com  Pa$$w0rd1234
  ...
```

When the password isn't in LSA, supply it via `--chrome-password` (repeatable):

```
$ vmkatz --chrome --chrome-password vagrant --chrome-password 'P@ssword!' disk.vmdk
```

### Hybrid (memory + disk)

Pairing a memory snapshot with `--disk` gives the best v20 ABE yield —
LSASS-cached masterkeys cover GUIDs that disk-side derivation alone can't
unlock, and Chrome's elevation-service-only MKs land in this path.

```
$ vmkatz --chrome --disk windows.vmdk snapshot.vmsn
...
[Chrome] user/Default (Chrome)
  artifacts: local_state=225878 login_data=40960 cookies=40960 web_data=135168
[+] Chrome findings: 1 password, 83 cookies, 0 autofill
```

### In-process discovery (`--chrome-process-scan`, opt-in)

Walks every running `chrome.exe` / `msedge.exe` / `brave.exe` in the
snapshot through the page-table region enumerator and logs each
process's PID, image and resident memory size. Pair with `-v` to see
the discovery lines:

```
$ vmkatz -v --chrome --chrome-process-scan --disk windows.vmdk snapshot.vmsn
[INFO] [chrome-mem] PID 5688 msedge.exe (115 MiB mapped userland) — discovery only; structured CookieMonster walking is queued behind per-Chrome-version locator signatures
[INFO] [chrome-mem] PID 7732 msedge.exe (7 MiB mapped userland) — discovery only; ...
[INFO] [chrome-mem] PID 8372 msedge.exe (23 MiB mapped userland) — discovery only; ...
[INFO] [chrome-mem] discovered 5 chromium process(es); no in-memory cookies/passwords emitted (heuristic was structurally unreliable, signature locator pending)
```

The flag's `findings` output is intentionally empty today: an earlier
heuristic-based extractor (search for `https://` UTF-16 plus the next
two strings; search for ASCII domains plus the next four strings) was
removed because chrome process memory is filled with minified-JavaScript
string tables and chrome.dll constants that look syntactically identical
to cookie or credential data once isolated from their structural context.
The triples it produced were dominated by URL-path-fragment usernames
(`internal/`, `api/v1/`) and JS-token cookie values (`Symbol&&Symbol.`,
`||void 0===t||t`) — every filter pass either still leaked thousands of
false positives or rejected real cookies too.

The proper fix is the per-Chrome-version `CookieMonster` locator
signature ChromeKatz uses: pattern-match the destructor in chrome.dll,
resolve the vtable, scan the heap for objects with that vtable, then
walk the `std::map` red-black tree to read each `CanonicalCookie`. The
[struct layouts in `src/chrome/cookie_monster.rs`](https://github.com/nikaiw/VMkatz/blob/dev/src/chrome/cookie_monster.rs)
are ready; only the locator pattern is missing. Once it lands the same
flag will return real cookies and the plaintext passwords Edge ≤ 147
keeps mapped for the whole session ([Rønning, April
2026](https://www.threatlocker.com/blog/microsoft-edge-is-keeping-your-passwords-in-plaintext-memory-heres-what-that-actually-means)).

### JSON output

For tooling integration, pretty text becomes a single JSON document
containing every profile and finding:

```
$ vmkatz --chrome --chrome-json disk.vmdk
{
  "profiles": [
    { "user": "user", "browser": "Chrome", "profile_name": "Default", ... }
  ],
  "findings": {
    "passwords": [ { "url": "...", "username": "...", "password": "..." } ],
    "cookies":   [ { "host": "...", "name": "...", "value": "..." } ],
    "autofill":  [ ... ]
  }
}
```
