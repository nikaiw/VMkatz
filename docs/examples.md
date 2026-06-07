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
