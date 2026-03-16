use std::fs;
use std::path::{Path, PathBuf};

use crate::error::Result;

/// Discovered VM files for automatic processing.
pub struct VmDiscovery {
    /// LSASS snapshot files (.vmsn with matching .vmem, .sav files)
    pub lsass_files: Vec<PathBuf>,
    /// Disk image files for SAM extraction (.vmdk descriptors, .vdi, .qcow2)
    pub disk_files: Vec<PathBuf>,
}

/// Scan a VM directory and discover all processable files.
///
/// Looks in the root directory and any `Snapshots/` subdirectory for:
/// - LSASS: `.vmsn` files with matching `.vmem`, `.sav` files
/// - SAM: latest VMDK descriptor, VDI diff images, QCOW2 files
pub fn discover_vm_files(dir: &Path) -> Result<VmDiscovery> {
    let mut lsass_files = Vec::new();
    let mut disk_files = Vec::new();

    // Directories to scan: root + Snapshots/ if present
    let mut scan_dirs = vec![dir.to_path_buf()];
    let snapshots_dir = dir.join("Snapshots");
    if snapshots_dir.is_dir() {
        scan_dirs.push(snapshots_dir);
    }

    // Collect all files from scan directories
    let mut all_files: Vec<PathBuf> = Vec::new();
    for scan_dir in &scan_dirs {
        if let Ok(entries) = fs::read_dir(scan_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    all_files.push(path);
                }
            }
        }
    }

    // --- LSASS candidates ---
    discover_lsass_files(&all_files, &mut lsass_files);

    // --- SAM/disk candidates ---
    discover_vmdk(dir, &all_files, &mut disk_files);
    discover_vdi(&all_files, &scan_dirs, &mut disk_files);
    discover_qcow2(&all_files, &mut disk_files);
    discover_vhdx(&all_files, &mut disk_files);
    discover_vhd(&all_files, &mut disk_files);

    // Sort for consistent ordering
    lsass_files.sort();
    disk_files.sort();

    Ok(VmDiscovery {
        lsass_files,
        disk_files,
    })
}

/// Find memory snapshot files: .vmsn+.vmem, .sav, .elf, .bin, .raw
fn discover_lsass_files(all_files: &[PathBuf], out: &mut Vec<PathBuf>) {
    for file in all_files {
        let ext = file.extension().and_then(|e| e.to_str()).unwrap_or("");

        if ext.eq_ignore_ascii_case("vmsn") || ext.eq_ignore_ascii_case("vmss") {
            // Only include .vmsn/.vmss if a matching .vmem exists in same directory
            let vmem = file.with_extension("vmem");
            if vmem.is_file() {
                out.push(file.clone());
            }
        } else if ext.eq_ignore_ascii_case("sav") {
            // VirtualBox saved state - skip empty files
            if let Ok(meta) = file.metadata() {
                if meta.len() > 0 {
                    out.push(file.clone());
                }
            }
        } else if ext.eq_ignore_ascii_case("elf") {
            // QEMU ELF core dump (from dump-guest-memory / virsh dump --memory-only)
            if is_elf_core(file) {
                out.push(file.clone());
            }
        } else if ext.eq_ignore_ascii_case("vmrs") {
            // Hyper-V modern saved state (.vmrs)
            if let Ok(meta) = file.metadata() {
                if meta.len() > 1024 * 1024 {
                    out.push(file.clone());
                }
            }
        } else if ext.eq_ignore_ascii_case("bin") {
            // Hyper-V legacy .bin or ELF dump with .bin extension
            if let Ok(meta) = file.metadata() {
                // Hyper-V .bin files are VM-RAM-sized; skip tiny metadata files
                if meta.len() > 1024 * 1024 {
                    out.push(file.clone());
                }
            }
        } else if ext.eq_ignore_ascii_case("raw") {
            // Raw memory dump (from MemProcFS export, etc.)
            if let Ok(meta) = file.metadata() {
                if meta.len() > 1024 * 1024 {
                    out.push(file.clone());
                }
            }
        }
    }
}

/// Check if a file is an ELF core dump (magic + ET_CORE). Reads only 18 bytes.
fn is_elf_core(path: &Path) -> bool {
    use std::io::Read;
    let Ok(mut f) = fs::File::open(path) else {
        return false;
    };
    let mut buf = [0u8; 18];
    if f.read_exact(&mut buf).is_err() {
        return false;
    }
    // ELF magic: 7f 45 4c 46
    if buf[0..4] != [0x7f, b'E', b'L', b'F'] {
        return false;
    }
    // e_type at offset 16 (u16 LE) should be ET_CORE (4)
    let e_type = u16::from_le_bytes([buf[16], buf[17]]);
    e_type == 4
}

/// Find the latest VMDK descriptor file for SAM extraction.
///
/// Strategy: find the highest-numbered snapshot descriptor (`*-NNNNNN.vmdk`),
/// filtering out binary extent files (`*-sNNN.vmdk`).
/// Falls back to the base VMDK if no numbered snapshots exist.
fn discover_vmdk(dir: &Path, all_files: &[PathBuf], out: &mut Vec<PathBuf>) {
    let mut best_descriptor: Option<(u32, PathBuf)> = None;
    let mut base_descriptor: Option<PathBuf> = None;

    for file in all_files {
        let ext = file.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !ext.eq_ignore_ascii_case("vmdk") {
            continue;
        }

        // Only look in root dir for VMDKs (not Snapshots/)
        if file.parent() != Some(dir) {
            continue;
        }

        let stem = file.file_stem().and_then(|s| s.to_str()).unwrap_or("");

        // Skip extent files: pattern *-sNNN
        if is_extent_filename(stem) {
            continue;
        }

        // Check if this is a numbered snapshot descriptor: *-NNNNNN
        if let Some(num) = parse_snapshot_number(stem) {
            if is_text_descriptor(file) {
                match &best_descriptor {
                    Some((best_num, _)) if num > *best_num => {
                        best_descriptor = Some((num, file.clone()));
                    }
                    None => {
                        best_descriptor = Some((num, file.clone()));
                    }
                    _ => {}
                }
            }
        } else if is_text_descriptor(file) {
            base_descriptor = Some(file.clone());
        }
    }

    // Prefer highest-numbered snapshot, fall back to base
    if let Some((_, path)) = best_descriptor {
        out.push(path);
    } else if let Some(path) = base_descriptor {
        out.push(path);
    } else {
        // No descriptor found — check for orphan extent files (-sNNN.vmdk)
        // If present, pass the first extent so VmdkDisk::open detects it as binary
        // and auto-discovers all sibling extents from the directory.
        let mut has_extents = false;
        let mut first_extent: Option<PathBuf> = None;
        for file in all_files {
            let ext = file.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !ext.eq_ignore_ascii_case("vmdk") {
                continue;
            }
            if file.parent() != Some(dir) {
                continue;
            }
            let stem = file.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            if is_extent_filename(stem) {
                has_extents = true;
                if first_extent.is_none() {
                    first_extent = Some(file.clone());
                }
            }
        }
        if has_extents {
            if let Some(path) = first_extent {
                out.push(path);
            }
        }
    }
}

/// Find VDI files: prefer Snapshots/ subdirectory (diff images = latest state).
fn discover_vdi(all_files: &[PathBuf], scan_dirs: &[PathBuf], out: &mut Vec<PathBuf>) {
    let snapshots_dir = scan_dirs.get(1);

    // Look for VDIs in Snapshots/ first (diff images = latest state)
    if let Some(snap_dir) = snapshots_dir {
        let mut found = false;
        for file in all_files {
            let ext = file.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext.eq_ignore_ascii_case("vdi") && file.parent() == Some(snap_dir.as_path()) {
                if let Ok(meta) = file.metadata() {
                    if meta.len() > 0 {
                        out.push(file.clone());
                        found = true;
                    }
                }
            }
        }
        if found {
            return;
        }
    }

    // Fall back to base VDI in root
    let root_dir = &scan_dirs[0];
    for file in all_files {
        let ext = file.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext.eq_ignore_ascii_case("vdi") && file.parent() == Some(root_dir.as_path()) {
            out.push(file.clone());
        }
    }
}

/// Find QCOW2/QCOW files.
fn discover_qcow2(all_files: &[PathBuf], out: &mut Vec<PathBuf>) {
    for file in all_files {
        let ext = file.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext.eq_ignore_ascii_case("qcow2") || ext.eq_ignore_ascii_case("qcow") {
            out.push(file.clone());
        }
    }
}

/// Find VHDX files.
fn discover_vhdx(all_files: &[PathBuf], out: &mut Vec<PathBuf>) {
    for file in all_files {
        let ext = file.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext.eq_ignore_ascii_case("vhdx") {
            out.push(file.clone());
        }
    }
}

/// Find VHD files.
fn discover_vhd(all_files: &[PathBuf], out: &mut Vec<PathBuf>) {
    for file in all_files {
        let ext = file.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext.eq_ignore_ascii_case("vhd") {
            out.push(file.clone());
        }
    }
}

/// Check if a VMDK filename stem matches the extent pattern `*-sNNN`.
fn is_extent_filename(stem: &str) -> bool {
    if let Some(pos) = stem.rfind("-s") {
        let suffix = &stem[pos + 2..];
        !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit())
    } else {
        false
    }
}

/// Extract snapshot number from stem like `Base Name-000003`.
/// Returns `Some(3)` for 6-digit suffix after last hyphen.
fn parse_snapshot_number(stem: &str) -> Option<u32> {
    let dash_pos = stem.rfind('-')?;
    let suffix = &stem[dash_pos + 1..];
    if suffix.len() == 6 && suffix.chars().all(|c| c.is_ascii_digit()) {
        suffix.parse().ok()
    } else {
        None
    }
}

/// Check if a VMDK file is a text descriptor (not a binary extent).
/// Descriptor files start with `# Disk DescriptorFile`.
fn is_text_descriptor(path: &Path) -> bool {
    use std::io::Read;
    let mut buf = [0u8; 21];
    let Ok(mut f) = fs::File::open(path) else { return false };
    if f.read(&mut buf).unwrap_or(0) >= 21 {
        return buf.starts_with(b"# Disk DescriptorFile");
    }
    false
}

/// VM file extensions that indicate a directory contains VM files.
const VM_EXTENSIONS: &[&str] = &[
    // Memory snapshots
    "vmsn", "vmss", "vmem", "sav", "elf", "bin", "raw",
    // Disk images
    "vmdk", "vdi", "qcow2", "qcow", "vhdx", "vhd",
    // VM configuration (proves this is a VM directory)
    "vmx", "vbox",
];

/// Recursively discover directories that contain VM files.
///
/// Walks the directory tree under `root` and returns directories containing
/// at least one VM-related file (snapshot, disk image, or config).
/// Results are sorted by path for consistent ordering.
pub fn discover_vm_directories(root: &Path) -> Result<Vec<PathBuf>> {
    let mut vm_dirs = Vec::new();
    walk_for_vm_dirs(root, &mut vm_dirs, 0)?;
    vm_dirs.sort();
    vm_dirs.dedup();
    Ok(vm_dirs)
}

fn walk_for_vm_dirs(dir: &Path, out: &mut Vec<PathBuf>, depth: usize) -> Result<()> {
    // Safety: don't recurse too deep (prevents symlink loops)
    if depth > 20 {
        return Ok(());
    }

    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()), // skip unreadable directories
    };

    let mut has_vm_files = false;
    let mut subdirs = Vec::new();

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // Skip hidden directories and common non-VM directories
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if !name_str.starts_with('.') && name_str != "Logs" {
                subdirs.push(path);
            }
        } else if path.is_file() && !has_vm_files {
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                let ext_lower = ext.to_ascii_lowercase();
                if VM_EXTENSIONS.iter().any(|&vm_ext| vm_ext == ext_lower) {
                    has_vm_files = true;
                }
            }
        }
    }

    if has_vm_files {
        out.push(dir.to_path_buf());
    }

    // Recurse into subdirectories (but don't recurse into VM directories' Snapshots/)
    for subdir in subdirs {
        walk_for_vm_dirs(&subdir, out, depth + 1)?;
    }

    Ok(())
}
