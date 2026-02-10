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

/// Find .vmsn files with matching .vmem, and standalone .sav files.
fn discover_lsass_files(all_files: &[PathBuf], out: &mut Vec<PathBuf>) {
    for file in all_files {
        let ext = file.extension().and_then(|e| e.to_str()).unwrap_or("");

        if ext.eq_ignore_ascii_case("vmsn") {
            // Only include .vmsn if a matching .vmem exists in same directory
            let vmem = file.with_extension("vmem");
            if vmem.is_file() {
                out.push(file.clone());
            }
        } else if ext.eq_ignore_ascii_case("sav") {
            // Skip empty .sav files (0 bytes = incomplete/placeholder snapshot)
            if let Ok(meta) = file.metadata() {
                if meta.len() > 0 {
                    out.push(file.clone());
                }
            }
        }
    }
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

        let stem = file
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("");

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
    if let Ok(data) = fs::read(path) {
        if data.len() >= 21 {
            return data.starts_with(b"# Disk DescriptorFile");
        }
    }
    false
}
