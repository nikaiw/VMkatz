//! Detect and open memory snapshots, including format-specific layout probing.

use std::path::Path;

use anyhow::Context;
use vmkatz::memory::PhysicalMemory;

/// Snapshot formats, including formats unavailable in the current build.
pub(super) enum SnapshotFormat {
    VBox,
    QemuElf,
    #[cfg(feature = "qemu")]
    QemuSavevm,
    HypervBin,
    HypervVmrs,
    Vmware,
    UnsupportedDisk,
}

/// Detect the memory snapshot format from extension and magic bytes.
pub(super) fn detect_snapshot_format(path: &Path, ext: &str, carve: bool) -> SnapshotFormat {
    // Extension-based detection first
    if ext.eq_ignore_ascii_case("sav") {
        return SnapshotFormat::VBox;
    }
    if ext.eq_ignore_ascii_case("elf") {
        return SnapshotFormat::QemuElf;
    }
    if ext.eq_ignore_ascii_case("vmrs") {
        return SnapshotFormat::HypervVmrs;
    }
    if ext.eq_ignore_ascii_case("bin") {
        // Could be Hyper-V .bin, QEMU savevm, or a raw dump — check magic
        #[cfg(feature = "qemu")]
        if vmkatz::qemu::is_qemu_savevm(path) {
            return SnapshotFormat::QemuSavevm;
        }
        if has_elf_magic(path) {
            return SnapshotFormat::QemuElf;
        }
        #[cfg(feature = "hyperv")]
        if vmkatz::hyperv::is_vmrs_file(path) {
            return SnapshotFormat::HypervVmrs;
        }
        return SnapshotFormat::HypervBin;
    }
    if ext.eq_ignore_ascii_case("raw") {
        // Raw memory dump — check for QEVM/ELF magic
        #[cfg(feature = "qemu")]
        if vmkatz::qemu::is_qemu_savevm(path) {
            return SnapshotFormat::QemuSavevm;
        }
        if has_elf_magic(path) {
            return SnapshotFormat::QemuElf;
        }
        return SnapshotFormat::HypervBin;
    }

    #[cfg(feature = "qemu")]
    if vmkatz::qemu::is_qemu_savevm(path) {
        return SnapshotFormat::QemuSavevm;
    }
    if has_elf_magic(path) {
        return SnapshotFormat::QemuElf;
    }

    if ext.eq_ignore_ascii_case("vmem")
        || ext.eq_ignore_ascii_case("vmsn")
        || ext.eq_ignore_ascii_case("vmss")
    {
        return SnapshotFormat::Vmware;
    }

    // Reject disk image extensions — these should never reach LSASS extraction
    if ext.eq_ignore_ascii_case("vmdk")
        || ext.eq_ignore_ascii_case("vdi")
        || ext.eq_ignore_ascii_case("qcow2")
        || ext.eq_ignore_ascii_case("qcow")
        || ext.eq_ignore_ascii_case("vhdx")
        || ext.eq_ignore_ascii_case("vhd")
    {
        return SnapshotFormat::UnsupportedDisk;
    }

    // In carve mode, truly unknown files default to identity-mapped raw (HypervBin)
    if carve {
        return SnapshotFormat::HypervBin;
    }

    SnapshotFormat::Vmware
}

fn has_elf_magic(path: &Path) -> bool {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic).is_ok() && magic == [0x7f, b'E', b'L', b'F']
}

#[cfg(feature = "vbox")]
pub(super) fn vbox(input_path: &Path, verbose: bool) -> anyhow::Result<vmkatz::vbox::VBoxLayer> {
    if verbose {
        eprintln!(
            "[*] Opening VirtualBox saved state: {}",
            input_path.display()
        );
    }
    let layer =
        vmkatz::vbox::VBoxLayer::open(input_path).context("Failed to open VirtualBox .sav file")?;
    if verbose {
        eprintln!(
            "[+] RAM: {} MB ({} pages mapped)",
            layer.phys_size() / (1024 * 1024),
            layer.page_count()
        );
    }
    Ok(layer)
}

#[cfg(feature = "qemu")]
pub(super) fn qemu_elf(
    input_path: &Path,
    verbose: bool,
) -> anyhow::Result<vmkatz::qemu::QemuElfLayer> {
    if verbose {
        eprintln!("[*] Opening QEMU ELF core dump: {}", input_path.display());
    }
    let layer = vmkatz::qemu::QemuElfLayer::open(input_path)
        .context("Failed to open QEMU ELF core dump")?;
    if verbose {
        eprintln!(
            "[+] ELF: {} MB physical, {} PT_LOAD segments",
            layer.phys_size() / (1024 * 1024),
            layer.segment_count()
        );
    }
    Ok(layer)
}

#[cfg(feature = "hyperv")]
pub(super) fn hyperv_bin(
    input_path: &Path,
    verbose: bool,
) -> anyhow::Result<vmkatz::hyperv::HypervLayer> {
    if verbose {
        eprintln!("[*] Opening Hyper-V memory dump: {}", input_path.display());
    }
    let layer = vmkatz::hyperv::HypervLayer::open(input_path)
        .context("Failed to open Hyper-V .bin memory dump")?;
    if verbose {
        eprintln!(
            "[+] RAM: {} MB identity-mapped",
            layer.phys_size() / (1024 * 1024)
        );
    }
    Ok(layer)
}

#[cfg(feature = "hyperv")]
pub(super) fn hyperv_vmrs(
    input_path: &Path,
    verbose: bool,
) -> anyhow::Result<vmkatz::hyperv::VmrsLayer> {
    if verbose {
        eprintln!(
            "[*] Opening Hyper-V VMRS saved state: {}",
            input_path.display()
        );
    }
    let layer =
        vmkatz::hyperv::VmrsLayer::open(input_path).context("Failed to open VMRS saved state")?;
    if verbose {
        eprintln!(
            "[+] VMRS: {} MB guest physical memory",
            layer.phys_size() / (1024 * 1024)
        );
    }
    Ok(layer)
}

#[cfg(feature = "vmware")]
pub(super) fn vmware(
    input_path: &Path,
    verbose: bool,
) -> anyhow::Result<vmkatz::vmware::VmwareLayer> {
    if verbose {
        eprintln!("[*] Opening VMware memory dump: {}", input_path.display());
    }
    let layer = vmkatz::vmware::VmwareLayer::open(input_path)
        .context("Failed to open VMware memory dump")?;
    if verbose {
        eprintln!("[+] VMEM mapped: {} MB", layer.phys_size() / (1024 * 1024));
        eprintln!("[+] Memory regions: {}", layer.regions.len());
        for (i, region) in layer.regions.iter().enumerate() {
            eprintln!(
                "    Region {}: guest=0x{:x} vmem=0x{:x} pages=0x{:x} ({}MB)",
                i,
                region.guest_page_num,
                region.vmem_page_num,
                region.page_count,
                (region.page_count * 0x1000) / (1024 * 1024)
            );
        }
    }
    Ok(layer)
}

#[cfg(feature = "qemu")]
pub(super) fn qemu_savevm(
    input_path: &Path,
    verbose: bool,
) -> anyhow::Result<vmkatz::qemu::QemuSavevmLayer> {
    use vmkatz::windows::process;

    // savevm omits the MMIO gap; the wrong gap misplaces high guest memory.
    // Probe candidate mappings using the Windows process list.
    const GAP_CANDIDATES: &[u64] = &[0x8000_0000, 0xB000_0000, 0xC000_0000, 0xE000_0000];
    let mut chosen_gap: Option<u64> = None;
    for gap in GAP_CANDIDATES {
        let Ok(layer) = vmkatz::qemu::QemuSavevmLayer::open_with_gap(input_path, *gap) else {
            continue;
        };
        // Finding System alone can succeed even with misplaced page tables.
        let healthy_list = match process::find_system_process_auto(&layer) {
            Ok((system, offsets)) => process::enumerate_processes(&layer, &system, &offsets)
                .is_ok_and(|ps| ps.len() >= 5),
            Err(_) => false,
        };
        if healthy_list {
            chosen_gap = Some(*gap);
            break;
        }
    }

    if verbose {
        eprintln!("[*] Opening QEMU savevm state: {}", input_path.display());
    }
    let layer = match chosen_gap {
        Some(gap) => vmkatz::qemu::QemuSavevmLayer::open_with_gap(input_path, gap),
        None => vmkatz::qemu::QemuSavevmLayer::open(input_path),
    }
    .context("Failed to open QEMU savevm state")?;
    if verbose {
        eprintln!(
            "[+] QEMU savevm: {} MB physical memory",
            layer.phys_size() / (1024 * 1024),
        );
    }
    Ok(layer)
}
