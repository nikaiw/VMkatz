//! Memory-snapshot pipeline: open the hypervisor layer, find System/LSASS,
//! extract credentials, BitLocker keys and (optionally) chrome secrets.

use std::path::Path;

use anyhow::Context;

#[cfg(feature = "hyperv")]
use vmkatz::hyperv::HypervLayer;
use vmkatz::lsass;
use vmkatz::lsass::finder::PagefileRef;
#[cfg(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv"
))]
use vmkatz::memory::PhysicalMemory;
#[cfg(feature = "qemu")]
use vmkatz::qemu::QemuElfLayer;
#[cfg(feature = "vbox")]
use vmkatz::vbox::VBoxLayer;
#[cfg(feature = "vmware")]
use vmkatz::vmware::VmwareLayer;
// EPROCESS offsets auto-detected at runtime from ALL_EPROCESS_OFFSETS
#[cfg(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv"
))]
use vmkatz::windows::process;

use super::args::Args;
#[cfg(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv"
))]
use super::args::get_colors;
#[cfg(all(
    feature = "chrome",
    any(
        feature = "vmware",
        feature = "vbox",
        feature = "qemu",
        feature = "hyperv"
    )
))]
use super::args::parse_chrome_nthashes;
#[cfg(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv"
))]
use super::output::export_bitlocker_fvek;
#[cfg(all(
    feature = "sam",
    any(
        feature = "vmware",
        feature = "vbox",
        feature = "qemu",
        feature = "hyperv"
    )
))]
use super::output::print_registry_creds;
use super::output::{export_kerberos_tickets, output_credentials};

/// Merge `extra` findings into `dst` in place. Used to fold in-process scan
/// results into the disk-side `DiscoverySummary` so the renderer emits one
/// document. Profiles aren't merged here — in-process findings get
/// per-record `ChromeSource::Memory { pid, … }` tagging instead.
#[cfg(all(
    feature = "chrome",
    any(
        feature = "vmware",
        feature = "vbox",
        feature = "qemu",
        feature = "hyperv"
    )
))]
fn merge_findings(
    dst: &mut vmkatz::chrome::types::ChromeFindings,
    mut extra: vmkatz::chrome::types::ChromeFindings,
) {
    dst.passwords.append(&mut extra.passwords);
    dst.cookies.append(&mut extra.cookies);
    dst.autofill.append(&mut extra.autofill);
}

/// Run the hybrid chrome flow sharing one file handle: SAM/LSA secrets +
/// disk-side DPAPI keyrings, combined with the mem-side keyring, then chrome
/// discovery + decrypt. One handle avoids a second `open_disk()` racing
/// external FS locks (e.g. ESXi datastores) into EBUSY.
#[cfg(all(
    feature = "chrome",
    any(
        feature = "vmware",
        feature = "vbox",
        feature = "qemu",
        feature = "hyperv"
    )
))]
fn run_chrome_hybrid(
    disk_path: &Path,
    mem_keyring: &vmkatz::chrome::hybrid::HybridKeyring,
    extra_passwords: &[String],
    extra_nt_hashes: &[(String, [u8; 16])],
) -> anyhow::Result<vmkatz::chrome::runner::DiscoverySummary> {
    let mut disk = vmkatz::disk::open_disk(disk_path)?;
    let secrets = vmkatz::sam::extract_secrets_from_reader(&mut disk)?;
    let (disk_user_kr, disk_sys_kr) = vmkatz::chrome::runner::build_keyrings_from_reader(
        &mut disk,
        &secrets,
        extra_passwords,
        extra_nt_hashes,
    );
    let user_resolver = vmkatz::chrome::hybrid::ComposedResolver {
        primary: mem_keyring,
        fallback: &disk_user_kr,
    };
    Ok(vmkatz::chrome::runner::run_reader_with_keyring(
        &mut disk,
        &user_resolver,
        Some(&disk_sys_kr),
    )?)
}

/// Handle LSASS minidump files.
pub(crate) fn run_minidump(input_path: &Path, args: &Args) -> anyhow::Result<()> {
    if args.verbose {
        eprintln!("[*] Parsing LSASS minidump: {}", input_path.display());
    }

    let mdmp = vmkatz::minidump::Minidump::open(input_path).context("Failed to parse minidump")?;

    if args.verbose {
        eprintln!(
            "[+] Minidump: {} memory regions, {} modules, Windows {}.{} build {} ({:?})",
            mdmp.region_count(),
            mdmp.modules.len(),
            mdmp.major_version,
            mdmp.minor_version,
            mdmp.build_number,
            mdmp.arch,
        );
        for m in &mdmp.modules {
            eprintln!("    0x{:016x} ({:8} bytes) {}", m.base, m.size, m.base_name);
        }
    }

    let region_ranges = mdmp.region_ranges();
    let credentials = lsass::finder::extract_credentials_from_minidump(
        &mdmp,
        &mdmp.modules,
        mdmp.build_number,
        &region_ranges,
        mdmp.arch,
    )
    .context("Credential extraction from minidump failed")?;

    // Export Kerberos tickets if requested
    export_kerberos_tickets(&credentials, args);

    output_credentials(&credentials, args);

    Ok(())
}

pub(crate) fn run_lsass(
    input_path: &Path,
    args: &Args,
    pagefile: PagefileRef<'_>,
    disk_path: vmkatz::lsass::finder::DiskPathRef<'_>,
) -> anyhow::Result<()> {
    #[cfg(not(any(
        feature = "vmware",
        feature = "vbox",
        feature = "qemu",
        feature = "hyperv"
    )))]
    {
        let _ = (input_path, args, pagefile, disk_path);
        anyhow::bail!(
            "No hypervisor support compiled in (rebuild with --features vmware,vbox,qemu,hyperv)"
        );
    }

    #[cfg(any(
        feature = "vmware",
        feature = "vbox",
        feature = "qemu",
        feature = "hyperv"
    ))]
    {
        let verbose = args.verbose || args.list_processes;
        let ext = input_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        // Detect format by extension and magic bytes
        let format = detect_lsass_format(input_path, ext, args.carve());

        match format {
            LsassFormat::VBox => {
                #[cfg(feature = "vbox")]
                {
                    run_with_layer(
                        || {
                            if verbose {
                                eprintln!(
                                    "[*] Opening VirtualBox saved state: {}",
                                    input_path.display()
                                );
                            }
                            let layer = VBoxLayer::open(input_path)
                                .context("Failed to open VirtualBox .sav file")?;
                            if verbose {
                                eprintln!(
                                    "[+] RAM: {} MB ({} pages mapped)",
                                    layer.phys_size() / (1024 * 1024),
                                    layer.page_count()
                                );
                            }
                            Ok(layer)
                        },
                        args,
                        verbose,
                        pagefile,
                        disk_path,
                    )
                }
                #[cfg(not(feature = "vbox"))]
                {
                    let _ = (pagefile, disk_path);
                    anyhow::bail!(
                        "VirtualBox .sav support not enabled (compile with --features vbox)"
                    )
                }
            }
            LsassFormat::QemuElf => {
                #[cfg(feature = "qemu")]
                {
                    run_with_layer(
                        || {
                            if verbose {
                                eprintln!(
                                    "[*] Opening QEMU ELF core dump: {}",
                                    input_path.display()
                                );
                            }
                            let layer = QemuElfLayer::open(input_path)
                                .context("Failed to open QEMU ELF core dump")?;
                            if verbose {
                                eprintln!(
                                    "[+] ELF: {} MB physical, {} PT_LOAD segments",
                                    layer.phys_size() / (1024 * 1024),
                                    layer.segment_count()
                                );
                            }
                            Ok(layer)
                        },
                        args,
                        verbose,
                        pagefile,
                        disk_path,
                    )
                }
                #[cfg(not(feature = "qemu"))]
                {
                    let _ = (pagefile, disk_path);
                    anyhow::bail!("QEMU ELF support not enabled (compile with --features qemu)")
                }
            }
            #[cfg(feature = "qemu")]
            LsassFormat::QemuSavevm => {
                // The savevm stream omits the MMIO gap splitting pc.ram into
                // below-4G / above-4G GPA regions; a wrong gap misplaces all
                // high memory (all of kernel RAM on 32-bit guests). Probe the
                // candidates, keep the one yielding a valid System EPROCESS.
                const GAP_CANDIDATES: &[u64] =
                    &[0x8000_0000, 0xB000_0000, 0xC000_0000, 0xE000_0000];
                let mut chosen_gap: Option<u64> = None;
                for gap in GAP_CANDIDATES {
                    let Ok(layer) = vmkatz::qemu::QemuSavevmLayer::open_with_gap(input_path, *gap)
                    else {
                        continue;
                    };
                    // Require a healthy process-list walk, not just a System
                    // hit: a wrong gap can still find System but then faults a
                    // hop or two in when a page table lands misplaced.
                    let healthy_list = match process::find_system_process_auto(&layer) {
                        Ok((system, offsets)) => {
                            process::enumerate_processes(&layer, &system, &offsets)
                                .is_ok_and(|ps| ps.len() >= 5)
                        }
                        Err(_) => false,
                    };
                    if healthy_list {
                        chosen_gap = Some(*gap);
                        break;
                    }
                }

                run_with_layer(
                    || {
                        if verbose {
                            eprintln!("[*] Opening QEMU savevm state: {}", input_path.display());
                        }
                        let layer = match chosen_gap {
                            // The probe above already scanned with this gap and
                            // found System; re-open with the same mapping so
                            // the real scan sees the validated layout.
                            Some(gap) => {
                                vmkatz::qemu::QemuSavevmLayer::open_with_gap(input_path, gap)
                            }
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
                    },
                    args,
                    verbose,
                    pagefile,
                    disk_path,
                )
            }
            LsassFormat::HypervBin => {
                #[cfg(feature = "hyperv")]
                {
                    run_with_layer(
                        || {
                            if verbose {
                                eprintln!(
                                    "[*] Opening Hyper-V memory dump: {}",
                                    input_path.display()
                                );
                            }
                            let layer = HypervLayer::open(input_path)
                                .context("Failed to open Hyper-V .bin memory dump")?;
                            if verbose {
                                eprintln!(
                                    "[+] RAM: {} MB identity-mapped",
                                    layer.phys_size() / (1024 * 1024)
                                );
                            }
                            Ok(layer)
                        },
                        args,
                        verbose,
                        pagefile,
                        disk_path,
                    )
                }
                #[cfg(not(feature = "hyperv"))]
                {
                    let _ = (pagefile, disk_path);
                    anyhow::bail!("Hyper-V support not enabled (compile with --features hyperv)")
                }
            }
            LsassFormat::HypervVmrs => {
                #[cfg(feature = "hyperv")]
                {
                    run_with_layer(
                        || {
                            if verbose {
                                eprintln!(
                                    "[*] Opening Hyper-V VMRS saved state: {}",
                                    input_path.display()
                                );
                            }
                            let layer = vmkatz::hyperv::VmrsLayer::open(input_path)
                                .context("Failed to open VMRS saved state")?;
                            if verbose {
                                eprintln!(
                                    "[+] VMRS: {} MB guest physical memory",
                                    layer.phys_size() / (1024 * 1024)
                                );
                            }
                            Ok(layer)
                        },
                        args,
                        verbose,
                        pagefile,
                        disk_path,
                    )
                }
                #[cfg(not(feature = "hyperv"))]
                {
                    let _ = (pagefile, disk_path);
                    anyhow::bail!("Hyper-V support not enabled (compile with --features hyperv)")
                }
            }
            LsassFormat::Vmware => {
                #[cfg(feature = "vmware")]
                {
                    run_with_layer(
                        || {
                            if verbose {
                                eprintln!(
                                    "[*] Opening VMware memory dump: {}",
                                    input_path.display()
                                );
                            }
                            let layer = VmwareLayer::open(input_path)
                                .context("Failed to open VMware memory dump")?;
                            if verbose {
                                eprintln!(
                                    "[+] VMEM mapped: {} MB",
                                    layer.phys_size() / (1024 * 1024)
                                );
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
                        },
                        args,
                        verbose,
                        pagefile,
                        disk_path,
                    )
                }
                #[cfg(not(feature = "vmware"))]
                {
                    let _ = (pagefile, disk_path);
                    anyhow::bail!(
                        "VMware .vmem/.vmsn support not enabled (compile with --features vmware)"
                    )
                }
            }
            LsassFormat::UnsupportedDisk => {
                let _ = (pagefile, disk_path);
                anyhow::bail!(
                    "{} is a disk image, not a memory snapshot. Use --sam for SAM hash extraction, \
                 or provide a memory snapshot (.vmsn, .vmem, .sav, .elf, .bin)",
                    input_path.display()
                )
            }
        }
    } // cfg(any hypervisor)
}

/// Format detection for LSASS memory snapshot files. Guarded to the layer
/// features that construct its variants; all are live under the default and
/// `--all-features` builds. (A rare `--features <single-layer>` build may leave
/// one variant unconstructed — a benign warning, not carried by CI.)
#[cfg(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv"
))]
enum LsassFormat {
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
#[cfg(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv"
))]
fn detect_lsass_format(path: &Path, ext: &str, carve: bool) -> LsassFormat {
    // Extension-based detection first
    if ext.eq_ignore_ascii_case("sav") {
        return LsassFormat::VBox;
    }
    if ext.eq_ignore_ascii_case("elf") {
        return LsassFormat::QemuElf;
    }
    if ext.eq_ignore_ascii_case("vmrs") {
        return LsassFormat::HypervVmrs;
    }
    if ext.eq_ignore_ascii_case("bin") {
        // Could be Hyper-V .bin, QEMU savevm, or a raw dump — check magic
        #[cfg(feature = "qemu")]
        if vmkatz::qemu::is_qemu_savevm(path) {
            return LsassFormat::QemuSavevm;
        }
        if has_elf_magic(path) {
            return LsassFormat::QemuElf;
        }
        #[cfg(feature = "hyperv")]
        if vmkatz::hyperv::is_vmrs_file(path) {
            return LsassFormat::HypervVmrs;
        }
        return LsassFormat::HypervBin;
    }
    if ext.eq_ignore_ascii_case("raw") {
        // Raw memory dump — check for QEVM/ELF magic
        #[cfg(feature = "qemu")]
        if vmkatz::qemu::is_qemu_savevm(path) {
            return LsassFormat::QemuSavevm;
        }
        if has_elf_magic(path) {
            return LsassFormat::QemuElf;
        }
        return LsassFormat::HypervBin;
    }

    // For unknown extensions, try magic-based detection
    #[cfg(feature = "qemu")]
    if vmkatz::qemu::is_qemu_savevm(path) {
        return LsassFormat::QemuSavevm;
    }
    if has_elf_magic(path) {
        return LsassFormat::QemuElf;
    }

    // Known VMware extensions always use VMware format
    if ext.eq_ignore_ascii_case("vmem")
        || ext.eq_ignore_ascii_case("vmsn")
        || ext.eq_ignore_ascii_case("vmss")
    {
        return LsassFormat::Vmware;
    }

    // Reject disk image extensions — these should never reach LSASS extraction
    if ext.eq_ignore_ascii_case("vmdk")
        || ext.eq_ignore_ascii_case("vdi")
        || ext.eq_ignore_ascii_case("qcow2")
        || ext.eq_ignore_ascii_case("qcow")
        || ext.eq_ignore_ascii_case("vhdx")
        || ext.eq_ignore_ascii_case("vhd")
    {
        return LsassFormat::UnsupportedDisk;
    }

    // In carve mode, truly unknown files default to identity-mapped raw (HypervBin)
    if carve {
        return LsassFormat::HypervBin;
    }

    // Default: VMware (anything else)
    LsassFormat::Vmware
}

/// Check if file starts with ELF magic bytes (reads only 4 bytes).
#[cfg(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv"
))]
fn has_elf_magic(path: &Path) -> bool {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic).is_ok() && magic == [0x7f, b'E', b'L', b'F']
}

#[cfg(all(
    feature = "carve",
    any(
        feature = "vmware",
        feature = "vbox",
        feature = "qemu",
        feature = "hyperv"
    )
))]
fn run_carve<L: PhysicalMemory>(
    layer: &L,
    args: &Args,
    pagefile: PagefileRef<'_>,
    disk_path: lsass::finder::DiskPathRef<'_>,
) -> anyhow::Result<()> {
    let credentials = lsass::carve::carve_credentials(layer, pagefile, disk_path);

    // BitLocker FVEK extraction runs on physical memory — works in carve mode too
    extract_and_output_bitlocker(layer, args);

    if credentials.is_empty() {
        anyhow::bail!("Carve mode: no credentials found");
    }

    output_credentials(&credentials, args);

    Ok(())
}

/// Carve SAM/SYSTEM/SECURITY registry hives directly from physical memory and
/// print the recovered bootkey, local NT hashes and LSA secrets. Independent of
/// the process list, so it works under Credential Guard. Returns `true` when it
/// recovered credentials (so the caller can stop), `false` when nothing usable was
/// found (so the caller falls through to the LSASS-cache pipeline).
#[cfg(all(
    feature = "sam",
    any(
        feature = "vmware",
        feature = "vbox",
        feature = "qemu",
        feature = "hyperv"
    )
))]
fn run_mem_registry<L: PhysicalMemory>(layer: &L, args: &Args) -> bool {
    let c = get_colors(args);
    eprintln!(
        "{}[*] Carving registry hives from physical memory...{}",
        c.cyan, c.reset
    );
    let creds = vmkatz::sam::mem_hive::extract_from_memory(layer);
    print_registry_creds(&creds, args)
}

/// Signature-carve SAM/LSA only when `--registry-carve` asks for it; otherwise
/// say why the hive-map walk gave nothing and how to go further. Returns true
/// when the carve printed credentials.
#[cfg(all(
    feature = "sam",
    any(
        feature = "vmware",
        feature = "vbox",
        feature = "qemu",
        feature = "hyperv"
    )
))]
fn registry_carve_or_hint<L: PhysicalMemory>(layer: &L, args: &Args, why: &str) -> bool {
    if args.no_mem_registry {
        return false;
    }
    if args.registry_carve {
        return run_mem_registry(layer, args);
    }
    eprintln!(
        "[*] {why} — rerun with --registry-carve to signature-scan SAM/LSA from physical memory"
    );
    false
}

#[cfg(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv"
))]
fn run_with_layer<L: PhysicalMemory, F: FnOnce() -> anyhow::Result<L>>(
    make_layer: F,
    args: &Args,
    verbose: bool,
    pagefile: PagefileRef<'_>,
    disk_path: vmkatz::lsass::finder::DiskPathRef<'_>,
) -> anyhow::Result<()> {
    // Try each EPT candidate (ranked by non-zero translated pages).
    // Limit to 5 attempts — if System isn't in the top candidates, it's likely
    // not a Windows VM or VBS isn't active.
    const MAX_EPT_ATTEMPTS: usize = 5;

    let layer = make_layer()?;

    // Registry (SAM/LSA) recovery runs inside run_with_system: the exact CM
    // hive-map walk first, the signature carve (scans all RAM, reassembles
    // scattered bins — slow) only as a fallback. The carve is still reached
    // below when no System process is found at all (VBS without page tables).

    // -- Phase 1: Direct L1 scan for System process --
    let t_system = std::time::Instant::now();
    match process::find_system_process_auto(&layer) {
        Ok((system, eprocess_offsets)) => {
            eprintln!("[*] System discovery: {:?}", t_system.elapsed());
            run_with_system(
                &layer,
                &system,
                &eprocess_offsets,
                args,
                verbose,
                pagefile,
                disk_path,
            )
        }
        #[cfg(feature = "carve")]
        Err(_) if !args.ept && args.carve => {
            eprintln!("[*] System process not found — falling back to carve mode");
            run_carve(&layer, args, pagefile, disk_path)
        }
        Err(_) if !args.ept => {
            // No page tables here (System not in L1, EPT disabled), so the CM
            // hive-map walk can't run — the signature carve is the only registry
            // recovery. Works under Credential Guard.
            #[cfg(feature = "sam")]
            if registry_carve_or_hint(&layer, args, "No page tables for the registry hive-map") {
                return Ok(());
            }
            anyhow::bail!(
                "System process not found in physical memory (EPT scan disabled, use --ept to enable)"
            );
        }
        #[cfg(feature = "carve")]
        Err(_) if args.carve && layer.is_truncated() => {
            // Truncated file + carve mode: skip expensive EPT scanning.
            // EPT is almost certainly wrong (the System process is just in the truncated
            // part). Go straight to L1 carve.
            eprintln!("[*] lsass.exe not found in process list — falling back to carve mode");
            run_carve(&layer, args, pagefile, disk_path)
        }
        Err(_) => {
            eprintln!(
                "[*] System discovery (L1, not found): {:?}",
                t_system.elapsed()
            );
            // -- Phase 2: EPT candidate scan (VBS/Hyper-V nested paging) --
            log::info!("System process not found in L1 physical memory, trying EPT scan...");
            eprintln!(
                "[*] System process not found in L1 memory — trying nested EPT (VBS/Hyper-V)..."
            );

            let t_ept = std::time::Instant::now();
            let candidates = vmkatz::paging::ept::find_ept_candidates(&layer)
                .context("Failed to find System process in physical memory (no valid EPT found)")?;
            eprintln!("[*] EPT candidate scan: {:?}", t_ept.elapsed());

            let mut last_err = None;
            for (i, candidate) in candidates.iter().take(MAX_EPT_ATTEMPTS).enumerate() {
                eprintln!(
                    "[*] Trying EPT #{} at L1=0x{:x} ({}/{} non-zero pages, {} PML4E)",
                    i + 1,
                    candidate.pml4_addr,
                    candidate.nonzero_pages,
                    candidate.total_sampled,
                    candidate.valid_pml4e,
                );

                let ept_layer = vmkatz::paging::ept::EptLayer::new(
                    &layer,
                    candidate.pml4_addr,
                    candidate.l2_size,
                );

                // Skip EPTs that were aborted (too many mapped pages = hypervisor-level)
                if ept_layer.is_aborted() {
                    eprintln!(
                        "[*] EPT #{}: skipped (>{} mapped pages — hypervisor-level EPT)",
                        i + 1,
                        ept_layer.mapped_page_count(),
                    );
                    continue;
                }

                let mapped = ept_layer.mapped_page_count();
                // Skip EPTs too large for the page-by-page scan (>4M pages = ~16 GB)
                if mapped > 4_000_000 {
                    eprintln!(
                        "[*] EPT #{}: skipped ({} mapped pages — too large to scan)",
                        i + 1,
                        mapped,
                    );
                    continue;
                }
                eprintln!(
                    "[*] EPT #{}: {} mapped pages ({} MB of L2 space)",
                    i + 1,
                    mapped,
                    mapped * 4 / 1024,
                );

                // Single-pass scan: iterates mapped pages once, tries all offsets at each match.
                let result = process::find_system_process_ept(&ept_layer, &layer)
                    .map_err(|e| -> anyhow::Error { e.into() });

                match result {
                    Ok((system, eprocess_offsets)) => {
                        eprintln!(
                            "[+] System found via EPT #{} at L2=0x{:x}, DTB=0x{:x}",
                            i + 1,
                            system.eprocess_phys,
                            system.dtb,
                        );
                        return run_with_system(
                            &ept_layer,
                            &system,
                            &eprocess_offsets,
                            args,
                            verbose,
                            pagefile,
                            disk_path,
                        );
                    }
                    Err(e) => {
                        log::info!("EPT #{} (L1=0x{:x}): {}", i + 1, candidate.pml4_addr, e);
                        last_err = Some(e);
                    }
                }
            }

            // -- Phase 3: Carve mode on EPT layers --
            #[cfg(feature = "carve")]
            if args.carve {
                eprintln!("[*] EPT System scan failed — trying carve mode on EPT layers...");

                // Try carve on each viable EPT layer (guest memory is behind EPT)
                for (i, candidate) in candidates.iter().take(MAX_EPT_ATTEMPTS).enumerate() {
                    let ept_layer = vmkatz::paging::ept::EptLayer::new(
                        &layer,
                        candidate.pml4_addr,
                        candidate.l2_size,
                    );
                    if ept_layer.is_aborted() {
                        continue;
                    }
                    let mapped = ept_layer.mapped_page_count();
                    if !(100..=4_000_000).contains(&mapped) {
                        continue;
                    }
                    eprintln!(
                        "[*] Carve: trying EPT #{} ({} mapped pages, {} MB)",
                        i + 1,
                        mapped,
                        mapped * 4 / 1024,
                    );
                    match run_carve(&ept_layer, args, pagefile, disk_path) {
                        Ok(()) => return Ok(()),
                        Err(e) => {
                            log::info!("Carve EPT #{}: {}", i + 1, e);
                        }
                    }
                }

                // -- Phase 4: Carve L1 directly (non-VBS VMs) --
                eprintln!("[*] Carve: falling back to L1 physical memory");
                return run_carve(&layer, args, pagefile, disk_path);
            }

            // System never found (L1 + EPT): no page tables for the hive-map walk,
            // so fall back to the signature carve for registry (SAM/LSA) recovery.
            #[cfg(feature = "sam")]
            if registry_carve_or_hint(&layer, args, "No page tables for the registry hive-map") {
                return Ok(());
            }
            Err(last_err
                .unwrap_or_else(|| vmkatz::error::VmkatzError::SystemProcessNotFound.into()))
        }
    }
}

#[cfg(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv"
))]
#[cfg_attr(not(feature = "sam"), allow(unused_variables))]
fn run_with_system<L: PhysicalMemory>(
    layer: &L,
    system: &vmkatz::windows::process::Process,
    eprocess_offsets: &vmkatz::windows::offsets::EprocessOffsets,
    args: &Args,
    verbose: bool,
    pagefile: PagefileRef<'_>,
    disk_path: vmkatz::lsass::finder::DiskPathRef<'_>,
) -> anyhow::Result<()> {
    // Enumerate all processes
    let t_enum = std::time::Instant::now();
    let processes = process::enumerate_processes(layer, system, eprocess_offsets)
        .context("Failed to enumerate processes")?;
    eprintln!("[*] Process enumeration: {:?}", t_enum.elapsed());

    if verbose {
        eprintln!("[+] Found {} processes:", processes.len());
        for p in &processes {
            eprintln!(
                "    PID={:>6}  DTB=0x{:012x}  PEB=0x{:016x}  {}",
                p.pid, p.dtb, p.peb_vaddr, p.name
            );
        }
    }

    // Registry recovery: the CM hive-map walk (exact, low-memory, Registry
    // process DTB on 1803+ else System's) is primary; the signature carve
    // (scans all RAM, reassembles scattered bins) is a fallback for hives it
    // can't resolve. LSASS extraction runs afterwards either way.
    #[cfg(feature = "sam")]
    if !args.no_mem_registry && !args.list_processes {
        let reg_dtb = processes
            .iter()
            .find(|p| p.name.eq_ignore_ascii_case("Registry"))
            .map_or(system.dtb, |p| p.dtb);
        eprintln!("[*] Recovering registry hives via CM hive-map...");
        let creds = vmkatz::sam::cm_hive::extract_from_cm_map(layer, reg_dtb);
        if !print_registry_creds(&creds, args) {
            registry_carve_or_hint(layer, args, "CM hive-map recovered nothing");
        }
    }

    if args.list_processes {
        return Ok(());
    }

    // Process dump mode
    #[cfg(feature = "dump")]
    if let Some(ref dump_name) = args.dump {
        let target = find_process_by_name(&processes, dump_name)
            .ok_or_else(|| anyhow::anyhow!("Process '{dump_name}' not found in process list"))?;

        let default_output = format!("{}.dmp", dump_name.to_lowercase().trim_end_matches(".exe"));
        let output = args.output.as_deref().unwrap_or(&default_output);
        let output_path = std::path::Path::new(output);

        eprintln!(
            "[*] Dumping {} (PID={}, DTB=0x{:x})...",
            target.name, target.pid, target.dtb
        );

        vmkatz::dump::dump_process(layer, target, args.build, output_path, pagefile, disk_path)?;

        let file_size = std::fs::metadata(output_path).map_or(0, |m| m.len());
        eprintln!(
            "[+] Dumped {} → {} ({:.1} MB)",
            target.name,
            output,
            file_size as f64 / (1024.0 * 1024.0)
        );
        return Ok(());
    }

    // Find LSASS
    let lsass_proc = processes
        .iter()
        .find(|p| p.name.eq_ignore_ascii_case("lsass.exe"));

    #[cfg(feature = "carve")]
    if lsass_proc.is_none() && args.carve {
        eprintln!("[*] lsass.exe not found in process list — falling back to carve mode");
        return run_carve(layer, args, pagefile, disk_path);
    }
    let lsass_proc =
        lsass_proc.ok_or_else(|| anyhow::anyhow!("lsass.exe not found in process list"))?;

    if verbose {
        eprintln!(
            "\n[+] LSASS: PID={}, DTB=0x{:x}, PEB=0x{:x}",
            lsass_proc.pid, lsass_proc.dtb, lsass_proc.peb_vaddr
        );
    }

    // Extract credentials (bitness-aware: dispatches to Vista+ or pre-Vista path)
    let t_creds = std::time::Instant::now();
    let credentials = match lsass::finder::extract_all_credentials_auto(
        layer,
        lsass_proc,
        system.dtb,
        eprocess_offsets,
        pagefile,
        disk_path,
    ) {
        Ok(c) => c,
        #[cfg(feature = "carve")]
        Err(e) if args.carve => {
            eprintln!("[*] Credential extraction failed ({e}) — falling back to carve mode");
            return run_carve(layer, args, pagefile, disk_path);
        }
        Err(e) => return Err(e).context("Credential extraction failed"),
    };
    eprintln!("[*] Credential extraction: {:?}", t_creds.elapsed());

    // Report pagefile resolution stats
    #[cfg(feature = "sam")]
    if let Some(pf) = pagefile {
        let resolved = pf.pages_resolved();
        if resolved > 0 {
            eprintln!("[+] Pagefile: {resolved} pages resolved from disk");
        }
    }

    // Export Kerberos tickets if requested
    export_kerberos_tickets(&credentials, args);

    // BitLocker FVEK extraction (physical memory scan — independent of LSASS)
    extract_and_output_bitlocker(layer, args);

    output_credentials(&credentials, args);

    #[cfg(feature = "chrome")]
    {
        if args.chrome {
            // Collect cleartext DPAPI master keys from LSASS memory.
            let pairs: Vec<(String, Vec<u8>)> = credentials
                .iter()
                .flat_map(|c| c.dpapi.iter())
                .map(|d| (d.guid.clone(), d.key.clone()))
                .collect();
            let mem_keyring = vmkatz::chrome::runner::keyring_from_pairs(pairs);

            // Feed every plaintext password LSASS gave us (WDigest/Kerberos/
            // TsPkg/SSP/LiveSSP/CredMan) into the DPAPI masterkey decrypt as
            // extra candidates: the SHA1 pre-key path can then unlock a user's
            // on-disk masterkey when it isn't in the LSASS cache.
            let mut chrome_passwords: Vec<String> = args.chrome_password.clone();
            for c in &credentials {
                let provider_pw = [
                    c.wdigest.as_ref().map(|w| &w.password),
                    c.kerberos.as_ref().map(|k| &k.password),
                    c.tspkg.as_ref().map(|t| &t.password),
                    c.ssp.as_ref().map(|s| &s.password),
                    c.livessp.as_ref().map(|l| &l.password),
                ];
                for pw in provider_pw.into_iter().flatten() {
                    if !pw.is_empty() {
                        chrome_passwords.push(pw.clone());
                    }
                }
                for cm in &c.credman {
                    if !cm.password.is_empty() {
                        chrome_passwords.push(cm.password.clone());
                    }
                }
            }
            chrome_passwords.sort();
            chrome_passwords.dedup();

            // NT-hash candidates for the DPAPI masterkey NTLM path: MSV NT hashes
            // recovered from LSASS (keyed by the session SID — a domain user's NT
            // hash is never in the local SAM), plus any `--chrome-nthash SID:hex`.
            let mut chrome_nt_hashes: Vec<(String, [u8; 16])> =
                parse_chrome_nthashes(&args.chrome_nthash);
            for c in &credentials {
                if let Some(msv) = &c.msv {
                    if !c.sid.is_empty() && msv.nt_hash != [0u8; 16] {
                        chrome_nt_hashes.push((c.sid.clone(), msv.nt_hash));
                    }
                }
            }
            chrome_nt_hashes.sort();
            chrome_nt_hashes.dedup();

            // In-process scan: walk each chromium process, dump its userland
            // via the page-table walker, run the heuristic password/cookie
            // scans. Opt-in (`--chrome-process-scan`) — noisy; disk-side is the
            // high-fidelity path.
            let mem_findings = if args.chrome_process_scan {
                match vmkatz::chrome::process_scan::scan_chromium_processes(layer, &processes) {
                    Ok(f) => f,
                    Err(e) => {
                        log::warn!("chrome (in-process scan) failed: {e}");
                        vmkatz::chrome::types::ChromeFindings::default()
                    }
                }
            } else {
                vmkatz::chrome::types::ChromeFindings::default()
            };

            if let Some(disk_str) = args.disk.as_deref() {
                let disk_path = std::path::Path::new(disk_str);
                match run_chrome_hybrid(
                    disk_path,
                    &mem_keyring,
                    &chrome_passwords,
                    &chrome_nt_hashes,
                ) {
                    Ok(mut summary) => {
                        merge_findings(&mut summary.findings, mem_findings);
                        let out =
                            vmkatz::chrome::runner::render_summary(&summary, args.chrome_json);
                        if !out.trim().is_empty() {
                            println!("{out}");
                        }
                    }
                    Err(e) => log::warn!("chrome (hybrid) failed: {e}"),
                }
            } else {
                // No disk supplied: emit just the in-process scan, plus an
                // info line if DPAPI MKs are sitting in memory unused.
                if !mem_findings.is_empty() {
                    let summary = vmkatz::chrome::runner::DiscoverySummary {
                        profiles: Vec::new(),
                        findings: mem_findings,
                    };
                    let out = vmkatz::chrome::runner::render_summary(&summary, args.chrome_json);
                    if !out.trim().is_empty() {
                        println!("{out}");
                    }
                }
                if !mem_keyring.is_empty() {
                    log::info!(
                        "[chrome] {} DPAPI MKs in memory but no --disk supplied; pass --disk <vmdk> to decrypt cookies/passwords from disk too",
                        mem_keyring.len()
                    );
                }
            }
        }
    }

    Ok(())
}

#[cfg(all(
    feature = "dump",
    any(
        feature = "vmware",
        feature = "vbox",
        feature = "qemu",
        feature = "hyperv"
    )
))]
fn find_process_by_name<'a>(
    processes: &'a [vmkatz::windows::process::Process],
    name: &str,
) -> Option<&'a vmkatz::windows::process::Process> {
    // Single-pass: check both exact and .exe-appended match
    let mut exe_match = None;
    for p in processes {
        if p.name.eq_ignore_ascii_case(name) {
            return Some(p);
        }
        if exe_match.is_none()
            && p.name.len() == name.len() + 4
            && p.name[..name.len()].eq_ignore_ascii_case(name)
            && p.name[name.len()..].eq_ignore_ascii_case(".exe")
        {
            exe_match = Some(p);
        }
    }
    exe_match
}

// ---------------------------------------------------------------------------
// BitLocker FVEK extraction and export
// ---------------------------------------------------------------------------

/// Extract `BitLocker` FVEK keys from physical memory, display results, and
/// optionally export as dislocker-compatible `.fvek` files.
#[cfg(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv"
))]
fn extract_and_output_bitlocker<L: PhysicalMemory>(
    layer: &L,
    args: &Args,
) -> Vec<vmkatz::lsass::bitlocker::BitLockerKey> {
    let t_bl = std::time::Instant::now();
    let keys = vmkatz::lsass::bitlocker::extract_bitlocker_keys(layer);
    if keys.is_empty() {
        log::debug!("BitLocker: no FVEK candidates found ({:?})", t_bl.elapsed());
        return keys;
    }
    eprintln!(
        "[+] BitLocker: {} FVEK candidate(s) found ({:?})",
        keys.len(),
        t_bl.elapsed()
    );

    let c = get_colors(args);

    println!(
        "\n{}[+] BitLocker FVEK ({} candidate(s)):{}\n",
        c.green,
        keys.len(),
        c.reset
    );

    for (i, key) in keys.iter().enumerate() {
        println!("  {}Candidate #{}{}", c.bold, i + 1, c.reset);
        println!("    Cipher  : {}{}{}", c.yellow, key.cipher, c.reset);
        println!(
            "    FVEK    : {}{}{}",
            c.yellow,
            hex::encode(&key.fvek),
            c.reset
        );
        if !key.tweak.is_empty() {
            println!(
                "    Tweak   : {}{}{}",
                c.yellow,
                hex::encode(&key.tweak),
                c.reset
            );
        }
        println!("    Pool tag: {} @ 0x{:x}", key.pool_tag, key.phys_addr);
        println!("    Method  : 0x{:04x} ({})", key.method, key.key_bits());
        println!("    Dislocker: dislocker-fuse -K fvek_{i}.bin -- /dev/sdX /mnt");
        println!();
    }

    // Export .fvek files if --bitlocker-fvek is set
    if let Some(dir) = &args.bitlocker_fvek {
        export_bitlocker_fvek(&keys, dir);
    }

    keys
}

/// Extract `BitLocker` FVEK keys from a memory snapshot file (without full LSASS extraction).
///
/// Opens the snapshot in the appropriate format, scans physical memory for
/// pool tags, and returns any FVEK candidates found.
#[cfg(all(
    feature = "sam",
    any(
        feature = "vmware",
        feature = "vbox",
        feature = "qemu",
        feature = "hyperv"
    )
))]
pub(crate) fn extract_bitlocker_keys_from_snapshot(
    path: &Path,
) -> Vec<vmkatz::lsass::bitlocker::BitLockerKey> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let format = detect_lsass_format(path, ext, false);

    // Open the memory layer and extract BitLocker keys
    macro_rules! try_layer {
        ($make_layer:expr_2021) => {
            match $make_layer {
                Ok(layer) => {
                    return vmkatz::lsass::bitlocker::extract_bitlocker_keys(&layer);
                }
                Err(e) => {
                    log::info!(
                        "BitLocker key extraction: failed to open {}: {}",
                        path.display(),
                        e
                    );
                    return Vec::new();
                }
            }
        };
    }

    match format {
        #[cfg(feature = "vbox")]
        LsassFormat::VBox => try_layer!(VBoxLayer::open(path)),
        #[cfg(feature = "qemu")]
        LsassFormat::QemuElf => try_layer!(QemuElfLayer::open(path)),
        #[cfg(feature = "qemu")]
        LsassFormat::QemuSavevm => try_layer!(vmkatz::qemu::QemuSavevmLayer::open(path)),
        #[cfg(feature = "hyperv")]
        LsassFormat::HypervBin => try_layer!(HypervLayer::open(path)),
        #[cfg(feature = "hyperv")]
        LsassFormat::HypervVmrs => try_layer!(vmkatz::hyperv::VmrsLayer::open(path)),
        #[cfg(feature = "vmware")]
        LsassFormat::Vmware => try_layer!(VmwareLayer::open(path)),
        _ => Vec::new(),
    }
}
