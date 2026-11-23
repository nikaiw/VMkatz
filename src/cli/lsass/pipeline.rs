//! System discovery, EPT/carve fallbacks and extraction from physical memory.

use anyhow::Context;
use vmkatz::lsass;
use vmkatz::lsass::finder::PagefileRef;
use vmkatz::memory::PhysicalMemory;
use vmkatz::windows::process;

use crate::cli::args::Args;
#[cfg(feature = "sam")]
use crate::cli::args::get_colors;
#[cfg(feature = "sam")]
use crate::cli::output::print_registry_creds;
use crate::cli::output::{export_kerberos_tickets, output_credentials};

use super::bitlocker::extract_and_output_bitlocker;
#[cfg(feature = "chrome")]
use super::chrome::run_chrome_for_snapshot;

#[cfg(feature = "carve")]
fn run_carve<L: PhysicalMemory>(
    layer: &L,
    args: &Args,
    pagefile: PagefileRef<'_>,
    disk_path: lsass::finder::DiskPathRef<'_>,
) -> anyhow::Result<()> {
    let credentials = lsass::carve::carve_credentials(layer, pagefile, disk_path);

    // FVEK recovery does not require LSASS credentials.
    extract_and_output_bitlocker(layer, args);

    if credentials.is_empty() {
        anyhow::bail!("Carve mode: no credentials found");
    }

    output_credentials(&credentials, args);

    Ok(())
}

/// Recover registry secrets without a process list, including under Credential Guard.
/// Return whether credentials were printed.
#[cfg(feature = "sam")]
fn run_mem_registry<L: PhysicalMemory>(layer: &L, args: &Args) -> bool {
    let c = get_colors(args);
    eprintln!(
        "{}[*] Carving registry hives from physical memory...{}",
        c.cyan, c.reset
    );
    let creds = vmkatz::sam::mem_hive::extract_from_memory(layer);
    print_registry_creds(&creds, args)
}

/// Carve registry secrets only on request; otherwise print a hint unless disabled.
/// Return whether credentials were printed.
#[cfg(feature = "sam")]
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

pub(super) fn run_with_layer<L: PhysicalMemory, F: FnOnce() -> anyhow::Result<L>>(
    make_layer: F,
    args: &Args,
    verbose: bool,
    pagefile: PagefileRef<'_>,
    disk_path: vmkatz::lsass::finder::DiskPathRef<'_>,
) -> anyhow::Result<()> {
    let layer = make_layer()?;

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
            // Without System's page tables, registry recovery requires signature carving.
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
            // Missing System data in a truncated dump does not justify an EPT scan.
            eprintln!("[*] lsass.exe not found in process list — falling back to carve mode");
            run_carve(&layer, args, pagefile, disk_path)
        }
        Err(_) => {
            eprintln!(
                "[*] System discovery (L1, not found): {:?}",
                t_system.elapsed()
            );
            run_with_ept(&layer, args, verbose, pagefile, disk_path)
        }
    }
}

/// Try nested EPT mappings after direct System discovery failed.
fn run_with_ept<L: PhysicalMemory>(
    layer: &L,
    args: &Args,
    verbose: bool,
    pagefile: PagefileRef<'_>,
    disk_path: vmkatz::lsass::finder::DiskPathRef<'_>,
) -> anyhow::Result<()> {
    // Bound repeated scans when the best EPT candidates do not yield System.
    const MAX_EPT_ATTEMPTS: usize = 5;

    log::info!("System process not found in L1 physical memory, trying EPT scan...");
    eprintln!("[*] System process not found in L1 memory — trying nested EPT (VBS/Hyper-V)...");

    let t_ept = std::time::Instant::now();
    let candidates = vmkatz::paging::ept::find_ept_candidates(layer)
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

        let ept_layer =
            vmkatz::paging::ept::EptLayer::new(layer, candidate.pml4_addr, candidate.l2_size);

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

        let result = process::find_system_process_ept(&ept_layer, layer)
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

    #[cfg(feature = "carve")]
    if args.carve {
        eprintln!("[*] EPT System scan failed — trying carve mode on EPT layers...");

        // Guest memory may be accessible only through EPT.
        for (i, candidate) in candidates.iter().take(MAX_EPT_ATTEMPTS).enumerate() {
            let ept_layer =
                vmkatz::paging::ept::EptLayer::new(layer, candidate.pml4_addr, candidate.l2_size);
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

        eprintln!("[*] Carve: falling back to L1 physical memory");
        return run_carve(layer, args, pagefile, disk_path);
    }

    // No usable page tables: registry recovery still requires signature carving.
    #[cfg(feature = "sam")]
    if registry_carve_or_hint(layer, args, "No page tables for the registry hive-map") {
        return Ok(());
    }
    Err(last_err.unwrap_or_else(|| vmkatz::error::VmkatzError::SystemProcessNotFound.into()))
}

fn run_with_system<L: PhysicalMemory>(
    layer: &L,
    system: &vmkatz::windows::process::Process,
    eprocess_offsets: &vmkatz::windows::offsets::EprocessOffsets,
    args: &Args,
    verbose: bool,
    pagefile: PagefileRef<'_>,
    disk_path: vmkatz::lsass::finder::DiskPathRef<'_>,
) -> anyhow::Result<()> {
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

    // Prefer the hive map over a full RAM scan. Use Registry's DTB when available.
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

    #[cfg(feature = "disk")]
    if let Some(pf) = pagefile {
        let resolved = pf.pages_resolved();
        if resolved > 0 {
            eprintln!("[+] Pagefile: {resolved} pages resolved from disk");
        }
    }

    export_kerberos_tickets(&credentials, args);

    extract_and_output_bitlocker(layer, args);

    output_credentials(&credentials, args);

    #[cfg(feature = "chrome")]
    if args.chrome || args.all {
        run_chrome_for_snapshot(layer, &processes, &credentials, args);
    }

    Ok(())
}

#[cfg(feature = "dump")]
fn find_process_by_name<'a>(
    processes: &'a [vmkatz::windows::process::Process],
    name: &str,
) -> Option<&'a vmkatz::windows::process::Process> {
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
