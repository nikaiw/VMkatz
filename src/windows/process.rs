use crate::error::{VmkatzError, Result};
use crate::memory::{PhysicalMemory, VirtualMemory};
use crate::paging::entry::PAGE_PHYS_MASK;
use crate::paging::ept::EptLayer;
use crate::paging::translate::{PageTableWalker, PaePageTableWalker, PaeProcessMemory, ProcessMemory};
use crate::windows::eprocess::EprocessReader;
use crate::windows::offsets::{EprocessOffsets, WindowsBitness, ALL_EPROCESS_OFFSETS};

/// Check if a Flink address is a valid kernel-mode linked list pointer.
/// x64: canonical kernel address (top 16 bits = 0xFFFF).
/// x86 PAE: kernel address in upper 2GB (0x80000000..=0xFFFFFFFF).
fn is_valid_kernel_flink(flink: u64, bitness: WindowsBitness) -> bool {
    match bitness {
        WindowsBitness::X64 => (flink >> 48) == 0xFFFF,
        WindowsBitness::X86Pae => (0x80000000..=0xFFFFFFFF).contains(&flink),
    }
}

/// Validate that a Flink VA can be translated to a physical address and the
/// linked EPROCESS contains a plausible PID. This rejects stale System process
/// remnants where the DTB points to freed/corrupted page tables.
fn validate_flink_translation(
    phys: &impl PhysicalMemory,
    dtb: u64,
    flink: u64,
    offsets: &EprocessOffsets,
) -> bool {
    // Walk the first few entries of the process list to verify the page tables work.
    // Translate flink VA → physical, read the linked EPROCESS, check it has a
    // non-zero process name and a valid kernel-mode Flink.
    let translate = |va: u64| -> std::result::Result<u64, ()> {
        match offsets.bitness {
            WindowsBitness::X64 => PageTableWalker::new(phys).translate(dtb, va).map_err(|_| ()),
            WindowsBitness::X86Pae => PaePageTableWalker::new(phys).translate(dtb, va).map_err(|_| ()),
        }
    };

    let flink_phys = match translate(flink) {
        Ok(p) if p < phys.phys_size() => p,
        _ => return false,
    };

    if flink_phys < offsets.active_process_links {
        return false;
    }
    let next_eprocess = flink_phys - offsets.active_process_links;

    // The next EPROCESS must have a non-zero ImageFileName
    let mut name_buf = [0u8; 15];
    if phys.read_phys(next_eprocess + offsets.image_file_name, &mut name_buf).is_err() {
        return false;
    }
    if name_buf.iter().all(|&b| b == 0) {
        return false;
    }
    // Process name must be printable ASCII
    if !name_buf.iter().take_while(|&&b| b != 0).all(|&b| b.is_ascii_graphic() || b == b' ') {
        return false;
    }

    // The next process's Flink must be a valid kernel VA
    let reader = EprocessReader::new(offsets);
    let next_flink = match reader.read_flink(phys, next_eprocess) {
        Ok(f) => f,
        Err(_) => return false,
    };
    is_valid_kernel_flink(next_flink, offsets.bitness)
}

/// PEB + 0x20 = ProcessParameters (RTL_USER_PROCESS_PARAMETERS*)
const PEB_PROCESS_PARAMETERS: u64 = 0x20;
/// RTL_USER_PROCESS_PARAMETERS + 0x60 = ImagePathName (UNICODE_STRING)
const PROCESS_PARAMS_IMAGE_PATH: u64 = 0x60;

/// A discovered Windows process.
#[derive(Debug)]
pub struct Process {
    pub pid: u64,
    pub name: String,
    pub dtb: u64,
    pub eprocess_phys: u64,
    pub peb_vaddr: u64,
}

/// Find the System process by scanning physical memory once and trying all known
/// EPROCESS offset sets at each match. Single-pass scan avoids repeated full-memory
/// reads when the VM is non-Windows or uses unknown offsets.
/// Read chunk size for bulk physical memory scans (1 MB = 256 pages).
const SCAN_CHUNK_SIZE: usize = 256 * 4096;

pub fn find_system_process_auto(phys: &impl PhysicalMemory) -> Result<(Process, EprocessOffsets)> {
    let pattern = b"System\0\0\0\0\0\0\0\0\0";
    let phys_size = phys.phys_size();

    log::info!(
        "Scanning {} MB of physical memory for System process (all offsets, single pass)...",
        phys_size / (1024 * 1024)
    );

    let mut chunk_buf = vec![0u8; SCAN_CHUNK_SIZE];
    let mut addr: u64 = 0;

    while addr < phys_size {
        let read_len = SCAN_CHUNK_SIZE.min((phys_size - addr) as usize);
        if phys.read_phys(addr, &mut chunk_buf[..read_len]).is_err() {
            addr += read_len as u64;
            continue;
        }

        // Scan each 4KB page within the chunk
        for page_off in (0..read_len).step_by(4096) {
            let page_end = (page_off + 4096).min(read_len);
            let page = &chunk_buf[page_off..page_end];

            let mut off = 0usize;
            while off + pattern.len() <= page.len() {
                if &page[off..off + pattern.len()] != pattern {
                    off += 1;
                    continue;
                }

                let match_phys = addr + page_off as u64 + off as u64;

                // Try all offset sets at this match location
                for offsets in ALL_EPROCESS_OFFSETS {
                    if match_phys < offsets.image_file_name {
                        continue;
                    }
                    let eprocess_phys = match_phys - offsets.image_file_name;

                    let reader = EprocessReader::new(offsets);

                    // Validate PID = 4
                    let pid = match reader.read_pid(phys, eprocess_phys) {
                        Ok(pid) if pid == 4 => pid,
                        _ => continue,
                    };

                    // Validate DTB
                    let dtb = match reader.read_dtb(phys, eprocess_phys) {
                        Ok(dtb) => dtb,
                        Err(_) => continue,
                    };
                    let dtb_base = dtb & PAGE_PHYS_MASK;
                    if dtb_base == 0 || dtb_base >= phys_size {
                        continue;
                    }

                    // Validate Flink (bitness-aware)
                    let flink = match reader.read_flink(phys, eprocess_phys) {
                        Ok(f) => f,
                        Err(_) => continue,
                    };
                    if !is_valid_kernel_flink(flink, offsets.bitness) {
                        continue;
                    }

                    // Validate page table walk: translate the Flink VA to physical,
                    // then verify the linked EPROCESS is readable with a valid PID.
                    // This catches stale EPROCESS remnants where DTB points to
                    // freed/corrupted page tables (common in QEMU savevm snapshots).
                    let flink_valid = validate_flink_translation(phys, dtb, flink, offsets);
                    if !flink_valid {
                        log::debug!(
                            "Rejecting System candidate at 0x{:x}: Flink 0x{:x} translation produced invalid EPROCESS (DTB=0x{:x})",
                            eprocess_phys, flink, dtb
                        );
                        continue;
                    }

                    let peb = reader.read_peb(phys, eprocess_phys).unwrap_or(0);

                    log::info!(
                        "Found System process: eprocess_phys=0x{:x}, PID={}, DTB=0x{:x}, Flink=0x{:x}, bitness={:?}",
                        eprocess_phys, pid, dtb, flink, offsets.bitness
                    );

                    return Ok((
                        Process {
                            pid,
                            name: "System".to_string(),
                            dtb,
                            eprocess_phys,
                            peb_vaddr: peb,
                        },
                        *offsets,
                    ));
                }

                off += 1;
            }
        }

        addr += read_len as u64;
    }

    Err(VmkatzError::SystemProcessNotFound)
}

/// Maximum EPT mapped pages for EPROCESS scan. EPTs larger than this are
/// skipped — they map too much L2 space to scan efficiently on constrained hosts.
const MAX_EPT_SCAN_PAGES: usize = 4_000_000; // ~16 GB

/// Fast System process scan for EPT layers (single-pass).
/// Iterates mapped regions in bulk (up to 1MB per read), trying all EPROCESS
/// offset sets at each "System\0" match. Reads L1 data directly for the bulk
/// scan, uses EPT translation only for validation.
pub fn find_system_process_ept<P: PhysicalMemory>(
    ept: &EptLayer<'_, P>,
    l1: &P,
) -> Result<(Process, EprocessOffsets)> {
    let pattern = b"System\0\0\0\0\0\0\0\0\0";
    let mapped = ept.mapped_page_count();

    if mapped > MAX_EPT_SCAN_PAGES {
        log::info!(
            "EPT fast scan: skipping — {} mapped pages exceeds {} page scan limit",
            mapped,
            MAX_EPT_SCAN_PAGES,
        );
        return Err(VmkatzError::SystemProcessNotFound);
    }

    log::info!(
        "EPT fast scan: {} mapped pages ({} MB)",
        mapped,
        mapped * 4 / 1024,
    );

    // Read contiguous L1 regions in chunks (up to 1MB) instead of page-by-page
    let mut chunk_buf = vec![0u8; SCAN_CHUNK_SIZE];
    for region in ept.mapped_regions() {
        let mut region_off: u64 = 0;
        while region_off < region.size {
            let remaining = (region.size - region_off) as usize;
            let read_len = SCAN_CHUNK_SIZE.min(remaining);
            let l1_addr = region.l1_base + region_off;
            let l2_addr = region.l2_base + region_off;

            if l1.read_phys(l1_addr, &mut chunk_buf[..read_len]).is_err() {
                region_off += read_len as u64;
                continue;
            }

            // Scan each 4KB page within the chunk
            for page_off in (0..read_len).step_by(4096) {
                let page = &chunk_buf[page_off..page_off + 4096];

                // Skip zero pages
                if page.iter().all(|&b| b == 0) {
                    continue;
                }

                let l2_page = l2_addr + page_off as u64;

                // Search for "System\0" in this page
                let mut off = 0usize;
                while off + pattern.len() <= page.len() {
                    if &page[off..off + pattern.len()] != pattern {
                        off += 1;
                        continue;
                    }

                    // Try all offset sets at this match (single-pass approach)
                    let match_l2 = l2_page + off as u64;

                    for offsets in ALL_EPROCESS_OFFSETS {
                        if match_l2 < offsets.image_file_name {
                            continue;
                        }
                        let eprocess_l2 = match_l2 - offsets.image_file_name;
                        let reader = EprocessReader::new(offsets);

                        // Validate PID = 4 (read through EPT)
                        let pid = match reader.read_pid(ept, eprocess_l2) {
                            Ok(pid) if pid == 4 => pid,
                            _ => continue,
                        };

                        // Validate DTB
                        let dtb = match reader.read_dtb(ept, eprocess_l2) {
                            Ok(dtb) => dtb,
                            Err(_) => continue,
                        };
                        let dtb_base = dtb & PAGE_PHYS_MASK;
                        if dtb_base == 0 || dtb_base >= ept.phys_size() {
                            continue;
                        }

                        // Validate Flink (bitness-aware)
                        let flink = match reader.read_flink(ept, eprocess_l2) {
                            Ok(f) => f,
                            Err(_) => continue,
                        };
                        if !is_valid_kernel_flink(flink, offsets.bitness) {
                            continue;
                        }

                        let peb = reader.read_peb(ept, eprocess_l2).unwrap_or(0);

                        log::info!(
                            "EPT: Found System at L2=0x{:x} (L1=0x{:x}+0x{:x}), PID={}, DTB=0x{:x}, Flink=0x{:x}",
                            eprocess_l2, l1_addr, page_off + off, pid, dtb, flink
                        );

                        return Ok((
                            Process {
                                pid,
                                name: "System".to_string(),
                                dtb,
                                eprocess_phys: eprocess_l2,
                                peb_vaddr: peb,
                            },
                            *offsets,
                        ));
                    }

                    off += 1;
                }
            }

            region_off += read_len as u64;
        }
    }

    Err(VmkatzError::SystemProcessNotFound)
}

/// Walk the EPROCESS linked list starting from the System process.
/// Uses the kernel DTB for virtual-to-physical translation of ActiveProcessLinks pointers.
/// Dispatches to x64 or PAE page table walker based on EPROCESS bitness.
pub fn enumerate_processes(
    phys: &impl PhysicalMemory,
    system: &Process,
    offsets: &EprocessOffsets,
) -> Result<Vec<Process>> {
    let reader = EprocessReader::new(offsets);
    let kernel_dtb = system.dtb;

    // Read System's ActiveProcessLinks.Flink
    let head_flink = reader.read_flink(phys, system.eprocess_phys)?;
    let mut processes = vec![];

    // Add System itself
    processes.push(Process {
        pid: system.pid,
        name: system.name.clone(),
        dtb: system.dtb,
        eprocess_phys: system.eprocess_phys,
        peb_vaddr: system.peb_vaddr,
    });

    let mut current_flink = head_flink;
    let mut visited = std::collections::HashSet::new();
    visited.insert(system.eprocess_phys + offsets.active_process_links);

    // Create appropriate page table walker based on bitness
    let x64_walker;
    let pae_walker;
    match offsets.bitness {
        WindowsBitness::X64 => {
            x64_walker = Some(PageTableWalker::new(phys));
            pae_walker = None;
        }
        WindowsBitness::X86Pae => {
            x64_walker = None;
            pae_walker = Some(PaePageTableWalker::new(phys));
        }
    }

    loop {
        if visited.contains(&current_flink) {
            break;
        }
        visited.insert(current_flink);

        // Translate the virtual Flink address to physical (bitness-aware)
        let flink_phys = if let Some(ref walker) = x64_walker {
            walker.translate(kernel_dtb, current_flink)
        } else if let Some(ref walker) = pae_walker {
            walker.translate(kernel_dtb, current_flink)
        } else {
            unreachable!()
        };

        let flink_phys = match flink_phys {
            Ok(p) => p,
            Err(e) => {
                log::warn!("Failed to translate Flink 0x{:x}: {}", current_flink, e);
                break;
            }
        };

        // EPROCESS base = Flink physical address - ActiveProcessLinks offset
        if flink_phys < offsets.active_process_links {
            continue;
        }
        let eprocess_phys = flink_phys - offsets.active_process_links;

        // Read process info
        let pid = match reader.read_pid(phys, eprocess_phys) {
            Ok(p) => p,
            Err(e) => {
                log::warn!("Failed to read PID at 0x{:x}: {}", eprocess_phys, e);
                break;
            }
        };

        // Read next Flink before potentially skipping this entry
        let next_flink = match reader.read_flink(phys, eprocess_phys) {
            Ok(f) => f,
            Err(e) => {
                log::warn!("Failed to read Flink at 0x{:x}: {}", eprocess_phys, e);
                break;
            }
        };

        // Skip PID 0 (System Idle Process) - has no valid DTB, PEB, or name
        if pid != 0 {
            let short_name = reader
                .read_image_name(phys, eprocess_phys)
                .unwrap_or_else(|_| "<unknown>".to_string());

            let dtb = reader.read_dtb(phys, eprocess_phys).unwrap_or(0);
            let peb = reader.read_peb(phys, eprocess_phys).unwrap_or(0);

            // Try full name from PEB if available (fixes 15-char truncation)
            let name = if peb != 0 && dtb != 0 {
                match offsets.bitness {
                    WindowsBitness::X64 => read_full_image_name(phys, dtb, peb).unwrap_or(short_name),
                    WindowsBitness::X86Pae => read_full_image_name_32(phys, dtb, peb).unwrap_or(short_name),
                }
            } else {
                short_name
            };

            processes.push(Process {
                pid,
                name,
                dtb,
                eprocess_phys,
                peb_vaddr: peb,
            });
        }

        current_flink = next_flink;
    }

    Ok(processes)
}

/// Read the full image name from PEB → ProcessParameters → ImagePathName (x64).
/// Returns just the filename (e.g. "fontdrvhost.exe") from the full NT path.
fn read_full_image_name(phys: &impl PhysicalMemory, dtb: u64, peb: u64) -> Option<String> {
    let vmem = ProcessMemory::new(phys, dtb);

    // PEB + 0x20 → ProcessParameters pointer
    let params_ptr = vmem.read_virt_u64(peb + PEB_PROCESS_PARAMETERS).ok()?;
    if params_ptr == 0 || params_ptr < 0x10000 {
        return None;
    }

    // ProcessParameters + 0x60 → ImagePathName (UNICODE_STRING)
    let full_path = vmem
        .read_win_unicode_string(params_ptr + PROCESS_PARAMS_IMAGE_PATH)
        .ok()?;
    if full_path.is_empty() {
        return None;
    }

    // Extract just the filename from the path (handles both \ and / separators)
    let name = full_path.rsplit(['\\', '/']).next().unwrap_or(&full_path);

    if name.is_empty() {
        return None;
    }

    Some(name.to_string())
}

/// PEB offsets for 32-bit Windows
const PEB32_PROCESS_PARAMETERS: u64 = 0x10;
/// RTL_USER_PROCESS_PARAMETERS offsets for 32-bit
const PROCESS_PARAMS32_IMAGE_PATH: u64 = 0x38;

/// Read the full image name from PEB → ProcessParameters → ImagePathName (32-bit PAE).
fn read_full_image_name_32(phys: &impl PhysicalMemory, dtb: u64, peb: u64) -> Option<String> {
    let vmem = PaeProcessMemory::new(phys, dtb);

    // 32-bit PEB + 0x10 → ProcessParameters pointer (u32)
    let params_ptr = vmem.read_virt_u32(peb + PEB32_PROCESS_PARAMETERS).ok()? as u64;
    if params_ptr == 0 || params_ptr < 0x10000 {
        return None;
    }

    // 32-bit ProcessParameters + 0x38 → ImagePathName (UNICODE_STRING32)
    let full_path = vmem
        .read_win_unicode_string_32(params_ptr + PROCESS_PARAMS32_IMAGE_PATH)
        .ok()?;
    if full_path.is_empty() {
        return None;
    }

    let name = full_path.rsplit(['\\', '/']).next().unwrap_or(&full_path);

    if name.is_empty() {
        return None;
    }

    Some(name.to_string())
}
