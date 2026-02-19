//! Process memory dump in Windows minidump format.
//!
//! Produces minidump files compatible with pypykatz and other analysis tools.
//! Writes 3 streams: SystemInfoStream, ModuleListStream, Memory64ListStream.

use std::collections::BTreeSet;
use std::io::{BufWriter, Write};
use std::path::Path;

use crate::error::{GovmemError, Result};
use crate::lsass::finder::{DiskPathRef, PagefileRef};
use crate::memory::{PhysicalMemory, VirtualMemory};
use crate::paging::entry::PageTableEntry;
use crate::paging::translate::ProcessMemory;
use crate::windows::offsets::X64_LDR;
use crate::windows::peb::{self, LoadedModule};
use crate::windows::process::Process;

// Minidump constants
const MINIDUMP_SIGNATURE: u32 = 0x504D_444D; // "MDMP"
const MINIDUMP_VERSION: u32 = 0x0000_A793;
const STREAM_TYPE_SYSTEM_INFO: u32 = 7;
const STREAM_TYPE_MODULE_LIST: u32 = 4;
const STREAM_TYPE_MEMORY64_LIST: u32 = 9;
const PROCESSOR_ARCHITECTURE_AMD64: u16 = 9;
const VER_PLATFORM_WIN32_NT: u32 = 2;

/// A contiguous virtual memory region.
struct MemoryRegion {
    start_va: u64,
    size: u64,
}

/// Dump a process's virtual memory as a Windows minidump (.dmp) file.
///
/// Compatible with `pypykatz lsa minidump <file>` for LSASS credential extraction.
pub fn dump_process<P: PhysicalMemory>(
    phys: &P,
    process: &Process,
    build_number: u32,
    output_path: &Path,
    pagefile: PagefileRef<'_>,
    disk_path: DiskPathRef<'_>,
) -> Result<()> {
    // Create initial virtual memory reader for module enumeration
    #[cfg(feature = "sam")]
    let vmem_init = ProcessMemory::with_resolvers(phys, process.dtb, pagefile, None);
    #[cfg(not(feature = "sam"))]
    let vmem_init = {
        let _ = (pagefile, disk_path);
        ProcessMemory::new(phys, process.dtb)
    };

    // Enumerate loaded modules from PEB
    let modules = if process.peb_vaddr != 0 {
        match peb::enumerate_modules(&vmem_init, process.peb_vaddr, &X64_LDR) {
            Ok(m) => {
                log::info!("Dump: enumerated {} modules for {}", m.len(), process.name);
                m
            }
            Err(e) => {
                log::warn!("Module enumeration failed: {}", e);
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    // Build file-backed resolver from disk for demand-paged DLL sections
    #[cfg(feature = "sam")]
    let filebacked = disk_path.and_then(|p| {
        match crate::paging::filebacked::FileBackedResolver::from_disk_and_modules(p, &modules) {
            Ok(fb) if fb.section_count() > 0 => {
                log::info!(
                    "Dump file-backed: {} sections, {:.1} MB",
                    fb.section_count(),
                    fb.total_bytes() as f64 / (1024.0 * 1024.0),
                );
                Some(fb)
            }
            Ok(_) => None,
            Err(e) => {
                log::info!("Dump file-backed unavailable: {}", e);
                None
            }
        }
    });

    // Full ProcessMemory with all resolvers
    #[cfg(feature = "sam")]
    let vmem = ProcessMemory::with_resolvers(phys, process.dtb, pagefile, filebacked.as_ref());
    #[cfg(not(feature = "sam"))]
    let vmem = ProcessMemory::new(phys, process.dtb);

    // Collect all user-mode page VAs (present + transition + pagefile PTEs)
    let mut page_vas: BTreeSet<u64> = BTreeSet::new();
    collect_all_user_pages(phys, process.dtb, &mut page_vas);
    let pt_count = page_vas.len();

    // Add module VA ranges for file-backed DLL page resolution
    for m in &modules {
        let page_count = (m.size as u64).div_ceil(0x1000);
        for i in 0..page_count {
            page_vas.insert(m.base + i * 0x1000);
        }
    }
    log::info!(
        "Dump pages: {} from page tables, {} total with modules",
        pt_count,
        page_vas.len()
    );

    // Coalesce into contiguous regions
    let sorted_vas: Vec<u64> = page_vas.into_iter().collect();
    let regions = coalesce_pages(&sorted_vas);
    log::info!("Dump: {} contiguous memory regions", regions.len());

    // Write minidump
    write_minidump(output_path, &vmem, &modules, &regions, build_number)?;

    // Report pagefile stats
    #[cfg(feature = "sam")]
    if let Some(pf) = pagefile {
        let resolved = pf.pages_resolved();
        if resolved > 0 {
            log::info!("Dump: {} pagefile pages resolved", resolved);
        }
    }

    Ok(())
}

/// Walk page tables collecting all user-mode VAs with valid PTEs.
/// Includes present, transition, and pagefile PTEs (not just present+transition).
fn collect_all_user_pages<P: PhysicalMemory>(phys: &P, cr3: u64, pages: &mut BTreeSet<u64>) {
    let pml4_base = cr3 & 0x000F_FFFF_FFFF_F000;

    for pml4_idx in 0..256u64 {
        let pml4e = match phys.read_phys_u64(pml4_base + pml4_idx * 8) {
            Ok(v) => PageTableEntry(v),
            Err(_) => continue,
        };
        if !pml4e.is_present() {
            continue;
        }

        let pdpt_base = pml4e.frame_addr();
        for pdpt_idx in 0..512u64 {
            let pdpte = match phys.read_phys_u64(pdpt_base + pdpt_idx * 8) {
                Ok(v) => PageTableEntry(v),
                Err(_) => continue,
            };
            if !pdpte.is_present() {
                continue;
            }
            if pdpte.is_large_page() {
                let base_va = (pml4_idx << 39) | (pdpt_idx << 30);
                for i in 0..(0x4000_0000u64 / 0x1000) {
                    pages.insert(base_va + i * 0x1000);
                }
                continue;
            }

            let pd_base = pdpte.frame_addr();
            for pd_idx in 0..512u64 {
                let pde = match phys.read_phys_u64(pd_base + pd_idx * 8) {
                    Ok(v) => PageTableEntry(v),
                    Err(_) => continue,
                };
                if !pde.is_present() {
                    continue;
                }
                if pde.is_large_page() {
                    let base_va = (pml4_idx << 39) | (pdpt_idx << 30) | (pd_idx << 21);
                    for i in 0..512u64 {
                        pages.insert(base_va + i * 0x1000);
                    }
                    continue;
                }

                let pt_base = pde.frame_addr();
                for pt_idx in 0..512u64 {
                    let pte = match phys.read_phys_u64(pt_base + pt_idx * 8) {
                        Ok(v) => PageTableEntry(v),
                        Err(_) => continue,
                    };
                    // Include present, transition, and pagefile PTEs
                    if pte.is_present() || pte.is_transition() || pte.is_pagefile() {
                        let va =
                            (pml4_idx << 39) | (pdpt_idx << 30) | (pd_idx << 21) | (pt_idx << 12);
                        pages.insert(va);
                    }
                }
            }
        }
    }
}

/// Coalesce sorted page VAs into contiguous memory regions.
fn coalesce_pages(sorted_vas: &[u64]) -> Vec<MemoryRegion> {
    let mut regions = Vec::new();
    if sorted_vas.is_empty() {
        return regions;
    }

    let mut start = sorted_vas[0];
    let mut end = start + 0x1000;

    for &va in &sorted_vas[1..] {
        if va == end {
            end += 0x1000;
        } else {
            regions.push(MemoryRegion {
                start_va: start,
                size: end - start,
            });
            start = va;
            end = va + 0x1000;
        }
    }
    regions.push(MemoryRegion {
        start_va: start,
        size: end - start,
    });

    regions
}

/// Write the minidump file with 3 streams.
fn write_minidump(
    output_path: &Path,
    vmem: &impl VirtualMemory,
    modules: &[LoadedModule],
    regions: &[MemoryRegion],
    build_number: u32,
) -> Result<()> {
    let file = std::fs::File::create(output_path).map_err(GovmemError::Io)?;
    let mut w = BufWriter::new(file);

    // === Layout computation ===
    let header_size = 32u32;
    let dir_size = 3u32 * 12;

    let sysinfo_rva = header_size + dir_size; // 0x44
    let sysinfo_size = 56u32;

    // CSD version string (empty MINIDUMP_STRING: Length=0 + null terminator)
    let csd_rva = sysinfo_rva + sysinfo_size;
    let csd_size = 4u32 + 2;

    // ModuleListStream: 4-byte count + N * 108-byte entries
    let modlist_rva = csd_rva + csd_size;
    let modlist_data_size = 4 + modules.len() as u32 * 108;

    // Module name strings placed after module entries
    let names_base = modlist_rva + modlist_data_size;
    let mut name_entries: Vec<(u32, Vec<u16>)> = Vec::new();
    let mut names_offset = 0u32;
    for m in modules {
        let rva = names_base + names_offset;
        let utf16: Vec<u16> = m.full_name.encode_utf16().collect();
        // MINIDUMP_STRING: Length(4) + UTF-16LE data + null(2)
        names_offset += 4 + utf16.len() as u32 * 2 + 2;
        name_entries.push((rva, utf16));
    }

    // Memory64ListStream
    let mem64_rva = names_base + names_offset;
    let mem64_header = 16u64; // NumberOfMemoryRanges(8) + BaseRva(8)
    let mem64_descs = regions.len() as u64 * 16;
    let mem64_list_size = mem64_header + mem64_descs;
    let memory_data_rva = mem64_rva as u64 + mem64_list_size;

    // === MINIDUMP_HEADER (32 bytes) ===
    w.write_all(&MINIDUMP_SIGNATURE.to_le_bytes())?;
    w.write_all(&MINIDUMP_VERSION.to_le_bytes())?;
    w.write_all(&3u32.to_le_bytes())?; // NumberOfStreams
    w.write_all(&header_size.to_le_bytes())?; // StreamDirectoryRva (dir follows header)
    w.write_all(&0u32.to_le_bytes())?; // CheckSum
    w.write_all(&0u32.to_le_bytes())?; // TimeDateStamp
    w.write_all(&2u64.to_le_bytes())?; // Flags = MiniDumpWithFullMemory

    // === MINIDUMP_DIRECTORY[3] (36 bytes) ===
    w.write_all(&STREAM_TYPE_SYSTEM_INFO.to_le_bytes())?;
    w.write_all(&sysinfo_size.to_le_bytes())?;
    w.write_all(&sysinfo_rva.to_le_bytes())?;

    w.write_all(&STREAM_TYPE_MODULE_LIST.to_le_bytes())?;
    w.write_all(&modlist_data_size.to_le_bytes())?;
    w.write_all(&modlist_rva.to_le_bytes())?;

    w.write_all(&STREAM_TYPE_MEMORY64_LIST.to_le_bytes())?;
    w.write_all(&(mem64_list_size as u32).to_le_bytes())?;
    w.write_all(&mem64_rva.to_le_bytes())?;

    // === SystemInfoStream (56 bytes) ===
    w.write_all(&PROCESSOR_ARCHITECTURE_AMD64.to_le_bytes())?;
    w.write_all(&0u16.to_le_bytes())?; // ProcessorLevel
    w.write_all(&0u16.to_le_bytes())?; // ProcessorRevision
    w.write_all(&[1u8])?; // NumberOfProcessors
    w.write_all(&[1u8])?; // ProductType = VER_NT_WORKSTATION
    w.write_all(&10u32.to_le_bytes())?; // MajorVersion (Windows 10)
    w.write_all(&0u32.to_le_bytes())?; // MinorVersion
    w.write_all(&build_number.to_le_bytes())?;
    w.write_all(&VER_PLATFORM_WIN32_NT.to_le_bytes())?;
    w.write_all(&csd_rva.to_le_bytes())?; // CSDVersionRva
    w.write_all(&0u16.to_le_bytes())?; // SuiteMask
    w.write_all(&0u16.to_le_bytes())?; // Reserved2
    w.write_all(&[0u8; 24])?; // CPU_INFORMATION (zeroed)

    // === CSD version string (6 bytes) ===
    w.write_all(&0u32.to_le_bytes())?; // Length = 0
    w.write_all(&0u16.to_le_bytes())?; // Null terminator

    // === ModuleListStream ===
    w.write_all(&(modules.len() as u32).to_le_bytes())?;
    for (i, m) in modules.iter().enumerate() {
        // MINIDUMP_MODULE: 108 bytes total
        w.write_all(&m.base.to_le_bytes())?; // BaseOfImage (8)
        w.write_all(&m.size.to_le_bytes())?; // SizeOfImage (4)
        w.write_all(&0u32.to_le_bytes())?; // CheckSum (4)
        w.write_all(&0u32.to_le_bytes())?; // TimeDateStamp (4)
        w.write_all(&name_entries[i].0.to_le_bytes())?; // ModuleNameRva (4)
        w.write_all(&[0u8; 52])?; // VS_FIXEDFILEINFO (52)
        w.write_all(&[0u8; 8])?; // CvRecord (8)
        w.write_all(&[0u8; 8])?; // MiscRecord (8)
        w.write_all(&[0u8; 16])?; // Reserved0 + Reserved1 (16)
    }

    // Module name strings
    for (_, utf16) in &name_entries {
        let byte_len = utf16.len() as u32 * 2;
        w.write_all(&byte_len.to_le_bytes())?; // Length (bytes, excludes null)
        for &ch in utf16 {
            w.write_all(&ch.to_le_bytes())?;
        }
        w.write_all(&0u16.to_le_bytes())?; // Null terminator
    }

    // === Memory64ListStream ===
    w.write_all(&(regions.len() as u64).to_le_bytes())?;
    w.write_all(&memory_data_rva.to_le_bytes())?;
    for region in regions {
        w.write_all(&region.start_va.to_le_bytes())?;
        w.write_all(&region.size.to_le_bytes())?;
    }

    // === Memory data (sequential pages) ===
    let mut page_buf = [0u8; 4096];
    let mut total_pages = 0u64;
    for region in regions {
        let page_count = region.size / 0x1000;
        for i in 0..page_count {
            let va = region.start_va + i * 0x1000;
            if vmem.read_virt(va, &mut page_buf).is_err() {
                page_buf.fill(0);
            }
            w.write_all(&page_buf)?;
            total_pages += 1;
        }
    }

    w.flush()?;

    let file_size = memory_data_rva + total_pages * 0x1000;
    log::info!(
        "Minidump written: {} regions, {} pages, {:.1} MB → {}",
        regions.len(),
        total_pages,
        file_size as f64 / (1024.0 * 1024.0),
        output_path.display(),
    );

    Ok(())
}
