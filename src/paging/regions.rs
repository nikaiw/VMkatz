//! Enumerate mapped userland virtual-address regions for a process.
//!
//! Walks the page-table tree top-down (PML4 → PDPT → PD → PT) and emits
//! contiguous mapped regions. Used by the chrome memory scanner to find
//! candidate areas for pattern matching without doing a brute-force scan of
//! the full 128 TB user address space.

use crate::error::Result;
use crate::memory::PhysicalMemory;
use crate::paging::entry::{PageTableEntry, PAGE_OFFSET_1GB, PAGE_OFFSET_2MB, PAGE_PHYS_MASK};

/// A contiguous run of mapped 4 KiB pages in a single process's address space.
#[derive(Debug, Clone, Copy)]
pub struct MappedRegion {
    /// Virtual address of the first byte.
    pub start: u64,
    /// Length in bytes. Always a multiple of 0x1000.
    pub len: u64,
}

impl MappedRegion {
    pub fn end(&self) -> u64 {
        self.start + self.len
    }
}

/// Walk the process's page tables and enumerate every present 4 KiB page in
/// the canonical low half (userland, PML4 indices 0..256). Adjacent 4 KiB
/// pages are coalesced into a single [`MappedRegion`]. Large (2 MiB) and
/// huge (1 GiB) pages contribute a single region each.
///
/// Pages flagged "transition" (Windows-specific: still resident but marked
/// not-present) are included; pages flagged pagefile/prototype are skipped
/// since their backing isn't resolvable from page-table flags alone here.
pub fn enumerate_user_regions<P: PhysicalMemory>(
    phys: &P,
    dtb: u64,
) -> Result<Vec<MappedRegion>> {
    // Cap on total bytes returned: 4 GiB is plenty for a chrome process's heap
    // and prevents runaway allocations if a page table is corrupt and points
    // back at itself or yields wild entries.
    const MAX_TOTAL_BYTES: u64 = 4 * 1024 * 1024 * 1024;

    let mut regions: Vec<MappedRegion> = Vec::new();
    let mut total_bytes: u64 = 0;
    let emit = |start: u64, len: u64, regions: &mut Vec<MappedRegion>, total_bytes: &mut u64| {
        // Merge with the previous region if this one is contiguous.
        if let Some(last) = regions.last_mut() {
            if last.end() == start {
                last.len += len;
                *total_bytes += len;
                return;
            }
        }
        regions.push(MappedRegion { start, len });
        *total_bytes += len;
    };

    let pml4_base = dtb & PAGE_PHYS_MASK;

    // PML4 covers 256 entries of 512 GiB each for the low (user) half. Bit 47
    // determines kernel-vs-user; PML4 indices 0..256 are canonical low-half.
    for pml4_idx in 0..256u64 {
        if total_bytes >= MAX_TOTAL_BYTES {
            break;
        }
        let pml4e_raw = match phys.read_phys_u64(pml4_base + pml4_idx * 8) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let pml4e = PageTableEntry(pml4e_raw);
        if !pml4e.is_present() {
            continue;
        }
        let pdpt_base = pml4e.frame_addr();
        let pml4_va = pml4_idx << 39;

        for pdpt_idx in 0..512u64 {
            if total_bytes >= MAX_TOTAL_BYTES {
                break;
            }
            let pdpte_raw = match phys.read_phys_u64(pdpt_base + pdpt_idx * 8) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let pdpte = PageTableEntry(pdpte_raw);
            if !pdpte.is_present() {
                continue;
            }
            let pdpt_va = pml4_va | (pdpt_idx << 30);

            // 1 GiB huge page → emit the whole gig.
            if pdpte.is_large_page() {
                emit(pdpt_va, PAGE_OFFSET_1GB + 1, &mut regions, &mut total_bytes);
                continue;
            }

            let pd_base = pdpte.frame_addr();
            for pd_idx in 0..512u64 {
                if total_bytes >= MAX_TOTAL_BYTES {
                    break;
                }
                let pde_raw = match phys.read_phys_u64(pd_base + pd_idx * 8) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let pde = PageTableEntry(pde_raw);
                if !pde.is_present() {
                    continue;
                }
                let pd_va = pdpt_va | (pd_idx << 21);

                // 2 MiB large page → emit the whole 2 MiB.
                if pde.is_large_page() {
                    emit(pd_va, PAGE_OFFSET_2MB + 1, &mut regions, &mut total_bytes);
                    continue;
                }

                let pt_base = pde.frame_addr();
                for pt_idx in 0..512u64 {
                    if total_bytes >= MAX_TOTAL_BYTES {
                        break;
                    }
                    let pte_raw = match phys.read_phys_u64(pt_base + pt_idx * 8) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    let pte = PageTableEntry(pte_raw);
                    if !pte.is_present() && !pte.is_transition() {
                        continue;
                    }
                    let page_va = pd_va | (pt_idx << 12);
                    emit(page_va, 0x1000, &mut regions, &mut total_bytes);
                }
            }
        }
    }

    Ok(regions)
}
