//! Extended Page Table (EPT) walker for nested virtualization (VBS/Hyper-V).
//!
//! When VBS is enabled, Hyper-V runs inside the VM as a nested hypervisor.
//! ESXi captures L1 guest physical memory, but the Windows kernel runs in
//! L2 guest physical space mapped through Hyper-V's EPT (SLAT).
//!
//! This module finds and walks the EPT to reconstruct L2→L1 translation,
//! allowing us to scan L2 physical memory for EPROCESS structures.
//!
//! Optimization: EptLayer precomputes the full L2→L1 mapping on construction,
//! so subsequent reads use O(log n) binary search instead of 4-level walk.

use crate::error::{Result, VmkatzError};
use crate::memory::PhysicalMemory;
use crate::paging::entry::{LARGE_1GB_MASK, LARGE_2MB_MASK, PAGE_PHYS_MASK};

const PAGE_SIZE: u64 = 4096;
const EPT_PRESENT_MASK: u64 = 0x7; // bits 2:0 = RWX
const EPT_LARGE_PAGE: u64 = 1 << 7; // bit 7 = large page

/// A contiguous L2→L1 mapping region from an EPT leaf entry.
#[derive(Debug, Clone, Copy)]
struct EptMapping {
    l2_base: u64, // L2 guest physical base address
    l1_base: u64, // L1 physical base address
    size: u64,    // Region size: 4KB, 2MB, or 1GB
}

/// EPT-translated physical memory layer with precomputed mappings.
/// Construction walks the full EPT once; reads use binary search.
pub struct EptLayer<'a, P: PhysicalMemory> {
    l1: &'a P,
    mappings: Vec<EptMapping>, // sorted by l2_base
    l2_size: u64,
    mapped_count: usize, // total number of mapped 4KB-equivalent pages
}

/// Public view of a contiguous L2→L1 mapping region for bulk reads.
#[derive(Debug, Clone, Copy)]
pub struct EptRegion {
    pub l2_base: u64,
    pub l1_base: u64,
    pub size: u64,
}

/// A scored EPT candidate, sorted by quality (non-zero translated pages).
#[derive(Debug)]
pub struct EptCandidate {
    pub pml4_addr: u64,
    pub l2_size: u64,
    pub valid_pml4e: u32,
    pub nonzero_pages: u32,
    pub total_sampled: u32,
}

/// Maximum mapped pages before aborting EPT construction.
/// A Windows kernel EPT typically maps 1-8 GB = 256K-2M pages.
/// Anything above 20M pages (~80 GB) is a hypervisor-level EPT.
const MAX_EPT_MAPPED_PAGES: u64 = 20_000_000;

impl<'a, P: PhysicalMemory> EptLayer<'a, P> {
    /// Create an EPT layer by precomputing all L2→L1 mappings.
    /// This walks the full 4-level EPT once, then all subsequent reads are O(log n).
    /// Aborts early if mapped page count exceeds the cap (hypervisor-level EPT).
    pub fn new(l1: &'a P, ept_pml4: u64, l2_size: u64) -> Self {
        Self::new_with_limit(l1, ept_pml4, l2_size, MAX_EPT_MAPPED_PAGES)
    }

    /// Create an EPT layer with a custom mapped page limit.
    fn new_with_limit(l1: &'a P, ept_pml4: u64, l2_size: u64, max_pages: u64) -> Self {
        let l1_size = l1.phys_size();
        let mut mappings = Vec::new();
        let mut mapped_pages: u64 = 0;
        let mut aborted = false;

        let mut pml4_buf = [0u8; PAGE_SIZE as usize];
        if l1.read_phys(ept_pml4, &mut pml4_buf).is_ok() {
            'pml4: for pml4_idx in 0..512u64 {
                let pml4e = read_entry(&pml4_buf, pml4_idx);
                if pml4e & EPT_PRESENT_MASK == 0 {
                    continue;
                }
                let pdpt_addr = pml4e & PAGE_PHYS_MASK;
                if pdpt_addr >= l1_size {
                    continue;
                }

                let mut pdpt_buf = [0u8; PAGE_SIZE as usize];
                if l1.read_phys(pdpt_addr, &mut pdpt_buf).is_err() {
                    continue;
                }

                for pdpt_idx in 0..512u64 {
                    let pdpte = read_entry(&pdpt_buf, pdpt_idx);
                    if pdpte & EPT_PRESENT_MASK == 0 {
                        continue;
                    }

                    let l2_1g = (pml4_idx << 39) | (pdpt_idx << 30);

                    // 1GB large page (262144 × 4KB pages)
                    if pdpte & EPT_LARGE_PAGE != 0 {
                        let l1_base = pdpte & LARGE_1GB_MASK;
                        if l1_base < l1_size {
                            mappings.push(EptMapping {
                                l2_base: l2_1g,
                                l1_base,
                                size: 1 << 30,
                            });
                            mapped_pages += (1 << 30) / PAGE_SIZE;
                            if mapped_pages > max_pages {
                                aborted = true;
                                break 'pml4;
                            }
                        }
                        continue;
                    }

                    let pd_addr = pdpte & PAGE_PHYS_MASK;
                    if pd_addr >= l1_size {
                        continue;
                    }

                    let mut pd_buf = [0u8; PAGE_SIZE as usize];
                    if l1.read_phys(pd_addr, &mut pd_buf).is_err() {
                        continue;
                    }

                    for pd_idx in 0..512u64 {
                        let pde = read_entry(&pd_buf, pd_idx);
                        if pde & EPT_PRESENT_MASK == 0 {
                            continue;
                        }

                        let l2_2m = l2_1g | (pd_idx << 21);

                        // 2MB large page (512 × 4KB pages)
                        if pde & EPT_LARGE_PAGE != 0 {
                            let l1_base = pde & LARGE_2MB_MASK;
                            if l1_base < l1_size {
                                mappings.push(EptMapping {
                                    l2_base: l2_2m,
                                    l1_base,
                                    size: 1 << 21,
                                });
                                mapped_pages += (1 << 21) / PAGE_SIZE;
                                if mapped_pages > max_pages {
                                    aborted = true;
                                    break 'pml4;
                                }
                            }
                            continue;
                        }

                        let pt_addr = pde & PAGE_PHYS_MASK;
                        if pt_addr >= l1_size {
                            continue;
                        }

                        let mut pt_buf = [0u8; PAGE_SIZE as usize];
                        if l1.read_phys(pt_addr, &mut pt_buf).is_err() {
                            continue;
                        }

                        for pt_idx in 0..512u64 {
                            let pte = read_entry(&pt_buf, pt_idx);
                            if pte & EPT_PRESENT_MASK == 0 {
                                continue;
                            }
                            let l1_addr = pte & PAGE_PHYS_MASK;
                            if l1_addr >= l1_size {
                                continue;
                            }
                            mappings.push(EptMapping {
                                l2_base: l2_2m | (pt_idx << 12),
                                l1_base: l1_addr,
                                size: PAGE_SIZE,
                            });
                            mapped_pages += 1;
                        }

                        if mapped_pages > max_pages {
                            aborted = true;
                            break 'pml4;
                        }
                    }
                }
            }
        }

        if aborted {
            log::info!(
                "EPT at 0x{ept_pml4:x}: aborted after {mapped_pages} pages (exceeds {max_pages} page cap — hypervisor-level EPT)",
            );
            // Return empty layer — caller should skip this candidate
            return Self {
                l1,
                mappings: Vec::new(),
                l2_size,
                mapped_count: mapped_pages as usize,
            };
        }

        mappings.sort_by_key(|m| m.l2_base);

        log::info!(
            "EPT prebuilt: {} mapping regions, ~{} mapped pages ({} MB of L2 space)",
            mappings.len(),
            mapped_pages,
            mapped_pages * 4 / 1024,
        );

        Self {
            l1,
            mappings,
            l2_size,
            mapped_count: mapped_pages as usize,
        }
    }

    /// Returns true if the EPT was aborted during construction (too many pages).
    pub const fn is_aborted(&self) -> bool {
        self.mapped_count > 0 && self.mappings.is_empty()
    }

    /// Number of mapped 4KB-equivalent pages.
    pub const fn mapped_page_count(&self) -> usize {
        self.mapped_count
    }

    /// Translate L2 → L1 via binary search on precomputed mappings.
    fn translate_l2(&self, l2_phys: u64) -> Result<u64> {
        // Binary search: find the mapping region containing this L2 address
        let idx = self
            .mappings
            .partition_point(|m| m.l2_base + m.size <= l2_phys);

        if idx < self.mappings.len() {
            let m = &self.mappings[idx];
            if l2_phys >= m.l2_base && l2_phys < m.l2_base + m.size {
                let offset = l2_phys - m.l2_base;
                return Ok(m.l1_base + offset);
            }
        }

        Err(VmkatzError::UnmappablePhysical(l2_phys))
    }

    /// Iterate over all mapped L2 page-aligned addresses and their L1 targets.
    /// Used for efficient EPROCESS scanning (scan L1 pages directly).
    pub fn mapped_pages(&self) -> MappedPageIter<'_> {
        MappedPageIter {
            mappings: &self.mappings,
            region_idx: 0,
            page_offset: 0,
        }
    }

    /// Iterate over contiguous L2→L1 mapping regions for bulk reads.
    pub fn mapped_regions(&self) -> impl Iterator<Item = EptRegion> + '_ {
        self.mappings.iter().map(|m| EptRegion {
            l2_base: m.l2_base,
            l1_base: m.l1_base,
            size: m.size,
        })
    }
}

/// Iterator over (L2_page_base, L1_page_addr) for all mapped pages.
pub struct MappedPageIter<'a> {
    mappings: &'a [EptMapping],
    region_idx: usize,
    page_offset: u64,
}

impl Iterator for MappedPageIter<'_> {
    type Item = (u64, u64); // (L2 page base, L1 page address)

    fn next(&mut self) -> Option<Self::Item> {
        while self.region_idx < self.mappings.len() {
            let m = &self.mappings[self.region_idx];
            if self.page_offset < m.size {
                let l2 = m.l2_base + self.page_offset;
                let l1 = m.l1_base + self.page_offset;
                self.page_offset += PAGE_SIZE;
                return Some((l2, l1));
            }
            self.region_idx += 1;
            self.page_offset = 0;
        }
        None
    }
}

impl<P: PhysicalMemory> PhysicalMemory for EptLayer<'_, P> {
    fn read_phys(&self, phys_addr: u64, buf: &mut [u8]) -> Result<()> {
        // Handle reads that might cross page boundaries
        let mut offset = 0;
        while offset < buf.len() {
            let current_addr = phys_addr + offset as u64;
            let page_remaining = PAGE_SIZE as usize - (current_addr as usize & 0xFFF);
            let to_read = std::cmp::min(buf.len() - offset, page_remaining);

            let l1_addr = self.translate_l2(current_addr)?;
            self.l1
                .read_phys(l1_addr, &mut buf[offset..offset + to_read])?;
            offset += to_read;
        }
        Ok(())
    }

    fn phys_size(&self) -> u64 {
        self.l2_size
    }
}

/// Maximum EPT candidates to collect before stopping the scan.
const MAX_EPT_CANDIDATES: usize = 15;

/// Find all EPT candidates, ranked by quality (most non-zero translated pages first).
/// Stops scanning after finding enough good candidates to avoid wasting time on
/// non-Windows VMs where no valid EPT exists.
/// Read chunk size for bulk EPT scans (1 MB = 256 pages).
const SCAN_CHUNK_SIZE: usize = 256 * 4096;

pub fn find_ept_candidates<P: PhysicalMemory>(l1: &P) -> Result<Vec<EptCandidate>> {
    // Scan budget: if no candidates found after scanning a portion of L1, give up.
    // EPT PML4 tables are placed by the hypervisor in the lower portion of L1 memory.
    // For genuine VBS VMs, candidates appear within the first few GB.
    // Cap at 4GB — scanning more is wasteful since EPTs live in low memory.
    const MAX_SCAN_BUDGET: u64 = 4 * 1024 * 1024 * 1024;
    // Give up if we've scanned 256K pages (1GB) without finding a candidate.
    const PAGES_WITHOUT_CANDIDATE_LIMIT: u64 = 256_000;

    let l1_size = l1.phys_size();

    log::info!(
        "EPT scan: searching {} MB for EPT PML4 tables...",
        l1_size / (1024 * 1024)
    );

    let mut chunk_buf = vec![0u8; SCAN_CHUNK_SIZE];
    let mut candidates: Vec<EptCandidate> = Vec::new();

    let scan_budget = if l1_size < 2 * 1024 * 1024 * 1024 {
        l1_size / 4
    } else {
        (l1_size / 4).min(MAX_SCAN_BUDGET)
    };
    let mut pages_since_last_candidate: u64 = 0;

    let mut addr: u64 = 0;
    while addr < l1_size {
        let read_len = SCAN_CHUNK_SIZE.min((l1_size - addr) as usize);
        if l1.read_phys(addr, &mut chunk_buf[..read_len]).is_err() {
            // If full chunk fails, try page-by-page within this range
            addr += read_len as u64;
            pages_since_last_candidate += (read_len / PAGE_SIZE as usize) as u64;
            continue;
        }

        // Score each 4KB page within the chunk
        for page_off in (0..read_len).step_by(PAGE_SIZE as usize) {
            let page = &chunk_buf[page_off..page_off + PAGE_SIZE as usize];
            let page_addr = addr + page_off as u64;

            if page.iter().all(|&b| b == 0) {
                pages_since_last_candidate += 1;
                continue;
            }

            let (valid, zero, invalid, max_l2) = score_ept_page(page, l1_size);

            if (1..=64).contains(&valid) && zero >= 400 && invalid == 0 {
                // Two-level validation: check that a PDPT under this PML4 is also structurally valid
                if !validate_ept_pdpt(l1, page, l1_size) {
                    pages_since_last_candidate += 1;
                    continue;
                }

                let (nonzero, sampled) = sample_nonzero_translated(l1, page_addr, l1_size, 64);

                let l2_size = std::cmp::min((max_l2 + 1) * (1u64 << 39), l1_size * 2);

                log::debug!(
                    "EPT candidate at L1=0x{:x}: {} PML4E, {}/{} non-zero, l2={} MB",
                    page_addr,
                    valid,
                    nonzero,
                    sampled,
                    l2_size / (1024 * 1024)
                );

                candidates.push(EptCandidate {
                    pml4_addr: page_addr,
                    l2_size,
                    valid_pml4e: valid,
                    nonzero_pages: nonzero,
                    total_sampled: sampled,
                });
                pages_since_last_candidate = 0;

                // Stop scanning after collecting enough candidates
                if candidates.len() >= MAX_EPT_CANDIDATES {
                    log::info!("EPT scan: reached {MAX_EPT_CANDIDATES} candidates, stopping scan");
                    break;
                }
            } else {
                pages_since_last_candidate += 1;
            }

            // Give up if we've scanned past the budget without finding anything
            if candidates.is_empty() && page_addr > scan_budget {
                log::info!(
                    "EPT scan: scanned {} MB ({} pages) without finding candidates, giving up",
                    page_addr / (1024 * 1024),
                    page_addr / PAGE_SIZE,
                );
                // Use outer break via flag
                addr = l1_size;
                break;
            }

            // Also give up if too many pages since last candidate (gap too wide)
            if pages_since_last_candidate > PAGES_WITHOUT_CANDIDATE_LIMIT {
                log::info!(
                    "EPT scan: {pages_since_last_candidate} pages since last candidate, stopping scan",
                );
                addr = l1_size;
                break;
            }
        }

        // Break if we hit MAX_EPT_CANDIDATES inside inner loop
        if candidates.len() >= MAX_EPT_CANDIDATES || addr >= l1_size {
            break;
        }

        addr += read_len as u64;
    }

    // Sort: prefer EPTs closer to Windows kernel (fewer PML4E = more specific).
    // A Windows kernel EPT typically has 1-4 PML4E covering 8-16 GB of L2 space.
    // Hypervisor-level EPTs have 8+ PML4E mapping all of L1 memory.
    // Primary: non-zero > 0 (must have data), then fewer PML4E preferred,
    // then non-zero count as tiebreaker.
    candidates.sort_by(|a, b| {
        // First: any non-zero data beats none
        let a_has = u32::from(a.nonzero_pages > 0);
        let b_has = u32::from(b.nonzero_pages > 0);
        b_has
            .cmp(&a_has)
            // Fewer PML4E = more likely Windows kernel EPT
            .then(a.valid_pml4e.cmp(&b.valid_pml4e))
            // More non-zero pages as tiebreaker
            .then(b.nonzero_pages.cmp(&a.nonzero_pages))
    });

    // Filter out zero-data candidates if we have any good ones
    let good_count = candidates.iter().filter(|c| c.nonzero_pages > 0).count();
    if good_count > 0 {
        candidates.retain(|c| c.nonzero_pages > 0);
    }

    log::info!(
        "EPT scan: {} candidates found{}",
        candidates.len(),
        if let Some(best) = candidates.first() {
            format!(
                ", best at L1=0x{:x} ({}/{} non-zero)",
                best.pml4_addr, best.nonzero_pages, best.total_sampled
            )
        } else {
            String::new()
        }
    );

    if candidates.is_empty() {
        return Err(VmkatzError::SystemProcessNotFound);
    }

    Ok(candidates)
}

#[inline]
fn read_entry(buf: &[u8], idx: u64) -> u64 {
    let off = (idx * 8) as usize;
    crate::utils::read_u64_le(buf, off).unwrap_or(0)
}

/// Score a page as a potential EPT PML4 table.
/// Applies strict validation: reserved bits 63:52 must be 0, bit 7 (large page) must be 0
/// for PML4E entries (PML4E cannot be a large page in EPT).
fn score_ept_page(page: &[u8], l1_size: u64) -> (u32, u32, u32, u64) {
    let mut valid = 0u32;
    let mut zero = 0u32;
    let mut invalid = 0u32;
    let mut max_idx: u64 = 0;

    for i in 0..512u64 {
        let entry = read_entry(page, i);
        if entry == 0 {
            zero += 1;
            continue;
        }

        let rwx = entry & EPT_PRESENT_MASK;
        let phys = entry & PAGE_PHYS_MASK;
        let reserved_high = entry >> 52;
        let is_large = entry & EPT_LARGE_PAGE != 0;

        if rwx != 0 && phys < l1_size && phys != 0
            && reserved_high == 0  // EPT reserved bits 63:52 must be 0
            && !is_large
        // PML4E cannot be a large page
        {
            valid += 1;
            max_idx = i;
        } else {
            invalid += 1;
        }
    }

    (valid, zero, invalid, max_idx)
}

/// Validate an EPT candidate by checking PDPT structural integrity.
/// Follows the first valid PML4E down to its PDPT page and verifies it also
/// has valid EPT structure (at least 1 valid entry, >=400 zeros).
fn validate_ept_pdpt<P: PhysicalMemory>(l1: &P, pml4_buf: &[u8], l1_size: u64) -> bool {
    // Find first valid PML4E
    for i in 0..512u64 {
        let entry = read_entry(pml4_buf, i);
        if entry == 0 {
            continue;
        }
        let rwx = entry & EPT_PRESENT_MASK;
        let phys = entry & PAGE_PHYS_MASK;
        let reserved_high = entry >> 52;
        let is_large = entry & EPT_LARGE_PAGE != 0;

        if rwx == 0 || phys >= l1_size || phys == 0 || reserved_high != 0 || is_large {
            continue;
        }

        // Read the PDPT page pointed to by this PML4E
        let mut pdpt_buf = [0u8; PAGE_SIZE as usize];
        if l1.read_phys(phys, &mut pdpt_buf).is_err() {
            continue;
        }

        // Score the PDPT page: entries can have large page bit set (1GB pages)
        let mut pdpt_valid = 0u32;
        let mut pdpt_zero = 0u32;
        let mut pdpt_invalid = 0u32;
        for j in 0..512u64 {
            let pdpte = read_entry(&pdpt_buf, j);
            if pdpte == 0 {
                pdpt_zero += 1;
                continue;
            }
            let pdpte_rwx = pdpte & EPT_PRESENT_MASK;
            let pdpte_phys = pdpte & PAGE_PHYS_MASK;
            let pdpte_reserved = pdpte >> 52;

            if pdpte_rwx != 0 && pdpte_phys < l1_size && pdpte_phys != 0 && pdpte_reserved == 0 {
                pdpt_valid += 1;
            } else {
                pdpt_invalid += 1;
            }
        }

        // PDPT should also be sparse: at least 1 valid entry, many zeros, no invalid
        return pdpt_valid >= 1 && pdpt_zero >= 400 && pdpt_invalid == 0;
    }

    // No valid PML4E found — shouldn't happen since score_ept_page found some
    false
}

/// Sample translated pages to verify an EPT candidate maps non-zero data.
fn sample_nonzero_translated<P: PhysicalMemory>(
    l1: &P,
    pml4_addr: u64,
    l1_size: u64,
    max_samples: usize,
) -> (u32, u32) {
    let mut targets: Vec<u64> = Vec::with_capacity(max_samples);
    let mut pml4_buf = [0u8; PAGE_SIZE as usize];

    if l1.read_phys(pml4_addr, &mut pml4_buf).is_err() {
        return (0, 0);
    }

    'outer: for pml4_idx in 0..512u64 {
        let pml4e = read_entry(&pml4_buf, pml4_idx);
        if pml4e & EPT_PRESENT_MASK == 0 {
            continue;
        }
        let pdpt_addr = pml4e & PAGE_PHYS_MASK;
        if pdpt_addr >= l1_size {
            continue;
        }

        let mut pdpt_buf = [0u8; PAGE_SIZE as usize];
        if l1.read_phys(pdpt_addr, &mut pdpt_buf).is_err() {
            continue;
        }

        for pdpt_idx in 0..512u64 {
            let pdpte = read_entry(&pdpt_buf, pdpt_idx);
            if pdpte & EPT_PRESENT_MASK == 0 {
                continue;
            }

            if pdpte & EPT_LARGE_PAGE != 0 {
                let base = pdpte & LARGE_1GB_MASK;
                if base < l1_size {
                    targets.push(base);
                }
                if targets.len() >= max_samples {
                    break 'outer;
                }
                continue;
            }

            let pd_addr = pdpte & PAGE_PHYS_MASK;
            if pd_addr >= l1_size {
                continue;
            }

            let mut pd_buf = [0u8; PAGE_SIZE as usize];
            if l1.read_phys(pd_addr, &mut pd_buf).is_err() {
                continue;
            }

            for pd_idx in 0..512u64 {
                let pde = read_entry(&pd_buf, pd_idx);
                if pde & EPT_PRESENT_MASK == 0 {
                    continue;
                }

                if pde & EPT_LARGE_PAGE != 0 {
                    let base = pde & LARGE_2MB_MASK;
                    if base < l1_size {
                        targets.push(base);
                    }
                    if targets.len() >= max_samples {
                        break 'outer;
                    }
                    continue;
                }

                let pt_addr = pde & PAGE_PHYS_MASK;
                if pt_addr >= l1_size {
                    continue;
                }

                let mut pt_buf = [0u8; PAGE_SIZE as usize];
                if l1.read_phys(pt_addr, &mut pt_buf).is_err() {
                    continue;
                }

                for pt_idx in 0..512u64 {
                    let pte = read_entry(&pt_buf, pt_idx);
                    if pte & EPT_PRESENT_MASK == 0 {
                        continue;
                    }
                    let target = pte & PAGE_PHYS_MASK;
                    if target < l1_size {
                        targets.push(target);
                    }
                    if targets.len() >= max_samples {
                        break 'outer;
                    }
                }
            }
        }
    }

    let mut nonzero = 0u32;
    let total = targets.len() as u32;
    let mut page_buf = [0u8; PAGE_SIZE as usize];

    for &target in &targets {
        if l1.read_phys(target, &mut page_buf).is_ok() && !page_buf.iter().all(|&b| b == 0) {
            nonzero += 1;
        }
    }

    (nonzero, total)
}
