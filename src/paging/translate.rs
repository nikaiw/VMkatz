use std::cell::Cell;

use crate::error::{Result, VmkatzError};
use crate::memory::{PhysicalMemory, VirtualMemory};
use crate::paging::entry::{
    LARGE_1GB_MASK, LARGE_2MB_MASK, PAGE_OFFSET_1GB, PAGE_OFFSET_2MB, PAGE_PHYS_MASK,
    PageTableEntry,
};

/// TLB cache size: 256 entries, direct-mapped by VA page number.
/// Each entry is (va_page, pa_page_base) where va_page = vaddr >> 12.
/// A va_page of 0 is treated as empty (VA 0 is rarely valid in practice).
const TLB_SIZE: usize = 256;

/// 4-level x86-64 page table walker with a small TLB cache.
///
/// The TLB avoids redundant 4-level page table walks for adjacent virtual
/// addresses that share the same 4KB page mapping. Uses `Cell` for interior
/// mutability so `translate()` can remain `&self`.
pub struct PageTableWalker<'a, P: PhysicalMemory> {
    phys: &'a P,
    /// Direct-mapped TLB: index = (va_page) % TLB_SIZE.
    /// Each slot caches (va_page, pa_page_base) for a single 4KB mapping.
    tlb: [Cell<(u64, u64)>; TLB_SIZE],
}

impl<'a, P: PhysicalMemory> PageTableWalker<'a, P> {
    pub fn new(phys: &'a P) -> Self {
        Self {
            phys,
            tlb: std::array::from_fn(|_| Cell::new((0, 0))),
        }
    }

    /// Look up a VA page in the TLB. Returns Some(pa_page_base) on hit.
    #[inline]
    const fn tlb_lookup(&self, va_page: u64) -> Option<u64> {
        let idx = (va_page as usize) % TLB_SIZE;
        let (cached_va, cached_pa) = self.tlb[idx].get();
        if cached_va == va_page && va_page != 0 {
            Some(cached_pa)
        } else {
            None
        }
    }

    /// Insert a VA→PA page mapping into the TLB.
    #[inline]
    fn tlb_insert(&self, va_page: u64, pa_page_base: u64) {
        if va_page == 0 {
            return; // Don't cache VA 0 (sentinel value)
        }
        let idx = (va_page as usize) % TLB_SIZE;
        self.tlb[idx].set((va_page, pa_page_base));
    }

    /// Translate a virtual address to a physical address using the given CR3 (DTB).
    pub fn translate(&self, cr3: u64, vaddr: u64) -> Result<u64> {
        let va_page = vaddr >> 12;
        let page_offset = vaddr & 0xFFF;

        // TLB fast path: check cache before doing a full page table walk
        if let Some(pa_base) = self.tlb_lookup(va_page) {
            return Ok(pa_base | page_offset);
        }

        let pml4_base = cr3 & PAGE_PHYS_MASK;

        // PML4: bits [47:39]
        let pml4_idx = (vaddr >> 39) & 0x1FF;
        let pml4e = PageTableEntry(self.phys.read_phys_u64(pml4_base + pml4_idx * 8)?);
        if !pml4e.is_present() {
            return Err(VmkatzError::PageFault(vaddr, "PML4"));
        }

        // PDPT: bits [38:30]
        let pdpt_base = pml4e.frame_addr();
        let pdpt_idx = (vaddr >> 30) & 0x1FF;
        let pdpte = PageTableEntry(self.phys.read_phys_u64(pdpt_base + pdpt_idx * 8)?);
        if !pdpte.is_present() {
            return Err(VmkatzError::PageFault(vaddr, "PDPT"));
        }
        if pdpte.is_large_page() {
            // 1GB huge page
            let pa_base = pdpte.raw() & LARGE_1GB_MASK;
            let phys = pa_base | (vaddr & PAGE_OFFSET_1GB);
            // Cache: map the specific 4KB VA page to its PA page base
            self.tlb_insert(va_page, phys & !0xFFF);
            return Ok(phys);
        }

        // PD: bits [29:21]
        let pd_base = pdpte.frame_addr();
        let pd_idx = (vaddr >> 21) & 0x1FF;
        let pde = PageTableEntry(self.phys.read_phys_u64(pd_base + pd_idx * 8)?);
        if !pde.is_present() {
            return Err(VmkatzError::PageFault(vaddr, "PD"));
        }
        if pde.is_large_page() {
            // 2MB large page
            let pa_base = pde.raw() & LARGE_2MB_MASK;
            let phys = pa_base | (vaddr & PAGE_OFFSET_2MB);
            self.tlb_insert(va_page, phys & !0xFFF);
            return Ok(phys);
        }

        // PT: bits [20:12]
        let pt_base = pde.frame_addr();
        let pt_idx = (vaddr >> 12) & 0x1FF;
        let pte = PageTableEntry(self.phys.read_phys_u64(pt_base + pt_idx * 8)?);
        if !pte.is_present() {
            // Check for transition PTE (Windows-specific)
            if pte.is_transition() {
                let pa_base = pte.frame_addr();
                self.tlb_insert(va_page, pa_base);
                return Ok(pa_base | page_offset);
            }
            // Check for pagefile PTE (non-zero, not transition, not prototype)
            if pte.is_pagefile() {
                log::trace!(
                    "PageFileFault: VA=0x{:x} PTE=0x{:016x} pfn={} offset=0x{:x}",
                    vaddr,
                    pte.raw(),
                    pte.pagefile_number(),
                    pte.pagefile_offset()
                );
                return Err(VmkatzError::PageFileFault(vaddr, pte.raw()));
            }
            return Err(VmkatzError::PageFault(vaddr, "PT"));
        }

        let pa_base = pte.frame_addr();
        self.tlb_insert(va_page, pa_base);
        Ok(pa_base | page_offset)
    }

    /// Translate with multi-level pagefile resolution.
    ///
    /// When page table pages (PDPT/PD/PT) are themselves paged out, the parent
    /// entry becomes a pagefile PTE. This method resolves page table pages from
    /// the pagefile at each level, enabling full virtual address translation even
    /// when the page table hierarchy is partially swapped to disk.
    #[cfg(feature = "sam")]
    pub fn translate_with_pagefile(
        &self,
        cr3: u64,
        vaddr: u64,
        pagefile: &crate::paging::pagefile::PagefileReader,
    ) -> Result<u64> {
        let pml4_base = cr3 & PAGE_PHYS_MASK;

        // PML4: bits [47:39] — PML4 page is always resident (CR3 page)
        let pml4_idx = (vaddr >> 39) & 0x1FF;
        let pml4e = PageTableEntry(self.phys.read_phys_u64(pml4_base + pml4_idx * 8)?);
        if !pml4e.is_present() {
            // PML4E not present — try pagefile resolution for the PDPT page
            if pml4e.is_pagefile() {
                let pdpt_page = pagefile
                    .resolve_pte(pml4e.raw())
                    .ok_or(VmkatzError::PageFault(vaddr, "PML4-pagefile"))?;
                return self.walk_from_pdpt(&pdpt_page, vaddr, Some(pagefile));
            }
            return Err(VmkatzError::PageFault(vaddr, "PML4"));
        }

        // PDPT: bits [38:30]
        let pdpt_base = pml4e.frame_addr();
        let pdpt_idx = (vaddr >> 30) & 0x1FF;
        let pdpte = PageTableEntry(self.phys.read_phys_u64(pdpt_base + pdpt_idx * 8)?);
        if !pdpte.is_present() {
            if pdpte.is_pagefile() {
                let pd_page = pagefile
                    .resolve_pte(pdpte.raw())
                    .ok_or(VmkatzError::PageFault(vaddr, "PDPT-pagefile"))?;
                return self.walk_from_pd(&pd_page, vaddr, Some(pagefile));
            }
            return Err(VmkatzError::PageFault(vaddr, "PDPT"));
        }
        if pdpte.is_large_page() {
            let phys = (pdpte.raw() & LARGE_1GB_MASK) | (vaddr & PAGE_OFFSET_1GB);
            return Ok(phys);
        }

        // PD: bits [29:21]
        let pd_base = pdpte.frame_addr();
        let pd_idx = (vaddr >> 21) & 0x1FF;
        let pde = PageTableEntry(self.phys.read_phys_u64(pd_base + pd_idx * 8)?);
        if !pde.is_present() {
            if pde.is_pagefile() {
                let pt_page = pagefile
                    .resolve_pte(pde.raw())
                    .ok_or(VmkatzError::PageFault(vaddr, "PD-pagefile"))?;
                return Self::walk_from_pt(&pt_page, vaddr, Some(pagefile));
            }
            return Err(VmkatzError::PageFault(vaddr, "PD"));
        }
        if pde.is_large_page() {
            let phys = (pde.raw() & LARGE_2MB_MASK) | (vaddr & PAGE_OFFSET_2MB);
            return Ok(phys);
        }

        // PT: bits [20:12]
        let pt_base = pde.frame_addr();
        let pt_idx = (vaddr >> 12) & 0x1FF;
        let pte = PageTableEntry(self.phys.read_phys_u64(pt_base + pt_idx * 8)?);
        if !pte.is_present() {
            if pte.is_transition() {
                return Ok(pte.frame_addr() | (vaddr & 0xFFF));
            }
            if pte.is_pagefile() {
                return Err(VmkatzError::PageFileFault(vaddr, pte.raw()));
            }
            return Err(VmkatzError::PageFault(vaddr, "PT"));
        }

        Ok(pte.frame_addr() | (vaddr & 0xFFF))
    }

    /// Continue page table walk from a resolved PDPT page (in-memory buffer).
    #[cfg(feature = "sam")]
    fn walk_from_pdpt(
        &self,
        pdpt_page: &[u8; 4096],
        vaddr: u64,
        pagefile: Option<&crate::paging::pagefile::PagefileReader>,
    ) -> Result<u64> {
        let pdpt_idx = ((vaddr >> 30) & 0x1FF) as usize;
        let pdpte = PageTableEntry(u64::from_le_bytes(
            pdpt_page[pdpt_idx * 8..pdpt_idx * 8 + 8]
                .try_into()
                .unwrap(),
        ));
        if !pdpte.is_present() {
            if let Some(pf) = pagefile {
                if pdpte.is_pagefile() {
                    let pd_page = pf
                        .resolve_pte(pdpte.raw())
                        .ok_or(VmkatzError::PageFault(vaddr, "PDPT-pagefile"))?;
                    return self.walk_from_pd(&pd_page, vaddr, pagefile);
                }
            }
            return Err(VmkatzError::PageFault(vaddr, "PDPT"));
        }
        if pdpte.is_large_page() {
            return Ok((pdpte.raw() & LARGE_1GB_MASK) | (vaddr & PAGE_OFFSET_1GB));
        }

        // PD: read from physical memory (this level is resident)
        let pd_base = pdpte.frame_addr();
        let pd_idx = (vaddr >> 21) & 0x1FF;
        let pde = PageTableEntry(self.phys.read_phys_u64(pd_base + pd_idx * 8)?);
        if !pde.is_present() {
            if let Some(pf) = pagefile {
                if pde.is_pagefile() {
                    let pt_page = pf
                        .resolve_pte(pde.raw())
                        .ok_or(VmkatzError::PageFault(vaddr, "PD-pagefile"))?;
                    return Self::walk_from_pt(&pt_page, vaddr, pagefile);
                }
            }
            return Err(VmkatzError::PageFault(vaddr, "PD"));
        }
        if pde.is_large_page() {
            return Ok((pde.raw() & LARGE_2MB_MASK) | (vaddr & PAGE_OFFSET_2MB));
        }

        let pt_base = pde.frame_addr();
        self.walk_pt_level(pt_base, vaddr, pagefile)
    }

    /// Continue page table walk from a resolved PD page (in-memory buffer).
    #[cfg(feature = "sam")]
    fn walk_from_pd(
        &self,
        pd_page: &[u8; 4096],
        vaddr: u64,
        pagefile: Option<&crate::paging::pagefile::PagefileReader>,
    ) -> Result<u64> {
        let pd_idx = ((vaddr >> 21) & 0x1FF) as usize;
        let pde = PageTableEntry(u64::from_le_bytes(
            pd_page[pd_idx * 8..pd_idx * 8 + 8].try_into().unwrap(),
        ));
        if !pde.is_present() {
            if let Some(pf) = pagefile {
                if pde.is_pagefile() {
                    let pt_page = pf
                        .resolve_pte(pde.raw())
                        .ok_or(VmkatzError::PageFault(vaddr, "PD-pagefile"))?;
                    return Self::walk_from_pt(&pt_page, vaddr, pagefile);
                }
            }
            return Err(VmkatzError::PageFault(vaddr, "PD"));
        }
        if pde.is_large_page() {
            return Ok((pde.raw() & LARGE_2MB_MASK) | (vaddr & PAGE_OFFSET_2MB));
        }

        let pt_base = pde.frame_addr();
        self.walk_pt_level(pt_base, vaddr, pagefile)
    }

    /// Continue page table walk from a resolved PT page (in-memory buffer).
    #[cfg(feature = "sam")]
    fn walk_from_pt(
        pt_page: &[u8; 4096],
        vaddr: u64,
        _pagefile: Option<&crate::paging::pagefile::PagefileReader>,
    ) -> Result<u64> {
        let pt_idx = ((vaddr >> 12) & 0x1FF) as usize;
        let pte = PageTableEntry(u64::from_le_bytes(
            pt_page[pt_idx * 8..pt_idx * 8 + 8].try_into().unwrap(),
        ));
        if !pte.is_present() {
            if pte.is_transition() {
                return Ok(pte.frame_addr() | (vaddr & 0xFFF));
            }
            if pte.is_pagefile() {
                return Err(VmkatzError::PageFileFault(vaddr, pte.raw()));
            }
            return Err(VmkatzError::PageFault(vaddr, "PT"));
        }
        Ok(pte.frame_addr() | (vaddr & 0xFFF))
    }

    /// Walk PT level from a physical base address (common helper).
    #[cfg(feature = "sam")]
    fn walk_pt_level(
        &self,
        pt_base: u64,
        vaddr: u64,
        pagefile: Option<&crate::paging::pagefile::PagefileReader>,
    ) -> Result<u64> {
        let pt_idx = (vaddr >> 12) & 0x1FF;
        let pte = PageTableEntry(self.phys.read_phys_u64(pt_base + pt_idx * 8)?);
        if !pte.is_present() {
            if pte.is_transition() {
                return Ok(pte.frame_addr() | (vaddr & 0xFFF));
            }
            if pte.is_pagefile() {
                return Err(VmkatzError::PageFileFault(vaddr, pte.raw()));
            }
            // If physical read returned zero and we have pagefile, the PT page
            // itself might have been repurposed — try resolving the PDE from pagefile.
            // But we don't have the PDE at this point, so just report fault.
            let _ = pagefile;
            return Err(VmkatzError::PageFault(vaddr, "PT"));
        }
        Ok(pte.frame_addr() | (vaddr & 0xFFF))
    }
}

/// Read a page table entry from a pre-read buffer.
#[inline]
fn read_pte_from_buf(buf: &[u8], idx: usize) -> u64 {
    let off = idx * 8;
    u64::from_le_bytes(buf[off..off + 8].try_into().unwrap())
}

/// A mapping from virtual address to physical address for a present page.
pub struct PageMapping {
    pub vaddr: u64,
    pub paddr: u64,
    pub size: u64, // 4KB, 2MB, or 1GB
}

impl<P: PhysicalMemory> PageTableWalker<'_, P> {
    /// Enumerate all present user-mode pages for a given CR3.
    /// Calls the callback for each present page mapping.
    ///
    /// Reads entire 4KB page table pages (512 entries) at once instead of
    /// individual 8-byte reads, reducing I/O calls by ~500x per table level.
    pub fn enumerate_present_pages<F>(&self, cr3: u64, mut callback: F)
    where
        F: FnMut(PageMapping),
    {
        let pml4_base = cr3 & PAGE_PHYS_MASK;

        // Read PML4 table (only first 256 entries = user-mode half = 2KB)
        let mut pml4_buf = [0u8; 256 * 8];
        if self.phys.read_phys(pml4_base, &mut pml4_buf).is_err() {
            return;
        }

        let mut table_buf = [0u8; 4096]; // reused for PDPT/PD/PT pages

        for pml4_idx in 0..256u64 {
            let pml4e = PageTableEntry(read_pte_from_buf(&pml4_buf, pml4_idx as usize));
            if !pml4e.is_present() {
                continue;
            }

            // Read entire PDPT page (512 entries)
            let pdpt_base = pml4e.frame_addr();
            if self.phys.read_phys(pdpt_base, &mut table_buf).is_err() {
                continue;
            }
            // Copy PDPT since table_buf will be reused for PD
            let pdpt_buf = table_buf;

            for pdpt_idx in 0..512u64 {
                let pdpte = PageTableEntry(read_pte_from_buf(&pdpt_buf, pdpt_idx as usize));
                if !pdpte.is_present() {
                    continue;
                }
                if pdpte.is_large_page() {
                    let vaddr = (pml4_idx << 39) | (pdpt_idx << 30);
                    let paddr = pdpte.raw() & LARGE_1GB_MASK;
                    callback(PageMapping {
                        vaddr,
                        paddr,
                        size: 0x4000_0000,
                    });
                    continue;
                }

                // Read entire PD page
                let pd_base = pdpte.frame_addr();
                if self.phys.read_phys(pd_base, &mut table_buf).is_err() {
                    continue;
                }
                let pd_buf = table_buf;

                for pd_idx in 0..512u64 {
                    let pde = PageTableEntry(read_pte_from_buf(&pd_buf, pd_idx as usize));
                    if !pde.is_present() {
                        continue;
                    }
                    if pde.is_large_page() {
                        let vaddr = (pml4_idx << 39) | (pdpt_idx << 30) | (pd_idx << 21);
                        let paddr = pde.raw() & LARGE_2MB_MASK;
                        callback(PageMapping {
                            vaddr,
                            paddr,
                            size: 0x20_0000,
                        });
                        continue;
                    }

                    // Read entire PT page
                    let pt_base = pde.frame_addr();
                    if self.phys.read_phys(pt_base, &mut table_buf).is_err() {
                        continue;
                    }

                    for pt_idx in 0..512u64 {
                        let pte = PageTableEntry(read_pte_from_buf(&table_buf, pt_idx as usize));
                        if pte.is_present() || pte.is_transition() {
                            let vaddr = (pml4_idx << 39)
                                | (pdpt_idx << 30)
                                | (pd_idx << 21)
                                | (pt_idx << 12);
                            let paddr = pte.frame_addr();
                            callback(PageMapping {
                                vaddr,
                                paddr,
                                size: 0x1000,
                            });
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PAE (Physical Address Extension) page table walker for 32-bit Windows
// ---------------------------------------------------------------------------

/// 3-level PAE page table walker with TLB cache for 32-bit Windows kernels.
///
/// PAE paging: CR3 (bits 31:5) → PDPT (4 entries × 8B) → PD (512 × 8B) → PT (512 × 8B).
/// Virtual addresses are 32-bit; page table entries are 8 bytes (same as x64).
pub struct PaePageTableWalker<'a, P: PhysicalMemory> {
    phys: &'a P,
    /// Direct-mapped TLB: index = (va_page as u32) % TLB_SIZE.
    tlb: [Cell<(u32, u64)>; TLB_SIZE],
}

impl<'a, P: PhysicalMemory> PaePageTableWalker<'a, P> {
    pub fn new(phys: &'a P) -> Self {
        Self {
            phys,
            tlb: std::array::from_fn(|_| Cell::new((0, 0))),
        }
    }

    #[inline]
    const fn tlb_lookup(&self, va_page: u32) -> Option<u64> {
        let idx = (va_page as usize) % TLB_SIZE;
        let (cached_va, cached_pa) = self.tlb[idx].get();
        if cached_va == va_page && va_page != 0 {
            Some(cached_pa)
        } else {
            None
        }
    }

    #[inline]
    fn tlb_insert(&self, va_page: u32, pa_page_base: u64) {
        if va_page == 0 {
            return;
        }
        let idx = (va_page as usize) % TLB_SIZE;
        self.tlb[idx].set((va_page, pa_page_base));
    }

    /// Translate a 32-bit virtual address to physical using PAE paging.
    pub fn translate(&self, cr3: u64, vaddr: u64) -> Result<u64> {
        let vaddr32 = vaddr as u32;
        let va_page = vaddr32 >> 12;
        let page_offset = u64::from(vaddr32 & 0xFFF);

        // TLB fast path
        if let Some(pa_base) = self.tlb_lookup(va_page) {
            return Ok(pa_base | page_offset);
        }

        // PAE CR3: bits 31:5 specify the 32-byte-aligned PDPT physical base
        let pdpt_base = cr3 & 0xFFFF_FFE0;

        // PDPT index: bits 31:30 (2 bits → 4 entries, each 8 bytes → 32 bytes total)
        let pdpt_idx = u64::from((vaddr32 >> 30) & 0x3);
        let pdpte = self.phys.read_phys_u64(pdpt_base + pdpt_idx * 8)?;
        if pdpte & 1 == 0 {
            return Err(VmkatzError::PageFault(vaddr, "PAE-PDPT"));
        }
        let pd_base = pdpte & PAGE_PHYS_MASK;

        // PD index: bits 29:21 (9 bits → 512 entries)
        let pd_idx = u64::from((vaddr32 >> 21) & 0x1FF);
        let pde = self.phys.read_phys_u64(pd_base + pd_idx * 8)?;
        if pde & 1 == 0 {
            return Err(VmkatzError::PageFault(vaddr, "PAE-PD"));
        }
        // 2MB large page (bit 7)
        if pde & (1 << 7) != 0 {
            let frame = pde & LARGE_2MB_MASK;
            let pa = frame | (u64::from(vaddr32) & PAGE_OFFSET_2MB);
            self.tlb_insert(va_page, pa & !0xFFF);
            return Ok(pa);
        }
        let pt_base = pde & PAGE_PHYS_MASK;

        // PT index: bits 20:12 (9 bits → 512 entries)
        let pt_idx = u64::from((vaddr32 >> 12) & 0x1FF);
        let pte_val = self.phys.read_phys_u64(pt_base + pt_idx * 8)?;
        let pte = PageTableEntry(pte_val);
        if !pte.is_present() {
            if pte.is_transition() {
                let pa_base = pte.frame_addr();
                self.tlb_insert(va_page, pa_base);
                return Ok(pa_base | page_offset);
            }
            return Err(VmkatzError::PageFault(vaddr, "PAE-PT"));
        }

        let pa_base = pte.frame_addr();
        self.tlb_insert(va_page, pa_base);
        Ok(pa_base | page_offset)
    }

    /// Enumerate all present user-mode pages (VA < 0x80000000) for a PAE process.
    ///
    /// Reads entire 4KB page table pages at once for bulk efficiency.
    pub fn enumerate_present_pages<F>(&self, cr3: u64, mut callback: F)
    where
        F: FnMut(PageMapping),
    {
        let pdpt_base = cr3 & 0xFFFF_FFE0;

        // Read PDPT (4 entries × 8 bytes = 32 bytes)
        let mut pdpt_buf = [0u8; 32];
        if self.phys.read_phys(pdpt_base, &mut pdpt_buf).is_err() {
            return;
        }

        let mut table_buf = [0u8; 4096];

        // User-mode: PDPT entries 0-1 cover VA 0x00000000–0x7FFFFFFF
        for pdpt_idx in 0..2u64 {
            let pdpte = read_pte_from_buf(&pdpt_buf, pdpt_idx as usize);
            if pdpte & 1 == 0 {
                continue;
            }
            let pd_base = pdpte & PAGE_PHYS_MASK;

            // Read entire PD page
            if self.phys.read_phys(pd_base, &mut table_buf).is_err() {
                continue;
            }
            let pd_buf = table_buf;

            for pd_idx in 0..512u64 {
                let pde = read_pte_from_buf(&pd_buf, pd_idx as usize);
                if pde & 1 == 0 {
                    continue;
                }
                if pde & (1 << 7) != 0 {
                    // 2MB large page
                    let vaddr = (pdpt_idx << 30) | (pd_idx << 21);
                    let paddr = pde & LARGE_2MB_MASK;
                    callback(PageMapping {
                        vaddr,
                        paddr,
                        size: 0x20_0000,
                    });
                    continue;
                }
                let pt_base = pde & PAGE_PHYS_MASK;

                // Read entire PT page
                if self.phys.read_phys(pt_base, &mut table_buf).is_err() {
                    continue;
                }

                for pt_idx in 0..512u64 {
                    let pte = PageTableEntry(read_pte_from_buf(&table_buf, pt_idx as usize));
                    if pte.is_present() || pte.is_transition() {
                        let vaddr = (pdpt_idx << 30) | (pd_idx << 21) | (pt_idx << 12);
                        let paddr = pte.frame_addr();
                        callback(PageMapping {
                            vaddr,
                            paddr,
                            size: 0x1000,
                        });
                    }
                }
            }
        }
    }
}

/// Process virtual memory for 32-bit PAE Windows processes.
/// Same pattern as `ProcessMemory` but uses `PaePageTableWalker`.
pub struct PaeProcessMemory<'a, P: PhysicalMemory> {
    phys: &'a P,
    walker: PaePageTableWalker<'a, P>,
    dtb: u64,
}

impl<'a, P: PhysicalMemory> PaeProcessMemory<'a, P> {
    pub fn new(phys: &'a P, dtb: u64) -> Self {
        Self {
            phys,
            walker: PaePageTableWalker::new(phys),
            dtb,
        }
    }
}

impl<P: PhysicalMemory> VirtualMemory for PaeProcessMemory<'_, P> {
    fn read_virt(&self, vaddr: u64, buf: &mut [u8]) -> Result<()> {
        let mut offset = 0;
        while offset < buf.len() {
            let current_vaddr = vaddr + offset as u64;
            let page_remaining = 0x1000 - (current_vaddr & 0xFFF) as usize;
            let chunk = std::cmp::min(page_remaining, buf.len() - offset);

            match self.walker.translate(self.dtb, current_vaddr) {
                Ok(phys_addr) => {
                    if self
                        .phys
                        .read_phys(phys_addr, &mut buf[offset..offset + chunk])
                        .is_err()
                    {
                        buf[offset..offset + chunk].fill(0);
                    }
                }
                Err(_) => {
                    buf[offset..offset + chunk].fill(0);
                }
            }
            offset += chunk;
        }
        Ok(())
    }
}

/// Process virtual memory: combines a DTB (CR3) with physical memory for address translation.
///
/// Optional pagefile reader resolves pages swapped to pagefile.sys on disk.
/// Optional file-backed resolver serves demand-paged DLL sections from disk.
pub struct ProcessMemory<'a, P: PhysicalMemory> {
    phys: &'a P,
    walker: PageTableWalker<'a, P>,
    dtb: u64,
    #[cfg(feature = "sam")]
    pagefile: Option<&'a crate::paging::pagefile::PagefileReader>,
    #[cfg(feature = "sam")]
    filebacked: Option<&'a crate::paging::filebacked::FileBackedResolver>,
}

impl<'a, P: PhysicalMemory> ProcessMemory<'a, P> {
    pub fn new(phys: &'a P, dtb: u64) -> Self {
        Self {
            phys,
            walker: PageTableWalker::new(phys),
            dtb,
            #[cfg(feature = "sam")]
            pagefile: None,
            #[cfg(feature = "sam")]
            filebacked: None,
        }
    }

    #[cfg(feature = "sam")]
    pub fn with_resolvers(
        phys: &'a P,
        dtb: u64,
        pagefile: Option<&'a crate::paging::pagefile::PagefileReader>,
        filebacked: Option<&'a crate::paging::filebacked::FileBackedResolver>,
    ) -> Self {
        Self {
            phys,
            walker: PageTableWalker::new(phys),
            dtb,
            pagefile,
            filebacked,
        }
    }
}

impl<P: PhysicalMemory> VirtualMemory for ProcessMemory<'_, P> {
    fn read_virt(&self, vaddr: u64, buf: &mut [u8]) -> Result<()> {
        // Handle page-crossing reads, zero-fill pages that fault (demand-paged/swapped).
        let mut offset = 0;
        while offset < buf.len() {
            let current_vaddr = vaddr + offset as u64;
            let page_remaining = 0x1000 - (current_vaddr & 0xFFF) as usize;
            let chunk = std::cmp::min(page_remaining, buf.len() - offset);

            // Use multi-level pagefile-aware translation when pagefile is available
            #[cfg(feature = "sam")]
            let translate_result = if let Some(pf) = self.pagefile {
                self.walker
                    .translate_with_pagefile(self.dtb, current_vaddr, pf)
            } else {
                self.walker.translate(self.dtb, current_vaddr)
            };
            #[cfg(not(feature = "sam"))]
            let translate_result = self.walker.translate(self.dtb, current_vaddr);

            match translate_result {
                Ok(phys_addr) => {
                    if self
                        .phys
                        .read_phys(phys_addr, &mut buf[offset..offset + chunk])
                        .is_err()
                    {
                        buf[offset..offset + chunk].fill(0);
                    }
                }
                #[cfg(feature = "sam")]
                Err(VmkatzError::PageFileFault(_vaddr, raw_pte)) => {
                    // Data page is in pagefile — resolve directly
                    if let Some(pf) = self.pagefile {
                        if let Some(page_data) = pf.resolve_pte(raw_pte) {
                            let page_off = (current_vaddr & 0xFFF) as usize;
                            buf[offset..offset + chunk]
                                .copy_from_slice(&page_data[page_off..page_off + chunk]);
                        } else {
                            buf[offset..offset + chunk].fill(0);
                        }
                    } else {
                        buf[offset..offset + chunk].fill(0);
                    }
                }
                Err(ref e) => {
                    // Try file-backed resolution for demand-paged DLL sections
                    #[cfg(feature = "sam")]
                    if let Some(fb) = self.filebacked {
                        if let Some(page_data) = fb.resolve_page(current_vaddr) {
                            let page_off = (current_vaddr & 0xFFF) as usize;
                            buf[offset..offset + chunk]
                                .copy_from_slice(&page_data[page_off..page_off + chunk]);
                            offset += chunk;
                            continue;
                        }
                    }
                    log::trace!("Page fault: {e} at VA 0x{current_vaddr:x}");
                    buf[offset..offset + chunk].fill(0);
                }
            }
            offset += chunk;
        }
        Ok(())
    }
}
