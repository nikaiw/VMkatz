use crate::error::{GovmemError, Result};
use crate::memory::{PhysicalMemory, VirtualMemory};
use crate::paging::entry::PageTableEntry;

/// 4-level x86-64 page table walker.
pub struct PageTableWalker<'a, P: PhysicalMemory> {
    phys: &'a P,
}

impl<'a, P: PhysicalMemory> PageTableWalker<'a, P> {
    pub fn new(phys: &'a P) -> Self {
        Self { phys }
    }

    /// Translate a virtual address to a physical address using the given CR3 (DTB).
    pub fn translate(&self, cr3: u64, vaddr: u64) -> Result<u64> {
        let pml4_base = cr3 & 0x000F_FFFF_FFFF_F000;

        // PML4: bits [47:39]
        let pml4_idx = (vaddr >> 39) & 0x1FF;
        let pml4e = PageTableEntry(self.phys.read_phys_u64(pml4_base + pml4_idx * 8)?);
        if !pml4e.is_present() {
            return Err(GovmemError::PageFault(vaddr, "PML4"));
        }

        // PDPT: bits [38:30]
        let pdpt_base = pml4e.frame_addr();
        let pdpt_idx = (vaddr >> 30) & 0x1FF;
        let pdpte = PageTableEntry(self.phys.read_phys_u64(pdpt_base + pdpt_idx * 8)?);
        if !pdpte.is_present() {
            return Err(GovmemError::PageFault(vaddr, "PDPT"));
        }
        if pdpte.is_large_page() {
            // 1GB huge page
            let phys = (pdpte.raw() & 0x000F_FFFF_C000_0000) | (vaddr & 0x3FFF_FFFF);
            return Ok(phys);
        }

        // PD: bits [29:21]
        let pd_base = pdpte.frame_addr();
        let pd_idx = (vaddr >> 21) & 0x1FF;
        let pde = PageTableEntry(self.phys.read_phys_u64(pd_base + pd_idx * 8)?);
        if !pde.is_present() {
            return Err(GovmemError::PageFault(vaddr, "PD"));
        }
        if pde.is_large_page() {
            // 2MB large page
            let phys = (pde.raw() & 0x000F_FFFF_FFE0_0000) | (vaddr & 0x1F_FFFF);
            return Ok(phys);
        }

        // PT: bits [20:12]
        let pt_base = pde.frame_addr();
        let pt_idx = (vaddr >> 12) & 0x1FF;
        let pte = PageTableEntry(self.phys.read_phys_u64(pt_base + pt_idx * 8)?);
        if !pte.is_present() {
            // Check for transition PTE (Windows-specific)
            if pte.is_transition() {
                return Ok(pte.frame_addr() | (vaddr & 0xFFF));
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
                return Err(GovmemError::PageFileFault(vaddr, pte.raw()));
            }
            return Err(GovmemError::PageFault(vaddr, "PT"));
        }

        Ok(pte.frame_addr() | (vaddr & 0xFFF))
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
        let pml4_base = cr3 & 0x000F_FFFF_FFFF_F000;

        // PML4: bits [47:39] — PML4 page is always resident (CR3 page)
        let pml4_idx = (vaddr >> 39) & 0x1FF;
        let pml4e = PageTableEntry(self.phys.read_phys_u64(pml4_base + pml4_idx * 8)?);
        if !pml4e.is_present() {
            // PML4E not present — try pagefile resolution for the PDPT page
            if pml4e.is_pagefile() {
                let pdpt_page = pagefile
                    .resolve_pte(pml4e.raw())
                    .ok_or(GovmemError::PageFault(vaddr, "PML4-pagefile"))?;
                return self.walk_from_pdpt(&pdpt_page, vaddr, Some(pagefile));
            }
            return Err(GovmemError::PageFault(vaddr, "PML4"));
        }

        // PDPT: bits [38:30]
        let pdpt_base = pml4e.frame_addr();
        let pdpt_idx = (vaddr >> 30) & 0x1FF;
        let pdpte = PageTableEntry(self.phys.read_phys_u64(pdpt_base + pdpt_idx * 8)?);
        if !pdpte.is_present() {
            if pdpte.is_pagefile() {
                let pd_page = pagefile
                    .resolve_pte(pdpte.raw())
                    .ok_or(GovmemError::PageFault(vaddr, "PDPT-pagefile"))?;
                return self.walk_from_pd(&pd_page, vaddr, Some(pagefile));
            }
            return Err(GovmemError::PageFault(vaddr, "PDPT"));
        }
        if pdpte.is_large_page() {
            let phys = (pdpte.raw() & 0x000F_FFFF_C000_0000) | (vaddr & 0x3FFF_FFFF);
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
                    .ok_or(GovmemError::PageFault(vaddr, "PD-pagefile"))?;
                return self.walk_from_pt(&pt_page, vaddr, Some(pagefile));
            }
            return Err(GovmemError::PageFault(vaddr, "PD"));
        }
        if pde.is_large_page() {
            let phys = (pde.raw() & 0x000F_FFFF_FFE0_0000) | (vaddr & 0x1F_FFFF);
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
                return Err(GovmemError::PageFileFault(vaddr, pte.raw()));
            }
            return Err(GovmemError::PageFault(vaddr, "PT"));
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
                        .ok_or(GovmemError::PageFault(vaddr, "PDPT-pagefile"))?;
                    return self.walk_from_pd(&pd_page, vaddr, pagefile);
                }
            }
            return Err(GovmemError::PageFault(vaddr, "PDPT"));
        }
        if pdpte.is_large_page() {
            return Ok((pdpte.raw() & 0x000F_FFFF_C000_0000) | (vaddr & 0x3FFF_FFFF));
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
                        .ok_or(GovmemError::PageFault(vaddr, "PD-pagefile"))?;
                    return self.walk_from_pt(&pt_page, vaddr, pagefile);
                }
            }
            return Err(GovmemError::PageFault(vaddr, "PD"));
        }
        if pde.is_large_page() {
            return Ok((pde.raw() & 0x000F_FFFF_FFE0_0000) | (vaddr & 0x1F_FFFF));
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
                        .ok_or(GovmemError::PageFault(vaddr, "PD-pagefile"))?;
                    return self.walk_from_pt(&pt_page, vaddr, pagefile);
                }
            }
            return Err(GovmemError::PageFault(vaddr, "PD"));
        }
        if pde.is_large_page() {
            return Ok((pde.raw() & 0x000F_FFFF_FFE0_0000) | (vaddr & 0x1F_FFFF));
        }

        let pt_base = pde.frame_addr();
        self.walk_pt_level(pt_base, vaddr, pagefile)
    }

    /// Continue page table walk from a resolved PT page (in-memory buffer).
    #[cfg(feature = "sam")]
    fn walk_from_pt(
        &self,
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
                return Err(GovmemError::PageFileFault(vaddr, pte.raw()));
            }
            return Err(GovmemError::PageFault(vaddr, "PT"));
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
                return Err(GovmemError::PageFileFault(vaddr, pte.raw()));
            }
            // If physical read returned zero and we have pagefile, the PT page
            // itself might have been repurposed — try resolving the PDE from pagefile.
            // But we don't have the PDE at this point, so just report fault.
            let _ = pagefile;
            return Err(GovmemError::PageFault(vaddr, "PT"));
        }
        Ok(pte.frame_addr() | (vaddr & 0xFFF))
    }
}

/// A mapping from virtual address to physical address for a present page.
pub struct PageMapping {
    pub vaddr: u64,
    pub paddr: u64,
    pub size: u64, // 4KB, 2MB, or 1GB
}

impl<'a, P: PhysicalMemory> PageTableWalker<'a, P> {
    /// Enumerate all present user-mode pages for a given CR3.
    /// Calls the callback for each present page mapping.
    pub fn enumerate_present_pages<F>(&self, cr3: u64, mut callback: F)
    where
        F: FnMut(PageMapping),
    {
        let pml4_base = cr3 & 0x000F_FFFF_FFFF_F000;

        // Only scan user-mode half (PML4 entries 0-255)
        for pml4_idx in 0..256u64 {
            let pml4e_addr = pml4_base + pml4_idx * 8;
            let pml4e = match self.phys.read_phys_u64(pml4e_addr) {
                Ok(v) => PageTableEntry(v),
                Err(_) => continue,
            };
            if !pml4e.is_present() {
                continue;
            }

            let pdpt_base = pml4e.frame_addr();
            for pdpt_idx in 0..512u64 {
                let pdpte = match self.phys.read_phys_u64(pdpt_base + pdpt_idx * 8) {
                    Ok(v) => PageTableEntry(v),
                    Err(_) => continue,
                };
                if !pdpte.is_present() {
                    continue;
                }
                if pdpte.is_large_page() {
                    let vaddr = (pml4_idx << 39) | (pdpt_idx << 30);
                    let paddr = pdpte.raw() & 0x000F_FFFF_C000_0000;
                    callback(PageMapping {
                        vaddr,
                        paddr,
                        size: 0x4000_0000,
                    });
                    continue;
                }

                let pd_base = pdpte.frame_addr();
                for pd_idx in 0..512u64 {
                    let pde = match self.phys.read_phys_u64(pd_base + pd_idx * 8) {
                        Ok(v) => PageTableEntry(v),
                        Err(_) => continue,
                    };
                    if !pde.is_present() {
                        continue;
                    }
                    if pde.is_large_page() {
                        let vaddr = (pml4_idx << 39) | (pdpt_idx << 30) | (pd_idx << 21);
                        let paddr = pde.raw() & 0x000F_FFFF_FFE0_0000;
                        callback(PageMapping {
                            vaddr,
                            paddr,
                            size: 0x20_0000,
                        });
                        continue;
                    }

                    let pt_base = pde.frame_addr();
                    for pt_idx in 0..512u64 {
                        let pte = match self.phys.read_phys_u64(pt_base + pt_idx * 8) {
                            Ok(v) => PageTableEntry(v),
                            Err(_) => continue,
                        };
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

/// Process virtual memory: combines a DTB (CR3) with physical memory for address translation.
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

    pub fn dtb(&self) -> u64 {
        self.dtb
    }

    pub fn phys(&self) -> &'a P {
        self.phys
    }

    pub fn translate(&self, vaddr: u64) -> Result<u64> {
        self.walker.translate(self.dtb, vaddr)
    }
}

impl<'a, P: PhysicalMemory> VirtualMemory for ProcessMemory<'a, P> {
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
                Err(GovmemError::PageFileFault(_vaddr, raw_pte)) => {
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
                    log::trace!("Page fault: {} at VA 0x{:x}", e, current_vaddr);
                    buf[offset..offset + chunk].fill(0);
                }
            }
            offset += chunk;
        }
        Ok(())
    }
}
