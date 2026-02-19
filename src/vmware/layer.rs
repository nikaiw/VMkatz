use std::fs;
use std::path::Path;

use memmap2::Mmap;

use crate::error::{GovmemError, Result};
use crate::memory::PhysicalMemory;
use crate::vmware::header::{self, PAGE_SIZE};
use crate::vmware::tags::{self, Tag};

/// A memory region mapping guest physical pages to VMEM file offsets.
#[derive(Debug, Clone, Copy)]
pub struct MemoryRegion {
    /// Starting guest physical page number.
    pub guest_page_num: u64,
    /// Corresponding VMEM file page number (PPN).
    pub vmem_page_num: u64,
    /// Number of pages in this region.
    pub page_count: u64,
}

/// VMware memory layer: provides physical memory access from .vmsn + .vmem files.
pub struct VmwareLayer {
    mmap: Mmap,
    pub regions: Vec<MemoryRegion>,
    pub tags: Vec<Tag>,
    pub group_names: Vec<String>,
}

impl VmwareLayer {
    /// Open a VMware memory dump. Accepts either a .vmem or .vmsn file path.
    /// For .vmem: looks for a matching .vmsn for region info, falls back to identity mapping.
    /// For .vmsn: derives the .vmem path (existing behavior).
    pub fn open(path: &Path) -> Result<Self> {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        let (vmem_path, regions, all_tags, group_names) = if ext.eq_ignore_ascii_case("vmem") {
            let vmem_path = path.to_path_buf();
            let vmsn_path = path.with_extension("vmsn");

            if vmsn_path.exists() {
                let (regions, tags, groups) = Self::parse_vmsn_metadata(&vmsn_path)?;
                (vmem_path, regions, tags, groups)
            } else {
                // Identity mapping: no .vmsn available
                let vmem_file_size = fs::metadata(&vmem_path)?.len();
                let regions = vec![MemoryRegion {
                    guest_page_num: 0,
                    vmem_page_num: 0,
                    page_count: vmem_file_size / PAGE_SIZE as u64,
                }];
                log::info!(
                    "No .vmsn found, using identity mapping ({} pages)",
                    regions[0].page_count
                );
                (vmem_path, regions, Vec::new(), Vec::new())
            }
        } else {
            // .vmsn path: derive .vmem (existing behavior)
            let vmem_path = path.with_extension("vmem");
            if !vmem_path.exists() {
                return Err(GovmemError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("VMEM file not found: {}", vmem_path.display()),
                )));
            }
            let (regions, tags, groups) = Self::parse_vmsn_metadata(path)?;
            (vmem_path, regions, tags, groups)
        };

        // Memory-map the VMEM file
        let vmem_file = fs::File::open(&vmem_path)?;
        let mmap = unsafe { Mmap::map(&vmem_file)? };
        log::info!(
            "VMEM mapped: {} bytes ({} MB)",
            mmap.len(),
            mmap.len() / (1024 * 1024)
        );

        // Fall back to identity mapping when VMSN has no region tags
        // (older VMware snapshots or snapshots without explicit region metadata)
        let regions = if regions.is_empty() {
            let page_count = mmap.len() as u64 / PAGE_SIZE as u64;
            log::info!(
                "No memory regions in VMSN, using identity mapping ({} pages)",
                page_count
            );
            vec![MemoryRegion {
                guest_page_num: 0,
                vmem_page_num: 0,
                page_count,
            }]
        } else {
            regions
        };

        Ok(Self {
            mmap,
            regions,
            tags: all_tags,
            group_names,
        })
    }

    /// Parse a .vmsn file and return (regions, tags, group_names).
    fn parse_vmsn_metadata(vmsn_path: &Path) -> Result<(Vec<MemoryRegion>, Vec<Tag>, Vec<String>)> {
        let vmsn_data = fs::read(vmsn_path)?;

        let (hdr, groups) = header::parse_vmsn(&vmsn_data)?;
        log::info!(
            "VMSN: magic=0x{:08x}, groups={}",
            hdr.magic,
            hdr.group_count
        );

        let group_names: Vec<String> = groups.iter().map(|g| g.name.clone()).collect();

        let memory_group = groups
            .iter()
            .find(|g| g.name == "memory")
            .ok_or_else(|| GovmemError::GroupNotFound("memory".to_string()))?;

        log::info!(
            "Memory group: offset=0x{:x}, size=0x{:x}",
            memory_group.offset,
            memory_group.size
        );

        let tag_start = memory_group.offset as usize;
        let tag_end = tag_start + memory_group.size as usize;
        let tag_data = &vmsn_data[tag_start..tag_end.min(vmsn_data.len())];
        let all_tags = tags::parse_tags(tag_data, memory_group.offset)?;

        log::info!("Parsed {} tags", all_tags.len());
        for tag in &all_tags {
            log::debug!(
                "  tag: {} {:?} offset=0x{:x} size=0x{:x}",
                tag.name,
                tag.indices,
                tag.data_offset,
                tag.data_size
            );
        }

        let regions_count = tags::find_tag(&all_tags, "regionsCount", &[])
            .map(|t| {
                let off = t.data_offset as usize;
                u32::from_le_bytes(vmsn_data[off..off + 4].try_into().unwrap())
            })
            .unwrap_or(0);

        log::info!("Memory regions: {}", regions_count);

        let mut regions = Vec::with_capacity(regions_count as usize);
        for i in 0..regions_count {
            let vmem_page = tags::find_tag(&all_tags, "regionPageNum", &[i])
                .map(|t| {
                    let off = t.data_offset as usize;
                    u32::from_le_bytes(vmsn_data[off..off + 4].try_into().unwrap()) as u64
                })
                .unwrap_or(0);

            let guest_page = tags::find_tag(&all_tags, "regionPPN", &[i])
                .map(|t| {
                    let off = t.data_offset as usize;
                    u32::from_le_bytes(vmsn_data[off..off + 4].try_into().unwrap()) as u64
                })
                .unwrap_or(0);

            let page_count = tags::find_tag(&all_tags, "regionSize", &[i])
                .map(|t| {
                    let off = t.data_offset as usize;
                    u32::from_le_bytes(vmsn_data[off..off + 4].try_into().unwrap()) as u64
                })
                .unwrap_or(0);

            log::info!(
                "  Region {}: guest_phys=0x{:x} vmem_file=0x{:x} pages=0x{:x} ({}MB)",
                i,
                guest_page,
                vmem_page,
                page_count,
                (page_count * PAGE_SIZE as u64) / (1024 * 1024)
            );

            regions.push(MemoryRegion {
                guest_page_num: guest_page,
                vmem_page_num: vmem_page,
                page_count,
            });
        }

        Ok((regions, all_tags, group_names))
    }

    /// Translate a guest physical address to a byte offset in the VMEM mmap.
    fn guest_phys_to_vmem_offset(&self, phys_addr: u64) -> Result<usize> {
        let page_num = phys_addr / PAGE_SIZE as u64;
        let page_offset = phys_addr % PAGE_SIZE as u64;

        for region in &self.regions {
            if page_num >= region.guest_page_num
                && page_num < region.guest_page_num + region.page_count
            {
                let vmem_page = page_num - region.guest_page_num + region.vmem_page_num;
                let offset = vmem_page * PAGE_SIZE as u64 + page_offset;
                return Ok(offset as usize);
            }
        }

        Err(GovmemError::UnmappablePhysical(phys_addr))
    }
}

impl VmwareLayer {
    /// Get a reference to the raw VMEM mmap for direct scanning.
    pub fn raw_mmap(&self) -> &[u8] {
        &self.mmap
    }

    /// Convert a VMEM file offset to a guest physical address.
    pub fn vmem_offset_to_guest_phys(&self, vmem_offset: u64) -> Option<u64> {
        let vmem_page = vmem_offset / PAGE_SIZE as u64;
        let page_offset = vmem_offset % PAGE_SIZE as u64;
        for region in &self.regions {
            if vmem_page >= region.vmem_page_num
                && vmem_page < region.vmem_page_num + region.page_count
            {
                let guest_page = vmem_page - region.vmem_page_num + region.guest_page_num;
                return Some(guest_page * PAGE_SIZE as u64 + page_offset);
            }
        }
        None
    }

    /// Maximum guest physical address across all regions.
    pub fn max_guest_phys(&self) -> u64 {
        self.regions
            .iter()
            .map(|r| (r.guest_page_num + r.page_count) * PAGE_SIZE as u64)
            .max()
            .unwrap_or(0)
    }
}

impl PhysicalMemory for VmwareLayer {
    fn read_phys(&self, phys_addr: u64, buf: &mut [u8]) -> Result<()> {
        let offset = self.guest_phys_to_vmem_offset(phys_addr)?;
        let end = offset + buf.len();
        if end > self.mmap.len() {
            return Err(GovmemError::UnmappablePhysical(phys_addr));
        }
        buf.copy_from_slice(&self.mmap[offset..end]);
        Ok(())
    }

    fn phys_size(&self) -> u64 {
        self.max_guest_phys()
    }
}
