use std::fs;
use std::io::Read;
use std::path::Path;

use memmap2::Mmap;

use crate::error::{VmkatzError, Result};
use crate::memory::PhysicalMemory;
use crate::vmware::header::{self, PAGE_SIZE};
use crate::vmware::tags::{self, Tag};

/// File-backed memory: mmap when possible, heap-allocated Vec<u8> fallback
/// for platforms where mmap fails (e.g. VMFS-5 on ESXi 6.5).
enum MappedFile {
    Mmap(Mmap),
    Vec(Vec<u8>),
}

impl MappedFile {
    fn len(&self) -> usize {
        match self {
            MappedFile::Mmap(m) => m.len(),
            MappedFile::Vec(v) => v.len(),
        }
    }
}

impl std::ops::Deref for MappedFile {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            MappedFile::Mmap(m) => m,
            MappedFile::Vec(v) => v,
        }
    }
}

/// Try to mmap a file, falling back to read() into Vec<u8> if mmap fails.
/// This handles platforms where mmap is unsupported (VMFS-5, older ESXi kernels).
fn map_file(file: &mut fs::File) -> Result<MappedFile> {
    match unsafe { Mmap::map(&*file) } {
        Ok(m) => Ok(MappedFile::Mmap(m)),
        Err(mmap_err) => {
            // mmap failed — fall back to reading entire file into memory
            let size = file.metadata()?.len() as usize;
            eprintln!(
                "[*] mmap failed ({}), reading file into memory ({:.1} MB)...",
                mmap_err,
                size as f64 / (1024.0 * 1024.0)
            );
            let mut buf = Vec::with_capacity(size);
            use std::io::Seek;
            file.seek(std::io::SeekFrom::Start(0))?;
            file.read_to_end(&mut buf)?;
            Ok(MappedFile::Vec(buf))
        }
    }
}

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
    data: MappedFile,
    pub regions: Vec<MemoryRegion>,
    truncated: bool,
    /// Byte offset within the data where guest physical memory starts.
    /// Non-zero when memory is embedded in a .vmss/.vmsn file (after header/tags).
    base_offset: u64,
}

impl VmwareLayer {
    /// Open a VMware memory dump. Accepts .vmem, .vmsn, or .vmss file path.
    /// For .vmem: looks for a matching .vmsn for region info, falls back to identity mapping.
    /// For .vmsn/.vmss: uses separate .vmem if available, otherwise reads embedded memory.
    pub fn open(path: &Path) -> Result<Self> {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        let (vmem_path, regions, all_tags) = if ext.eq_ignore_ascii_case("vmem") {
            let vmem_path = path.to_path_buf();
            let vmsn_path = path.with_extension("vmsn");

            if vmsn_path.exists() {
                let (regions, tags) = Self::parse_vmsn_metadata(&vmsn_path)?;
                (vmem_path, regions, tags)
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
                (vmem_path, regions, Vec::new())
            }
        } else {
            // .vmsn/.vmss path: prefer separate .vmem, fall back to embedded memory
            let vmem_path = path.with_extension("vmem");
            let (regions, tags) = Self::parse_vmsn_metadata(path)?;
            if vmem_path.exists() {
                (vmem_path, regions, tags)
            } else {
                // Memory is embedded in the .vmsn/.vmss file itself
                log::info!("No separate .vmem file, using embedded memory from {}", path.display());
                (path.to_path_buf(), regions, tags)
            }
        };

        // Memory-map the VMEM file (falls back to read() on platforms without mmap)
        let mut vmem_file = fs::File::open(&vmem_path)?;
        let data = map_file(&mut vmem_file)?;
        log::info!(
            "VMEM loaded: {} bytes ({} MB)",
            data.len(),
            data.len() / (1024 * 1024)
        );

        // When memory is embedded in .vmsn (no separate .vmem), base_offset marks
        // where guest physical memory data starts in the file. For separate .vmem
        // files, pages start at file offset 0 so base_offset = 0.
        let embedded = !path.with_extension("vmem").exists();
        let base_offset: u64 = if embedded {
            // Find the Memory tag to get the base offset of RAM data
            let mem_tag = all_tags.iter().find(|t| t.name == "Memory");
            if let Some(tag) = mem_tag {
                let align_mask = tags::find_tag(&all_tags, "align_mask", &[0, 0])
                    .and_then(|t| {
                        let off = t.data_offset as usize;
                        if off + 4 <= data.len() {
                            Some(crate::utils::read_u32_le(&data, off).unwrap_or(0) as u64)
                        } else {
                            None
                        }
                    })
                    .unwrap_or(0xFFF);
                let offset = (tag.data_offset + align_mask) & !align_mask;
                log::info!("Embedded memory base offset: 0x{:x}", offset);
                offset
            } else {
                0
            }
        } else {
            0
        };
        let regions = if regions.is_empty() {
            // No region tags — create a single identity-mapped region
            let page_count = if embedded && base_offset > 0 {
                // Embedded: available memory = file size - base_offset
                (data.len() as u64 - base_offset) / PAGE_SIZE as u64
            } else {
                data.len() as u64 / PAGE_SIZE as u64
            };
            log::info!("No memory regions in VMSN, using identity mapping ({} pages)", page_count);
            vec![MemoryRegion {
                guest_page_num: 0,
                vmem_page_num: 0,
                page_count,
            }]
        } else {
            regions
        };

        // Warn if VMEM file is truncated (e.g. partial download)
        let expected_pages: u64 = regions
            .iter()
            .map(|r| r.vmem_page_num + r.page_count)
            .max()
            .unwrap_or(0);
        let expected_size = expected_pages * PAGE_SIZE as u64 + base_offset;
        let actual_size = data.len() as u64;
        if actual_size < expected_size {
            eprintln!(
                "[!] WARNING: VMEM file is truncated ({:.1} GB / {:.1} GB expected) — results may be incomplete",
                actual_size as f64 / (1024.0 * 1024.0 * 1024.0),
                expected_size as f64 / (1024.0 * 1024.0 * 1024.0),
            );
        }

        let truncated = actual_size < expected_size;

        Ok(Self {
            data,
            regions,
            truncated,
            base_offset,
        })
    }

    /// Parse a .vmsn file and return (regions, tags).
    fn parse_vmsn_metadata(vmsn_path: &Path) -> Result<(Vec<MemoryRegion>, Vec<Tag>)> {
        // Try mmap first, fall back to read() for platforms without mmap support.
        let mut vmsn_file = fs::File::open(vmsn_path)?;
        let vmsn_data = map_file(&mut vmsn_file)?;

        let (hdr, groups) = header::parse_vmsn(&vmsn_data)?;
        log::info!(
            "VMSN: magic=0x{:08x}, groups={}",
            hdr.magic,
            hdr.group_count
        );

        let memory_group = groups
            .iter()
            .find(|g| g.name == "memory")
            .ok_or(VmkatzError::GroupNotFound("memory"))?;

        log::info!(
            "Memory group: offset=0x{:x}, size=0x{:x}",
            memory_group.offset,
            memory_group.size
        );

        let tag_start = memory_group.offset as usize;
        let tag_end = tag_start.saturating_add(memory_group.size as usize);
        if tag_start > vmsn_data.len() {
            return Err(VmkatzError::GroupNotFound("memory group offset beyond file"));
        }
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
                crate::utils::read_u32_le(&vmsn_data, off).unwrap_or(0)
            })
            .unwrap_or(0);

        log::info!("Memory regions: {}", regions_count);

        // Cap allocation: regions_count comes from tag data and could be forged
        let mut regions = Vec::with_capacity((regions_count as usize).min(4096));
        for i in 0..regions_count {
            let vmem_page = tags::find_tag(&all_tags, "regionPageNum", &[i])
                .map(|t| {
                    let off = t.data_offset as usize;
                    crate::utils::read_u32_le(&vmsn_data, off).unwrap_or(0) as u64
                })
                .unwrap_or(0);

            let guest_page = tags::find_tag(&all_tags, "regionPPN", &[i])
                .map(|t| {
                    let off = t.data_offset as usize;
                    crate::utils::read_u32_le(&vmsn_data, off).unwrap_or(0) as u64
                })
                .unwrap_or(0);

            let page_count = tags::find_tag(&all_tags, "regionSize", &[i])
                .map(|t| {
                    let off = t.data_offset as usize;
                    crate::utils::read_u32_le(&vmsn_data, off).unwrap_or(0) as u64
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

        regions.sort_by_key(|r| r.guest_page_num);

        Ok((regions, all_tags))
    }

    /// Translate a guest physical address to a byte offset in the VMEM data.
    fn guest_phys_to_vmem_offset(&self, phys_addr: u64) -> Result<usize> {
        let page_num = phys_addr / PAGE_SIZE as u64;
        let page_offset = phys_addr % PAGE_SIZE as u64;

        // Regions are sorted by guest_page_num; use binary search.
        let idx = self.regions.partition_point(|r| r.guest_page_num + r.page_count <= page_num);
        if let Some(region) = self.regions.get(idx) {
            if page_num >= region.guest_page_num && page_num < region.guest_page_num + region.page_count {
                let vmem_page = page_num - region.guest_page_num + region.vmem_page_num;
                let offset = vmem_page * PAGE_SIZE as u64 + page_offset + self.base_offset;
                return Ok(offset as usize);
            }
        }

        Err(VmkatzError::UnmappablePhysical(phys_addr))
    }
}

impl VmwareLayer {
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
        if end > self.data.len() {
            return Err(VmkatzError::UnmappablePhysical(phys_addr));
        }
        buf.copy_from_slice(&self.data[offset..end]);
        Ok(())
    }

    fn phys_size(&self) -> u64 {
        self.max_guest_phys()
    }

    fn is_truncated(&self) -> bool {
        self.truncated
    }
}
