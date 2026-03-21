//! QEMU/KVM/Proxmox ELF core dump reader.
//!
//! Reads ELF64 core dumps produced by:
//!   - `dump-guest-memory` in QEMU monitor
//!   - `virsh dump <domain> <file> --memory-only`
//!   - Proxmox: `qm monitor <VMID>` then `dump-guest-memory`
//!
//! The file contains PT_LOAD segments with p_paddr = guest physical address.

use std::fs;
use std::path::Path;


use crate::error::{VmkatzError, Result};
use crate::memory::PhysicalMemory;

const PAGE_SIZE: u64 = 4096;

// ELF64 constants
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1; // little-endian
const ET_CORE: u16 = 4;
const PT_LOAD: u32 = 1;
const ELF64_EHDR_SIZE: usize = 64;
const ELF64_PHDR_SIZE: usize = 56;

/// A PT_LOAD segment: maps guest physical address range to file offset.
#[derive(Debug, Clone, Copy)]
struct LoadSegment {
    /// File offset where segment data starts.
    file_offset: u64,
    /// Guest physical address (from p_paddr).
    gpa_start: u64,
    /// Size of data in file (p_filesz).
    file_size: u64,
}

/// QEMU ELF core dump memory layer.
pub struct QemuElfLayer {
    mmap: crate::utils::MappedFile,
    segments: Vec<LoadSegment>,
    phys_end: u64,
}

impl QemuElfLayer {
    /// Open a QEMU ELF core dump file (.elf or any extension).
    pub fn open(path: &Path) -> Result<Self> {
        let file = fs::File::open(path)?;
        let mmap = crate::utils::mmap_file(&file)?;

        if mmap.len() < ELF64_EHDR_SIZE {
            return Err(VmkatzError::InvalidMagic(0));
        }

        // For pread fallback: read the ELF header + program headers (first 1MB covers it)
        let header_buf: Vec<u8>;
        let data: &[u8] = if mmap.is_pread() {
            header_buf = crate::utils::read_file_header(&file, 1024 * 1024)?;
            &header_buf
        } else {
            mmap.as_bytes()
        };
        if data[0..4] != ELF_MAGIC {
            return Err(VmkatzError::InvalidMagic(u32::from_le_bytes([
                data[0], data[1], data[2], data[3],
            ])));
        }
        if data[4] != ELFCLASS64 {
            return Err(VmkatzError::ElfError(
                "Not ELF64 (only 64-bit supported)".into(),
            ));
        }
        if data[5] != ELFDATA2LSB {
            return Err(VmkatzError::ElfError("Not little-endian ELF".into()));
        }

        let e_type = u16::from_le_bytes([data[16], data[17]]);
        if e_type != ET_CORE {
            return Err(VmkatzError::ElfError(
                format!("ELF type {} is not ET_CORE (expected {})", e_type, ET_CORE),
            ));
        }

        let e_phoff = u64::from_le_bytes(data[32..40].try_into().unwrap());
        let e_phentsize = u16::from_le_bytes([data[54], data[55]]) as usize;
        let e_phnum = u16::from_le_bytes([data[56], data[57]]) as usize;

        if e_phentsize < ELF64_PHDR_SIZE {
            return Err(VmkatzError::ElfError(
                format!(
                    "ELF phdr size {} < expected {}",
                    e_phentsize, ELF64_PHDR_SIZE
                ),
            ));
        }

        // Parse program headers, collect PT_LOAD segments
        let mut segments = Vec::new();
        let mut phys_end: u64 = 0;

        for i in 0..e_phnum {
            let Some(off) = (e_phoff as usize).checked_add(i.saturating_mul(e_phentsize)) else {
                break;
            };
            if off + ELF64_PHDR_SIZE > data.len() {
                break;
            }
            let ph = &data[off..off + ELF64_PHDR_SIZE];

            let p_type = u32::from_le_bytes(ph[0..4].try_into().unwrap());
            if p_type != PT_LOAD {
                continue;
            }

            let p_offset = u64::from_le_bytes(ph[8..16].try_into().unwrap());
            let p_paddr = u64::from_le_bytes(ph[24..32].try_into().unwrap());
            let p_filesz = u64::from_le_bytes(ph[32..40].try_into().unwrap());

            if p_filesz == 0 {
                continue;
            }

            let seg_end = p_paddr.saturating_add(p_filesz);
            if seg_end > phys_end {
                phys_end = seg_end;
            }

            segments.push(LoadSegment {
                file_offset: p_offset,
                gpa_start: p_paddr,
                file_size: p_filesz,
            });
        }

        if segments.is_empty() {
            return Err(VmkatzError::ElfError(
                "No PT_LOAD segments found in ELF".into(),
            ));
        }

        // Sort by GPA for binary search
        segments.sort_by_key(|s| s.gpa_start);

        // Align phys_end to page boundary
        phys_end = (phys_end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

        log::info!(
            "QEMU ELF: {} PT_LOAD segments, physical end: 0x{:x} ({} MB)",
            segments.len(),
            phys_end,
            phys_end / (1024 * 1024)
        );

        Ok(Self {
            mmap,
            segments,
            phys_end,
        })
    }

    /// Number of PT_LOAD segments.
    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    /// Find the segment containing the given GPA using binary search.
    fn find_segment(&self, gpa: u64) -> Option<&LoadSegment> {
        let idx = self.segments.partition_point(|s| s.gpa_start <= gpa);
        if idx == 0 {
            return None;
        }
        let seg = &self.segments[idx - 1];
        if gpa < seg.gpa_start + seg.file_size {
            Some(seg)
        } else {
            None
        }
    }
}

impl PhysicalMemory for QemuElfLayer {
    fn read_phys(&self, phys_addr: u64, buf: &mut [u8]) -> Result<()> {
        let len = buf.len() as u64;
        if len == 0 {
            return Ok(());
        }

        // Fast path: entire read fits in one segment
        if let Some(seg) = self.find_segment(phys_addr) {
            let offset_in_seg = phys_addr - seg.gpa_start;
            let avail = seg.file_size - offset_in_seg;
            if avail >= len {
                let file_off = (seg.file_offset + offset_in_seg) as usize;
                let end = file_off + buf.len();
                if end <= self.mmap.len() {
                    self.mmap.read_at(file_off, buf)
                        .map_err(|_| VmkatzError::UnmappablePhysical(phys_addr))?;
                    return Ok(());
                }
            }
        }

        // Slow path: read may span segments or hit unmapped regions
        // Fill with zeros first, then overlay mapped data
        buf.fill(0);
        let mut pos = 0u64;
        while pos < len {
            let cur_gpa = phys_addr + pos;
            if let Some(seg) = self.find_segment(cur_gpa) {
                let offset_in_seg = cur_gpa - seg.gpa_start;
                let avail = seg.file_size - offset_in_seg;
                let to_copy = std::cmp::min(avail, len - pos) as usize;
                let file_off = (seg.file_offset + offset_in_seg) as usize;
                let end = file_off + to_copy;
                if end <= self.mmap.len() {
                    let dst_start = pos as usize;
                    let _ = self.mmap.read_at(file_off, &mut buf[dst_start..dst_start + to_copy]);
                }
                pos += to_copy as u64;
            } else {
                // Skip to next segment or end
                let next_seg_start = self
                    .segments
                    .iter()
                    .find(|s| s.gpa_start > cur_gpa)
                    .map(|s| s.gpa_start);
                match next_seg_start {
                    Some(next) => {
                        let skip = std::cmp::min(next - cur_gpa, len - pos);
                        pos += skip;
                    }
                    None => break, // No more segments
                }
            }
        }

        Ok(())
    }

    fn phys_size(&self) -> u64 {
        self.phys_end
    }
}
