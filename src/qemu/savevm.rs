//! QEMU/KVM/Proxmox savevm state reader.
//!
//! Parses the QEMU migration stream format used by:
//!   - `qm snapshot <VMID> <name> --vmstate 1` on Proxmox
//!   - `savevm` in QEMU monitor
//!   - Proxmox VM state stored in LVM thin volumes
//!
//! The format stores RAM as a stream of page entries (4KB each):
//!   - PAGE entries: 4096 bytes of raw guest physical memory
//!   - ZERO entries: page filled with a single byte value (usually 0x00)
//!
//! Non-RAM device state sections (CPU, PIC, etc.) are skipped.

use std::fs;
use std::path::Path;


use crate::error::{VmkatzError, Result};
use crate::memory::PhysicalMemory;

const PAGE_SIZE: usize = 4096;

// File header
const QEVM_MAGIC: u32 = 0x5145_564D; // "QEVM" big-endian

// Outer section types
const QEMU_VM_EOF: u8 = 0x00;
const QEMU_VM_SECTION_START: u8 = 0x01;
const QEMU_VM_SECTION_PART: u8 = 0x02;
const QEMU_VM_SECTION_END: u8 = 0x03;
const QEMU_VM_SECTION_FULL: u8 = 0x04;
const QEMU_VM_CONFIGURATION: u8 = 0x07;
const QEMU_VM_SECTION_FOOTER: u8 = 0x7E;

// RAM save flags (low 12 bits of addr|flags u64 BE)
const RAM_SAVE_FLAG_ZERO: u64 = 0x002;
const RAM_SAVE_FLAG_MEM_SIZE: u64 = 0x004;
const RAM_SAVE_FLAG_PAGE: u64 = 0x008;
const RAM_SAVE_FLAG_EOS: u64 = 0x010;
const RAM_SAVE_FLAG_CONTINUE: u64 = 0x020;

/// Mask to extract flags from the addr|flags u64 (low 12 bits, page-aligned).
const RAM_FLAG_MASK: u64 = 0xFFF;
const RAM_SAVE_FLAG_COMPRESS_PAGE: u64 = 0x100;

/// A mapped RAM page: GPA → file offset of its 4096 bytes.
#[derive(Clone, Copy)]
struct MappedPage {
    /// Guest physical address (page-aligned).
    gpa: u64,
    /// Offset in the mmap where the 4096-byte page data lives.
    file_offset: u64,
}

/// A RAM block described in the MEM_SIZE header.
#[derive(Debug)]
#[allow(dead_code)]
struct RamBlock {
    name: String,
    size: u64,
}

/// QEMU savevm state memory layer.
pub struct QemuSavevmLayer {
    mmap: crate::utils::MappedFile,
    /// Sorted by GPA for binary search.
    pages: Vec<MappedPage>,
    /// Total physical address space (max GPA of pc.ram block).
    phys_end: u64,
}

impl QemuSavevmLayer {
    /// Open a QEMU savevm state file.
    /// Supports both regular files and block devices (LVM volumes on Proxmox).
    pub fn open(path: &Path) -> Result<Self> {
        let file = fs::File::open(path)?;
        let mmap = crate::utils::mmap_file(&file)?;

        if mmap.len() < 16 {
            return Err(VmkatzError::InvalidMagic(0));
        }

        // parse_ram_stream needs slice access to the entire file — pread fallback
        // would be too slow (millions of small reads). Require mmap.
        if mmap.is_pread() {
            return Err(io_err(
                "QEMU savevm requires mmap support (file I/O fallback too slow for stream parsing)".to_string()
            ));
        }
        let data = mmap.as_bytes();

        // Verify magic
        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if magic != QEVM_MAGIC {
            return Err(VmkatzError::InvalidMagic(magic));
        }
        let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if version < 3 {
            return Err(io_err(format!(
                "Unsupported QEMU savevm version {} (expected >= 3)", version
            )));
        }

        log::info!("QEMU savevm: version {}, file size {} MB", version, mmap.len() / (1024 * 1024));

        // Parse the stream to find RAM section and build page index
        let (pages, phys_end) = Self::parse_ram_stream(data)?;

        log::info!(
            "QEMU savevm: {} mapped pages ({} MB), phys_end=0x{:x}",
            pages.len(),
            pages.len() * PAGE_SIZE / (1024 * 1024),
            phys_end
        );

        Ok(Self { mmap, pages, phys_end })
    }

    /// Parse the entire savevm stream and extract RAM page locations.
    fn parse_ram_stream(data: &[u8]) -> Result<(Vec<MappedPage>, u64)> {
        let mut offset = 8usize; // skip magic + version
        let len = data.len();
        let mut ram_section_id: Option<u32> = None;
        let mut pages: Vec<MappedPage> = Vec::new();
        let mut ram_blocks: Vec<RamBlock> = Vec::new();
        let mut phys_end: u64 = 0;
        let mut below_4g: u64 = 0;
        let mut current_block_idx: usize = 0;
        let mut block_gpa_bases: Vec<u64> = Vec::new();

        while offset < len.saturating_sub(8) {
            let section_type = data[offset];
            offset += 1;

            match section_type {
                QEMU_VM_CONFIGURATION => {
                    if offset + 4 > len { break; }
                    let clen = read_be_u32(data, offset) as usize;
                    offset += 4 + clen;
                }
                QEMU_VM_SECTION_START | QEMU_VM_SECTION_FULL => {
                    if offset + 4 > len { break; }
                    let sid = read_be_u32(data, offset);
                    offset += 4;
                    let (name, new_off) = read_string(data, offset)?;
                    offset = new_off;
                    offset += 8; // instance_id(4) + version_id(4)

                    if name == "ram" {
                        ram_section_id = Some(sid);
                        // Parse MEM_SIZE + block list + EOS
                        offset = Self::parse_ram_setup(data, offset, &mut ram_blocks, &mut block_gpa_bases, &mut phys_end, &mut below_4g)?;
                    } else {
                        // Non-RAM device (dirty-bitmap, cpu, etc.) — skip by scanning
                        // forward for the next outer section marker we can recognize.
                        log::debug!("QEMU savevm: skipping non-RAM device '{}' at 0x{:x}", name, offset);
                        if let Some(next) = Self::scan_for_next_section(data, offset, ram_section_id) {
                            log::debug!("QEMU savevm: found next RAM section at 0x{:x}", next);
                            offset = next;
                        } else {
                            break;
                        }
                    }
                }
                QEMU_VM_SECTION_PART => {
                    if offset + 4 > len { break; }
                    let sid = read_be_u32(data, offset);
                    offset += 4;

                    if ram_section_id == Some(sid) {
                        offset = Self::parse_ram_pages(data, offset, &ram_blocks, &mut pages, &mut current_block_idx, below_4g)?;
                    } else {
                        // Non-RAM section part — scan forward for next recognizable marker
                        log::debug!("QEMU savevm: skipping non-RAM SECTION_PART id={} at 0x{:x}", sid, offset);
                        if let Some(next) = Self::scan_for_next_section(data, offset, ram_section_id) {
                            offset = next;
                        } else {
                            break;
                        }
                    }
                }
                QEMU_VM_SECTION_FOOTER => {
                    offset += 4; // section_id
                }
                QEMU_VM_SECTION_END => {
                    offset += 4; // section_id
                }
                QEMU_VM_EOF => {
                    break;
                }
                _ => {
                    // Unknown section type — try scanning forward for next RAM section
                    log::debug!("QEMU savevm: unknown section type 0x{:02x} at 0x{:x}, scanning", section_type, offset - 1);
                    if let Some(next) = Self::scan_for_next_section(data, offset, ram_section_id) {
                        offset = next;
                        continue;
                    }
                    break;
                }
            }
        }

        if pages.is_empty() {
            return Err(io_err("No RAM pages found in QEMU savevm stream".to_string()));
        }

        // Deduplicate: later entries (from dirty page iterations) overwrite earlier ones.
        // Use a HashMap so the last write wins, then collect and sort for binary search.
        let mut page_map: std::collections::HashMap<u64, u64> =
            std::collections::HashMap::with_capacity(pages.len());
        for p in &pages {
            page_map.insert(p.gpa, p.file_offset);
        }
        let mut pages: Vec<MappedPage> = page_map
            .into_iter()
            .map(|(gpa, file_offset)| MappedPage { gpa, file_offset })
            .collect();
        pages.sort_unstable_by_key(|p| p.gpa);

        Ok((pages, phys_end))
    }

    /// Parse the RAM setup phase: MEM_SIZE block list + EOS.
    fn parse_ram_setup(
        data: &[u8],
        mut offset: usize,
        ram_blocks: &mut Vec<RamBlock>,
        block_gpa_bases: &mut Vec<u64>,
        phys_end: &mut u64,
        below_4g: &mut u64,
    ) -> Result<usize> {
        let len = data.len();
        if offset + 8 > len {
            return Err(io_err("Truncated RAM MEM_SIZE".to_string()));
        }

        let val = read_be_u64(data, offset);
        offset += 8;
        let flags = val & RAM_FLAG_MASK;

        if flags & RAM_SAVE_FLAG_MEM_SIZE == 0 {
            return Err(io_err(format!(
                "Expected RAM_SAVE_FLAG_MEM_SIZE, got flags 0x{:x}", flags
            )));
        }

        let total_ram = val & !RAM_FLAG_MASK;
        log::info!("QEMU savevm: total RAM = {} MB", total_ram / (1024 * 1024));

        // Parse block list
        let mut remaining = total_ram;
        let mut gpa_base = 0u64;
        while remaining > 0 && offset < len.saturating_sub(9) {
            let (name, new_off) = read_string(data, offset)?;
            offset = new_off;
            if offset + 8 > len { break; }
            let block_size = read_be_u64(data, offset);
            offset += 8;

            log::info!("  RAM block '{}': {} MB", name, block_size / (1024 * 1024));

            block_gpa_bases.push(gpa_base);
            if name == "pc.ram" {
                // The MMIO gap boundary (below_4g) depends on machine type and firmware:
                //   - q35 + OVMF (UEFI): typically 0x8000_0000 (2 GB)
                //   - q35 + SeaBIOS:     typically 0xB000_0000 (2.75 GB)
                //   - i440fx:            typically 0xE000_0000 (3.5 GB)
                // We try the common values; the caller validates by checking page tables.
                // For VMs with RAM <= below_4g, there's no MMIO gap remapping needed.
                if block_size <= 0x8000_0000 {
                    // RAM fits below 2GB — no MMIO gap, identity mapping
                    *below_4g = block_size;
                } else {
                    // Default to 0x8000_0000 (UEFI/OVMF, most common on Proxmox).
                    // This is validated later; if page table walks fail, other values
                    // could be tried (0xB0000000 for SeaBIOS, 0xE0000000 for i440fx).
                    *below_4g = 0x8000_0000;
                }
                let above_4g = block_size.saturating_sub(*below_4g);
                *phys_end = if above_4g > 0 {
                    0x1_0000_0000 + above_4g
                } else {
                    block_size
                };
            }
            gpa_base += block_size;
            ram_blocks.push(RamBlock { name, size: block_size });
            remaining = remaining.saturating_sub(block_size);
        }

        // Read EOS
        if offset + 8 <= len {
            let eos_val = read_be_u64(data, offset);
            if eos_val & RAM_FLAG_MASK == RAM_SAVE_FLAG_EOS {
                offset += 8;
            }
        }

        Ok(offset)
    }

    /// Parse RAM page entries from a SECTION_PART until EOS.
    fn parse_ram_pages(
        data: &[u8],
        mut offset: usize,
        ram_blocks: &[RamBlock],
        pages: &mut Vec<MappedPage>,
        current_block_idx: &mut usize,
        below_4g: u64,
    ) -> Result<usize> {
        let len = data.len();

        while offset + 8 <= len {
            let val = read_be_u64(data, offset);
            let flags = val & RAM_FLAG_MASK;
            let addr = val & !RAM_FLAG_MASK;
            offset += 8;

            if flags & RAM_SAVE_FLAG_EOS != 0 {
                break;
            }

            // Read block identifier if not CONTINUE
            if flags & RAM_SAVE_FLAG_CONTINUE == 0 {
                if offset >= len { break; }
                let (block_name, new_off) = read_string(data, offset)?;
                offset = new_off;
                // Find block index
                if let Some(idx) = ram_blocks.iter().position(|b| b.name == block_name) {
                    *current_block_idx = idx;
                }
            }

            // Only store pages from pc.ram (block index 0) — that's the guest physical RAM.
            // Other blocks (vga.vram, ROM, flash) are device memory, not relevant for forensics.
            let is_main_ram = *current_block_idx == 0
                || ram_blocks.get(*current_block_idx).is_some_and(|b| b.name == "pc.ram");

            // For pc.ram, addr is the offset within the RAM block.
            // QEMU maps pc.ram into two GPA regions separated by an MMIO gap:
            //   offset < below_4g             → GPA = offset
            //   offset >= below_4g            → GPA = 0x1_0000_0000 + (offset - below_4g)
            // For q35: below_4g = min(ram_size, 0xB000_0000)
            // For i440fx: below_4g = min(ram_size, 0xE000_0000)
            let gpa = if is_main_ram && addr >= below_4g {
                0x1_0000_0000 + (addr - below_4g)
            } else {
                addr
            };

            if flags & RAM_SAVE_FLAG_PAGE != 0 {
                // Full page: 4096 bytes of data follow
                if offset + PAGE_SIZE > len {
                    break;
                }
                if is_main_ram {
                    pages.push(MappedPage {
                        gpa,
                        file_offset: offset as u64,
                    });
                }
                offset += PAGE_SIZE;
            } else if flags & RAM_SAVE_FLAG_ZERO != 0 {
                // Zero page: single fill byte follows (always 0x00 in practice)
                if offset >= len { break; }
                let _fill = data[offset];
                offset += 1;
                // Don't store zero pages — read_phys returns zeros for unmapped GPAs
            } else if flags & RAM_SAVE_FLAG_COMPRESS_PAGE != 0 {
                // Compressed page (legacy, removed in QEMU 9.1) — skip
                // We can't easily determine the compressed size without zlib parsing
                log::warn!("QEMU savevm: COMPRESS_PAGE encountered, skipping rest of stream");
                break;
            } else if flags == 0 {
                // No flags set — could be padding or end marker
                break;
            }
        }

        Ok(offset)
    }

    /// Scan forward in the data stream for the next SECTION_PART with the RAM
    /// section ID, or another recognizable outer section marker. This skips past
    /// non-RAM device state sections whose internal format is opaque.
    fn scan_for_next_section(data: &[u8], start: usize, ram_section_id: Option<u32>) -> Option<usize> {
        let ram_sid = ram_section_id?;
        // Build the 5-byte pattern: SECTION_PART(0x02) + section_id(BE u32)
        let pattern = [
            QEMU_VM_SECTION_PART,
            (ram_sid >> 24) as u8,
            (ram_sid >> 16) as u8,
            (ram_sid >> 8) as u8,
            ram_sid as u8,
        ];
        // Scan forward for this pattern
        for i in start..data.len().saturating_sub(pattern.len() + 8) {
            if data[i..i + pattern.len()] == pattern {
                // Verify: the 8 bytes after the header should look like valid RAM flags
                let val = u64::from_be_bytes(data[i + 5..i + 13].try_into().ok()?);
                let flags = val & RAM_FLAG_MASK;
                let has_page_or_zero = flags & (RAM_SAVE_FLAG_PAGE | RAM_SAVE_FLAG_ZERO | RAM_SAVE_FLAG_EOS) != 0;
                if has_page_or_zero {
                    log::debug!("QEMU savevm: found RAM SECTION_PART at 0x{:x} (skipped {} bytes)", i, i - start);
                    return Some(i);
                }
            }
        }
        None
    }

    /// Find the page entry for a given GPA using binary search.
    fn find_page(&self, gpa: u64) -> Option<&MappedPage> {
        let page_gpa = gpa & !(PAGE_SIZE as u64 - 1);
        let idx = self.pages.partition_point(|p| p.gpa <= page_gpa);
        if idx == 0 {
            return None;
        }
        let page = &self.pages[idx - 1];
        if page.gpa == page_gpa {
            Some(page)
        } else {
            None
        }
    }
}

impl PhysicalMemory for QemuSavevmLayer {
    fn read_phys(&self, phys_addr: u64, buf: &mut [u8]) -> Result<()> {
        let len = buf.len();
        if len == 0 {
            return Ok(());
        }

        // Fill with zeros first (unmapped pages return zeros)
        buf.fill(0);

        let mut pos = 0usize;
        while pos < len {
            let cur_gpa = phys_addr + pos as u64;
            let page_gpa = cur_gpa & !(PAGE_SIZE as u64 - 1);
            let offset_in_page = (cur_gpa - page_gpa) as usize;
            let remaining_in_page = PAGE_SIZE - offset_in_page;
            let to_copy = std::cmp::min(remaining_in_page, len - pos);

            if let Some(page) = self.find_page(cur_gpa) {
                let file_off = page.file_offset as usize + offset_in_page;
                let end = file_off + to_copy;
                if end <= self.mmap.len() {
                    let _ = self.mmap.read_at(file_off, &mut buf[pos..pos + to_copy]);
                }
            }
            // Unmapped pages stay as zeros (already filled)

            pos += to_copy;
        }

        Ok(())
    }

    fn phys_size(&self) -> u64 {
        self.phys_end
    }
}

/// Check if a file starts with the QEVM magic.
/// Uses a simple read instead of mmap to work on block devices (LVM volumes).
pub fn is_qemu_savevm(path: &Path) -> bool {
    use std::io::Read;
    let Ok(mut f) = fs::File::open(path) else { return false };
    let mut magic = [0u8; 4];
    if f.read_exact(&mut magic).is_err() { return false; }
    u32::from_be_bytes(magic) == QEVM_MAGIC
}

/// Create a VmkatzError::Io from a string message.
fn io_err(msg: String) -> VmkatzError {
    VmkatzError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, msg))
}

// Helpers for big-endian reads from a byte slice.

fn read_be_u32(data: &[u8], offset: usize) -> u32 {
    data.get(offset..offset + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_be_bytes)
        .unwrap_or(0)
}

fn read_be_u64(data: &[u8], offset: usize) -> u64 {
    data.get(offset..offset + 8)
        .and_then(|s| s.try_into().ok())
        .map(u64::from_be_bytes)
        .unwrap_or(0)
}

/// Read a length-prefixed string (u8 len + bytes).
fn read_string(data: &[u8], offset: usize) -> Result<(String, usize)> {
    if offset >= data.len() {
        return Err(io_err("Truncated string in savevm stream".to_string()));
    }
    let name_len = data[offset] as usize;
    let start = offset + 1;
    let end = start + name_len;
    if end > data.len() {
        return Err(io_err("Truncated string in savevm stream".to_string()));
    }
    let name = String::from_utf8_lossy(&data[start..end]).to_string();
    Ok((name, end))
}
