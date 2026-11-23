//! QEMU RAM migration records and their compact page index.

use super::{PAGE_SIZE, io_err};
use crate::error::{Result, VmkatzError};
use crate::memory::page_index::PageIndex;
use crate::utils::{u32_be_or0, u64_be_or0};

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

/// Keep the latest mapping without expanding consecutive pages into individual entries.
#[derive(Default)]
struct RamPageIndex {
    offsets: PageIndex,
    saw_pages: bool,
}

impl RamPageIndex {
    fn record(&mut self, gpa: u64, offset: Option<u64>) -> Result<()> {
        if offset.is_some() {
            self.offsets.insert(gpa, offset)?;
        } else {
            self.offsets.remove(gpa)?;
        }
        self.saw_pages = true;
        Ok(())
    }

    fn finish(self) -> Result<PageIndex> {
        if !self.saw_pages {
            return Err(io_err("No RAM pages found in QEMU savevm stream".into()));
        }
        Ok(self.offsets)
    }
}

/// A RAM block described in the MEM_SIZE header.
#[derive(Debug)]
struct RamBlock {
    name: String,
    size: u64,
}

/// Parse the entire savevm stream and extract RAM page locations.
pub(super) fn parse(data: &[u8], gap_override: Option<u64>) -> Result<(PageIndex, u64)> {
    let mut offset = 8usize; // skip magic + version
    let len = data.len();
    let mut ram_section_id: Option<u32> = None;
    let mut pages = RamPageIndex::default();
    let mut ram_blocks: Vec<RamBlock> = Vec::new();
    let mut phys_end: u64 = 0;
    let mut below_4g: u64 = 0;
    let mut current_block_idx = None;

    while offset < len {
        let section_type = data[offset];
        offset += 1;

        match section_type {
            QEMU_VM_CONFIGURATION => {
                let payload = checked_end(data, offset, 4, "configuration length")?;
                let clen = u32_be_or0(data, offset) as usize;
                offset = checked_end(data, payload, clen, "configuration")?;
            }
            QEMU_VM_SECTION_START | QEMU_VM_SECTION_FULL => {
                checked_end(data, offset, 4, "section ID")?;
                let sid = u32_be_or0(data, offset);
                offset += 4;
                let (name, new_off) = read_string(data, offset)?;
                offset = new_off;
                offset = checked_end(data, offset, 8, "section header")?;

                if name == "ram" {
                    ram_section_id = Some(sid);
                    // Parse MEM_SIZE + block list + EOS
                    offset = parse_ram_setup(
                        data,
                        offset,
                        &mut ram_blocks,
                        &mut phys_end,
                        &mut below_4g,
                        gap_override,
                    )?;
                } else {
                    // Non-RAM device (dirty-bitmap, cpu, etc.) — skip by scanning
                    // forward for the next outer section marker we can recognize.
                    log::debug!("QEMU savevm: skipping non-RAM device '{name}' at 0x{offset:x}");
                    if let Some(next) = scan_for_next_section(data, offset, ram_section_id) {
                        log::debug!("QEMU savevm: found next RAM section at 0x{next:x}");
                        offset = next;
                    } else {
                        break;
                    }
                }
            }
            QEMU_VM_SECTION_PART | QEMU_VM_SECTION_END => {
                checked_end(data, offset, 4, "section ID")?;
                let sid = u32_be_or0(data, offset);
                offset += 4;

                if ram_section_id == Some(sid) {
                    offset = parse_ram_pages(
                        data,
                        offset,
                        &ram_blocks,
                        &mut pages,
                        &mut current_block_idx,
                        below_4g,
                    )?;
                } else {
                    // Non-RAM section part — scan forward for next recognizable marker
                    log::debug!(
                        "QEMU savevm: skipping non-RAM SECTION_PART id={sid} at 0x{offset:x}"
                    );
                    if let Some(next) = scan_for_next_section(data, offset, ram_section_id) {
                        offset = next;
                    } else {
                        break;
                    }
                }
            }
            QEMU_VM_SECTION_FOOTER => {
                offset = checked_end(data, offset, 4, "section footer")?;
            }
            QEMU_VM_EOF => {
                break;
            }
            _ => {
                // Unknown section type — try scanning forward for next RAM section
                log::debug!(
                    "QEMU savevm: unknown section type 0x{:02x} at 0x{:x}, scanning",
                    section_type,
                    offset - 1
                );
                if let Some(next) = scan_for_next_section(data, offset, ram_section_id) {
                    offset = next;
                    continue;
                }
                break;
            }
        }
    }

    Ok((pages.finish()?, phys_end))
}

/// Parse the RAM setup phase: MEM_SIZE block list + EOS.
fn parse_ram_setup(
    data: &[u8],
    mut offset: usize,
    ram_blocks: &mut Vec<RamBlock>,
    phys_end: &mut u64,
    below_4g: &mut u64,
    gap_override: Option<u64>,
) -> Result<usize> {
    checked_end(data, offset, 8, "RAM MEM_SIZE")?;
    let val = u64_be_or0(data, offset);
    offset += 8;
    let flags = val & RAM_FLAG_MASK;

    if flags & RAM_SAVE_FLAG_MEM_SIZE == 0 {
        return Err(io_err(format!(
            "Expected RAM_SAVE_FLAG_MEM_SIZE, got flags 0x{flags:x}"
        )));
    }

    let total_ram = val & !RAM_FLAG_MASK;
    log::info!("QEMU savevm: total RAM = {} MB", total_ram / (1024 * 1024));

    // Parse block list
    let mut remaining = total_ram;
    while remaining > 0 {
        let (name, new_off) = read_string(data, offset)?;
        offset = new_off;
        checked_end(data, offset, 8, "RAM block size")?;
        let block_size = u64_be_or0(data, offset);
        offset += 8;
        if block_size == 0 || !block_size.is_multiple_of(PAGE_SIZE as u64) {
            return Err(io_err("Invalid QEMU RAM block size".into()));
        }
        remaining = remaining
            .checked_sub(block_size)
            .ok_or_else(|| io_err("QEMU RAM blocks exceed declared memory size".into()))?;

        log::info!("  RAM block '{}': {} MB", name, block_size / (1024 * 1024));

        if name == "pc.ram" {
            // The stream omits the MMIO split. Small RAM maps directly; larger
            // guests use the caller's probed boundary or the 2 GiB OVMF default.
            *below_4g = if block_size <= 0x8000_0000 {
                block_size
            } else {
                gap_override.unwrap_or(0x8000_0000)
            };
            let above_4g = block_size.saturating_sub(*below_4g);
            *phys_end = if above_4g > 0 {
                above_4g
                    .checked_add(0x1_0000_0000)
                    .ok_or_else(|| io_err("QEMU RAM size overflow".into()))?
            } else {
                block_size
            };
        }
        if ram_blocks.len() >= 65_536 {
            return Err(VmkatzError::RecoveryLimit(
                "QEMU RAM block declarations exceed 65536",
            ));
        }
        ram_blocks
            .try_reserve(1)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::OutOfMemory, error))?;
        ram_blocks.push(RamBlock {
            name,
            size: block_size,
        });
    }

    checked_end(data, offset, 8, "RAM setup EOS")?;
    if u64_be_or0(data, offset) != RAM_SAVE_FLAG_EOS {
        return Err(io_err("Missing QEMU RAM setup EOS".into()));
    }
    Ok(offset + 8)
}

/// Parse RAM page entries from a PART or END section through its EOS.
fn parse_ram_pages(
    data: &[u8],
    mut offset: usize,
    ram_blocks: &[RamBlock],
    pages: &mut RamPageIndex,
    current_block_idx: &mut Option<usize>,
    below_4g: u64,
) -> Result<usize> {
    loop {
        checked_end(data, offset, 8, "RAM page header or EOS")?;
        let val = u64_be_or0(data, offset);
        let flags = val & RAM_FLAG_MASK;
        let addr = val & !RAM_FLAG_MASK;
        offset += 8;

        if val == RAM_SAVE_FLAG_EOS {
            return Ok(offset);
        }
        let kind = flags & !RAM_SAVE_FLAG_CONTINUE;
        if !matches!(kind, RAM_SAVE_FLAG_PAGE | RAM_SAVE_FLAG_ZERO) {
            let detail = if kind == RAM_SAVE_FLAG_COMPRESS_PAGE {
                "compressed pages are unsupported"
            } else {
                "unsupported RAM flags"
            };
            return Err(io_err(format!("QEMU savevm: {detail} (0x{flags:x})")));
        }

        if flags & RAM_SAVE_FLAG_CONTINUE == 0 {
            let (block_name, new_off) = read_string(data, offset)?;
            offset = new_off;
            *current_block_idx = Some(
                ram_blocks
                    .iter()
                    .position(|b| b.name == block_name)
                    .ok_or_else(|| io_err(format!("Unknown QEMU RAM block '{block_name}'")))?,
            );
        }
        let block = current_block_idx
            .and_then(|idx| ram_blocks.get(idx))
            .ok_or_else(|| io_err("QEMU RAM CONTINUE without a block identifier".into()))?;
        if addr
            .checked_add(PAGE_SIZE as u64)
            .is_none_or(|end| end > block.size)
        {
            return Err(io_err("QEMU RAM page exceeds its block".into()));
        }
        let is_main_ram = block.name == "pc.ram";

        // pc.ram offsets above the MMIO gap resume at GPA 4 GiB.
        let gpa = if is_main_ram && addr >= below_4g {
            (addr - below_4g)
                .checked_add(0x1_0000_0000)
                .ok_or_else(|| io_err("QEMU RAM address overflow".into()))?
        } else {
            addr
        };
        if kind == RAM_SAVE_FLAG_PAGE {
            let end = checked_end(data, offset, PAGE_SIZE, "RAM page payload")?;
            if is_main_ram {
                pages.record(gpa, Some(offset as u64))?;
            }
            offset = end;
        } else {
            checked_end(data, offset, 1, "RAM zero-page fill")?;
            if data[offset] != 0 {
                return Err(io_err("QEMU nonzero RAM fill is unsupported".into()));
            }
            offset += 1;
            if is_main_ram {
                pages.record(gpa, None)?;
            }
        }
    }
}

/// Find the next RAM PART or END after opaque device state.
fn scan_for_next_section(data: &[u8], start: usize, ram_section_id: Option<u32>) -> Option<usize> {
    let ram_sid = ram_section_id?;
    let last = data.len().checked_sub(13)?;
    for i in start..=last {
        if matches!(data[i], QEMU_VM_SECTION_PART | QEMU_VM_SECTION_END)
            && data[i + 1..i + 5] == ram_sid.to_be_bytes()
        {
            // Verify: the 8 bytes after the header should look like valid RAM flags
            let val = u64::from_be_bytes(data[i + 5..i + 13].try_into().ok()?);
            let flags = val & RAM_FLAG_MASK;
            let has_page_or_zero =
                flags & (RAM_SAVE_FLAG_PAGE | RAM_SAVE_FLAG_ZERO | RAM_SAVE_FLAG_EOS) != 0;
            if has_page_or_zero {
                log::debug!(
                    "QEMU savevm: found RAM section at 0x{:x} (skipped {} bytes)",
                    i,
                    i - start
                );
                return Some(i);
            }
        }
    }
    None
}
fn checked_end(data: &[u8], offset: usize, size: usize, what: &str) -> Result<usize> {
    offset
        .checked_add(size)
        .filter(|&end| end <= data.len())
        .ok_or_else(|| io_err(format!("Truncated QEMU savevm {what}")))
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

#[cfg(test)]
mod tests;
