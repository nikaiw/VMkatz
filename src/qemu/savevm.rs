//! QEMU/KVM/Proxmox savevm state reader.
//!
//! Parses the QEMU migration stream format used by:
//!   - `qm snapshot <VMID> <name> --vmstate 1` on Proxmox
//!   - `savevm` in QEMU monitor
//!   - Proxmox VM state stored in LVM thin volumes
//!
//! The format stores RAM as a stream of page entries (4KB each):
//!   - PAGE entries: 4096 bytes of raw guest physical memory
//!   - ZERO entries: zero-filled pages (legacy nonzero fills are unsupported)
//!
//! Non-RAM device state sections (CPU, PIC, etc.) are skipped.

use std::fs;
use std::path::Path;

use crate::error::{Result, VmkatzError};
use crate::memory::{
    PhysicalMemory,
    page_index::{PageIndex, PageLocation},
};

mod stream;

const PAGE_SIZE: usize = 4096;

// File header
const QEVM_MAGIC: u32 = 0x5145_564D; // "QEVM" big-endian

/// QEMU savevm state memory layer.
pub struct QemuSavevmLayer {
    mmap: crate::utils::MappedFile,
    /// Consecutive pages share one mapping run.
    pages: PageIndex,
    /// Total physical address space (max GPA of pc.ram block).
    phys_end: u64,
}

impl QemuSavevmLayer {
    /// Open a regular savevm file or a block device containing a savevm stream.
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with_options(path, None)
    }

    /// Rebuild the page index using an explicit MMIO gap boundary.
    /// The stream stores pc.ram contiguously and does not record the gap split.
    pub fn open_with_gap(path: &Path, below_4g: u64) -> Result<Self> {
        Self::open_with_options(path, Some(below_4g))
    }

    fn open_with_options(path: &Path, gap_override: Option<u64>) -> Result<Self> {
        let file = fs::File::open(path)?;
        let mmap = crate::utils::mmap_file(&file, path)?;
        if mmap.len() < 16 {
            return Err(VmkatzError::InvalidMagic(0));
        }
        // Stream parsing requires slice access; other formats retain pread support.
        let data = mmap.as_bytes().ok_or_else(|| {
            io_err(
                "QEMU savevm requires mmap support (file I/O fallback too slow for stream parsing)"
                    .to_string(),
            )
        })?;
        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if magic != QEVM_MAGIC {
            return Err(VmkatzError::InvalidMagic(magic));
        }
        let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if version < 3 {
            return Err(io_err(format!(
                "Unsupported QEMU savevm version {version} (expected >= 3)"
            )));
        }
        if gap_override.is_none() {
            log::info!(
                "QEMU savevm: version {}, file size {} MB",
                version,
                mmap.len() / (1024 * 1024)
            );
        }
        let (pages, phys_end) = stream::parse(data, gap_override)?;
        if gap_override.is_none() {
            log::info!(
                "QEMU savevm: {} mapped pages ({} MB), phys_end=0x{:x}",
                pages.page_count(),
                pages.page_count() * PAGE_SIZE as u64 / (1024 * 1024),
                phys_end
            );
        }
        Ok(Self {
            mmap,
            pages,
            phys_end,
        })
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
            let cur_gpa = phys_addr
                .checked_add(pos as u64)
                .ok_or(VmkatzError::UnmappablePhysical(phys_addr))?;
            let page_gpa = cur_gpa & !(PAGE_SIZE as u64 - 1);
            let offset_in_page = (cur_gpa - page_gpa) as usize;
            let remaining_in_page = PAGE_SIZE - offset_in_page;
            let to_copy = std::cmp::min(remaining_in_page, len - pos);

            if let Some(offset) = self.pages.get(cur_gpa).and_then(PageLocation::offset) {
                let file_off = offset + offset_in_page as u64;
                let end = file_off + to_copy as u64;
                if end <= self.mmap.len() as u64 {
                    self.mmap
                        .read_at(file_off, &mut buf[pos..pos + to_copy])
                        .map_err(|_| VmkatzError::UnmappablePhysical(cur_gpa))?;
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
    let Ok(mut f) = fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 4];
    if f.read_exact(&mut magic).is_err() {
        return false;
    }
    u32::from_be_bytes(magic) == QEVM_MAGIC
}

/// Create a VmkatzError::Io from a string message.
fn io_err(msg: String) -> VmkatzError {
    VmkatzError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, msg))
}

#[cfg(test)]
mod tests;
