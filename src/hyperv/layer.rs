//! Hyper-V memory layer.
//!
//! Supports:
//! - Legacy `.bin` files (Hyper-V 2008/2012): raw physical memory dump (identity mapping)
//! - Modern `.vmrs` files (Hyper-V 2016+): native parser for HyperVStorage format
//! - Raw memory dumps from MemProcFS pmem export or vm2dmp conversions

use std::fs;
use std::path::Path;

use memmap2::Mmap;

use crate::error::{VmkatzError, Result};
use crate::memory::PhysicalMemory;

/// Hyper-V memory layer: provides physical memory from .bin or raw dump files.
pub struct HypervLayer {
    mmap: Mmap,
    size: u64,
}

impl HypervLayer {
    /// Open a Hyper-V legacy .bin file or raw memory dump.
    ///
    /// The file is identity-mapped: file offset = guest physical address.
    /// For .bin files, optionally loads CPU state from a companion .vsv file (future).
    pub fn open(path: &Path) -> Result<Self> {
        let file = fs::File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };
        let size = mmap.len() as u64;

        if size == 0 {
            return Err(VmkatzError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Empty memory dump file",
            )));
        }

        // Sanity check: .bin files should be at least a few MB (VM RAM)
        // Skip check for very small files (< 1MB) that are likely not memory dumps
        if size < 1024 * 1024 {
            log::warn!(
                "File is only {} KB - may not be a valid memory dump",
                size / 1024
            );
        }

        log::info!("Hyper-V .bin: {} MB identity-mapped", size / (1024 * 1024));

        Ok(Self { mmap, size })
    }
}

impl PhysicalMemory for HypervLayer {
    fn read_phys(&self, phys_addr: u64, buf: &mut [u8]) -> Result<()> {
        let end = phys_addr + buf.len() as u64;
        if end > self.size {
            // Partial read: fill with zeros for out-of-bounds portion
            buf.fill(0);
            if phys_addr < self.size {
                let avail = (self.size - phys_addr) as usize;
                buf[..avail].copy_from_slice(&self.mmap[phys_addr as usize..self.size as usize]);
            }
            return Ok(());
        }
        buf.copy_from_slice(&self.mmap[phys_addr as usize..end as usize]);
        Ok(())
    }

    fn phys_size(&self) -> u64 {
        self.size
    }
}
