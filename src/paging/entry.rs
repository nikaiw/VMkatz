/// Wrapper for a 64-bit page table entry.
#[derive(Debug, Clone, Copy)]
pub struct PageTableEntry(pub u64);

impl PageTableEntry {
    /// Present bit (bit 0).
    pub fn is_present(&self) -> bool {
        self.0 & 1 != 0
    }

    /// Page Size bit (bit 7) - indicates 2MB page (PDE) or 1GB page (PDPTE).
    pub fn is_large_page(&self) -> bool {
        self.0 & (1 << 7) != 0
    }

    /// Extract the physical frame address (bits 12-51, mask lower 12 bits).
    pub fn frame_addr(&self) -> u64 {
        self.0 & 0x000F_FFFF_FFFF_F000
    }

    /// Windows transition PTE: bit 11 set (prototype) and bit 10 clear.
    /// Transition PTEs point to pages still in physical memory but marked not-present.
    pub fn is_transition(&self) -> bool {
        (self.0 & (1 << 11)) != 0 && (self.0 & (1 << 10)) == 0
    }

    pub fn raw(&self) -> u64 {
        self.0
    }

    /// Windows pagefile PTE: not present (bit 0=0), not transition (bit 10=0),
    /// not prototype (bit 11=0), and non-zero (has pagefile info).
    /// Bits 1-4 = pagefile number, bits 32-63 = page offset in pagefile.
    pub fn is_pagefile(&self) -> bool {
        self.0 != 0 && (self.0 & 1) == 0 && (self.0 & (1 << 10)) == 0 && (self.0 & (1 << 11)) == 0
    }

    /// Pagefile number from bits 1-4 (usually 0 for primary pagefile.sys).
    pub fn pagefile_number(&self) -> u8 {
        ((self.0 >> 1) & 0xF) as u8
    }

    /// Byte offset into pagefile from bits 32-63 (page index * 4096).
    pub fn pagefile_offset(&self) -> u64 {
        ((self.0 >> 32) & 0xFFFF_FFFF) * 4096
    }
}
