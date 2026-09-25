/// Physical address mask: bits 51:12 (standard 4KB page table entry).
pub const PAGE_PHYS_MASK: u64 = 0x000F_FFFF_FFFF_F000;
/// Address mask for 1GB huge pages (bits 51:30).
pub const LARGE_1GB_MASK: u64 = 0x000F_FFFF_C000_0000;
/// Address mask for 2MB large pages (bits 51:21).
pub const LARGE_2MB_MASK: u64 = 0x000F_FFFF_FFE0_0000;
/// Offset within 1GB huge page (bits 29:0).
pub const PAGE_OFFSET_1GB: u64 = 0x3FFF_FFFF;
/// Offset within 2MB large page (bits 20:0).
pub const PAGE_OFFSET_2MB: u64 = 0x1F_FFFF;

/// Wrapper for a 64-bit page table entry.
#[derive(Debug, Clone, Copy)]
pub struct PageTableEntry(pub u64);

impl PageTableEntry {
    /// Present bit (bit 0).
    pub const fn is_present(&self) -> bool {
        self.0 & 1 != 0
    }

    /// Page Size bit (bit 7) - indicates 2MB page (PDE) or 1GB page (PDPTE).
    pub const fn is_large_page(&self) -> bool {
        self.0 & (1 << 7) != 0
    }

    /// Extract the physical frame address (bits 12-51, mask lower 12 bits).
    pub const fn frame_addr(&self) -> u64 {
        self.0 & PAGE_PHYS_MASK
    }

    /// Windows transition PTE: bit 11 set (prototype) and bit 10 clear.
    /// Transition PTEs point to pages still in physical memory but marked not-present.
    pub const fn is_transition(&self) -> bool {
        (self.0 & (1 << 11)) != 0 && (self.0 & (1 << 10)) == 0
    }

    pub const fn raw(&self) -> u64 {
        self.0
    }

    /// Windows pagefile PTE: not present (bit 0=0), not transition (bit 10=0),
    /// not prototype (bit 11=0), and non-zero (has pagefile info).
    /// Bits 1-4 = pagefile number, bits 32-63 = page offset in pagefile.
    pub const fn is_pagefile(&self) -> bool {
        self.0 != 0 && (self.0 & 1) == 0 && (self.0 & (1 << 10)) == 0 && (self.0 & (1 << 11)) == 0
    }

    /// Pagefile number from bits 1-4 (usually 0 for primary pagefile.sys).
    pub const fn pagefile_number(&self) -> u8 {
        ((self.0 >> 1) & 0xF) as u8
    }

    /// Byte offset into pagefile from bits 32-63 (page index * 4096).
    pub const fn pagefile_offset(&self) -> u64 {
        ((self.0 >> 32) & 0xFFFF_FFFF) * 4096
    }
}
