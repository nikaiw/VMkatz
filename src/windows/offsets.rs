use crate::error::{GovmemError, Result};

/// EPROCESS field offsets for Windows x64.
#[derive(Debug, Clone, Copy)]
pub struct EprocessOffsets {
    pub directory_table_base: u64,
    pub unique_process_id: u64,
    pub active_process_links: u64,
    pub image_file_name: u64,
    pub peb: u64,
    pub section_base_address: u64,
}

/// PEB / LDR offsets for enumerating loaded DLLs.
/// Stable across Windows 7-11 x64.
#[derive(Debug, Clone, Copy)]
pub struct LdrOffsets {
    pub peb_ldr: u64,
    pub ldr_in_load_order: u64,
    pub ldr_in_memory_order: u64,
    pub ldr_entry_dll_base: u64,
    pub ldr_entry_size_of_image: u64,
    pub ldr_entry_full_dll_name: u64,
    pub ldr_entry_base_dll_name: u64,
}

// -- EPROCESS offsets by build range (x64) --

/// Windows 7 SP1 / Server 2008 R2 (build 7601)
const WIN7_X64_EPROCESS: EprocessOffsets = EprocessOffsets {
    directory_table_base: 0x28,
    unique_process_id: 0x180,
    active_process_links: 0x188,
    image_file_name: 0x2E0,
    peb: 0x338,
    section_base_address: 0x268,
};

/// Windows 8 / Server 2012 (build 9200)
const WIN8_X64_EPROCESS: EprocessOffsets = EprocessOffsets {
    directory_table_base: 0x28,
    unique_process_id: 0x2E0,
    active_process_links: 0x2E8,
    image_file_name: 0x438,
    peb: 0x338,
    section_base_address: 0x268,
};

/// Windows 8.1 / Server 2012 R2 (build 9600)
const WIN81_X64_EPROCESS: EprocessOffsets = EprocessOffsets {
    directory_table_base: 0x28,
    unique_process_id: 0x2E0,
    active_process_links: 0x2E8,
    image_file_name: 0x438,
    peb: 0x3E8,
    section_base_address: 0x268,
};

/// Windows 10 1507/1511/1607 (builds 10240-14393) / Server 2016
const WIN10_EARLY_X64_EPROCESS: EprocessOffsets = EprocessOffsets {
    directory_table_base: 0x28,
    unique_process_id: 0x2E8,
    active_process_links: 0x2F0,
    image_file_name: 0x450,
    peb: 0x3F8,
    section_base_address: 0x3C0,
};

/// Windows 10 1703-22H2 (builds 15063-19045) / Server 2019/2022 / Windows 11 21H2-23H2
pub const WIN10_X64_EPROCESS: EprocessOffsets = EprocessOffsets {
    directory_table_base: 0x28,
    unique_process_id: 0x440,
    active_process_links: 0x448,
    image_file_name: 0x5A8,
    peb: 0x550,
    section_base_address: 0x520,
};

/// Windows 11 24H2+ (build 26100+) — EPROCESS fields shifted +8 from Win10
const WIN11_24H2_X64_EPROCESS: EprocessOffsets = EprocessOffsets {
    directory_table_base: 0x28,
    unique_process_id: 0x448,
    active_process_links: 0x450,
    image_file_name: 0x5B0,
    peb: 0x558,
    section_base_address: 0x528,
};

/// LDR offsets — stable across Windows 7-11 x64.
pub const X64_LDR: LdrOffsets = LdrOffsets {
    peb_ldr: 0x18,
    ldr_in_load_order: 0x10,
    ldr_in_memory_order: 0x20,
    ldr_entry_dll_base: 0x30,
    ldr_entry_size_of_image: 0x40,
    ldr_entry_full_dll_name: 0x48,
    ldr_entry_base_dll_name: 0x58,
};

// Keep the old name as alias for backward compatibility
pub const WIN10_X64_LDR: LdrOffsets = X64_LDR;

/// Get EPROCESS offsets for a given Windows build number.
pub fn offsets_for_build(build: u32) -> Result<EprocessOffsets> {
    match build {
        // Win7 SP1 / Server 2008 R2
        7600..=7601 => Ok(WIN7_X64_EPROCESS),
        // Win8 / Server 2012
        9200 => Ok(WIN8_X64_EPROCESS),
        // Win8.1 / Server 2012 R2
        9600 => Ok(WIN81_X64_EPROCESS),
        // Win10 1507-1607 / Server 2016
        10240..=14393 => Ok(WIN10_EARLY_X64_EPROCESS),
        // Win10 1703+ / Server 2019/2022 / Win11 21H2-23H2
        15063..=26099 => Ok(WIN10_X64_EPROCESS),
        // Win11 24H2+ (build 26100+)
        26100..=29999 => Ok(WIN11_24H2_X64_EPROCESS),
        _ => Err(GovmemError::UnsupportedBuild(build)),
    }
}

/// All known EPROCESS offset sets for brute-force scan (when build is unknown).
/// Ordered by likelihood (most common first).
pub const ALL_EPROCESS_OFFSETS: &[EprocessOffsets] = &[
    WIN10_X64_EPROCESS,       // Win10 1703+ / Win11 21H2-23H2
    WIN11_24H2_X64_EPROCESS,  // Win11 24H2+
    WIN10_EARLY_X64_EPROCESS, // Win10 1507-1607
    WIN81_X64_EPROCESS,       // Win8.1
    WIN8_X64_EPROCESS,        // Win8
    WIN7_X64_EPROCESS,        // Win7
];
