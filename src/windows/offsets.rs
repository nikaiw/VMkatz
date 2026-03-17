/// Whether the Windows kernel is 64-bit (x86-64) or 32-bit (x86 with PAE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsBitness {
    X64,
    X86Pae,
}

/// EPROCESS field offsets for a given Windows version/architecture.
/// Some fields document struct layout for future use and may not be read yet.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct EprocessOffsets {
    pub bitness: WindowsBitness,
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
#[allow(dead_code)]
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
    bitness: WindowsBitness::X64,
    directory_table_base: 0x28,
    unique_process_id: 0x180,
    active_process_links: 0x188,
    image_file_name: 0x2E0,
    peb: 0x338,
    section_base_address: 0x270,
};

/// Windows 8 / Server 2012 (build 9200)
const WIN8_X64_EPROCESS: EprocessOffsets = EprocessOffsets {
    bitness: WindowsBitness::X64,
    directory_table_base: 0x28,
    unique_process_id: 0x2E0,
    active_process_links: 0x2E8,
    image_file_name: 0x438,
    peb: 0x3E8,
    section_base_address: 0x3B0,
};

/// Windows 8.1 / Server 2012 R2 (build 9600)
const WIN81_X64_EPROCESS: EprocessOffsets = EprocessOffsets {
    bitness: WindowsBitness::X64,
    directory_table_base: 0x28,
    unique_process_id: 0x2E0,
    active_process_links: 0x2E8,
    image_file_name: 0x438,
    peb: 0x3E8,
    section_base_address: 0x3B0,
};

/// Windows Vista SP0-SP2 / Server 2008 (builds 6000-6003)
const VISTA_X64_EPROCESS: EprocessOffsets = EprocessOffsets {
    bitness: WindowsBitness::X64,
    directory_table_base: 0x28,
    unique_process_id: 0xE0,
    active_process_links: 0xE8,
    image_file_name: 0x238,
    peb: 0x290,
    section_base_address: 0x1D0,
};

/// Windows 10 1507 (build 10240) — filename at 0x448, not 0x450
/// Note: 1511 (10586) moved ImageFileName to 0x450; use WIN10_1607 for that build.
const WIN10_1507_X64_EPROCESS: EprocessOffsets = EprocessOffsets {
    bitness: WindowsBitness::X64,
    directory_table_base: 0x28,
    unique_process_id: 0x2E8,
    active_process_links: 0x2F0,
    image_file_name: 0x448,
    peb: 0x3F8,
    section_base_address: 0x3C0,
};

/// Windows 10 1511/1607 (builds 10586, 14393) / Server 2016
const WIN10_1607_X64_EPROCESS: EprocessOffsets = EprocessOffsets {
    bitness: WindowsBitness::X64,
    directory_table_base: 0x28,
    unique_process_id: 0x2E8,
    active_process_links: 0x2F0,
    image_file_name: 0x450,
    peb: 0x3F8,
    section_base_address: 0x3C0,
};

/// Windows 10 1903/1909 (builds 18362-18363) — SectionBaseAddress at 0x3C8 (not 0x3C0)
const WIN10_1903_X64_EPROCESS: EprocessOffsets = EprocessOffsets {
    bitness: WindowsBitness::X64,
    directory_table_base: 0x28,
    unique_process_id: 0x2E8,
    active_process_links: 0x2F0,
    image_file_name: 0x450,
    peb: 0x3F8,
    section_base_address: 0x3C8,
};

/// Windows 10 1703-1809 (builds 15063-17763) — PID at 0x2E0 (not 0x2E8)
const WIN10_1703_X64_EPROCESS: EprocessOffsets = EprocessOffsets {
    bitness: WindowsBitness::X64,
    directory_table_base: 0x28,
    unique_process_id: 0x2E0,
    active_process_links: 0x2E8,
    image_file_name: 0x450,
    peb: 0x3F8,
    section_base_address: 0x3C0,
};

/// Windows 10 2004-22H2 (builds 19041-19045) / Server 2019/2022 / Windows 11 21H2-23H2
pub const WIN10_X64_EPROCESS: EprocessOffsets = EprocessOffsets {
    bitness: WindowsBitness::X64,
    directory_table_base: 0x28,
    unique_process_id: 0x440,
    active_process_links: 0x448,
    image_file_name: 0x5A8,
    peb: 0x550,
    section_base_address: 0x520,
};

/// Windows 11 24H2+ / Server 2025 (build 26100+) — major EPROCESS restructuring
const WIN11_24H2_X64_EPROCESS: EprocessOffsets = EprocessOffsets {
    bitness: WindowsBitness::X64,
    directory_table_base: 0x28,
    unique_process_id: 0x1D0,
    active_process_links: 0x1D8,
    image_file_name: 0x338,
    peb: 0x2E0,
    section_base_address: 0x2B0,
};

/// Windows Vista SP2 x86 (builds 6002-6003)
const VISTA_X86_EPROCESS: EprocessOffsets = EprocessOffsets {
    bitness: WindowsBitness::X86Pae,
    directory_table_base: 0x18,
    unique_process_id: 0x9C,
    active_process_links: 0xA0,
    image_file_name: 0x14C,
    peb: 0x188,
    section_base_address: 0x114,
};

/// Windows 7 SP1 x86 (build 7601)
const WIN7_X86_EPROCESS: EprocessOffsets = EprocessOffsets {
    bitness: WindowsBitness::X86Pae,
    directory_table_base: 0x18,
    unique_process_id: 0xB4,
    active_process_links: 0xB8,
    image_file_name: 0x16C,
    peb: 0x1A8,
    section_base_address: 0x12C,
};

/// Windows 8 / 8.1 x86 (builds 9200-9600)
const WIN8_X86_EPROCESS: EprocessOffsets = EprocessOffsets {
    bitness: WindowsBitness::X86Pae,
    directory_table_base: 0x18,
    unique_process_id: 0xB4,
    active_process_links: 0xB8,
    image_file_name: 0x170,
    peb: 0x140,
    section_base_address: 0x120,
};

/// Windows 10 1507-1607 x86 (builds 10240-14393)
const WIN10_EARLY_X86_EPROCESS: EprocessOffsets = EprocessOffsets {
    bitness: WindowsBitness::X86Pae,
    directory_table_base: 0x18,
    unique_process_id: 0xB4,
    active_process_links: 0xB8,
    image_file_name: 0x170,
    peb: 0x1A8,
    section_base_address: 0x130,
};

/// Windows 10 1703-22H2 x86 (builds 15063-19045)
const WIN10_LATE_X86_EPROCESS: EprocessOffsets = EprocessOffsets {
    bitness: WindowsBitness::X86Pae,
    directory_table_base: 0x18,
    unique_process_id: 0xE8,
    active_process_links: 0xEC,
    image_file_name: 0x2E0,
    peb: 0x288,
    section_base_address: 0x258,
};

/// Windows XP SP3 (build 2600, 32-bit)
const WINXP_X86_EPROCESS: EprocessOffsets = EprocessOffsets {
    bitness: WindowsBitness::X86Pae,
    directory_table_base: 0x18,
    unique_process_id: 0x84,
    active_process_links: 0x88,
    image_file_name: 0x174,
    peb: 0x1B0,
    section_base_address: 0x13C,
};

/// Windows Server 2003 SP2 (build 3790, 32-bit)
const WIN2003_X86_EPROCESS: EprocessOffsets = EprocessOffsets {
    bitness: WindowsBitness::X86Pae,
    directory_table_base: 0x18,
    unique_process_id: 0x94,
    active_process_links: 0x98,
    image_file_name: 0x164,
    peb: 0x1A0,
    section_base_address: 0x128,
};

/// Windows Server 2003 SP2 / XP x64 Edition (build 3790, 64-bit)
const WIN2003_X64_EPROCESS: EprocessOffsets = EprocessOffsets {
    bitness: WindowsBitness::X64,
    directory_table_base: 0x28,
    unique_process_id: 0xD8,
    active_process_links: 0xE0,
    image_file_name: 0x268,
    peb: 0x2C0,
    section_base_address: 0x1F8,
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

/// All known EPROCESS offset sets for brute-force scan (when build is unknown).
/// Ordered by likelihood (most common first). Pre-Vista offsets are last to avoid
/// false matches on modern VMs.
pub const ALL_EPROCESS_OFFSETS: &[EprocessOffsets] = &[
    WIN10_X64_EPROCESS,        // Win10 2004+ / Win11 21H2-23H2 (most common)
    WIN11_24H2_X64_EPROCESS,   // Win11 24H2+ / Server 2025
    WIN10_1903_X64_EPROCESS,   // Win10 1903/1909 (SectionBaseAddress=0x3C8)
    WIN10_1703_X64_EPROCESS,   // Win10 1703-1809 (PID=0x2E0)
    WIN10_1607_X64_EPROCESS,   // Win10 1511/1607 (PID=0x2E8, filename=0x450)
    WIN10_1507_X64_EPROCESS,   // Win10 1507 only (filename=0x448)
    WIN81_X64_EPROCESS,        // Win8.1
    WIN8_X64_EPROCESS,         // Win8
    WIN7_X64_EPROCESS,         // Win7
    VISTA_X64_EPROCESS,        // Vista SP0-SP2
    WIN10_LATE_X86_EPROCESS,   // Win10 1703-22H2 x86
    WIN10_EARLY_X86_EPROCESS,  // Win10 1507-1607 x86
    WIN8_X86_EPROCESS,         // Win8/8.1 x86
    WIN7_X86_EPROCESS,         // Win7 x86
    VISTA_X86_EPROCESS,        // Vista x86
    WIN2003_X64_EPROCESS,      // Win2003 x64
    WIN2003_X86_EPROCESS,      // Win2003 x86
    WINXP_X86_EPROCESS,        // WinXP x86
];
