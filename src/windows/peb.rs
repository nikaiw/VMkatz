use crate::error::Result;
use crate::memory::VirtualMemory;
use crate::windows::offsets::LdrOffsets;

/// PEB / LDR offsets for 32-bit Windows (WinXP, Win2003).
/// PEB.Ldr is at 0x0C (not 0x18 as in x64).
pub const X86_LDR: LdrOffsets = LdrOffsets {
    peb_ldr: 0x0C,
    ldr_in_load_order: 0x0C, // InLoadOrderModuleList at PEB_LDR_DATA+0x0C
    ldr_in_memory_order: 0x14,
    ldr_entry_dll_base: 0x18,      // DllBase in LDR_DATA_TABLE_ENTRY
    ldr_entry_size_of_image: 0x20, // SizeOfImage
    ldr_entry_full_dll_name: 0x24, // FullDllName (UNICODE_STRING32)
    ldr_entry_base_dll_name: 0x2C, // BaseDllName (UNICODE_STRING32)
};

/// A loaded DLL in a process's address space.
#[derive(Debug)]
pub struct LoadedModule {
    pub base: u64,
    pub size: u32,
    pub full_name: String,
    pub base_name: String,
}

/// Walk PEB -> PEB_LDR_DATA -> InLoadOrderModuleList to enumerate loaded DLLs.
pub fn enumerate_modules(
    vmem: &dyn VirtualMemory,
    peb_addr: u64,
    ldr_offsets: &LdrOffsets,
) -> Result<Vec<LoadedModule>> {
    let mut modules = Vec::new();

    // PEB.Ldr
    let ldr = vmem.read_virt_u64(peb_addr + ldr_offsets.peb_ldr)?;
    if ldr == 0 {
        return Ok(modules);
    }

    // PEB_LDR_DATA.InLoadOrderModuleList (LIST_ENTRY: Flink, Blink)
    let list_head = ldr + ldr_offsets.ldr_in_load_order;
    let first_flink = vmem.read_virt_u64(list_head)?;
    if first_flink == 0 || first_flink == list_head {
        return Ok(modules);
    }

    let mut current = first_flink;
    let mut visited = std::collections::HashSet::new();

    loop {
        if current == list_head || visited.contains(&current) || current == 0 {
            break;
        }
        visited.insert(current);

        // LDR_DATA_TABLE_ENTRY starts at the LIST_ENTRY (InLoadOrderLinks is at offset 0)
        let entry_base = current;

        let Ok(dll_base) = vmem.read_virt_u64(entry_base + ldr_offsets.ldr_entry_dll_base) else {
            break;
        };

        if dll_base == 0 {
            // Skip sentinel entries
            let next = vmem.read_virt_u64(current)?;
            current = next;
            continue;
        }

        let size = vmem
            .read_virt_u32(entry_base + ldr_offsets.ldr_entry_size_of_image)
            .unwrap_or(0);

        let base_name = vmem
            .read_win_unicode_string(entry_base + ldr_offsets.ldr_entry_base_dll_name)
            .unwrap_or_default();

        let full_name = vmem
            .read_win_unicode_string(entry_base + ldr_offsets.ldr_entry_full_dll_name)
            .unwrap_or_default();

        modules.push(LoadedModule {
            base: dll_base,
            size,
            full_name,
            base_name,
        });

        // Follow Flink to next entry
        let Ok(next) = vmem.read_virt_u64(current) else {
            break;
        };
        current = next;
    }

    Ok(modules)
}

/// Walk PEB -> PEB_LDR_DATA -> InLoadOrderModuleList for 32-bit processes.
/// Uses 32-bit pointers and 32-bit UNICODE_STRING structures.
pub fn enumerate_modules_32(
    vmem: &dyn VirtualMemory,
    peb_addr: u64,
    ldr_offsets: &LdrOffsets,
) -> Result<Vec<LoadedModule>> {
    let mut modules = Vec::new();

    // PEB.Ldr (32-bit pointer)
    let ldr = u64::from(vmem.read_virt_u32(peb_addr + ldr_offsets.peb_ldr)?);
    if ldr == 0 {
        return Ok(modules);
    }

    // PEB_LDR_DATA.InLoadOrderModuleList (LIST_ENTRY32: Flink u32, Blink u32)
    let list_head = ldr + ldr_offsets.ldr_in_load_order;
    let first_flink = u64::from(vmem.read_virt_u32(list_head)?);
    if first_flink == 0 || first_flink == list_head {
        return Ok(modules);
    }

    let mut current = first_flink;
    let mut visited = std::collections::HashSet::new();

    loop {
        if current == list_head || visited.contains(&current) || current == 0 || current < 0x10000 {
            break;
        }
        visited.insert(current);

        let entry_base = current;

        // DllBase (32-bit pointer)
        let dll_base = match vmem.read_virt_u32(entry_base + ldr_offsets.ldr_entry_dll_base) {
            Ok(b) => u64::from(b),
            Err(_) => break,
        };

        if dll_base == 0 {
            let next = u64::from(vmem.read_virt_u32(current).unwrap_or(0));
            current = next;
            continue;
        }

        let size = vmem
            .read_virt_u32(entry_base + ldr_offsets.ldr_entry_size_of_image)
            .unwrap_or(0);

        // Use 32-bit UNICODE_STRING for names
        let base_name = vmem
            .read_win_unicode_string_32(entry_base + ldr_offsets.ldr_entry_base_dll_name)
            .unwrap_or_default();

        let full_name = vmem
            .read_win_unicode_string_32(entry_base + ldr_offsets.ldr_entry_full_dll_name)
            .unwrap_or_default();

        modules.push(LoadedModule {
            base: dll_base,
            size,
            full_name,
            base_name,
        });

        // Follow Flink (32-bit)
        let next = match vmem.read_virt_u32(current) {
            Ok(n) => u64::from(n),
            Err(_) => break,
        };
        current = next;
    }

    Ok(modules)
}
