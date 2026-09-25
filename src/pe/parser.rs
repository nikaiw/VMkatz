use crate::error::{Result, VmkatzError};
use crate::memory::VirtualMemory;

/// Parsed section header from in-memory PE.
#[derive(Debug, Clone)]
pub struct SectionHeader {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
}

// IMAGE_FILE_MACHINE constants (PE COFF header).
const IMAGE_FILE_MACHINE_I386: u16 = 0x14C;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_MACHINE_ARM64: u16 = 0xAA64;

/// Minimal in-memory PE parser.
#[derive(Debug)]
pub struct PeHeaders {
    pub image_base: u64,
    pub size_of_image: u32,
    pub sections: Vec<SectionHeader>,
}

impl PeHeaders {
    /// Parse PE headers from a DLL loaded in virtual memory at `base`.
    pub fn parse_from_memory(vmem: &dyn VirtualMemory, base: u64) -> Result<Self> {
        // DOS header: MZ signature
        let mz = vmem.read_virt_u16(base)?;
        if mz != 0x5A4D {
            return Err(VmkatzError::PeError(
                base,
                "Invalid MZ signature".to_string(),
            ));
        }

        // e_lfanew at offset 0x3C
        let e_lfanew = u64::from(vmem.read_virt_u32(base + 0x3C)?);
        let pe_offset = base + e_lfanew;

        // PE signature
        let pe_sig = vmem.read_virt_u32(pe_offset)?;
        if pe_sig != 0x00004550 {
            return Err(VmkatzError::PeError(
                base,
                "Invalid PE signature".to_string(),
            ));
        }

        // COFF header (20 bytes after PE signature)
        let coff_offset = pe_offset + 4;

        // Machine type validation
        let machine = vmem.read_virt_u16(coff_offset)?;
        match machine {
            IMAGE_FILE_MACHINE_I386 | IMAGE_FILE_MACHINE_AMD64 | IMAGE_FILE_MACHINE_ARM64 => {}
            _ => {
                return Err(VmkatzError::PeError(
                    base,
                    format!("Unsupported PE machine type: 0x{machine:04x}"),
                ));
            }
        }

        let num_sections = vmem.read_virt_u16(coff_offset + 2)? as usize;
        if num_sections > 96 {
            return Err(VmkatzError::PeError(
                base,
                format!("Too many PE sections: {num_sections}"),
            ));
        }

        let size_of_optional = u64::from(vmem.read_virt_u16(coff_offset + 16)?);

        // Optional header
        let opt_offset = coff_offset + 20;
        let magic = vmem.read_virt_u16(opt_offset)?;
        let is_pe32plus = magic == 0x20B;

        // SizeOfOptionalHeader minimum validation
        let min_opt_size: u64 = if is_pe32plus { 112 } else { 96 };
        if size_of_optional < min_opt_size {
            return Err(VmkatzError::PeError(
                base,
                format!(
                    "PE SizeOfOptionalHeader too small: {size_of_optional} (min {min_opt_size})"
                ),
            ));
        }

        let size_of_image = vmem.read_virt_u32(opt_offset + 56)?;

        let image_base = if is_pe32plus {
            vmem.read_virt_u64(opt_offset + 24)?
        } else {
            u64::from(vmem.read_virt_u32(opt_offset + 28)?)
        };

        // Section table starts after optional header
        let sections_offset = opt_offset + size_of_optional;
        let mut sections = Vec::with_capacity(num_sections);

        for i in 0..num_sections {
            let sec_offset = sections_offset + (i as u64 * 40);
            let mut name_buf = [0u8; 8];
            vmem.read_virt(sec_offset, &mut name_buf)?;
            let end = name_buf.iter().position(|&b| b == 0).unwrap_or(8);
            let name = String::from_utf8_lossy(&name_buf[..end]).into_owned();

            let virtual_size = vmem.read_virt_u32(sec_offset + 8)?;
            let virtual_address = vmem.read_virt_u32(sec_offset + 12)?;

            sections.push(SectionHeader {
                name,
                virtual_address,
                virtual_size,
            });
        }

        Ok(Self {
            image_base,
            size_of_image,
            sections,
        })
    }

    /// Find a section by name.
    pub fn find_section(&self, name: &str) -> Option<&SectionHeader> {
        self.sections.iter().find(|s| s.name == name)
    }
}
