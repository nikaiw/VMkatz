use crate::error::Result;
use crate::memory::PhysicalMemory;
use crate::windows::offsets::EprocessOffsets;

/// Read EPROCESS fields from a physical address.
pub struct EprocessReader<'a> {
    pub offsets: &'a EprocessOffsets,
}

impl<'a> EprocessReader<'a> {
    pub fn new(offsets: &'a EprocessOffsets) -> Self {
        Self { offsets }
    }

    /// Read the DirectoryTableBase (CR3/DTB) from an EPROCESS at the given physical address.
    pub fn read_dtb(&self, phys: &impl PhysicalMemory, eprocess_phys: u64) -> Result<u64> {
        phys.read_phys_u64(eprocess_phys + self.offsets.directory_table_base)
    }

    /// Read the UniqueProcessId (PID) from an EPROCESS at the given physical address.
    pub fn read_pid(&self, phys: &impl PhysicalMemory, eprocess_phys: u64) -> Result<u64> {
        phys.read_phys_u64(eprocess_phys + self.offsets.unique_process_id)
    }

    /// Read the ImageFileName (15-byte ASCII) from an EPROCESS at the given physical address.
    pub fn read_image_name(
        &self,
        phys: &impl PhysicalMemory,
        eprocess_phys: u64,
    ) -> Result<String> {
        let mut buf = [0u8; 15];
        phys.read_phys(eprocess_phys + self.offsets.image_file_name, &mut buf)?;
        // ImageFileName is null-terminated ASCII; filter to printable bytes
        // to avoid garbage characters (e.g. PID 0 Idle process has 0xFF fill)
        let name: String = buf
            .iter()
            .take_while(|&&b| b != 0)
            .filter(|&&b| b.is_ascii_graphic() || b == b' ' || b == b'.')
            .map(|&b| b as char)
            .collect();
        Ok(name)
    }

    /// Read the ActiveProcessLinks.Flink from an EPROCESS at the given physical address.
    pub fn read_flink(&self, phys: &impl PhysicalMemory, eprocess_phys: u64) -> Result<u64> {
        phys.read_phys_u64(eprocess_phys + self.offsets.active_process_links)
    }

    /// Read the PEB virtual address from an EPROCESS at the given physical address.
    pub fn read_peb(&self, phys: &impl PhysicalMemory, eprocess_phys: u64) -> Result<u64> {
        phys.read_phys_u64(eprocess_phys + self.offsets.peb)
    }
}
