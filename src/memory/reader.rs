use crate::error::Result;

/// Read from guest physical address space.
pub trait PhysicalMemory {
    fn read_phys(&self, phys_addr: u64, buf: &mut [u8]) -> Result<()>;

    fn read_phys_u8(&self, addr: u64) -> Result<u8> {
        let mut buf = [0u8; 1];
        self.read_phys(addr, &mut buf)?;
        Ok(buf[0])
    }

    fn read_phys_u16(&self, addr: u64) -> Result<u16> {
        let mut buf = [0u8; 2];
        self.read_phys(addr, &mut buf)?;
        Ok(u16::from_le_bytes(buf))
    }

    fn read_phys_u32(&self, addr: u64) -> Result<u32> {
        let mut buf = [0u8; 4];
        self.read_phys(addr, &mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn read_phys_u64(&self, addr: u64) -> Result<u64> {
        let mut buf = [0u8; 8];
        self.read_phys(addr, &mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    fn read_phys_bytes(&self, addr: u64, len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        self.read_phys(addr, &mut buf)?;
        Ok(buf)
    }

    /// Total size of the physical address space.
    fn phys_size(&self) -> u64;

    /// Whether the backing file is truncated (smaller than expected).
    /// Used by carve mode to skip expensive EPT scanning on truncated files.
    fn is_truncated(&self) -> bool {
        false
    }
}

/// Read from a process's virtual address space (page-table-translated).
pub trait VirtualMemory {
    fn read_virt(&self, vaddr: u64, buf: &mut [u8]) -> Result<()>;

    fn read_virt_u8(&self, addr: u64) -> Result<u8> {
        let mut buf = [0u8; 1];
        self.read_virt(addr, &mut buf)?;
        Ok(buf[0])
    }

    fn read_virt_u16(&self, addr: u64) -> Result<u16> {
        let mut buf = [0u8; 2];
        self.read_virt(addr, &mut buf)?;
        Ok(u16::from_le_bytes(buf))
    }

    fn read_virt_u32(&self, addr: u64) -> Result<u32> {
        let mut buf = [0u8; 4];
        self.read_virt(addr, &mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn read_virt_u64(&self, addr: u64) -> Result<u64> {
        let mut buf = [0u8; 8];
        self.read_virt(addr, &mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    fn read_virt_bytes(&self, addr: u64, len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        self.read_virt(addr, &mut buf)?;
        Ok(buf)
    }

    /// Read a null-terminated UTF-16LE string.
    fn read_unicode_string(&self, addr: u64, max_len: usize) -> Result<String> {
        let data = self.read_virt_bytes(addr, max_len)?;
        Ok(utf16le_to_string(&data))
    }

    /// Read a Windows UNICODE_STRING structure (Length u16, MaxLength u16, padding, Buffer ptr).
    fn read_win_unicode_string(&self, addr: u64) -> Result<String> {
        let length = self.read_virt_u16(addr)? as usize;
        if length == 0 || length > 0x1000 {
            return Ok(String::new());
        }
        let max_length = self.read_virt_u16(addr + 2)? as usize;
        if max_length < length {
            return Ok(String::new());
        }
        let buffer_ptr = self.read_virt_u64(addr + 8)?;
        if buffer_ptr == 0 || buffer_ptr < 0x10000 {
            return Ok(String::new());
        }
        // Check for canonical address (user-mode or kernel)
        let high = buffer_ptr >> 48;
        if high != 0 && high != 0xFFFF {
            return Ok(String::new());
        }
        let data = self.read_virt_bytes(buffer_ptr, length)?;
        Ok(utf16le_to_string(&data))
    }

    /// Read a 32-bit Windows UNICODE_STRING structure (Length u16, MaxLength u16, Buffer u32).
    /// Used for pre-Vista 32-bit processes where pointers are 4 bytes.
    fn read_win_unicode_string_32(&self, addr: u64) -> Result<String> {
        let length = self.read_virt_u16(addr)? as usize;
        if length == 0 || length > 0x1000 {
            return Ok(String::new());
        }
        let max_length = self.read_virt_u16(addr + 2)? as usize;
        if max_length < length {
            return Ok(String::new());
        }
        // 32-bit UNICODE_STRING: Buffer pointer is at offset 4 (u32), not offset 8 (u64)
        let buffer_ptr = u64::from(self.read_virt_u32(addr + 4)?);
        if buffer_ptr == 0 || buffer_ptr < 0x10000 {
            return Ok(String::new());
        }
        let data = self.read_virt_bytes(buffer_ptr, length)?;
        Ok(utf16le_to_string(&data))
    }

    /// Read a UTF-16LE string given a buffer address and byte length directly.
    fn read_win_unicode_string_raw(&self, buffer_ptr: u64, byte_len: usize) -> Result<String> {
        if byte_len == 0 || byte_len > 0x1000 || buffer_ptr == 0 {
            return Ok(String::new());
        }
        let data = self.read_virt_bytes(buffer_ptr, byte_len)?;
        Ok(utf16le_to_string(&data))
    }
}

/// Decode UTF-16LE bytes to String (shared impl in `crate::utils`).
fn utf16le_to_string(data: &[u8]) -> String {
    crate::utils::utf16le_decode(data)
}
