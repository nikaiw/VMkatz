//! Minimal Windows NT registry hive binary parser.
//!
//! Parses regf hive files to navigate keys, read values, and extract
//! class names needed for bootkey/SAM hash extraction.

use crate::error::{GovmemError, Result};

const HBIN_BASE: usize = 0x1000;

/// A parsed registry hive backed by a byte slice.
pub struct Hive<'a> {
    data: &'a [u8],
    root_cell_offset: u32,
}

/// A named key (NK) cell reference.
#[derive(Clone, Debug)]
pub struct Key<'a> {
    data: &'a [u8],
    /// File offset of NK cell data (after cell size i32).
    cell_offset: usize,
}

impl<'a> Hive<'a> {
    /// Parse a registry hive from raw bytes.
    /// Validates "regf" signature and extracts root cell offset.
    pub fn new(data: &'a [u8]) -> Result<Self> {
        if data.len() < HBIN_BASE {
            return Err(hive_err("Hive too small"));
        }
        if &data[0..4] != b"regf" {
            return Err(hive_err("Invalid regf signature"));
        }
        let root_cell_offset = u32_at(data, 0x24);
        Ok(Hive {
            data,
            root_cell_offset,
        })
    }

    /// Get the root key of the hive.
    pub fn root_key(&self) -> Result<Key<'a>> {
        self.key_at_offset(self.root_cell_offset)
    }

    /// Read a key at a given hive-relative offset (relative to HBIN_BASE).
    fn key_at_offset(&self, offset: u32) -> Result<Key<'a>> {
        let file_off = HBIN_BASE + offset as usize + 4; // skip cell size i32
        if file_off + 0x4C > self.data.len() {
            return Err(hive_err("NK cell out of bounds"));
        }
        let sig = u16_at(self.data, file_off);
        if sig != 0x6B6E {
            // "nk" as u16 LE
            return Err(hive_err(&format!(
                "Expected NK signature at 0x{:x}, got 0x{:04x}",
                file_off, sig
            )));
        }
        Ok(Key {
            data: self.data,
            cell_offset: file_off,
        })
    }

    /// Read raw cell data at a hive-relative offset.
    fn cell_data(&self, offset: u32) -> Result<&'a [u8]> {
        let file_off = HBIN_BASE + offset as usize;
        if file_off + 4 > self.data.len() {
            return Err(hive_err("Cell offset out of bounds"));
        }
        let size = i32::from_le_bytes(self.data[file_off..file_off + 4].try_into().unwrap());
        // Allocated cells have negative size
        let abs_size = size.unsigned_abs() as usize;
        if abs_size < 4 || file_off + abs_size > self.data.len() {
            return Err(hive_err("Invalid cell size"));
        }
        Ok(&self.data[file_off + 4..file_off + abs_size])
    }
}

impl<'a> Key<'a> {
    /// Navigate to a subkey by name (case-insensitive ASCII).
    pub fn subkey(&self, hive: &Hive<'a>, name: &str) -> Result<Key<'a>> {
        let subkey_count = u32_at(self.data, self.cell_offset + 0x14);
        if subkey_count == 0 {
            return Err(hive_err(&format!(
                "Key has no subkeys, looking for '{}'",
                name
            )));
        }
        let subkeys_list_offset = u32_at(self.data, self.cell_offset + 0x1C);
        if subkeys_list_offset == 0xFFFF_FFFF {
            return Err(hive_err(&format!(
                "No subkeys list, looking for '{}'",
                name
            )));
        }

        self.find_in_subkey_list(hive, subkeys_list_offset, name)
    }

    /// Enumerate all subkeys.
    pub fn subkeys(&self, hive: &Hive<'a>) -> Result<Vec<Key<'a>>> {
        let subkey_count = u32_at(self.data, self.cell_offset + 0x14) as usize;
        if subkey_count == 0 {
            return Ok(Vec::new());
        }
        let subkeys_list_offset = u32_at(self.data, self.cell_offset + 0x1C);
        if subkeys_list_offset == 0xFFFF_FFFF {
            return Ok(Vec::new());
        }

        self.collect_subkeys(hive, subkeys_list_offset)
    }

    /// Read a binary value by name.
    pub fn value(&self, hive: &Hive<'a>, name: &str) -> Result<Vec<u8>> {
        let value_count = u32_at(self.data, self.cell_offset + 0x24);
        let values_list_offset = u32_at(self.data, self.cell_offset + 0x28);
        if value_count == 0 || values_list_offset == 0xFFFF_FFFF {
            return Err(hive_err(&format!("No values, looking for '{}'", name)));
        }

        let list_data = hive.cell_data(values_list_offset)?;
        for i in 0..value_count as usize {
            if i * 4 + 4 > list_data.len() {
                break;
            }
            let vk_offset = u32_at(list_data, i * 4);
            let vk_file_off = HBIN_BASE + vk_offset as usize + 4; // skip cell size
            if vk_file_off + 0x14 > self.data.len() {
                continue;
            }
            let vk_sig = u16_at(self.data, vk_file_off);
            if vk_sig != 0x6B76 {
                // "vk" as u16 LE
                continue;
            }
            let name_len = u16_at(self.data, vk_file_off + 0x02) as usize;
            let vk_name = if name_len > 0 && vk_file_off + 0x14 + name_len <= self.data.len() {
                std::str::from_utf8(&self.data[vk_file_off + 0x14..vk_file_off + 0x14 + name_len])
                    .unwrap_or("")
            } else {
                ""
            };

            if !vk_name.eq_ignore_ascii_case(name) {
                continue;
            }

            let data_size_raw = u32_at(self.data, vk_file_off + 0x04);
            let data_offset = u32_at(self.data, vk_file_off + 0x08);
            let is_inline = data_size_raw & 0x8000_0000 != 0;
            let data_size = (data_size_raw & 0x7FFF_FFFF) as usize;

            if is_inline || data_size <= 4 {
                // Data is stored inline in the data_offset field
                let inline_bytes = data_offset.to_le_bytes();
                return Ok(inline_bytes[..data_size.min(4)].to_vec());
            }

            // Data is in a separate cell
            let cell = hive.cell_data(data_offset)?;
            if data_size > cell.len() {
                return Err(hive_err("Value data exceeds cell"));
            }
            return Ok(cell[..data_size].to_vec());
        }

        Err(hive_err(&format!("Value '{}' not found", name)))
    }

    /// Read a DWORD value by name.
    pub fn value_dword(&self, hive: &Hive<'a>, name: &str) -> Result<u32> {
        let data = self.value(hive, name)?;
        if data.len() < 4 {
            return Err(hive_err(&format!(
                "DWORD value '{}' too short: {} bytes",
                name,
                data.len()
            )));
        }
        Ok(u32::from_le_bytes(data[..4].try_into().unwrap()))
    }

    /// Read the class name associated with this key.
    pub fn class_name(&self, hive: &Hive<'a>) -> Result<String> {
        let class_offset = u32_at(self.data, self.cell_offset + 0x30);
        let class_len = u16_at(self.data, self.cell_offset + 0x4A) as usize;
        if class_offset == 0xFFFF_FFFF || class_len == 0 {
            return Err(hive_err("No class name"));
        }

        let cell = hive.cell_data(class_offset)?;
        if class_len > cell.len() {
            return Err(hive_err("Class name exceeds cell"));
        }

        // Class name is typically UTF-16LE
        if class_len >= 2 && class_len.is_multiple_of(2) {
            let u16s: Vec<u16> = cell[..class_len]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            Ok(String::from_utf16_lossy(&u16s))
        } else {
            // ASCII fallback
            Ok(String::from_utf8_lossy(&cell[..class_len]).into_owned())
        }
    }

    /// Get the key name.
    pub fn name(&self) -> &str {
        let name_len = u16_at(self.data, self.cell_offset + 0x48) as usize;
        if name_len == 0 || self.cell_offset + 0x4C + name_len > self.data.len() {
            return "";
        }
        std::str::from_utf8(&self.data[self.cell_offset + 0x4C..self.cell_offset + 0x4C + name_len])
            .unwrap_or("")
    }

    // --- Internal helpers ---

    fn find_in_subkey_list(
        &self,
        hive: &Hive<'a>,
        list_offset: u32,
        name: &str,
    ) -> Result<Key<'a>> {
        let cell = hive.cell_data(list_offset)?;
        if cell.len() < 4 {
            return Err(hive_err("Subkey list cell too small"));
        }
        let sig = u16_at(cell, 0);
        let count = u16_at(cell, 2) as usize;

        match sig {
            // "lf" or "lh": array of (u32 offset, u32 hash)
            0x666C | 0x686C => {
                for i in 0..count {
                    let entry_off = 4 + i * 8;
                    if entry_off + 4 > cell.len() {
                        break;
                    }
                    let nk_offset = u32_at(cell, entry_off);
                    let key = hive.key_at_offset(nk_offset)?;
                    if key.name().eq_ignore_ascii_case(name) {
                        return Ok(key);
                    }
                }
            }
            // "li": array of u32 offsets (no hash)
            0x696C => {
                for i in 0..count {
                    let entry_off = 4 + i * 4;
                    if entry_off + 4 > cell.len() {
                        break;
                    }
                    let nk_offset = u32_at(cell, entry_off);
                    let key = hive.key_at_offset(nk_offset)?;
                    if key.name().eq_ignore_ascii_case(name) {
                        return Ok(key);
                    }
                }
            }
            // "ri": array of u32 offsets to sub-lists
            0x6972 => {
                for i in 0..count {
                    let entry_off = 4 + i * 4;
                    if entry_off + 4 > cell.len() {
                        break;
                    }
                    let sub_offset = u32_at(cell, entry_off);
                    if let Ok(key) = self.find_in_subkey_list(hive, sub_offset, name) {
                        return Ok(key);
                    }
                }
            }
            _ => {
                return Err(hive_err(&format!(
                    "Unknown subkey list signature: 0x{:04x}",
                    sig
                )));
            }
        }

        Err(hive_err(&format!("Subkey '{}' not found", name)))
    }

    fn collect_subkeys(&self, hive: &Hive<'a>, list_offset: u32) -> Result<Vec<Key<'a>>> {
        let cell = hive.cell_data(list_offset)?;
        if cell.len() < 4 {
            return Err(hive_err("Subkey list cell too small"));
        }
        let sig = u16_at(cell, 0);
        let count = u16_at(cell, 2) as usize;
        let mut keys = Vec::with_capacity(count);

        match sig {
            0x666C | 0x686C => {
                for i in 0..count {
                    let entry_off = 4 + i * 8;
                    if entry_off + 4 > cell.len() {
                        break;
                    }
                    let nk_offset = u32_at(cell, entry_off);
                    if let Ok(key) = hive.key_at_offset(nk_offset) {
                        keys.push(key);
                    }
                }
            }
            0x696C => {
                for i in 0..count {
                    let entry_off = 4 + i * 4;
                    if entry_off + 4 > cell.len() {
                        break;
                    }
                    let nk_offset = u32_at(cell, entry_off);
                    if let Ok(key) = hive.key_at_offset(nk_offset) {
                        keys.push(key);
                    }
                }
            }
            0x6972 => {
                for i in 0..count {
                    let entry_off = 4 + i * 4;
                    if entry_off + 4 > cell.len() {
                        break;
                    }
                    let sub_offset = u32_at(cell, entry_off);
                    if let Ok(mut sub_keys) = self.collect_subkeys(hive, sub_offset) {
                        keys.append(&mut sub_keys);
                    }
                }
            }
            _ => {}
        }

        Ok(keys)
    }
}

fn hive_err(msg: &str) -> GovmemError {
    GovmemError::DecryptionError(format!("Hive: {}", msg))
}

fn u16_at(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(data[off..off + 2].try_into().unwrap())
}

fn u32_at(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(data[off..off + 4].try_into().unwrap())
}
