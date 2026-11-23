//! Minimal Windows NT registry hive binary parser.
//!
//! Parses regf hive files to navigate keys, read values, and extract
//! class names needed for bootkey/SAM hash extraction.

use std::borrow::Cow;
use std::io::{Read, Seek};

use crate::error::{Result, VmkatzError};

mod source;
use crate::utils::{u16_le_or0, u32_le_or0};
use source::Source;

const HBIN_BASE: usize = 0x1000;

// NK cell field offsets (relative to cell data start, after "nk" signature).
// See https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md
const NK_OFF_SUBKEY_COUNT: usize = 0x14; // Number of stable subkeys (u32)
const NK_OFF_SUBKEYS_LIST: usize = 0x1C; // Offset to stable subkeys list (u32)
const NK_OFF_VALUE_COUNT: usize = 0x24; // Number of values (u32)
const NK_OFF_VALUES_LIST: usize = 0x28; // Offset to values list (u32)
const NK_OFF_CLASS_OFFSET: usize = 0x30; // Offset to class name (u32)
const NK_OFF_NAME_LEN: usize = 0x48; // Name length (u16)
const NK_OFF_CLASS_LEN: usize = 0x4A; // Class name length (u16)
const NK_OFF_NAME: usize = 0x4C; // Name string (variable length)

// VK cell field offsets (relative to cell data start, after "vk" signature).
const VK_OFF_NAME_LEN: usize = 0x02; // Name length (u16)
const VK_OFF_DATA_SIZE: usize = 0x04; // Data size (u32, high bit = inline flag)
const VK_OFF_DATA_OFFSET: usize = 0x08; // Data offset or inline data (u32)
const VK_OFF_NAME: usize = 0x14; // Name string (variable length)

/// A registry hive backed by bytes or bounded, seekable reads.
pub struct Hive<'a> {
    data: Source<'a>,
    root_cell_offset: u32,
}

/// A named key (NK) cell reference.
#[derive(Clone, Debug)]
pub struct Key<'a> {
    data: Cow<'a, [u8]>,
}

impl<'a> Hive<'a> {
    /// Parse a registry hive from raw bytes.
    /// Validates "regf" signature and extracts root cell offset.
    pub fn new(data: &'a [u8]) -> Result<Self> {
        Self::open_source(Source::bytes(data))
    }

    pub fn from_reader<R: Read + Seek + 'a>(reader: R) -> Result<Self> {
        Self::open_source(Source::reader(reader)?)
    }

    fn open_source(data: Source<'a>) -> Result<Self> {
        if data.len() < HBIN_BASE as u64 {
            return Err(hive_err("Hive too small"));
        }
        let header = data.read(0, 0x28)?;
        if &header[..4] != b"regf" {
            return Err(hive_err("Invalid regf signature"));
        }
        let root_cell_offset = u32_le_or0(&header, 0x24);
        Ok(Self {
            data,
            root_cell_offset,
        })
    }

    pub const fn len(&self) -> u64 {
        self.data.len()
    }
    pub const fn is_empty(&self) -> bool {
        self.data.len() == 0
    }

    pub fn root_key(&self) -> Result<Key<'a>> {
        self.key_at_offset(self.root_cell_offset)
    }

    pub(crate) fn finish<T>(&self, result: Result<T>) -> Result<T> {
        self.data.finish(result)
    }

    pub(super) fn read_range(&self, offset: u64, len: usize) -> Result<Cow<'a, [u8]>> {
        self.data.read(offset, len)
    }

    pub(super) fn key_at_offset(&self, offset: u32) -> Result<Key<'a>> {
        let file_off = HBIN_BASE as u64 + u64::from(offset) + 4;
        let header = self.data.read(file_off, NK_OFF_NAME)?;
        if u16_le_or0(&header, 0) != 0x6B6E {
            return Err(hive_err("Expected NK signature"));
        }
        let size = NK_OFF_NAME + usize::from(u16_le_or0(&header, NK_OFF_NAME_LEN));
        Ok(Key {
            data: self.data.read(file_off, size)?,
        })
    }

    fn cell_range(&self, offset: u32) -> Result<(u64, usize)> {
        let file_off = HBIN_BASE as u64 + u64::from(offset);
        let header = self.data.read(file_off, 4)?;
        let size = crate::utils::read_i32_le(&header, 0)
            .unwrap_or(0)
            .unsigned_abs();
        if size < 4 || file_off + u64::from(size) > self.data.len() {
            return Err(hive_err("Invalid cell size"));
        }
        Ok((file_off + 4, size as usize - 4))
    }

    fn cell_data(&self, offset: u32) -> Result<Cow<'a, [u8]>> {
        let (start, len) = self.cell_range(offset)?;
        self.data.read(start, len)
    }

    fn cell_prefix(&self, offset: u32, len: usize) -> Result<Cow<'a, [u8]>> {
        let (start, available) = self.cell_range(offset)?;
        if len > available {
            return Err(hive_err("Value data exceeds cell"));
        }
        self.data.read(start, len)
    }
}

impl<'a> Key<'a> {
    /// Navigate to a subkey by name (case-insensitive ASCII).
    pub fn subkey<'h>(&self, hive: &Hive<'h>, name: &str) -> Result<Key<'h>> {
        let subkey_count = u32_le_or0(&self.data, NK_OFF_SUBKEY_COUNT);
        if subkey_count == 0 {
            return Err(hive_err(&format!(
                "Key has no subkeys, looking for '{name}'"
            )));
        }
        let subkeys_list_offset = u32_le_or0(&self.data, NK_OFF_SUBKEYS_LIST);
        if subkeys_list_offset == 0xFFFF_FFFF {
            return Err(hive_err(&format!("No subkeys list, looking for '{name}'")));
        }

        hive.data
            .remember(Key::find_in_subkey_list(hive, subkeys_list_offset, name))
    }

    /// Enumerate all subkeys.
    pub fn subkeys<'h>(&self, hive: &Hive<'h>) -> Result<Vec<Key<'h>>> {
        let subkey_count = u32_le_or0(&self.data, NK_OFF_SUBKEY_COUNT) as usize;
        if subkey_count == 0 {
            return Ok(Vec::new());
        }
        let subkeys_list_offset = u32_le_or0(&self.data, NK_OFF_SUBKEYS_LIST);
        if subkeys_list_offset == 0xFFFF_FFFF {
            return Ok(Vec::new());
        }

        hive.data
            .remember(Key::collect_subkeys(hive, subkeys_list_offset))
    }

    /// Read a binary value by name.
    pub fn value(&self, hive: &Hive<'_>, name: &str) -> Result<Vec<u8>> {
        let value_count = u32_le_or0(&self.data, NK_OFF_VALUE_COUNT);
        let values_list_offset = u32_le_or0(&self.data, NK_OFF_VALUES_LIST);
        if value_count == 0 || values_list_offset == 0xFFFF_FFFF {
            return Err(hive_err(&format!("No values, looking for '{name}'")));
        }

        let list_data = hive.cell_data(values_list_offset)?;
        for i in 0..value_count as usize {
            if i * 4 + 4 > list_data.len() {
                break;
            }
            let vk_offset = u32_le_or0(&list_data, i * 4);
            let header = hive.cell_prefix(vk_offset, VK_OFF_NAME)?;
            if u16_le_or0(&header, 0) != 0x6B76 {
                continue;
            }
            let name_len = usize::from(u16_le_or0(&header, VK_OFF_NAME_LEN));
            let vk = hive.cell_prefix(vk_offset, VK_OFF_NAME + name_len)?;
            let vk_name = std::str::from_utf8(&vk[VK_OFF_NAME..]).unwrap_or("");
            if !vk_name.eq_ignore_ascii_case(name) {
                continue;
            }
            let data_size_raw = u32_le_or0(&vk, VK_OFF_DATA_SIZE);
            let data_offset = u32_le_or0(&vk, VK_OFF_DATA_OFFSET);
            let is_inline = data_size_raw & 0x8000_0000 != 0;
            let data_size = (data_size_raw & 0x7FFF_FFFF) as usize;

            if is_inline {
                // Data is stored inline in the data_offset field (high bit set)
                let inline_bytes = data_offset.to_le_bytes();
                return Ok(inline_bytes[..data_size.min(4)].to_vec());
            }

            // Data is in a separate cell
            return Ok(hive.cell_prefix(data_offset, data_size)?.into_owned());
        }

        Err(hive_err(&format!("Value '{name}' not found")))
    }

    /// Read a DWORD value by name.
    pub fn value_dword(&self, hive: &Hive<'_>, name: &str) -> Result<u32> {
        let data = self.value(hive, name)?;
        if data.len() < 4 {
            return Err(hive_err(&format!(
                "DWORD value '{}' too short: {} bytes",
                name,
                data.len()
            )));
        }
        Ok(crate::utils::read_u32_le(&data, 0).unwrap_or(0))
    }

    /// Read the class name associated with this key.
    pub fn class_name(&self, hive: &Hive<'_>) -> Result<String> {
        let class_offset = u32_le_or0(&self.data, NK_OFF_CLASS_OFFSET);
        let class_len = u16_le_or0(&self.data, NK_OFF_CLASS_LEN) as usize;
        if class_offset == 0xFFFF_FFFF || class_len == 0 {
            return Err(hive_err("No class name"));
        }

        let cell = hive.cell_prefix(class_offset, class_len)?;

        // Class name is typically UTF-16LE
        if class_len >= 2 && class_len.is_multiple_of(2) {
            Ok(crate::utils::utf16le_decode(&cell[..class_len]))
        } else {
            // ASCII fallback
            Ok(String::from_utf8_lossy(&cell[..class_len]).into_owned())
        }
    }

    /// Get the key name.
    pub fn name(&self) -> &str {
        let name_len = u16_le_or0(&self.data, NK_OFF_NAME_LEN) as usize;
        if name_len == 0 || NK_OFF_NAME + name_len > self.data.len() {
            return "";
        }
        std::str::from_utf8(&self.data[NK_OFF_NAME..NK_OFF_NAME + name_len]).unwrap_or("")
    }

    // --- Internal helpers ---

    fn find_in_subkey_list(hive: &Hive<'a>, list_offset: u32, name: &str) -> Result<Self> {
        let mut found = None;
        Self::visit_subkeys(hive, list_offset, |key| {
            let key = key?;
            if key.name().eq_ignore_ascii_case(name) {
                found = Some(key);
                return Ok(true);
            }
            Ok(false)
        })?;
        found.ok_or_else(|| hive_err(&format!("Subkey '{name}' not found")))
    }

    fn collect_subkeys(hive: &Hive<'a>, list_offset: u32) -> Result<Vec<Self>> {
        let mut keys = Vec::new();
        let mut bytes = 0usize;
        Self::visit_subkeys(hive, list_offset, |key| {
            if let Ok(key) = key {
                bytes += key.data.len() + std::mem::size_of::<Self>();
                if bytes > source::MAX_READ_BYTES {
                    return hive.data.remember(Err(VmkatzError::AllocTooLarge {
                        what: "registry subkey enumeration",
                        requested: bytes,
                        limit: source::MAX_READ_BYTES,
                    }));
                }
                keys.try_reserve(1)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::OutOfMemory, e))?;
                keys.push(key);
            }
            Ok(false)
        })?;
        Ok(keys)
    }

    fn visit_subkeys(
        hive: &Hive<'a>,
        list_offset: u32,
        mut visit: impl FnMut(Result<Self>) -> Result<bool>,
    ) -> Result<()> {
        let mut pending = vec![list_offset];
        let mut seen = std::collections::BTreeSet::new();
        while let Some(offset) = pending.pop() {
            if !seen.insert(offset) {
                continue;
            }
            if seen.len() > 65_536 {
                return hive.data.remember(Err(VmkatzError::RecoveryLimit(
                    "registry subkey traversal exceeds 65536 lists",
                )));
            }
            let cell = hive.cell_data(offset)?;
            if cell.len() < 4 {
                return Err(hive_err("Subkey list cell too small"));
            }
            let sig = u16_le_or0(&cell, 0);
            let count = usize::from(u16_le_or0(&cell, 2));
            let stride = match sig {
                0x666C | 0x686C => 8,
                0x696C | 0x6972 => 4,
                _ => return Err(hive_err("Unknown subkey list signature")),
            };
            if sig == 0x6972 {
                if pending.len() + count > 65_536 {
                    return hive.data.remember(Err(VmkatzError::RecoveryLimit(
                        "registry subkey traversal queue exceeds 65536 lists",
                    )));
                }
                pending
                    .try_reserve(count)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::OutOfMemory, e))?;
                for i in (0..count).rev() {
                    if 4 + i * stride + 4 <= cell.len() {
                        pending.push(u32_le_or0(&cell, 4 + i * stride));
                    }
                }
            } else {
                for i in 0..count {
                    if 4 + i * stride + 4 > cell.len() {
                        break;
                    }
                    if visit(hive.key_at_offset(u32_le_or0(&cell, 4 + i * stride)))? {
                        return Ok(());
                    }
                }
            }
        }
        Ok(())
    }
}

fn hive_err(msg: &str) -> VmkatzError {
    VmkatzError::DecryptionError(format!("Hive: {msg}"))
}

#[cfg(test)]
mod tests;
