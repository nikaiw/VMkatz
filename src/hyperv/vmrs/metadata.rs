//! Bounded metadata and streaming KeyTable traversal.

use std::collections::HashMap;
use std::fs;
use std::io::{self, BufReader, Read, Seek, SeekFrom};

use super::{ObjectTableEntry, RAM_BLOCK_SIZE, VmrsLayer};
use crate::error::{Result, VmkatzError};
use crate::utils::{u32_le, u64_le};

pub(super) const MAX_OBJECT_ENTRIES: usize = 262_144;
const MAX_KEY_BYTES: usize = 32 * 1024 * 1024;
const MAX_PATH_BYTES: usize = 4096;
const MAX_DEPTH: usize = 64;
const MAX_KEY_STEPS: usize = 1_000_000;

fn limit(message: &str) -> VmkatzError {
    io::Error::new(io::ErrorKind::OutOfMemory, message).into()
}

pub(super) fn reserve_object(entries: &mut Vec<ObjectTableEntry>) -> Result<()> {
    if entries.len() == MAX_OBJECT_ENTRIES {
        return Err(limit("VMRS ObjectTable metadata exceeds 262144 entries"));
    }
    if entries.len() == entries.capacity() {
        entries
            .try_reserve_exact(1024.min(MAX_OBJECT_ENTRIES - entries.len()))
            .map_err(|e| io::Error::new(io::ErrorKind::OutOfMemory, e))?;
    }
    Ok(())
}

struct TableFrame {
    file_offset: u64,
    size: u64,
    position: u64,
    parent: String,
}

fn read_at(reader: &mut BufReader<fs::File>, offset: u64, bytes: &mut [u8]) -> Result<()> {
    let delta = i128::from(offset) - i128::from(reader.stream_position()?);
    if let Ok(delta) = i64::try_from(delta) {
        reader.seek_relative(delta)?;
    } else {
        reader.seek(SeekFrom::Start(offset))?;
    }
    reader.read_exact(bytes)?;
    Ok(())
}

impl VmrsLayer {
    pub(super) fn insert_key(&mut self, key: String, value: (u64, u32)) -> Result<()> {
        if let Some(existing) = self.key_values.get_mut(&key) {
            *existing = value;
            return Ok(());
        }
        // Charge for the String, value, hash buckets, growth headroom and allocator overhead.
        let charge = key
            .capacity()
            .checked_add(128)
            .ok_or_else(|| limit("VMRS key length overflow"))?;
        let total = self
            .key_bytes
            .checked_add(charge)
            .filter(|&n| n <= MAX_KEY_BYTES)
            .ok_or_else(|| limit("VMRS key metadata exceeds its 32 MiB budget"))?;
        self.key_values
            .try_reserve(1)
            .map_err(|e| io::Error::new(io::ErrorKind::OutOfMemory, e))?;
        self.key_values.insert(key, value);
        self.key_bytes = total;
        Ok(())
    }

    pub(super) fn parse_key_tables(&mut self) -> Result<()> {
        let mut file = self.inner.borrow().file.try_clone()?;
        let file_size = crate::utils::file_size(&mut file)?;
        let mut reader = BufReader::with_capacity(64 * 1024, file);
        let mut steps = 0;
        for index in 0..self.object_entries.len() {
            let entry = self.object_entries[index].clone();
            if entry.entry_type != 2 || entry.size < 10 || entry.file_offset == 0 {
                continue;
            }
            if let Err(error) = self.walk_key_tables(&mut reader, file_size, &entry, &mut steps) {
                if error.is_resource_limit() {
                    return Err(error);
                }
                log::debug!("VMRS: KeyTable at {:#x}: {error}", entry.file_offset);
            }
        }
        if self.key_values.is_empty() {
            self.scan_for_ram_blocks()?;
        }
        Ok(())
    }

    fn walk_key_tables(
        &mut self,
        reader: &mut BufReader<fs::File>,
        file_size: u64,
        root: &ObjectTableEntry,
        steps: &mut usize,
    ) -> Result<()> {
        let mut stack = vec![TableFrame {
            file_offset: root.file_offset,
            size: u64::from(root.size),
            position: 10,
            parent: String::new(),
        }];
        while let Some(frame) = stack.last_mut() {
            if frame
                .file_offset
                .checked_add(frame.size)
                .is_none_or(|end| end > file_size)
            {
                return Err(VmkatzError::DiskFormatError(
                    "VMRS KeyTable exceeds file".into(),
                ));
            }
            if frame.position.saturating_add(21) > frame.size {
                stack.pop();
                continue;
            }
            *steps += 1;
            if *steps > MAX_KEY_STEPS {
                return Err(limit("VMRS KeyTable traversal exceeds 1000000 entries"));
            }
            let offset = frame.file_offset + frame.position;
            let mut header = [0; 21];
            read_at(reader, offset, &mut header)?;
            let size = u64::from(u32_le(&header, 2));
            if size == 0 {
                stack.pop();
                continue;
            }
            let name_len = usize::from(header[20]);
            if size < 21 + name_len as u64 || size > frame.size - frame.position {
                return Err(VmkatzError::DiskFormatError(
                    "Invalid VMRS key entry size".into(),
                ));
            }
            frame.position += size;
            let mut name = [0; 255];
            read_at(reader, offset + 21, &mut name[..name_len])?;
            let name = String::from_utf8_lossy(&name[..name_len]);
            let name = name.trim_end_matches('\0');
            if name.is_empty() {
                continue;
            }
            if frame.parent.len() + name.len() + 1 > MAX_PATH_BYTES {
                return Err(limit("VMRS key path exceeds 4096 bytes"));
            }
            let path = if frame.parent.is_empty() {
                name.to_owned()
            } else {
                format!("{}/{name}", frame.parent)
            };
            let value_offset = offset + 21 + name_len as u64;
            let value_room = size - 21 - name_len as u64;
            let value = if header[1] & 1 != 0 && value_room >= 12 {
                let mut reference = [0; 12];
                read_at(reader, value_offset, &mut reference)?;
                let value = (u64_le(&reference, 4), u32_le(&reference, 0));
                (value.0 != 0 && value.1 != 0).then_some(value)
            } else {
                match header[0] {
                    3 | 4 | 5 | 9 => Some((offset + 12, 8)),
                    8 => Some((offset + 12, 4)),
                    6 | 7 if value_room >= 4 => {
                        let mut length = [0; 4];
                        read_at(reader, value_offset, &mut length)?;
                        let len = u32::from_le_bytes(length);
                        (len != 0 && u64::from(len) <= value_room - 4)
                            .then_some((value_offset + 4, len))
                    }
                    _ => None,
                }
            };
            if let Some(value) = value {
                self.insert_key(path.clone(), value)?;
            }
            let child_ref = u32_le(&header, 8);
            if let Some(child) = (child_ref != 0)
                .then(|| self.find_object_entry(child_ref))
                .flatten()
            {
                if stack.iter().any(|f| f.file_offset == child.file_offset) {
                    return Err(VmkatzError::RecoveryLimit("VMRS KeyTable cycle"));
                }
                if stack.len() == MAX_DEPTH {
                    return Err(limit("VMRS KeyTable nesting exceeds 64 levels"));
                }
                stack.push(TableFrame {
                    file_offset: child.file_offset,
                    size: u64::from(child.size),
                    position: 10,
                    parent: path,
                });
            }
        }
        Ok(())
    }
}

fn block_index(key: &str) -> Option<u64> {
    let key = key
        .strip_prefix("/savedstate/")
        .or_else(|| key.strip_prefix("savedstate/"))
        .unwrap_or(key);
    key.strip_prefix("RamBlock")
        .or_else(|| key.strip_prefix("RamMemoryBlock"))?
        .parse()
        .ok()
}

fn preferred_key(keys: &HashMap<String, (u64, u32)>, index: u64) -> Option<String> {
    [
        format!("savedstate/RamBlock{index}"),
        format!("/savedstate/RamBlock{index}"),
        format!("RamBlock{index}"),
        format!("savedstate/RamMemoryBlock{index}"),
        format!("/savedstate/RamMemoryBlock{index}"),
    ]
    .into_iter()
    .find(|key| keys.contains_key(key))
}

/// Resolve jobs as workers request them; sparse block numbers never expand into a dense list.
pub(super) fn ram_jobs<'a>(
    keys: &'a HashMap<String, (u64, u32)>,
    entries: &'a [ObjectTableEntry],
    fallback_count: u64,
    gap_base: u64,
    gap_size: u64,
) -> impl Iterator<Item = (u64, u64, u64, u32)> + 'a {
    let named = keys.iter().filter_map(|(key, &value)| {
        let index = block_index(key)?;
        (preferred_key(keys, index).as_deref() == Some(key.as_str())).then_some((index, value))
    });
    let fallback = entries
        .iter()
        .filter(|e| {
            e.size > 0
                && e.size <= RAM_BLOCK_SIZE as u32
                && e.file_offset > 0
                && !matches!(e.entry_type, 0 | 2 | 4)
        })
        .take(usize::try_from(fallback_count).unwrap_or(usize::MAX))
        .enumerate()
        .filter_map(|(index, entry)| {
            let index = index as u64;
            preferred_key(keys, index)
                .is_none()
                .then_some((index, (entry.file_offset, entry.size)))
        });
    named
        .chain(fallback)
        .filter_map(move |(index, (offset, size))| {
            if size == 0 || size > RAM_BLOCK_SIZE as u32 {
                return None;
            }
            let ram_offset = index.checked_mul(RAM_BLOCK_SIZE as u64)?;
            let gpa = if ram_offset < gap_base {
                ram_offset
            } else {
                ram_offset.checked_add(gap_size)?
            };
            Some((index, gpa, offset, size))
        })
}
