use super::{Hive, PBOX};
use crate::error::{Result, VmkatzError};

/// Recover disconnected NK cells without loading a complete SYSTEM hive.
pub(super) fn recover(hive: &Hive<'_>) -> Result<Option<[u8; 16]>> {
    const MAX_SCAN_BYTES: u64 = 64 * 1024 * 1024;
    let started = std::time::Instant::now();
    let mut position = 0x1000u64;
    let mut attempts = 0;
    let names = ["JD", "Skew1", "GBG", "Data"];
    let mut parts = [None; 4];
    while position + 0x60 < hive.len() {
        attempts += 1;
        if position - 0x1000 >= MAX_SCAN_BYTES
            || attempts > 1_048_576
            || started.elapsed().as_secs() >= 30
        {
            return Err(VmkatzError::RecoveryLimit(
                "SYSTEM cell scan budget reached",
            ));
        }
        let header = hive.read_range(position, 6)?;
        if &header[..4] == b"hbin" {
            position += 0x20;
            continue;
        }
        let size = crate::utils::read_i32_le(&header, 0)
            .unwrap_or(0)
            .unsigned_abs();
        if !(8..=0x100000).contains(&size) || position + u64::from(size) > hive.len() {
            position += 4;
            continue;
        }
        if &header[4..] == b"nk" {
            let offset = u32::try_from(position - 0x1000).map_err(std::io::Error::other)?;
            if let Ok(key) = hive.key_at_offset(offset) {
                for (index, name) in names.iter().enumerate() {
                    if parts[index].is_none() && key.name().eq_ignore_ascii_case(name) {
                        if let Ok(class) = key.class_name(hive) {
                            if let Ok(bytes) = hex::decode(class) {
                                if let Ok(part) = <[u8; 4]>::try_from(bytes) {
                                    parts[index] = Some(part);
                                }
                            }
                        }
                    }
                }
            }
        }
        if let [Some(a), Some(b), Some(c), Some(d)] = parts {
            let raw = [a, b, c, d].concat();
            return Ok(Some(std::array::from_fn(|i| raw[PBOX[i]])));
        }
        position += u64::from(size);
    }
    Ok(None)
}
