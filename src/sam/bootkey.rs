//! Bootkey (System Key) extraction from the SYSTEM registry hive.
//!
//! The bootkey is derived from the class names of four LSA subkeys
//! (JD, Skew1, GBG, Data), concatenated and permuted.

use super::hive::Hive;
use crate::error::{GovmemError, Result};

/// Permutation table applied to the raw 16-byte key.
const PBOX: [usize; 16] = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7];

/// Extract the 16-byte bootkey from SYSTEM hive data.
pub fn extract_bootkey(system_hive_data: &[u8]) -> Result<[u8; 16]> {
    let hive = Hive::new(system_hive_data)?;
    let root = hive.root_key()?;

    // Determine ControlSet numbers to try.
    // Prefer Select\Current (canonical), fall back to trying 001/002/003 directly
    // when Select is missing (e.g., incomplete hives from fragmented disks).
    let cs_numbers = match root.subkey(&hive, "Select") {
        Ok(select) => match select.value_dword(&hive, "Current") {
            Ok(current) => {
                log::info!("Current ControlSet: {}", current);
                vec![current, 1, 2, 3]
            }
            Err(_) => vec![1, 2, 3],
        },
        Err(_) => {
            log::info!("Select key not found, trying ControlSet001/002/003 directly");
            vec![1, 2, 3]
        }
    };

    // Try each ControlSet until bootkey extraction succeeds
    let mut last_err = None;
    let mut seen = [false; 4]; // deduplicate cs_numbers (indices 1,2,3)
    for cs_num in cs_numbers {
        if cs_num == 0 || cs_num > 3 {
            continue;
        }
        if seen[cs_num as usize] {
            continue;
        }
        seen[cs_num as usize] = true;

        let cs_name = format!("ControlSet{:03}", cs_num);
        let lsa = match root
            .subkey(&hive, &cs_name)
            .and_then(|cs| cs.subkey(&hive, "Control"))
            .and_then(|ctrl| ctrl.subkey(&hive, "Lsa"))
        {
            Ok(lsa) => lsa,
            Err(e) => {
                log::debug!("ControlSet{:03}: LSA path not found: {}", cs_num, e);
                last_err = Some(e);
                continue;
            }
        };

        match extract_bootkey_from_lsa(&hive, &lsa) {
            Ok(bootkey) => {
                if cs_num != 1 || seen[1] {
                    log::info!("Bootkey extracted from ControlSet{:03}", cs_num);
                }
                return Ok(bootkey);
            }
            Err(e) => {
                log::debug!("ControlSet{:03}: bootkey extraction failed: {}", cs_num, e);
                last_err = Some(e);
            }
        }
    }

    // Fallback: brute-force scan all NK cells in the hive for JD/Skew1/GBG/Data.
    // On fragmented disks the tree navigation path (root→ControlSet→Control→Lsa)
    // may be broken, but the leaf NK cells with class names might be in available grains.
    log::info!("Tree navigation failed, trying brute-force NK cell scan for bootkey");
    if let Some(bootkey) = scan_hive_for_bootkey_cells(system_hive_data) {
        return Ok(bootkey);
    }

    // Provide clear diagnostics about why bootkey extraction failed
    let hive_size = system_hive_data.len();
    let zero_pages = system_hive_data
        .chunks(0x1000)
        .filter(|p| p.iter().all(|&b| b == 0))
        .count();
    let total_pages = hive_size / 0x1000;
    let gap_pct = if total_pages > 0 {
        zero_pages * 100 / total_pages
    } else {
        0
    };

    if gap_pct > 10 {
        Err(GovmemError::DecryptionError(format!(
            "Bootkey extraction failed: SYSTEM hive has {}% zero-filled pages ({}/{}) — \
             bootkey registry cells (JD/Skew1/GBG/Data) are in missing disk extents",
            gap_pct, zero_pages, total_pages,
        )))
    } else {
        Err(last_err.unwrap_or_else(|| {
            GovmemError::DecryptionError("No accessible ControlSet found in SYSTEM hive".into())
        }))
    }
}

/// Extract bootkey from a resolved LSA key.
fn extract_bootkey_from_lsa(hive: &Hive<'_>, lsa: &super::hive::Key<'_>) -> Result<[u8; 16]> {
    let key_names = ["JD", "Skew1", "GBG", "Data"];
    let mut raw = Vec::with_capacity(16);

    for &kn in &key_names {
        let sub = lsa.subkey(hive, kn)?;
        let class = sub.class_name(hive)?;
        let bytes = hex::decode(&class).map_err(|e| {
            GovmemError::DecryptionError(format!("Bad hex in {} class name '{}': {}", kn, class, e))
        })?;
        raw.extend_from_slice(&bytes);
    }

    if raw.len() != 16 {
        return Err(GovmemError::DecryptionError(format!(
            "Bootkey raw length {} (expected 16)",
            raw.len()
        )));
    }

    let mut bootkey = [0u8; 16];
    for (i, &p) in PBOX.iter().enumerate() {
        bootkey[i] = raw[p];
    }

    Ok(bootkey)
}

/// Brute-force scan all NK cells in the SYSTEM hive for bootkey class names.
/// Looks for NK cells named "JD", "Skew1", "GBG", "Data" with valid hex class names.
/// This bypasses tree navigation entirely — works even when the parent path is broken.
fn scan_hive_for_bootkey_cells(hive_data: &[u8]) -> Option<[u8; 16]> {
    const HBIN_BASE: usize = 0x1000;
    if hive_data.len() < HBIN_BASE + 0x100 {
        return None;
    }

    // NK cell signature bytes (little-endian "nk")
    let targets: [(&str, usize); 4] = [("JD", 0), ("Skew1", 1), ("GBG", 2), ("Data", 3)];
    let mut class_bytes: [Option<Vec<u8>>; 4] = [None, None, None, None];

    // Scan through all cells in the hive
    let mut pos = HBIN_BASE;
    while pos + 0x60 < hive_data.len() {
        // Look for hbin boundaries to jump through cells properly
        if pos + 4 <= hive_data.len() && &hive_data[pos..pos + 4] == b"hbin" {
            // Skip hbin header (0x20 bytes)
            pos += 0x20;
            continue;
        }

        // Read cell size (signed i32)
        if pos + 4 > hive_data.len() {
            break;
        }
        let size_raw = i32::from_le_bytes(hive_data[pos..pos + 4].try_into().unwrap());
        let cell_size = size_raw.unsigned_abs() as usize;
        if !(8..=0x100000).contains(&cell_size) || pos + cell_size > hive_data.len() {
            // Invalid cell — try next aligned position
            pos += 8;
            continue;
        }

        let cell_data_off = pos + 4; // Skip cell size

        // Check for NK signature
        if cell_data_off + 0x50 < hive_data.len() {
            let sig = u16::from_le_bytes(
                hive_data[cell_data_off..cell_data_off + 2]
                    .try_into()
                    .unwrap(),
            );
            if sig == 0x6B6E {
                // "nk"
                let name_len = u16::from_le_bytes(
                    hive_data[cell_data_off + 0x48..cell_data_off + 0x4A]
                        .try_into()
                        .unwrap(),
                ) as usize;

                if name_len > 0 && cell_data_off + 0x4C + name_len <= hive_data.len() {
                    let name = std::str::from_utf8(
                        &hive_data[cell_data_off + 0x4C..cell_data_off + 0x4C + name_len],
                    )
                    .unwrap_or("");

                    for &(target, idx) in &targets {
                        if name.eq_ignore_ascii_case(target) && class_bytes[idx].is_none() {
                            // Read class name from this NK cell
                            let class_offset = u32::from_le_bytes(
                                hive_data[cell_data_off + 0x30..cell_data_off + 0x34]
                                    .try_into()
                                    .unwrap(),
                            );
                            let class_len = u16::from_le_bytes(
                                hive_data[cell_data_off + 0x4A..cell_data_off + 0x4C]
                                    .try_into()
                                    .unwrap(),
                            ) as usize;

                            if class_offset != 0xFFFF_FFFF && class_len > 0 {
                                if let Some(bytes) =
                                    read_class_hex(hive_data, class_offset, class_len)
                                {
                                    log::info!(
                                        "Bootkey scan: found {} class ({} bytes) at hive offset 0x{:x}",
                                        target,
                                        bytes.len(),
                                        pos - HBIN_BASE,
                                    );
                                    class_bytes[idx] = Some(bytes);
                                }
                            }
                        }
                    }
                }
            }
        }

        pos += cell_size;
    }

    // Check we found all 4 components
    let found_count = class_bytes.iter().filter(|c| c.is_some()).count();
    log::info!(
        "Bootkey NK scan: found {}/4 components (JD={} Skew1={} GBG={} Data={})",
        found_count,
        class_bytes[0].is_some(),
        class_bytes[1].is_some(),
        class_bytes[2].is_some(),
        class_bytes[3].is_some(),
    );

    let mut raw = Vec::with_capacity(16);
    for (i, name) in ["JD", "Skew1", "GBG", "Data"].iter().enumerate() {
        match &class_bytes[i] {
            Some(bytes) => raw.extend_from_slice(bytes),
            None => {
                log::debug!("Bootkey scan: {} not found", name);
                return None;
            }
        }
    }

    if raw.len() != 16 {
        log::debug!("Bootkey scan: raw length {} (expected 16)", raw.len());
        return None;
    }

    let mut bootkey = [0u8; 16];
    for (i, &p) in PBOX.iter().enumerate() {
        bootkey[i] = raw[p];
    }

    log::info!(
        "Bootkey extracted via brute-force NK scan: {}",
        hex::encode(bootkey)
    );
    Some(bootkey)
}

/// Scan scattered hbin blocks for bootkey NK cells.
///
/// Unlike `scan_hive_for_bootkey_cells` which scans an assembled hive (with gaps),
/// this function takes raw hbin block data indexed by their offset_in_hive.
/// For class name resolution, it can look across blocks at different offsets.
///
/// `blocks` is a list of (offset_in_hive, raw_block_data) pairs.
pub fn scan_blocks_for_bootkey(blocks: &[(u32, Vec<u8>)]) -> Option<[u8; 16]> {
    let targets: [(&str, usize); 4] = [("JD", 0), ("Skew1", 1), ("GBG", 2), ("Data", 3)];
    let mut class_bytes: [Option<Vec<u8>>; 4] = [None, None, None, None];

    for &(block_hive_off, ref block_data) in blocks {
        // Scan cells within this hbin block (skip 0x20 hbin header)
        let mut pos = 0x20;
        while pos + 0x50 < block_data.len() {
            let size_raw = i32::from_le_bytes(block_data[pos..pos + 4].try_into().unwrap());
            let cell_size = size_raw.unsigned_abs() as usize;
            if !(8..=0x100000).contains(&cell_size) || pos + cell_size > block_data.len() {
                pos += 8;
                continue;
            }

            let cd = pos + 4; // cell data offset (past size)
            if cd + 0x50 < block_data.len() {
                let sig = u16::from_le_bytes(block_data[cd..cd + 2].try_into().unwrap());
                if sig == 0x6B6E {
                    // "nk"
                    let name_len =
                        u16::from_le_bytes(block_data[cd + 0x48..cd + 0x4A].try_into().unwrap())
                            as usize;

                    if name_len > 0 && cd + 0x4C + name_len <= block_data.len() {
                        let name =
                            std::str::from_utf8(&block_data[cd + 0x4C..cd + 0x4C + name_len])
                                .unwrap_or("");

                        for &(target, idx) in &targets {
                            if name.eq_ignore_ascii_case(target) && class_bytes[idx].is_none() {
                                let class_offset = u32::from_le_bytes(
                                    block_data[cd + 0x30..cd + 0x34].try_into().unwrap(),
                                );
                                let class_len = u16::from_le_bytes(
                                    block_data[cd + 0x4A..cd + 0x4C].try_into().unwrap(),
                                ) as usize;

                                if class_offset != 0xFFFF_FFFF && class_len > 0 {
                                    // Try to resolve class cell across all blocks
                                    if let Some(bytes) =
                                        resolve_class_across_blocks(blocks, class_offset, class_len)
                                    {
                                        log::info!(
                                            "Bootkey block scan: found {} class ({} bytes) in hbin at offset 0x{:x}",
                                            target, bytes.len(), block_hive_off,
                                        );
                                        class_bytes[idx] = Some(bytes);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            pos += cell_size;
        }
    }

    let found_count = class_bytes.iter().filter(|c| c.is_some()).count();
    if found_count > 0 {
        log::info!(
            "Bootkey block scan: found {}/4 components (JD={} Skew1={} GBG={} Data={})",
            found_count,
            class_bytes[0].is_some(),
            class_bytes[1].is_some(),
            class_bytes[2].is_some(),
            class_bytes[3].is_some(),
        );
    }

    let mut raw = Vec::with_capacity(16);
    for (i, name) in ["JD", "Skew1", "GBG", "Data"].iter().enumerate() {
        match &class_bytes[i] {
            Some(bytes) => raw.extend_from_slice(bytes),
            None => {
                log::debug!("Bootkey block scan: {} not found", name);
                return None;
            }
        }
    }

    if raw.len() != 16 {
        log::debug!("Bootkey block scan: raw length {} (expected 16)", raw.len());
        return None;
    }

    let mut bootkey = [0u8; 16];
    for (i, &p) in PBOX.iter().enumerate() {
        bootkey[i] = raw[p];
    }

    log::info!(
        "Bootkey extracted via scattered block scan: {}",
        hex::encode(bootkey)
    );
    Some(bootkey)
}

/// Resolve class name cell across all available hbin blocks.
///
/// class_offset is relative to hbin base (0x1000 in the hive file).
/// Find which block contains this offset and read the cell data.
fn resolve_class_across_blocks(
    blocks: &[(u32, Vec<u8>)],
    class_offset: u32,
    class_len: usize,
) -> Option<Vec<u8>> {
    // Find the block containing class_offset
    for &(block_off, ref block_data) in blocks {
        let block_end = block_off + block_data.len() as u32;
        if class_offset >= block_off && class_offset < block_end {
            let local_off = (class_offset - block_off) as usize;
            if local_off + 4 > block_data.len() {
                continue;
            }
            // Read cell at this position
            let size_raw =
                i32::from_le_bytes(block_data[local_off..local_off + 4].try_into().unwrap());
            let abs_size = size_raw.unsigned_abs() as usize;
            if abs_size < 4 || local_off + abs_size > block_data.len() {
                continue;
            }
            let cell_data = &block_data[local_off + 4..local_off + abs_size];
            if class_len > cell_data.len() {
                continue;
            }

            // UTF-16LE → string → hex decode
            let class_str = if class_len >= 2 && class_len.is_multiple_of(2) {
                let u16s: Vec<u16> = cell_data[..class_len]
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                String::from_utf16_lossy(&u16s)
            } else {
                String::from_utf8_lossy(&cell_data[..class_len]).into_owned()
            };

            return hex::decode(&class_str).ok();
        }
    }
    None
}

/// Read class name cell data and decode as hex string → bytes.
fn read_class_hex(hive_data: &[u8], class_offset: u32, class_len: usize) -> Option<Vec<u8>> {
    const HBIN_BASE: usize = 0x1000;
    let file_off = HBIN_BASE + class_offset as usize;
    if file_off + 4 > hive_data.len() {
        return None;
    }
    // Read cell size
    let size_raw = i32::from_le_bytes(hive_data[file_off..file_off + 4].try_into().unwrap());
    let abs_size = size_raw.unsigned_abs() as usize;
    if abs_size < 4 || file_off + abs_size > hive_data.len() {
        return None;
    }
    let cell_data = &hive_data[file_off + 4..file_off + abs_size];
    if class_len > cell_data.len() {
        return None;
    }

    // Class name is UTF-16LE → decode to string → hex decode
    let class_str = if class_len >= 2 && class_len.is_multiple_of(2) {
        let u16s: Vec<u16> = cell_data[..class_len]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&u16s)
    } else {
        String::from_utf8_lossy(&cell_data[..class_len]).into_owned()
    };

    hex::decode(&class_str).ok()
}
