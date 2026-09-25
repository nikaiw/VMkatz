use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::{Read as _, Seek as _, SeekFrom};

use super::disk_fallbacks::{CLUSTER_SIZE, MAX_HIVE_SIZE, MIN_SYSTEM_HIVE_SIZE};
use super::{bootkey, hive};
use crate::error::Result;

/// Scan all physically allocated VMDK grains for registry hive signatures.
///
/// Three-phase approach:
/// 1. Fast grain scan to collect candidate positions (regf headers, ALL hbin blocks)
/// 2. Try contiguous reads from regf headers and hbin roots
/// 3. Fragmented assembly: collect scattered hbin blocks by offset_in_hive,
///    chain them to rebuild hives fragmented by NTFS
pub(super) fn scan_vmdk_grains_for_hives(
    vmdk: &mut crate::disk::vmdk::VmdkDisk,
) -> Result<(super::HiveFiles, Option<[u8; 16]>)> {
    log::info!("Starting VMDK grain-direct scan for registry hives");

    let mut grains_scanned = 0u64;

    // Phase 1: Collect candidates from grain data
    let mut regf_candidates: Vec<(u64, u64)> = Vec::new(); // (virtual_offset, bins_size)
    let mut hbin_root_candidates: Vec<(u64, String)> = Vec::new(); // (virtual_offset, name)
    // ALL hbin blocks: (virtual_offset, offset_in_hive, block_size)
    let mut all_hbin_blocks: Vec<(u64, u32, u32)> = Vec::new();

    vmdk.scan_all_grains(|virtual_byte, grain_data| {
        grains_scanned += 1;

        let mut pos = 0;
        while pos + CLUSTER_SIZE <= grain_data.len() {
            let chunk = &grain_data[pos..];

            // Check for "regf" signature
            if pos + 0x2C <= grain_data.len() && chunk[0..4] == *b"regf" {
                let bins_size = u64::from(chunk.get(0x28..0x2C)
                    .and_then(|s| <[u8; 4]>::try_from(s).ok())
                    .map_or(0, u32::from_le_bytes));
                if bins_size > 0 && bins_size <= MAX_HIVE_SIZE {
                    regf_candidates.push((virtual_byte + pos as u64, bins_size));
                }
            }

            // Check for "hbin" signature (ANY hbin block, not just offset=0)
            if pos + 0x20 <= grain_data.len() && chunk[0..4] == *b"hbin" {
                let hbin_hive_off = chunk.get(4..8)
                    .and_then(|s| <[u8; 4]>::try_from(s).ok())
                    .map_or(u32::MAX, u32::from_le_bytes);
                let hbin_size = chunk.get(8..12)
                    .and_then(|s| <[u8; 4]>::try_from(s).ok())
                    .map_or(0, u32::from_le_bytes);
                if (0x1000..=0x100000).contains(&hbin_size)
                    && u64::from(hbin_hive_off) < MAX_HIVE_SIZE
                    && hbin_hive_off % 0x1000 == 0
                {
                    all_hbin_blocks.push((virtual_byte + pos as u64, hbin_hive_off, hbin_size));

                    // For offset=0 blocks, parse root NK cell to identify hive
                    if hbin_hive_off == 0 {
                        let cell_off = 0x20;
                        if cell_off + 0x60 < chunk.len()
                            && &chunk[cell_off + 4..cell_off + 6] == b"nk"
                        {
                            let name_len = chunk.get(cell_off + 0x4C..cell_off + 0x4E)
                                .and_then(|s| <[u8; 2]>::try_from(s).ok())
                                .map_or(0, u16::from_le_bytes) as usize;
                            if name_len > 0 && cell_off + 0x50 + name_len <= chunk.len() {
                                let name = String::from_utf8_lossy(
                                    &chunk[cell_off + 0x50..cell_off + 0x50 + name_len],
                                )
                                .to_uppercase();
                                if matches!(name.as_str(), "SAM" | "SYSTEM" | "SECURITY") {
                                    log::info!(
                                        "Grain scan: found {name} hbin(0) at virt 0x{virtual_byte:x}+0x{pos:x}",
                                    );
                                    hbin_root_candidates.push((virtual_byte + pos as u64, name));
                                }
                            }
                        }
                    }
                }
            }

            pos += CLUSTER_SIZE;
        }
        true // always scan all grains
    })?;

    log::info!(
        "Grain scan complete: {} grains, {} regf candidates, {} hbin roots, {} total hbin blocks",
        grains_scanned,
        regf_candidates.len(),
        hbin_root_candidates.len(),
        all_hbin_blocks.len(),
    );

    // Phase 2: Try to read full hive data using VmdkDisk seek/read

    let mut sam_data: Option<Vec<u8>> = None;
    let mut system_data: Option<Vec<u8>> = None;
    let mut security_data: Option<Vec<u8>> = None;

    // 2a: Try regf candidates — read total_size bytes contiguously
    for &(virt_off, bins_size) in &regf_candidates {
        let total_size = (0x1000 + bins_size) as usize;
        if vmdk.seek(SeekFrom::Start(virt_off)).is_err() {
            continue;
        }
        let mut data = vec![0u8; total_size];
        if vmdk.read_exact(&mut data).is_err() {
            continue;
        }
        let Ok(h) = hive::Hive::new(&data) else {
            continue;
        };
        let name = match h.root_key() {
            Ok(r) => r.name().to_uppercase(),
            Err(_) => continue,
        };
        let target = match name.as_str() {
            "SAM" if sam_data.is_none() => &mut sam_data,
            "SYSTEM" if system_data.is_none() && total_size as u64 >= MIN_SYSTEM_HIVE_SIZE => {
                &mut system_data
            }
            "SECURITY" if security_data.is_none() => &mut security_data,
            _ => continue,
        };
        log::info!("Grain scan: read {name} hive at virt 0x{virt_off:x} ({total_size} bytes)");
        *target = Some(data);

        if sam_data.is_some() && system_data.is_some() {
            break;
        }
    }

    match (sam_data, system_data) {
        (Some(sam), Some(system)) => return Ok(((sam, system, security_data), None)),
        (s, sys) => {
            sam_data = s;
            system_data = sys;
        }
    }

    // 2b: Try hbin root candidates — read contiguous hbin blocks
    for (hbin_virt, name) in &hbin_root_candidates {
        let target = match name.as_str() {
            "SAM" if sam_data.is_none() => &mut sam_data,
            "SYSTEM" if system_data.is_none() => &mut system_data,
            "SECURITY" if security_data.is_none() => &mut security_data,
            _ => continue,
        };

        let mut hbin_data = Vec::new();
        let mut read_offset = *hbin_virt;
        let mut hbin_buf = [0u8; CLUSTER_SIZE];

        loop {
            if hbin_data.len() as u64 >= MAX_HIVE_SIZE {
                break;
            }
            if vmdk.seek(SeekFrom::Start(read_offset)).is_err() {
                break;
            }
            if vmdk.read_exact(&mut hbin_buf).is_err() {
                break;
            }
            if &hbin_buf[0..4] != b"hbin" {
                break;
            }
            let hbin_hive_off = hbin_buf
                .get(4..8)
                .and_then(|s| <[u8; 4]>::try_from(s).ok())
                .map_or(u32::MAX, u32::from_le_bytes) as usize;
            let block_size = hbin_buf
                .get(8..12)
                .and_then(|s| <[u8; 4]>::try_from(s).ok())
                .map_or(0, u32::from_le_bytes) as usize;
            if !(0x1000..=0x100000).contains(&block_size) {
                break;
            }
            if hbin_hive_off != hbin_data.len() {
                break;
            }
            let mut block = vec![0u8; block_size];
            if vmdk.seek(SeekFrom::Start(read_offset)).is_err() {
                break;
            }
            if vmdk.read_exact(&mut block).is_err() {
                break;
            }
            hbin_data.extend_from_slice(&block);
            read_offset += block_size as u64;
        }

        if let Some(hive_data) = build_hive_from_hbins(vmdk, name, &hbin_data, &regf_candidates) {
            log::info!(
                "Grain scan: valid {} hive from contiguous hbin at virt 0x{:x} ({} bytes)",
                name,
                hbin_virt,
                hive_data.len()
            );
            *target = Some(hive_data);
        }
    }

    // If SYSTEM hive is too small, save it as fallback but allow Phase 2c to try
    // assembling a more complete hive from scattered hbin blocks.
    let mut small_system_fallback: Option<Vec<u8>> = None;
    if let Some(sys) = system_data.as_ref() {
        if (sys.len() as u64) < MIN_SYSTEM_HIVE_SIZE {
            log::info!(
                "SYSTEM hive only {} bytes (< {} minimum), will try fragmented assembly",
                sys.len(),
                MIN_SYSTEM_HIVE_SIZE,
            );
            small_system_fallback = system_data.take();
        }
    }

    match (sam_data, system_data) {
        (Some(sam), Some(system)) => return Ok(((sam, system, security_data), None)),
        (s, sys) => {
            sam_data = s;
            system_data = sys;
        }
    }

    // Phase 2c: Fragmented hive assembly
    // Collect all hbin blocks scattered across the disk, group by offset_in_hive,
    // and try to chain them into complete hives.
    if !hbin_root_candidates.is_empty()
        && (sam_data.is_none() || system_data.is_none() || security_data.is_none())
    {
        log::info!(
            "Attempting fragmented hive assembly from {} hbin blocks",
            all_hbin_blocks.len()
        );

        // Build lookup: offset_in_hive → list of (virtual_offset, block_size)
        let mut hbin_by_offset: HashMap<u32, Vec<(u64, u32)>> = HashMap::new();
        for &(virt_off, off_in_hive, blk_size) in &all_hbin_blocks {
            hbin_by_offset
                .entry(off_in_hive)
                .or_default()
                .push((virt_off, blk_size));
        }

        // Find the target bins_size for each hive from regf candidates
        let regf_info = find_regf_for_hives(vmdk, &regf_candidates);

        for (hbin_virt, name) in &hbin_root_candidates {
            let target = match name.as_str() {
                "SAM" if sam_data.is_none() => &mut sam_data,
                "SYSTEM" if system_data.is_none() => &mut system_data,
                "SECURITY" if security_data.is_none() => &mut security_data,
                _ => continue,
            };

            let bins_size = if let Some(&(_, bs)) = regf_info.get(name.as_str()) {
                bs as u32
            } else {
                // No matching regf header. Use conservative default size.
                // Greedy assembly will fill gaps with zeros.
                let default = match name.as_str() {
                    "SYSTEM" => 0x800000u32, // 8MB
                    _ => 0x10000u32,         // 64KB for SAM/SECURITY
                };
                log::info!(
                    "Fragmented {name}: no matching regf header, using default bins_size=0x{default:x}",
                );
                default
            };

            // Read the root hbin block
            let root_blocks = match hbin_by_offset.get(&0) {
                Some(v) => v.clone(),
                None => continue,
            };
            let root_entry = root_blocks.iter().find(|&&(vo, _)| vo == *hbin_virt);
            let root_block_size = match root_entry {
                Some(&(_, sz)) => sz,
                None => 0x1000, // default
            };

            // Assemble: chain hbin blocks by offset_in_hive
            let assembled = assemble_fragmented_hive(
                vmdk,
                &hbin_by_offset,
                name,
                bins_size,
                *hbin_virt,
                root_block_size,
            );

            if let Some(hbin_data) = assembled {
                if let Some(hive_data) =
                    build_hive_from_hbins(vmdk, name, &hbin_data, &regf_candidates)
                {
                    log::info!(
                        "Grain scan: valid {} hive assembled from fragmented hbin blocks ({} bytes)",
                        name,
                        hive_data.len()
                    );
                    *target = Some(hive_data);
                }
            }
        }
    }

    // Restore small SYSTEM fallback if Phase 2c didn't find a better one
    if system_data.is_none() {
        if let Some(small) = small_system_fallback {
            log::info!(
                "Using small SYSTEM hive fallback ({} bytes) from Phase 2b",
                small.len(),
            );
            system_data = Some(small);
        }
    }

    // Phase 3: Try scattered block bootkey extraction as fallback.
    // When the SYSTEM hive has gaps (fragmented assembly), regular bootkey
    // extraction may fail. Scanning individual hbin blocks can find bootkey
    // NK cells that survived in available grains.
    let scattered_bootkey = try_scattered_bootkey(vmdk, &all_hbin_blocks);

    let has_sam = sam_data.is_some();
    let has_system = system_data.is_some();
    if let (Some(sam), Some(system)) = (sam_data, system_data) {
        Ok(((sam, system, security_data), scattered_bootkey))
    } else {
        let mut detail = "VMDK grain scan:".to_string();
        if !has_sam {
            detail.push_str(" SAM not found");
        }
        if !has_system {
            if !has_sam {
                detail.push(',');
            }
            detail.push_str(" SYSTEM not found");
        }
        if !regf_candidates.is_empty() || !hbin_root_candidates.is_empty() {
            let _ = write!(
                detail,
                " ({} regf, {} hbin roots, {} total hbins scanned)",
                regf_candidates.len(),
                hbin_root_candidates.len(),
                all_hbin_blocks.len(),
            );
        }
        Err(crate::error::VmkatzError::DecryptionError(detail))
    }
}

/// Read all hbin blocks from VMDK and scan for bootkey NK cells.
///
/// This is a last-resort fallback: when the assembled SYSTEM hive has gaps
/// (missing extents), tree navigation and the per-hive NK scan both fail.
/// Here we read every physically present hbin block and search for
/// JD/Skew1/GBG/Data NK cells with valid hex class names.
fn try_scattered_bootkey(
    vmdk: &mut crate::disk::vmdk::VmdkDisk,
    all_hbin_blocks: &[(u64, u32, u32)],
) -> Option<[u8; 16]> {
    if all_hbin_blocks.is_empty() {
        return None;
    }

    log::info!(
        "Trying scattered bootkey scan across {} hbin blocks",
        all_hbin_blocks.len(),
    );

    let mut blocks: Vec<(u32, Vec<u8>)> = Vec::new();
    for &(virt_off, off_in_hive, blk_size) in all_hbin_blocks {
        // Limit block reads to reasonable sizes
        if blk_size > 0x100000 {
            continue;
        }
        if vmdk.seek(SeekFrom::Start(virt_off)).is_err() {
            continue;
        }
        let mut data = vec![0u8; blk_size as usize];
        if vmdk.read_exact(&mut data).is_err() {
            continue;
        }
        blocks.push((off_in_hive, data));
    }

    log::info!(
        "Read {} hbin blocks for scattered bootkey scan",
        blocks.len()
    );
    bootkey::scan_blocks_for_bootkey(&blocks)
}

/// Find matching regf headers for SAM/SYSTEM/SECURITY by path.
/// Returns name → (virtual_offset, bins_size).
fn find_regf_for_hives(
    vmdk: &mut crate::disk::vmdk::VmdkDisk,
    regf_candidates: &[(u64, u64)],
) -> HashMap<&'static str, (u64, u64)> {
    let mut result: HashMap<&'static str, (u64, u64)> = HashMap::new();

    for &(roff, rbins) in regf_candidates {
        if vmdk.seek(SeekFrom::Start(roff + 0x30)).is_err() {
            continue;
        }
        let mut path_buf = [0u8; 128];
        if vmdk.read_exact(&mut path_buf).is_err() {
            continue;
        }
        let path = String::from_utf8_lossy(&path_buf)
            .to_uppercase()
            .replace('\0', "");

        let hive_name: &'static str = if path.contains("CONFIG\\SAM") || path.ends_with("\\SAM") {
            "SAM"
        } else if path.contains("CONFIG\\SYSTEM") || path.ends_with("\\SYSTEM") {
            "SYSTEM"
        } else if path.contains("CONFIG\\SECURITY") || path.ends_with("\\SECURITY") {
            "SECURITY"
        } else {
            continue;
        };

        // Prefer the regf with the largest bins_size (most recent/complete)
        log::info!(
            "Matched regf at 0x{:x} as {} (bins_size=0x{:x}, path={})",
            roff,
            hive_name,
            rbins,
            path.trim()
        );
        if result.get(hive_name).is_none_or(|&(_, prev)| rbins > prev) {
            result.insert(hive_name, (roff, rbins));
        }
    }
    result
}

/// Assemble a fragmented hive by chaining hbin blocks from the global collection.
///
/// For small hives (SAM, SECURITY ≤ 256KB), tries all candidates at each offset
/// with backtracking. For large hives (SYSTEM), uses greedy first-match.
fn assemble_fragmented_hive(
    vmdk: &mut crate::disk::vmdk::VmdkDisk,
    hbin_by_offset: &HashMap<u32, Vec<(u64, u32)>>,
    name: &str,
    bins_size: u32,
    root_virt: u64,
    root_block_size: u32,
) -> Option<Vec<u8>> {
    // Read the root hbin block first
    if vmdk.seek(SeekFrom::Start(root_virt)).is_err() {
        return None;
    }
    let root_data = crate::disk::read_exact_alloc(vmdk, u64::from(root_block_size)).ok()?;
    if &root_data[0..4] != b"hbin" {
        return None;
    }

    // For small hives, try backtracking search first, fall back to greedy.
    // For large hives, go straight to greedy.
    let max_backtrack_size = 256 * 1024u32; // 256KB
    if bins_size <= max_backtrack_size {
        if let Some(result) =
            assemble_with_backtracking(vmdk, hbin_by_offset, name, bins_size, &root_data)
        {
            return Some(result);
        }
        log::info!("Fragmented {name}: backtracking failed, trying greedy fallback");
    }
    assemble_greedy(vmdk, hbin_by_offset, name, bins_size, root_data)
}

/// Backtracking assembly for small hives (SAM, SECURITY).
///
/// Sorts candidates at each offset by proximity to the root hbin block
/// (NTFS fragments tend to be nearby), then uses depth-first search with
/// incremental validation: after placing each block, checks if the partial
/// hive can parse successfully.
fn assemble_with_backtracking(
    vmdk: &mut crate::disk::vmdk::VmdkDisk,
    hbin_by_offset: &HashMap<u32, Vec<(u64, u32)>>,
    name: &str,
    bins_size: u32,
    root_data: &[u8],
) -> Option<Vec<u8>> {
    let root_virt = {
        // Find root block virtual address from the hbin_by_offset map
        let root_cands = hbin_by_offset.get(&0)?;
        // Use the first candidate at offset 0 (the one matching our root_data)
        root_cands.first()?.0
    };

    // Sort candidates at each offset by proximity to root_virt.
    // Closer blocks are more likely to belong to the same file (NTFS locality).
    let mut sorted_by_offset: HashMap<u32, Vec<(u64, u32)>> = HashMap::new();
    for (&off, cands) in hbin_by_offset {
        if off == 0 || off >= bins_size {
            continue;
        }
        let mut sorted = cands.clone();
        sorted.sort_by_key(|&(virt, _)| virt.abs_diff(root_virt));
        // Limit to closest candidates to keep search manageable
        sorted.truncate(10);
        sorted_by_offset.insert(off, sorted);
    }

    // Depth-first search with proximity-sorted candidates.
    // choices[i] = (offset_in_hive, candidate_index, block_data)
    let mut choices: Vec<(u32, usize, Vec<u8>)> = Vec::new();
    let mut current_offset = root_data.len() as u32;
    let mut validations = 0u32;
    let max_validations = 2000u32;
    // Track first structurally valid assembly as fallback when strict validation
    // never passes (e.g., delta disks where subkeys are in base disk)
    let mut first_structural: Option<Vec<u8>> = None;

    'outer: loop {
        if validations > max_validations {
            log::info!("Fragmented {name}: exceeded {max_validations} validations, giving up");
            break;
        }

        if current_offset >= bins_size {
            // Full chain — assemble and validate
            validations += 1;
            let assembled = assemble_from_choices(root_data, &choices);
            if validate_hive_content(name, &assembled) {
                log::info!(
                    "Fragmented {}: assembled {} bytes from {} blocks ({} validations)",
                    name,
                    assembled.len(),
                    choices.len() + 1,
                    validations,
                );
                return Some(assembled);
            }
            // Save first structurally valid assembly as fallback
            if first_structural.is_none() && validate_hive_structure(name, &assembled) {
                first_structural = Some(assembled);
            }
            // Backtrack: try next candidate at the deepest level
            if !do_backtrack(vmdk, &mut choices, &mut current_offset, &sorted_by_offset) {
                break;
            }
            continue;
        }

        // Find candidates at current_offset
        let candidates = match sorted_by_offset.get(&current_offset) {
            Some(v) if !v.is_empty() => v,
            _ => {
                if !do_backtrack(vmdk, &mut choices, &mut current_offset, &sorted_by_offset) {
                    log::info!("Fragmented {name}: no candidates at offset 0x{current_offset:x}");
                    break;
                }
                continue;
            }
        };

        // Try candidates starting from index 0 (proximity-sorted, closest first)
        for (ci, &(virt_off, blk_size)) in candidates.iter().enumerate() {
            if let Some(block) = read_hbin_at(vmdk, virt_off, blk_size, current_offset) {
                choices.push((current_offset, ci, block));
                current_offset += blk_size;
                continue 'outer;
            }
        }

        // All candidates unreadable — backtrack
        if !do_backtrack(vmdk, &mut choices, &mut current_offset, &sorted_by_offset) {
            break;
        }
    }

    // If strict validation never passed, use first structurally valid assembly
    if let Some(data) = first_structural {
        log::info!(
            "Fragmented {}: using structurally valid assembly ({} bytes, subkey check failed)",
            name,
            data.len(),
        );
        return Some(data);
    }

    log::info!("Fragmented {name}: search exhausted ({validations} validations)");
    None
}

/// Read and validate an hbin block from virtual disk.
fn read_hbin_at(
    vmdk: &mut crate::disk::vmdk::VmdkDisk,
    virt_off: u64,
    blk_size: u32,
    expected_offset: u32,
) -> Option<Vec<u8>> {
    if vmdk.seek(SeekFrom::Start(virt_off)).is_err() {
        return None;
    }
    let block = crate::disk::read_exact_alloc(vmdk, u64::from(blk_size)).ok()?;
    if block.len() < 12 || &block[0..4] != b"hbin" {
        return None;
    }
    let actual_off = block
        .get(4..8)
        .and_then(|s| <[u8; 4]>::try_from(s).ok())
        .map_or(u32::MAX, u32::from_le_bytes);
    if actual_off != expected_offset {
        return None;
    }
    Some(block)
}

/// Assemble hbin data from root + choices (without disk reads).
fn assemble_from_choices(root_data: &[u8], choices: &[(u32, usize, Vec<u8>)]) -> Vec<u8> {
    let total: usize = root_data.len() + choices.iter().map(|(_, _, d)| d.len()).sum::<usize>();
    let mut assembled = Vec::with_capacity(total);
    assembled.extend_from_slice(root_data);
    for (_, _, block) in choices {
        assembled.extend_from_slice(block);
    }
    assembled
}

/// Backtrack: pop last choice, try next candidates at that offset (reading block data).
/// If all candidates at that offset exhausted, pop further.
fn do_backtrack(
    vmdk: &mut crate::disk::vmdk::VmdkDisk,
    choices: &mut Vec<(u32, usize, Vec<u8>)>,
    current_offset: &mut u32,
    sorted_by_offset: &HashMap<u32, Vec<(u64, u32)>>,
) -> bool {
    while let Some((off, ci, _)) = choices.pop() {
        if let Some(candidates) = sorted_by_offset.get(&off) {
            for (next_ci, &(virt_off, blk_size)) in candidates.iter().enumerate().skip(ci + 1) {
                if let Some(block) = read_hbin_at(vmdk, virt_off, blk_size, off) {
                    choices.push((off, next_ci, block));
                    *current_offset = off + blk_size;
                    return true;
                }
            }
        }
        // All candidates exhausted at this offset — backtrack further
    }
    false
}

/// Greedy assembly for large hives (SYSTEM).
/// For each needed offset, reads the first available candidate.
fn assemble_greedy(
    vmdk: &mut crate::disk::vmdk::VmdkDisk,
    hbin_by_offset: &HashMap<u32, Vec<(u64, u32)>>,
    name: &str,
    bins_size: u32,
    root_data: Vec<u8>,
) -> Option<Vec<u8>> {
    let mut assembled = root_data;
    let mut next_offset = assembled.len() as u32;
    let mut blocks_found = 1u32;
    let mut blocks_missing = 0u32;

    while next_offset < bins_size {
        let candidates = hbin_by_offset.get(&next_offset);
        let mut found = false;

        if let Some(cands) = candidates {
            for &(virt_off, blk_size) in cands {
                if vmdk.seek(SeekFrom::Start(virt_off)).is_err() {
                    continue;
                }
                let Ok(block) = crate::disk::read_exact_alloc(vmdk, u64::from(blk_size)) else {
                    continue;
                };
                if block.len() >= 12 && &block[0..4] == b"hbin" {
                    let actual_off = block
                        .get(4..8)
                        .and_then(|s| <[u8; 4]>::try_from(s).ok())
                        .map_or(u32::MAX, u32::from_le_bytes);
                    if actual_off == next_offset {
                        assembled.extend_from_slice(&block);
                        next_offset += blk_size;
                        blocks_found += 1;
                        found = true;
                        break;
                    }
                }
            }
        }

        if !found {
            // Fill gap with zeros (this offset's data is in a missing extent)
            // Use 0x1000 as default block size for gaps
            let gap_size = 0x1000u32;
            let zeros = vec![0u8; gap_size as usize];
            assembled.extend_from_slice(&zeros);
            next_offset += gap_size;
            blocks_missing += 1;
        }
    }

    log::info!(
        "Fragmented {}: greedy assembled {} bytes ({} blocks found, {} gaps)",
        name,
        assembled.len(),
        blocks_found,
        blocks_missing
    );

    if u64::from(blocks_missing) * 0x1000 > u64::from(bins_size) / 2 {
        log::debug!("Fragmented {name}: too many missing blocks ({blocks_missing}), rejecting");
        return None;
    }

    Some(assembled)
}

/// Build a temporary hive (regf + hbin) for validation purposes.
fn build_temp_hive(hbin_data: &[u8]) -> Vec<u8> {
    let mut hive_data = vec![0u8; 0x1000];
    hive_data[0..4].copy_from_slice(b"regf");
    hive_data[0x24..0x28].copy_from_slice(&0x20u32.to_le_bytes());
    let bins_size = hbin_data.len() as u32;
    hive_data[0x28..0x2C].copy_from_slice(&bins_size.to_le_bytes());
    hive_data.extend_from_slice(hbin_data);
    hive_data
}

/// Strict validation: root key name matches AND expected subkey exists.
fn validate_hive_content(name: &str, hbin_data: &[u8]) -> bool {
    let hive_data = build_temp_hive(hbin_data);
    let Ok(h) = hive::Hive::new(&hive_data) else {
        return false;
    };
    let Ok(root) = h.root_key() else { return false };
    let rname = root.name().to_uppercase();
    if rname != name.to_uppercase() {
        return false;
    }
    match rname.as_str() {
        // Accept SYSTEM if Select OR any ControlSet is accessible
        "SYSTEM" => {
            root.subkey(&h, "Select").is_ok()
                || root.subkey(&h, "ControlSet001").is_ok()
                || root.subkey(&h, "ControlSet002").is_ok()
        }
        "SAM" => root.subkey(&h, "Domains").is_ok(),
        "SECURITY" => root.subkey(&h, "Policy").is_ok(),
        _ => false,
    }
}

/// Relaxed validation: only checks root key name matches the expected hive.
/// Used as fallback when strict validation fails (e.g., delta disks where
/// subkeys exist only in volatile storage or in the base disk).
fn validate_hive_structure(name: &str, hbin_data: &[u8]) -> bool {
    let hive_data = build_temp_hive(hbin_data);
    let Ok(h) = hive::Hive::new(&hive_data) else {
        return false;
    };
    let Ok(root) = h.root_key() else { return false };
    root.name().to_uppercase() == name.to_uppercase()
}

/// Build a complete hive (regf header + hbin data) from assembled hbin blocks.
/// Finds the best matching regf header and validates the result.
fn build_hive_from_hbins(
    vmdk: &mut crate::disk::vmdk::VmdkDisk,
    name: &str,
    hbin_data: &[u8],
    regf_candidates: &[(u64, u64)],
) -> Option<Vec<u8>> {
    if hbin_data.is_empty() {
        return None;
    }

    // Find matching regf header by path
    let mut best_regf: Option<(u64, u64)> = None;
    for &(roff, rbins) in regf_candidates {
        if vmdk.seek(SeekFrom::Start(roff + 0x30)).is_err() {
            continue;
        }
        let mut path_buf = [0u8; 128];
        if vmdk.read_exact(&mut path_buf).is_err() {
            continue;
        }
        let path = String::from_utf8_lossy(&path_buf)
            .to_uppercase()
            .replace('\0', "");
        let matches = match name {
            "SAM" => path.contains("CONFIG\\SAM") || path.ends_with("\\SAM"),
            "SYSTEM" => path.contains("CONFIG\\SYSTEM") || path.ends_with("\\SYSTEM"),
            "SECURITY" => path.contains("CONFIG\\SECURITY") || path.ends_with("\\SECURITY"),
            _ => false,
        };
        if matches && best_regf.is_none_or(|(_, prev)| rbins > prev) {
            best_regf = Some((roff, rbins));
        }
    }

    let bins_size = if let Some((_, rbins)) = best_regf {
        rbins as u32
    } else {
        hbin_data.len() as u32
    };

    // Build regf header
    let mut regf_hdr = vec![0u8; 0x1000];
    regf_hdr[0..4].copy_from_slice(b"regf");
    regf_hdr[0x24..0x28].copy_from_slice(&0x20u32.to_le_bytes());
    regf_hdr[0x28..0x2C].copy_from_slice(&bins_size.to_le_bytes());
    if let Some((roff, _)) = best_regf {
        if vmdk.seek(SeekFrom::Start(roff)).is_ok() {
            let mut real_hdr = [0u8; 0x30];
            if vmdk.read_exact(&mut real_hdr).is_ok() {
                regf_hdr[0x04..0x30].copy_from_slice(&real_hdr[0x04..0x30]);
            }
        }
    }

    let mut hive_data = regf_hdr;
    let actual_bins = bins_size.min(hbin_data.len() as u32);
    if (actual_bins as usize) < hbin_data.len() {
        hive_data.extend_from_slice(&hbin_data[..actual_bins as usize]);
    } else {
        hive_data.extend_from_slice(hbin_data);
        // Pad if we have less data than bins_size
        if (hbin_data.len() as u32) < bins_size {
            hive_data.resize(0x1000 + bins_size as usize, 0);
        }
    }

    // Validate: try strict first (expected subkeys), fall back to structural (root name only)
    let Ok(h) = hive::Hive::new(&hive_data) else {
        return None;
    };
    let Ok(root) = h.root_key() else { return None };
    let rname = root.name().to_uppercase();
    if rname != name.to_uppercase() {
        return None;
    }
    let strict = match rname.as_str() {
        "SYSTEM" => {
            root.subkey(&h, "Select").is_ok()
                || root.subkey(&h, "ControlSet001").is_ok()
                || root.subkey(&h, "ControlSet002").is_ok()
        }
        "SAM" => root.subkey(&h, "Domains").is_ok(),
        "SECURITY" => root.subkey(&h, "Policy").is_ok(),
        _ => false,
    };
    if !strict {
        log::debug!(
            "build_hive_from_hbins: {name} root key found but expected subkeys missing (delta disk?)",
        );
    }
    // Accept if root name matches — the extraction pipeline will report
    // specific errors if needed data is missing
    Some(hive_data)
}
