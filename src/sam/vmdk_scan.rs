use std::collections::HashMap;
use std::io::{Read as _, Seek as _, SeekFrom};

use super::disk_fallbacks::{CLUSTER_SIZE, MAX_HIVE_SIZE, MIN_SYSTEM_HIVE_SIZE};
use super::{bootkey, hive};
use crate::disk::DiskImage;
use crate::disk::vmdk::VmdkDisk;
use crate::error::{Result, VmkatzError};
use crate::fs::recovery::{MAX_CANDIDATES, MAX_FILE_BYTES, ScanBudget, check_raw_size};

#[cfg(test)]
mod tests;

/// Scan allocated VMDK grains with one budget shared by all recovery phases.
/// Prefer complete registry files, then contiguous hbins, then fragments.
pub(super) fn scan_vmdk_grains_for_hives(
    vmdk: &mut VmdkDisk,
) -> Result<(super::HiveFiles, Option<[u8; 16]>)> {
    check_raw_size(vmdk.disk_size())?;
    let budget = &ScanBudget::new();
    log::info!("Starting VMDK grain-direct scan for registry hives");
    let candidates = collect_candidates(vmdk, budget)?;
    let mut hives = RecoveredHives::default();

    read_regf_hives(vmdk, budget, &candidates, &mut hives)?;
    budget.check_time()?;
    if hives.has_required() {
        return hives.finish(&candidates, None);
    }

    read_contiguous_hives(vmdk, budget, &candidates, &mut hives)?;
    // Keep a small SYSTEM hive as fallback while trying fragmented recovery.
    let mut small_system_fallback: Option<Vec<u8>> = None;
    if let Some(sys) = hives.system.as_ref() {
        if (sys.len() as u64) < MIN_SYSTEM_HIVE_SIZE {
            log::info!(
                "SYSTEM hive only {} bytes (< {} minimum), will try fragmented assembly",
                sys.len(),
                MIN_SYSTEM_HIVE_SIZE,
            );
            small_system_fallback = hives.system.take();
        }
    }

    budget.check_time()?;
    if hives.has_required() {
        return hives.finish(&candidates, None);
    }

    read_fragmented_hives(vmdk, budget, &candidates, &mut hives)?;
    if hives.system.is_none() {
        if let Some(small) = small_system_fallback {
            log::info!(
                "Using small SYSTEM hive fallback ({} bytes) from Phase 2b",
                small.len(),
            );
            hives.system = Some(small);
        }
    }

    // Gaps in SYSTEM may require recovering bootkey cells from separate hbins.
    if candidates
        .hbins
        .iter()
        .map(|&(_, _, size)| u64::from(size))
        .sum::<u64>()
        > MAX_FILE_BYTES
    {
        return Err(VmkatzError::RecoveryLimit(
            "scattered hive blocks exceed 64 MiB",
        ));
    }
    let scattered_bootkey = try_scattered_bootkey(vmdk, budget, &candidates.hbins);

    budget.check_time()?;
    hives.finish(&candidates, scattered_bootkey)
}

/// Candidate positions in scan order; no hive data is retained during collection.
#[derive(Default)]
struct HiveCandidates {
    regf: Vec<(u64, u64)>,       // (virtual offset, bins size)
    roots: Vec<(u64, String)>,   // (virtual offset, hive name)
    hbins: Vec<(u64, u32, u32)>, // (virtual offset, offset in hive, block size)
}

impl HiveCandidates {
    fn scan_grain(&mut self, virtual_byte: u64, grain_data: &[u8]) -> Result<()> {
        let mut pos = 0;
        while pos + CLUSTER_SIZE <= grain_data.len() {
            if self.regf.len() + self.roots.len() + self.hbins.len() >= MAX_CANDIDATES {
                return Err(VmkatzError::RecoveryLimit(
                    "VMDK scan exceeds 65536 candidates",
                ));
            }
            let chunk = &grain_data[pos..];

            if pos + 0x2C <= grain_data.len() && chunk[0..4] == *b"regf" {
                let bins_size = u64::from(
                    chunk
                        .get(0x28..0x2C)
                        .and_then(|s| <[u8; 4]>::try_from(s).ok())
                        .map_or(0, u32::from_le_bytes),
                );
                if bins_size > 0 && bins_size <= MAX_HIVE_SIZE {
                    self.regf.push((virtual_byte + pos as u64, bins_size));
                }
            }

            // Keep non-root hbins too, for fragmented recovery.
            if pos + 0x20 <= grain_data.len() && chunk[0..4] == *b"hbin" {
                let hbin_hive_off = chunk
                    .get(4..8)
                    .and_then(|s| <[u8; 4]>::try_from(s).ok())
                    .map_or(u32::MAX, u32::from_le_bytes);
                let hbin_size = chunk
                    .get(8..12)
                    .and_then(|s| <[u8; 4]>::try_from(s).ok())
                    .map_or(0, u32::from_le_bytes);
                if (0x1000..=0x100000).contains(&hbin_size)
                    && u64::from(hbin_hive_off) < MAX_HIVE_SIZE
                    && hbin_hive_off % 0x1000 == 0
                {
                    self.hbins
                        .push((virtual_byte + pos as u64, hbin_hive_off, hbin_size));

                    // The first hbin's root NK cell identifies the hive.
                    if hbin_hive_off == 0 {
                        let cell_off = 0x20;
                        if cell_off + 0x60 < chunk.len()
                            && &chunk[cell_off + 4..cell_off + 6] == b"nk"
                        {
                            let name_len = chunk
                                .get(cell_off + 0x4C..cell_off + 0x4E)
                                .and_then(|s| <[u8; 2]>::try_from(s).ok())
                                .map_or(0, u16::from_le_bytes)
                                as usize;
                            if name_len > 0 && cell_off + 0x50 + name_len <= chunk.len() {
                                let name = String::from_utf8_lossy(
                                    &chunk[cell_off + 0x50..cell_off + 0x50 + name_len],
                                )
                                .to_uppercase();
                                if matches!(name.as_str(), "SAM" | "SYSTEM" | "SECURITY") {
                                    log::info!(
                                        "Grain scan: found {name} hbin(0) at virt 0x{virtual_byte:x}+0x{pos:x}",
                                    );
                                    self.roots.push((virtual_byte + pos as u64, name));
                                }
                            }
                        }
                    }
                }
            }

            pos += CLUSTER_SIZE;
        }
        Ok(())
    }
}

#[derive(Default)]
struct RecoveredHives {
    sam: Option<Vec<u8>>,
    system: Option<Vec<u8>>,
    security: Option<Vec<u8>>,
}

impl RecoveredHives {
    const fn has_required(&self) -> bool {
        self.sam.is_some() && self.system.is_some()
    }

    /// Recovery phases only fill missing hives; earlier results keep priority.
    fn missing_slot(&mut self, name: &str) -> Option<&mut Option<Vec<u8>>> {
        match name {
            "SAM" if self.sam.is_none() => Some(&mut self.sam),
            "SYSTEM" if self.system.is_none() => Some(&mut self.system),
            "SECURITY" if self.security.is_none() => Some(&mut self.security),
            _ => None,
        }
    }

    fn finish(
        self,
        candidates: &HiveCandidates,
        bootkey: Option<[u8; 16]>,
    ) -> Result<(super::HiveFiles, Option<[u8; 16]>)> {
        let missing = match (self.sam, self.system) {
            (Some(sam), Some(system)) => return Ok(((sam, system, self.security), bootkey)),
            (None, None) => " SAM not found, SYSTEM not found",
            (None, Some(_)) => " SAM not found",
            (Some(_), None) => " SYSTEM not found",
        };
        let detail = if candidates.regf.is_empty() && candidates.roots.is_empty() {
            format!("VMDK grain scan:{missing}")
        } else {
            format!(
                "VMDK grain scan:{missing} ({} regf, {} hbin roots, {} total hbins scanned)",
                candidates.regf.len(),
                candidates.roots.len(),
                candidates.hbins.len(),
            )
        };
        Err(VmkatzError::DecryptionError(detail))
    }
}

fn collect_candidates(vmdk: &mut VmdkDisk, budget: &ScanBudget) -> Result<HiveCandidates> {
    let mut candidates = HiveCandidates::default();
    let mut grains_scanned = 0u64;
    let mut limit = None;
    vmdk.scan_all_grains(|virtual_byte, grain_data| {
        if let Err(e) = budget.check_time() {
            limit = Some(e);
            return false;
        }
        grains_scanned += 1;
        if let Err(e) = candidates.scan_grain(virtual_byte, grain_data) {
            limit = Some(e);
            return false;
        }
        true
    })?;
    if let Some(e) = limit {
        return Err(e);
    }
    log::info!(
        "Grain scan complete: {} grains, {} regf candidates, {} hbin roots, {} total hbin blocks",
        grains_scanned,
        candidates.regf.len(),
        candidates.roots.len(),
        candidates.hbins.len(),
    );
    Ok(candidates)
}

/// Read complete hives from registry file headers.
fn read_regf_hives(
    vmdk: &mut VmdkDisk,
    budget: &ScanBudget,
    candidates: &HiveCandidates,
    hives: &mut RecoveredHives,
) -> Result<()> {
    for &(virt_off, bins_size) in &candidates.regf {
        budget.check_time()?;
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
        if name == "SYSTEM" && (total_size as u64) < MIN_SYSTEM_HIVE_SIZE {
            continue;
        }
        let Some(target) = hives.missing_slot(&name) else {
            continue;
        };
        log::info!("Grain scan: read {name} hive at virt 0x{virt_off:x} ({total_size} bytes)");
        drop(h);
        *target = Some(data);

        if hives.sam.is_some() && hives.system.is_some() {
            break;
        }
    }

    Ok(())
}

/// Read consecutive hbin blocks starting at each root.
fn read_contiguous_hives(
    vmdk: &mut VmdkDisk,
    budget: &ScanBudget,
    candidates: &HiveCandidates,
    hives: &mut RecoveredHives,
) -> Result<()> {
    for (hbin_virt, name) in &candidates.roots {
        budget.check_time()?;
        let Some(target) = hives.missing_slot(name) else {
            continue;
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

        if let Some(hive_data) =
            build_hive_from_hbins(vmdk, budget, name, &hbin_data, &candidates.regf)
        {
            log::info!(
                "Grain scan: valid {} hive from contiguous hbin at virt 0x{:x} ({} bytes)",
                name,
                hbin_virt,
                hive_data.len()
            );
            *target = Some(hive_data);
        }
    }

    Ok(())
}

/// Assemble missing hives from the indexed fragments.
fn read_fragmented_hives(
    vmdk: &mut VmdkDisk,
    budget: &ScanBudget,
    candidates: &HiveCandidates,
    hives: &mut RecoveredHives,
) -> Result<()> {
    if !candidates.roots.is_empty()
        && (hives.sam.is_none() || hives.system.is_none() || hives.security.is_none())
    {
        log::info!(
            "Attempting fragmented hive assembly from {} hbin blocks",
            candidates.hbins.len()
        );

        // Build lookup: offset_in_hive → list of (virtual_offset, block_size)
        let mut hbin_by_offset: HashMap<u32, Vec<(u64, u32)>> = HashMap::new();
        for &(virt_off, off_in_hive, blk_size) in &candidates.hbins {
            hbin_by_offset
                .entry(off_in_hive)
                .or_default()
                .push((virt_off, blk_size));
        }

        let regf_info = find_regf_for_hives(vmdk, budget, &candidates.regf);

        for (hbin_virt, name) in &candidates.roots {
            budget.check_time()?;
            let Some(target) = hives.missing_slot(name) else {
                continue;
            };

            let bins_size = if let Some(&(_, bs)) = regf_info.get(name.as_str()) {
                bs as u32
            } else {
                // Without a header, use a fixed size; greedy assembly zero-fills gaps.
                let default = match name.as_str() {
                    "SYSTEM" => 0x800000u32, // 8MB
                    _ => 0x10000u32,         // 64KB for SAM/SECURITY
                };
                log::info!(
                    "Fragmented {name}: no matching regf header, using default bins_size=0x{default:x}",
                );
                default
            };

            let Some(root_blocks) = hbin_by_offset.get(&0) else {
                continue;
            };
            let root_entry = root_blocks.iter().find(|&&(vo, _)| vo == *hbin_virt);
            let root_block_size = match root_entry {
                Some(&(_, sz)) => sz,
                None => 0x1000, // default
            };

            let assembled = assemble_fragmented_hive(
                vmdk,
                budget,
                &hbin_by_offset,
                name,
                bins_size,
                *hbin_virt,
                root_block_size,
            );

            if let Some(hbin_data) = assembled {
                if let Some(hive_data) =
                    build_hive_from_hbins(vmdk, budget, name, &hbin_data, &candidates.regf)
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

    Ok(())
}

/// Recover bootkey cells from separate hbins when SYSTEM has gaps.
/// Look for JD/Skew1/GBG/Data NK cells with valid hex class names.
fn try_scattered_bootkey(
    vmdk: &mut crate::disk::vmdk::VmdkDisk,
    budget: &ScanBudget,
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
        budget.check_time().ok()?;
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
    budget: &ScanBudget,
    regf_candidates: &[(u64, u64)],
) -> HashMap<&'static str, (u64, u64)> {
    let mut result: HashMap<&'static str, (u64, u64)> = HashMap::new();

    for &(roff, rbins) in regf_candidates {
        if budget.check_time().is_err() {
            return result;
        }
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

        // Prefer the largest candidate as a completeness heuristic.
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

/// Assemble hbins with backtracking for hives up to 256 KiB, then greedy fallback.
fn assemble_fragmented_hive(
    vmdk: &mut crate::disk::vmdk::VmdkDisk,
    budget: &ScanBudget,
    hbin_by_offset: &HashMap<u32, Vec<(u64, u32)>>,
    name: &str,
    bins_size: u32,
    root_virt: u64,
    root_block_size: u32,
) -> Option<Vec<u8>> {
    if vmdk.seek(SeekFrom::Start(root_virt)).is_err() {
        return None;
    }
    let root_data = crate::disk::read_exact_alloc(vmdk, u64::from(root_block_size)).ok()?;
    if &root_data[0..4] != b"hbin" {
        return None;
    }

    let max_backtrack_size = 256 * 1024u32; // 256KB
    if bins_size <= max_backtrack_size {
        if let Some(result) =
            assemble_with_backtracking(vmdk, budget, hbin_by_offset, name, bins_size, &root_data)
        {
            return Some(result);
        }
        log::info!("Fragmented {name}: backtracking failed, trying greedy fallback");
    }
    assemble_greedy(vmdk, budget, hbin_by_offset, name, bins_size, root_data)
}

/// Search candidate chains nearest-first and validate each complete assembly.
fn assemble_with_backtracking(
    vmdk: &mut crate::disk::vmdk::VmdkDisk,
    budget: &ScanBudget,
    hbin_by_offset: &HashMap<u32, Vec<(u64, u32)>>,
    name: &str,
    bins_size: u32,
    root_data: &[u8],
) -> Option<Vec<u8>> {
    let root_virt = {
        let root_cands = hbin_by_offset.get(&0)?;
        // Approximate locality using the first root candidate.
        root_cands.first()?.0
    };

    // Nearby NTFS fragments are more likely to belong to the same hive.
    let mut sorted_by_offset: HashMap<u32, Vec<(u64, u32)>> = HashMap::new();
    for (&off, cands) in hbin_by_offset {
        budget.check_time().ok()?;
        if off == 0 || off >= bins_size {
            continue;
        }
        let mut sorted = cands.clone();
        sorted.sort_by_key(|&(virt, _)| virt.abs_diff(root_virt));
        // Bound branching at each hive offset.
        sorted.truncate(10);
        sorted_by_offset.insert(off, sorted);
    }

    // choices[i] = (offset_in_hive, candidate_index, block_data)
    let mut choices: Vec<(u32, usize, Vec<u8>)> = Vec::new();
    let mut current_offset = root_data.len() as u32;
    let mut validations = 0u32;
    let max_validations = 2000u32;
    // Delta disks may lack subkeys: keep the first structurally valid fallback.
    let mut first_structural: Option<Vec<u8>> = None;

    'outer: loop {
        budget.check_time().ok()?;
        if validations > max_validations {
            log::info!("Fragmented {name}: exceeded {max_validations} validations, giving up");
            break;
        }

        if current_offset >= bins_size {
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
            if first_structural.is_none() && validate_hive_structure(name, &assembled) {
                first_structural = Some(assembled);
            }
            // Backtrack: try next candidate at the deepest level
            if !do_backtrack(
                vmdk,
                budget,
                &mut choices,
                &mut current_offset,
                &sorted_by_offset,
            ) {
                break;
            }
            continue;
        }

        let candidates = match sorted_by_offset.get(&current_offset) {
            Some(v) if !v.is_empty() => v,
            _ => {
                if !do_backtrack(
                    vmdk,
                    budget,
                    &mut choices,
                    &mut current_offset,
                    &sorted_by_offset,
                ) {
                    log::info!("Fragmented {name}: no candidates at offset 0x{current_offset:x}");
                    break;
                }
                continue;
            }
        };

        for (ci, &(virt_off, blk_size)) in candidates.iter().enumerate() {
            budget.check_time().ok()?;
            if let Some(block) = read_hbin_at(vmdk, budget, virt_off, blk_size, current_offset) {
                choices.push((current_offset, ci, block));
                current_offset += blk_size;
                continue 'outer;
            }
        }

        // All candidates unreadable — backtrack
        if !do_backtrack(
            vmdk,
            budget,
            &mut choices,
            &mut current_offset,
            &sorted_by_offset,
        ) {
            break;
        }
    }

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
    budget: &ScanBudget,
    virt_off: u64,
    blk_size: u32,
    expected_offset: u32,
) -> Option<Vec<u8>> {
    budget.check_time().ok()?;
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

/// Backtrack until an alternative readable block is found.
fn do_backtrack(
    vmdk: &mut crate::disk::vmdk::VmdkDisk,
    budget: &ScanBudget,
    choices: &mut Vec<(u32, usize, Vec<u8>)>,
    current_offset: &mut u32,
    sorted_by_offset: &HashMap<u32, Vec<(u64, u32)>>,
) -> bool {
    while let Some((off, ci, _)) = choices.pop() {
        if budget.check_time().is_err() {
            return false;
        }
        if let Some(candidates) = sorted_by_offset.get(&off) {
            for (next_ci, &(virt_off, blk_size)) in candidates.iter().enumerate().skip(ci + 1) {
                if budget.check_time().is_err() {
                    return false;
                }
                if let Some(block) = read_hbin_at(vmdk, budget, virt_off, blk_size, off) {
                    choices.push((off, next_ci, block));
                    *current_offset = off + blk_size;
                    return true;
                }
            }
        }
    }
    false
}

/// Greedy assembly for large hives (SYSTEM).
/// For each needed offset, reads the first available candidate.
fn assemble_greedy(
    vmdk: &mut crate::disk::vmdk::VmdkDisk,
    budget: &ScanBudget,
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
        budget.check_time().ok()?;
        let candidates = hbin_by_offset.get(&next_offset);
        let mut found = false;

        if let Some(cands) = candidates {
            for &(virt_off, blk_size) in cands {
                budget.check_time().ok()?;
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
            // Preserve offsets across missing extents with a zero-filled 4 KiB gap.
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

/// Accept a matching root name when missing subkeys prevent strict validation.
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
    budget: &ScanBudget,
    name: &str,
    hbin_data: &[u8],
    regf_candidates: &[(u64, u64)],
) -> Option<Vec<u8>> {
    if hbin_data.is_empty() {
        return None;
    }

    let mut best_regf: Option<(u64, u64)> = None;
    for &(roff, rbins) in regf_candidates {
        budget.check_time().ok()?;
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
        if (hbin_data.len() as u32) < bins_size {
            hive_data.resize(0x1000 + bins_size as usize, 0);
        }
    }

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
    drop(root);
    drop(h);
    // Extraction reports missing data after this structural check.
    Some(hive_data)
}
