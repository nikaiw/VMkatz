use std::io::{Read, Seek, SeekFrom};

use super::hive;
use crate::error::Result;

/// Read into `buf` with resilient I/O: on error, zero-fill the failing 4KB block
/// and continue. This allows extraction from live/in-use block devices where
/// individual sectors may be temporarily locked.
fn resilient_read<R: Read>(reader: &mut R, buf: &mut [u8]) -> usize {
    const BLOCK: usize = 4096;
    let mut total = 0;
    while total < buf.len() {
        let end = (total + BLOCK).min(buf.len());
        match reader.read(&mut buf[total..end]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(_) => {
                // Zero-fill this block and advance
                buf[total..end].fill(0);
                total = end;
            }
        }
    }
    total
}

/// Maximum hive size we'll try to read (16MB — covers even large SYSTEM hives).
pub(super) const MAX_HIVE_SIZE: u64 = 16 * 1024 * 1024;
/// Scan chunk size for reading the disk (1MB).
pub(super) const SCAN_CHUNK: usize = 1024 * 1024;
/// NTFS cluster size (4KB) — regf headers align to cluster boundaries.
pub(super) const CLUSTER_SIZE: usize = 4096;
/// Minimum valid SYSTEM hive size (real SYSTEM is 8-16MB; reject tiny false matches).
pub(super) const MIN_SYSTEM_HIVE_SIZE: u64 = 512 * 1024;
/// Minimum valid SAM hive size (real SAM is 40-256KB; reject stubs).
pub(super) const MIN_SAM_HIVE_SIZE: u64 = 16 * 1024;

/// Scan the raw disk for "regf" registry hive signatures and extract SAM + SYSTEM + SECURITY.
/// Used as fallback when NTFS MFT traversal fails (e.g., incomplete disk images).
pub(super) fn scan_for_hives<R: Read + Seek>(reader: &mut R) -> Result<super::HiveFiles> {
    let disk_size = reader.seek(SeekFrom::End(0))?;
    reader.seek(SeekFrom::Start(0))?;

    log::info!(
        "Scanning {}MB disk for regf signatures...",
        disk_size / (1024 * 1024)
    );

    let mut sam_data: Option<Vec<u8>> = None;
    let mut system_data: Option<Vec<u8>> = None;
    let mut security_data: Option<Vec<u8>> = None;
    let mut found_count = 0u32;

    let mut offset = 0u64;
    let mut chunk = vec![0u8; SCAN_CHUNK];

    while offset < disk_size {
        if reader.seek(SeekFrom::Start(offset)).is_err() {
            // Seek failed (I/O error on live device) — skip this chunk
            offset += SCAN_CHUNK as u64;
            continue;
        }
        let n = match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => {
                // I/O error (live VM, bad sector) — skip this chunk and continue
                offset += SCAN_CHUNK as u64;
                continue;
            }
        };

        // Scan this chunk at cluster boundaries for "regf" magic
        let mut pos = 0;
        while pos + 4 <= n {
            if &chunk[pos..pos + 4] == b"regf" {
                let hive_offset = offset + pos as u64;
                if let Some((name, data)) = try_read_hive(reader, hive_offset) {
                    log::info!(
                        "Found {} hive at offset 0x{:x} ({} bytes)",
                        name,
                        hive_offset,
                        data.len()
                    );
                    found_count += 1;
                    match name.as_str() {
                        "SAM" => sam_data = Some(data),
                        "SYSTEM" => system_data = Some(data),
                        "SECURITY" => security_data = Some(data),
                        _ => {} // Ignore other hives (SOFTWARE, DEFAULT, etc.)
                    }
                    // Stop once we have SAM + SYSTEM (SECURITY is optional)
                    if let (Some(_), Some(_)) = (&sam_data, &system_data) {
                        log::info!("Found all required hives ({found_count} total regf)");
                        // Move out of the Options -- both confirmed Some above
                        return Ok((
                            sam_data.take().unwrap_or_default(),
                            system_data.take().unwrap_or_default(),
                            security_data,
                        ));
                    }
                }
                // Restore read position for continued scanning
                let _ = reader.seek(SeekFrom::Start(offset + n as u64));
            }
            pos += CLUSTER_SIZE;
        }

        offset += n as u64;
    }

    let has_sam = sam_data.is_some();
    let has_system = system_data.is_some();
    if let (Some(sam), Some(system)) = (sam_data, system_data) {
        Ok((sam, system, security_data))
    } else {
        let mut detail = format!("Raw scan found {found_count} regf hive(s)");
        if !has_sam {
            detail.push_str(", SAM hive not found");
        }
        if !has_system {
            detail.push_str(", SYSTEM hive not found");
        }
        detail.push_str(". Disk image may be incomplete (missing extents or snapshot delta)");
        Err(crate::error::VmkatzError::DecryptionError(detail))
    }
}

/// Try to read and validate a registry hive at the given disk offset.
/// Returns `Some((hive_name, data))` if successful.
fn try_read_hive<R: Read + Seek>(reader: &mut R, offset: u64) -> Option<(String, Vec<u8>)> {
    // Read regf header (first 4KB)
    reader.seek(SeekFrom::Start(offset)).ok()?;
    let mut header = [0u8; 4096];
    reader.read_exact(&mut header).ok()?;

    // Validate magic
    if &header[0..4] != b"regf" {
        return None;
    }

    // hive_bins_data_size at offset 0x28
    let bins_size = u64::from(u32::from_le_bytes(
        header
            .get(0x28..0x2C)
            .and_then(|s| <[u8; 4]>::try_from(s).ok())
            .unwrap_or([0; 4]),
    ));
    if bins_size == 0 || bins_size > MAX_HIVE_SIZE {
        log::debug!("regf at 0x{offset:x}: bins_size={bins_size} (skipped)");
        return None;
    }

    let total_size = 0x1000 + bins_size;

    // Read the complete hive with resilient I/O (zero-fill on bad sectors)
    reader.seek(SeekFrom::Start(offset)).ok()?;
    let mut data = vec![0u8; total_size as usize];
    resilient_read(reader, &mut data);

    // Parse to get root key name
    let hive = match hive::Hive::new(&data) {
        Ok(h) => h,
        Err(e) => {
            log::debug!("regf at 0x{offset:x}: hive parse error: {e}");
            return None;
        }
    };
    let root = match hive.root_key() {
        Ok(r) => r,
        Err(e) => {
            log::debug!("regf at 0x{offset:x}: root key error: {e}");
            return None;
        }
    };
    let name = root.name().to_uppercase();
    log::debug!("regf at 0x{offset:x}: root='{name}', size={total_size}");

    // Accept known hive names with minimum size validation to reject
    // false matches (e.g. volatile "System" hive vs real config SYSTEM)
    match name.as_str() {
        "SYSTEM" if total_size >= MIN_SYSTEM_HIVE_SIZE => Some((name, data)),
        "SAM" if total_size >= MIN_SAM_HIVE_SIZE => Some((name, data)),
        "SECURITY" => Some((name, data)),
        "SYSTEM" | "SAM" => {
            log::debug!("regf at 0x{offset:x}: '{name}' too small ({total_size}B), skipping");
            None
        }
        _ => {
            log::debug!("regf at 0x{offset:x}: skipping hive '{name}'");
            None
        }
    }
}

/// Scan for hbin blocks with hive-offset=0 (first block of each hive).
/// This handles NTFS-fragmented hives where the regf header is at one disk
/// location but the hbin data starts at a different, non-contiguous location.
///
/// When a first-hbin is found with root key SAM/SYSTEM/SECURITY, we read
/// contiguous hbin blocks from that position to reconstruct the hive.
pub(super) fn scan_for_hbin_roots<R: Read + Seek>(reader: &mut R) -> Result<super::HiveFiles> {
    let disk_size = reader.seek(SeekFrom::End(0))?;
    reader.seek(SeekFrom::Start(0))?;

    log::info!(
        "Scanning {}MB disk for hbin(offset=0) blocks...",
        disk_size / (1024 * 1024)
    );

    let mut sam_data: Option<Vec<u8>> = None;
    let mut system_data: Option<Vec<u8>> = None;
    let mut security_data: Option<Vec<u8>> = None;
    let mut found_count = 0u32;

    let mut offset = 0u64;
    let mut chunk = vec![0u8; SCAN_CHUNK];

    while offset < disk_size {
        if reader.seek(SeekFrom::Start(offset)).is_err() {
            offset += SCAN_CHUNK as u64;
            continue;
        }
        let n = match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => {
                offset += SCAN_CHUNK as u64;
                continue;
            }
        };

        let mut pos = 0;
        while pos + 0x60 <= n {
            if &chunk[pos..pos + 4] == b"hbin" {
                // hbin header: "hbin"(4) + offset_in_hive(4) + size(4) + ...
                let hbin_hive_off = chunk
                    .get(pos + 4..pos + 8)
                    .and_then(|s| <[u8; 4]>::try_from(s).ok())
                    .map_or(u32::MAX, u32::from_le_bytes);
                let hbin_size = chunk
                    .get(pos + 8..pos + 12)
                    .and_then(|s| <[u8; 4]>::try_from(s).ok())
                    .map_or(0, u32::from_le_bytes);

                // Only interested in first hbin of a hive (offset_in_hive == 0)
                if hbin_hive_off == 0 && (0x1000..=0x100000).contains(&hbin_size) {
                    let disk_offset = offset + pos as u64;
                    if let Some((name, data)) = try_read_hbin_hive(reader, disk_offset) {
                        log::info!(
                            "Found {} hive via hbin at offset 0x{:x} ({} bytes)",
                            name,
                            disk_offset,
                            data.len()
                        );
                        found_count += 1;
                        match name.as_str() {
                            "SAM" => sam_data = Some(data),
                            "SYSTEM" => system_data = Some(data),
                            "SECURITY" => security_data = Some(data),
                            _ => {}
                        }
                        if let (Some(_), Some(_)) = (&sam_data, &system_data) {
                            log::info!("Found all required hives via hbin scan");
                            return Ok((
                                sam_data.take().unwrap_or_default(),
                                system_data.take().unwrap_or_default(),
                                security_data,
                            ));
                        }
                    }
                    let _ = reader.seek(SeekFrom::Start(offset + n as u64));
                }
            }
            pos += CLUSTER_SIZE;
        }

        offset += n as u64;
    }

    let has_sam = sam_data.is_some();
    let has_system = system_data.is_some();
    if let (Some(sam), Some(system)) = (sam_data, system_data) {
        Ok((sam, system, security_data))
    } else {
        let mut detail = format!("hbin scan found {found_count} candidate(s) but missing");
        if !has_sam {
            detail.push_str(" SAM");
        }
        if !has_system {
            if !has_sam {
                detail.push_str(" and");
            }
            detail.push_str(" SYSTEM");
        }
        detail.push_str(". Disk image may be incomplete (missing extents or snapshot delta)");
        Err(crate::error::VmkatzError::DecryptionError(detail))
    }
}

/// Try to read a hive starting from its first hbin block at the given offset.
/// The root NK cell within the first hbin tells us the hive name.
/// We then read contiguous hbin blocks to reconstruct the hive data.
fn try_read_hbin_hive<R: Read + Seek>(
    reader: &mut R,
    hbin_offset: u64,
) -> Option<(String, Vec<u8>)> {
    // Read the first hbin block
    reader.seek(SeekFrom::Start(hbin_offset)).ok()?;
    let mut first_block = [0u8; 4096];
    reader.read_exact(&mut first_block).ok()?;

    if &first_block[0..4] != b"hbin" {
        return None;
    }

    // Parse root NK cell at offset 0x20 within hbin data area
    let cell_off = 0x20usize;
    if cell_off + 0x60 >= first_block.len() {
        return None;
    }

    let nk_sig = &first_block[cell_off + 4..cell_off + 6];
    if nk_sig != b"nk" {
        return None;
    }

    // Note: we do NOT check KEY_HIVE_ENTRY (0x04) flag here.
    // Some hives (e.g. SAM) only set KEY_COMP_NAME (0x20) on their root key.
    // Since we already filtered for hbin offset_in_hive==0, the NK cell at
    // offset 0x20 IS the root key by definition.

    let name_len = first_block
        .get(cell_off + 0x4C..cell_off + 0x4E)
        .and_then(|s| <[u8; 2]>::try_from(s).ok())
        .map_or(0, u16::from_le_bytes) as usize;
    if name_len == 0 || cell_off + 0x50 + name_len > first_block.len() {
        return None;
    }

    let name = String::from_utf8_lossy(&first_block[cell_off + 0x50..cell_off + 0x50 + name_len])
        .to_uppercase();

    // Only accept target hive names
    if !matches!(name.as_str(), "SAM" | "SYSTEM" | "SECURITY") {
        return None;
    }

    // Read contiguous hbin blocks to reconstruct the hive
    // Build synthetic regf header (4KB) + contiguous hbin data
    let mut hive_data = Vec::new();

    // Create a minimal regf header
    let mut regf_hdr = vec![0u8; 0x1000];
    regf_hdr[0..4].copy_from_slice(b"regf");
    // root_cell_offset at +0x24: 0x20 (standard)
    regf_hdr[0x24..0x28].copy_from_slice(&0x20u32.to_le_bytes());

    // Read contiguous hbin blocks
    let mut hbin_data = Vec::new();
    let mut read_offset = hbin_offset;
    let mut hbin_buf = [0u8; 4096];

    loop {
        if hbin_data.len() as u64 >= MAX_HIVE_SIZE {
            break;
        }

        if reader.seek(SeekFrom::Start(read_offset)).is_err() {
            break;
        }

        // Read first page of potential hbin block
        let n = resilient_read(reader, &mut hbin_buf);
        if n < 12 {
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
        // Validate offset_in_hive matches accumulated data
        if hbin_hive_off != hbin_data.len() {
            break;
        }

        // Read the full hbin block with resilient I/O
        let mut block = vec![0u8; block_size];
        if reader.seek(SeekFrom::Start(read_offset)).is_err() {
            break;
        }
        resilient_read(reader, &mut block);

        hbin_data.extend_from_slice(&block);
        read_offset += block_size as u64;
    }

    if hbin_data.is_empty() {
        return None;
    }

    let bins_size = hbin_data.len() as u32;
    // Set hive_bins_data_size at +0x28
    regf_hdr[0x28..0x2C].copy_from_slice(&bins_size.to_le_bytes());

    hive_data.extend_from_slice(&regf_hdr);
    hive_data.extend_from_slice(&hbin_data);

    let total_size = hive_data.len() as u64;
    // Apply same size validation
    match name.as_str() {
        "SYSTEM" if total_size < MIN_SYSTEM_HIVE_SIZE => {
            log::debug!("hbin hive '{name}' too small ({total_size}B), skipping");
            return None;
        }
        "SAM" if total_size < MIN_SAM_HIVE_SIZE => {
            log::debug!("hbin hive '{name}' too small ({total_size}B), skipping");
            return None;
        }
        _ => {}
    }

    log::info!(
        "Reconstructed {} hive from hbin blocks: {} bytes ({} hbin data)",
        name,
        hive_data.len(),
        bins_size
    );

    Some((name, hive_data))
}
