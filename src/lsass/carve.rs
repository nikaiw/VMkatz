//! Carve mode: degraded credential extraction for partial/truncated/raw memory files.
//!
//! Two-level degradation:
//!   Level 1 — Direct LSASS scan: find lsass.exe EPROCESS directly (bypass System process).
//!   Level 2 — Raw page carving: scan ALL physical pages for self-contained crypto structures.

use crate::lsass::crypto::{self, CryptoKeys};
use crate::lsass::dpapi;
use crate::lsass::finder::{DiskPathRef, PagefileRef};
use crate::lsass::types::{Credential, DpapiCredential, MsvCredential};
use crate::memory::PhysicalMemory;
use crate::paging::entry::PAGE_PHYS_MASK;
use crate::paging::translate::PageTableWalker;
use crate::windows::eprocess::EprocessReader;
use crate::windows::offsets::ALL_EPROCESS_OFFSETS;
use crate::windows::process::Process;
use std::collections::{HashMap, HashSet};

use crate::lsass::msv::PRIMARY_CRED_OFFSET_VARIANTS as PRIMARY_CRED_OFFSETS;

/// Collected scan results from a single physical memory pass.
struct ScanResults {
    /// MSSK key candidates: (phys_addr, key_bytes)
    mssk_keys: Vec<(u64, Vec<u8>)>,
    /// IV candidates: (phys_addr, 16 bytes)
    iv_candidates: Vec<(u64, [u8; 16])>,
    /// Primary credential signature hits: (phys_addr, page_phys_base)
    primary_hits: Vec<(u64, u64)>,
    /// DPAPI entry matches: (phys_addr_of_entry, page_data_snapshot)
    dpapi_hits: Vec<(u64, Vec<u8>)>,
    /// Session metadata candidates found during scan, keyed by LUID
    session_candidates: HashMap<u64, SessionMeta>,
}

/// Main entry point for carve mode.
///
/// Returns extracted credentials (may be partial — no session context in Level 2).
pub fn carve_credentials<P: PhysicalMemory>(
    phys: &P,
    pagefile: PagefileRef<'_>,
    disk_path: DiskPathRef<'_>,
) -> Vec<Credential> {
    // Single-pass scan: find LSASS EPROCESS + crypto structures simultaneously.
    // This avoids reading the entire physical memory twice.
    println!("[*] Carve: single-pass scan for LSASS + crypto structures...");
    let (lsass_candidates, scan) = combined_scan_pass(phys);

    println!(
        "[*] Carve scan: {} LSASS candidates, {} MSSK keys, {} Primary hits, {} DPAPI hits",
        lsass_candidates.len(),
        scan.mssk_keys.len(),
        scan.primary_hits.len(),
        scan.dpapi_hits.len(),
    );

    // Level 1: try each LSASS candidate for full extraction
    let mut lsass_dtb = None;
    for process in &lsass_candidates {
        println!(
            "[+] Carve L1: trying LSASS at phys=0x{:x}, PID={}, DTB=0x{:x}",
            process.eprocess_phys, process.pid, process.dtb
        );
        match crate::lsass::finder::extract_all_credentials(phys, process, 0, pagefile, disk_path) {
            Ok(creds) => {
                println!("[+] Carve L1: extracted {} logon sessions", creds.len());
                return creds;
            }
            Err(e) => {
                println!("[!] Carve L1: full extraction failed ({e}), keeping DTB for L2");
                lsass_dtb = Some(process.dtb);
            }
        }
    }

    if lsass_candidates.is_empty() {
        println!("[!] Carve L1: lsass.exe EPROCESS not found");
    }

    // Level 2: raw page carving using scan results
    println!("[*] Carve Level 2: extracting credentials from scan results...");
    carve_level2(phys, lsass_dtb, &scan)
}

// ---------------------------------------------------------------------------
// Combined single-pass scan (LSASS + crypto structures)
// ---------------------------------------------------------------------------

/// Single-pass scan of ALL physical pages, collecting:
/// 1. LSASS EPROCESS candidates (from `lsass.exe\0` pattern)
/// 2. MSSK crypto keys, Primary credential signatures, DPAPI entries, IV candidates
///
/// This avoids multiple full-memory reads.
/// Read chunk size for the combined scan: 1MB = 256 pages.
/// Larger reads reduce syscall overhead (~240x fewer I/O calls vs page-at-a-time).
const SCAN_CHUNK_SIZE: usize = 256 * 4096; // 1 MB

fn combined_scan_pass<P: PhysicalMemory>(phys: &P) -> (Vec<Process>, ScanResults) {
    let lsass_pattern = b"lsass.exe\0\0\0\0\0\0"; // 15-byte ImageFileName
    let phys_size = phys.phys_size();
    log::info!(
        "Carve: combined_scan_pass phys_size=0x{:x} ({} MB)",
        phys_size,
        phys_size / (1024 * 1024)
    );

    let mut lsass_candidates = Vec::new();
    let mut results = ScanResults {
        mssk_keys: Vec::new(),
        iv_candidates: Vec::new(),
        primary_hits: Vec::new(),
        dpapi_hits: Vec::new(),
        session_candidates: HashMap::new(),
    };

    let mut chunk_buf = vec![0u8; SCAN_CHUNK_SIZE];
    let mut chunk_addr: u64 = 0;

    while chunk_addr < phys_size {
        let read_len = SCAN_CHUNK_SIZE.min((phys_size - chunk_addr) as usize);
        if phys
            .read_phys(chunk_addr, &mut chunk_buf[..read_len])
            .is_err()
        {
            chunk_addr += read_len as u64;
            continue;
        }

        // Process each 4KB page within the chunk
        let mut page_off = 0usize;
        while page_off + 4096 <= read_len {
            let page = &chunk_buf[page_off..page_off + 4096];
            let page_addr = chunk_addr + page_off as u64;

            // Skip zero pages (fast check on 8-byte boundaries, then full)
            if page[0..8] == [0; 8] && page[4088..4096] == [0; 8] && page.iter().all(|&b| b == 0) {
                page_off += 4096;
                continue;
            }

            // --- LSASS EPROCESS scan ---
            let mut off = 0usize;
            while off + lsass_pattern.len() <= 4096 {
                if &page[off..off + lsass_pattern.len()] == lsass_pattern {
                    try_validate_lsass(phys, page_addr + off as u64, &mut lsass_candidates);
                }
                off += 1;
            }

            // --- Crypto structure scan (8-byte aligned) ---
            let mut has_mssk = false;

            for off in (0..4096 - 8).step_by(8) {
                // MSSK tag at offset+4 (BCRYPT_KEY81 structure)
                if off + 0x40 <= 4096 {
                    let tag = super::types::read_u32_le(page, off + 4).unwrap_or(0);
                    if tag == 0x4D53_534B {
                        if let Some(key) = crypto::extract_key_from_bcrypt_data(page, off) {
                            log::info!(
                                "Carve: MSSK key at phys=0x{:x}+0x{:x}: {} bytes",
                                page_addr,
                                off,
                                key.len()
                            );
                            results.mssk_keys.push((page_addr + off as u64, key));
                            has_mssk = true;
                        }
                    }
                }

                // Primary credential signature: ANSI_STRING {len=7, maxlen=8}
                if off + 4 <= 4096 {
                    let sig = super::types::read_u32_le(page, off).unwrap_or(0);
                    if sig == 0x0008_0007 && verify_primary_signature(page, off) {
                        results
                            .primary_hits
                            .push((page_addr + off as u64, page_addr));
                    }
                }

                // DPAPI entry signature
                if dpapi::try_dpapi_entry_match(page, off) {
                    results
                        .dpapi_hits
                        .push((page_addr + off as u64, page.to_vec()));
                }
            }

            // Collect IV candidates from MSSK-containing pages
            if has_mssk {
                collect_iv_candidates(page, page_addr, &mut results.iv_candidates);
            }

            page_off += 4096;
        }

        // --- Session structure scan (chunk-level, 8-byte aligned) ---
        // Look for plausible session entries across the entire chunk.
        // LUID is at +0x70 in all Vista+ x64 variants.
        scan_chunk_for_sessions(
            &chunk_buf[..read_len],
            chunk_addr,
            &mut results.session_candidates,
        );

        chunk_addr += read_len as u64;
    }

    (lsass_candidates, results)
}

/// Try to validate a `lsass.exe` string match as a real EPROCESS.
fn try_validate_lsass<P: PhysicalMemory>(phys: &P, match_phys: u64, candidates: &mut Vec<Process>) {
    let phys_size = phys.phys_size();

    for offsets in ALL_EPROCESS_OFFSETS {
        if match_phys < offsets.image_file_name {
            continue;
        }
        let eprocess_phys = match_phys - offsets.image_file_name;
        let reader = EprocessReader::new(offsets);

        let pid = match reader.read_pid(phys, eprocess_phys) {
            Ok(pid) if pid > 0 && pid < 100_000 => pid,
            _ => continue,
        };

        let Ok(dtb) = reader.read_dtb(phys, eprocess_phys) else {
            continue;
        };
        let dtb_base = dtb & PAGE_PHYS_MASK;
        if dtb_base == 0 || dtb_base >= phys_size {
            continue;
        }

        let peb = reader.read_peb(phys, eprocess_phys).unwrap_or(0);
        if peb != 0 {
            let high = peb >> 48;
            if high != 0 && high != 0xFFFF {
                continue;
            }
            if peb >= 0x0000_8000_0000_0000 {
                continue;
            }
        }

        if !validate_dtb(phys, dtb) {
            log::info!(
                "Carve: lsass candidate at 0x{eprocess_phys:x} rejected: DTB 0x{dtb:x} fails PML4 validation"
            );
            continue;
        }

        log::info!(
            "Carve: found lsass.exe EPROCESS at phys=0x{eprocess_phys:x}, PID={pid}, DTB=0x{dtb:x}, PEB=0x{peb:x}"
        );

        // Avoid duplicate candidates (same PID+DTB)
        if !candidates.iter().any(|c| c.pid == pid && c.dtb == dtb) {
            candidates.push(Process {
                pid,
                name: "lsass.exe".to_string(),
                dtb,
                eprocess_phys,
                peb_vaddr: peb,
            });
        }
    }
}

/// Validate a DTB by reading its PML4 table and checking structural consistency.
///
/// A valid PML4 has a small number of present entries (1-50), all pointing to
/// physical frames within the file. This rejects random data and ASCII strings
/// being misinterpreted as DTB values.
fn validate_dtb<P: PhysicalMemory>(phys: &P, dtb: u64) -> bool {
    let pml4_base = dtb & PAGE_PHYS_MASK;
    let mut pml4 = [0u8; 4096];
    if phys.read_phys(pml4_base, &mut pml4).is_err() {
        return false;
    }

    let phys_size = phys.phys_size();
    let mut present = 0u32;
    let mut valid_frames = 0u32;

    for i in 0..512 {
        let entry = super::types::read_u64_le(&pml4, i * 8).unwrap_or(0);
        if entry & 1 != 0 {
            // Present bit set
            present += 1;
            let frame = entry & PAGE_PHYS_MASK;
            if frame < phys_size {
                valid_frames += 1;
            }
        }
    }

    // Valid PML4: at least 1 present entry, not too many (< 50),
    // and all present entries must have frames within physical range
    if !(1..=50).contains(&present) || valid_frames != present {
        log::info!(
            "Carve: DTB 0x{dtb:x} PML4 check: present={present}, valid_frames={valid_frames} — rejected"
        );
        return false;
    }

    log::info!("Carve: DTB 0x{dtb:x} PML4 validated: {present} present entries");
    true
}

// ---------------------------------------------------------------------------
// Level 2: Raw physical page carving
// ---------------------------------------------------------------------------

/// Carve credentials from raw physical pages using pre-computed scan results.
/// If `lsass_dtb` is provided (from Level 1), uses it for VA→PA translation
/// and LSASS-focused key extraction.
fn carve_level2<P: PhysicalMemory>(
    phys: &P,
    lsass_dtb: Option<u64>,
    scan: &ScanResults,
) -> Vec<Credential> {
    // Resolve crypto keys: prefer LSASS-focused extraction, fall back to physical scan keys.
    let Some((des_key, aes_key)) = resolve_crypto_keys(phys, lsass_dtb, &scan.mssk_keys) else {
        println!("[!] Carve L2: no valid 3DES/AES keys found — cannot decrypt credentials");
        return Vec::new();
    };

    println!(
        "[+] Carve L2: 3DES key ({} bytes), AES key ({} bytes)",
        des_key.len(),
        aes_key.len()
    );

    // For MSV hash extraction: IV doesn't matter.
    // In CBC mode, the IV only affects the first block (16B for AES, 8B for 3DES).
    // All hash offsets in PRIMARY_CRED_OFFSETS are ≥ 0x20 (past the first block).
    // SHA1(NT_hash) cross-validation still works with any IV.
    let msv_keys = CryptoKeys {
        iv: [0u8; 16],
        des_key: des_key.clone(),
        aes_key: aes_key.clone(),
    };

    // Also try ALL key combinations if LSASS-specific fails
    let all_key_pairs = build_key_pairs(&scan.mssk_keys);

    let mut credentials = Vec::new();

    // Carve MSV Primary credentials (IV-independent, SHA1-validated)
    let mut msv_creds = carve_primary_credentials(phys, &scan.primary_hits, &msv_keys, lsass_dtb);

    // If LSASS-specific keys produced nothing, try alternative key combinations.
    // Use a SINGLE physical memory pass testing all (key, page_offset) combinations
    // simultaneously, instead of N separate full scans.
    if msv_creds.is_empty() && !all_key_pairs.is_empty() {
        // Collect unique (blob_size, page_offset) targets from Primary hits
        let mut targets: Vec<(usize, usize)> = Vec::new(); // (blob_size, page_offset)
        for (primary_addr, _) in &scan.primary_hits {
            let blob_size = match read_primary_blob_size(phys, *primary_addr) {
                Some(s) if (0x40..=0x400).contains(&s) => s as usize,
                _ => continue,
            };
            if let Some(vptr) = read_primary_blob_vptr(phys, *primary_addr) {
                let page_offset = (vptr & 0xFFF) as usize;
                if page_offset + blob_size <= 4096 && !targets.contains(&(blob_size, page_offset)) {
                    targets.push((blob_size, page_offset));
                }
            }
        }

        if !targets.is_empty() {
            // 3DES is ~1300x slower than AES (no hardware acceleration).
            // Cap both target count and key count for 3DES to keep scan under ~90s.
            let has_3des_targets = targets.iter().any(|(sz, _)| sz.is_multiple_of(8));
            if has_3des_targets {
                targets.truncate(3);
            }
            let max_keys = if has_3des_targets { 2 } else { 8 };

            let alt_key_list: Vec<CryptoKeys> = all_key_pairs
                .iter()
                .take(max_keys)
                .map(|(dk, ak)| CryptoKeys {
                    iv: [0u8; 16],
                    des_key: dk.clone(),
                    aes_key: ak.clone(),
                })
                .collect();

            println!(
                "[*] Carve L2: trying {} key combos × {} targets in single pass{}...",
                alt_key_list.len(),
                targets.len(),
                if has_3des_targets { " (3DES)" } else { "" }
            );

            if let Some(msv) = search_blob_multi_keys(phys, &targets, &alt_key_list) {
                msv_creds.push(msv);
            }
        }
    }

    println!("[+] Carve L2: {} MSV credentials carved", msv_creds.len());
    for msv in msv_creds {
        credentials.push(Credential {
            msv: Some(msv),
            ..Credential::default()
        });
    }

    // For DPAPI: try to resolve IV (first block matters for master key correctness).
    // If IV can't be resolved, use zero IV (first 16B of master key will be wrong).
    let dpapi_keys = if let Some(iv) = resolve_iv(phys, scan, &des_key, &aes_key, lsass_dtb) {
        println!("[+] Carve L2: IV resolved: {}", hex::encode(iv));
        CryptoKeys {
            iv,
            des_key,
            aes_key,
        }
    } else {
        println!("[!] Carve L2: no valid IV found — DPAPI master keys may be partially incorrect");
        msv_keys
    };

    // Carve DPAPI entries
    let dpapi_creds = carve_dpapi_entries(&scan.dpapi_hits, &dpapi_keys);
    println!("[+] Carve L2: {} DPAPI entries carved", dpapi_creds.len());
    for (luid, dk) in dpapi_creds {
        // Try to attach to an existing credential with same LUID, or create new
        let existing = credentials.iter_mut().find(|c| c.luid == luid && luid != 0);
        if let Some(cred) = existing {
            cred.dpapi.push(dk);
        } else {
            credentials.push(Credential {
                luid,
                dpapi: vec![dk],
                ..Credential::default()
            });
        }
    }

    // Enrich credentials with session metadata (username, domain, logon time)
    // by scanning physical memory for session structures matching discovered LUIDs.
    enrich_session_metadata(&scan.session_candidates, &mut credentials);

    credentials
}

// ---------------------------------------------------------------------------
// Session metadata carving (physical memory scan for LIST_63-like structures)
// ---------------------------------------------------------------------------

/// Session structure layout for physical memory scanning.
/// Only variants with luid at 0x70 (the common case for Vista+ x64).
struct SessionLayout {
    username: usize,
    domain: usize,
    logon_type: usize,
    session_id: usize,
    logon_time: usize,
    /// Minimum entry size needed to read all fields
    min_size: usize,
}

const SESSION_LAYOUTS: &[SessionLayout] = &[
    // LIST_63 (Win10 1607+ / Win11)
    SessionLayout {
        username: 0x90,
        domain: 0xA0,
        logon_type: 0xD8,
        session_id: 0xE8,
        logon_time: 0xF0,
        min_size: 0x108,
    },
    // LIST_65 (Win11 24H2 newer)
    SessionLayout {
        username: 0xA0,
        domain: 0xB0,
        logon_type: 0xE8,
        session_id: 0xF8,
        logon_time: 0x100,
        min_size: 0x118,
    },
    // LIST_64 (Win11 24H2 early)
    SessionLayout {
        username: 0x98,
        domain: 0xA8,
        logon_type: 0xE0,
        session_id: 0xF0,
        logon_time: 0xF8,
        min_size: 0x110,
    },
    // LIST_62 (Win8/8.1)
    SessionLayout {
        username: 0x80,
        domain: 0x90,
        logon_type: 0xC8,
        session_id: 0xD8,
        logon_time: 0xE0,
        min_size: 0xF8,
    },
    // LIST_60 (Win7)
    SessionLayout {
        username: 0x80,
        domain: 0x90,
        logon_type: 0xB8,
        session_id: 0xBC,
        logon_time: 0xC0,
        min_size: 0xD8,
    },
];

/// FILETIME range for validation: Jan 1 2000 — Jan 1 2100
const FT_2000: u64 = 125_911_584_000_000_000;
const FT_2100: u64 = 157_766_112_000_000_000;

/// Enrich credentials with session metadata from pre-computed candidates.
/// The candidates were collected during the combined_scan_pass (no second memory pass needed).
fn enrich_session_metadata(candidates: &HashMap<u64, SessionMeta>, credentials: &mut [Credential]) {
    let target_luids: HashSet<u64> = credentials
        .iter()
        .map(|c| c.luid)
        .filter(|&l| l != 0)
        .collect();

    if target_luids.is_empty() {
        return;
    }

    let found_count = target_luids
        .iter()
        .filter(|l| candidates.contains_key(l))
        .count();
    if found_count > 0 {
        println!(
            "[+] Carve: found session metadata for {}/{} LUIDs",
            found_count,
            target_luids.len()
        );
    }

    // Merge into credentials
    for cred in credentials.iter_mut() {
        // Fill well-known LUIDs
        fill_wellknown_luid(cred);

        if let Some(meta) = candidates.get(&cred.luid) {
            cred.logon_type = meta.logon_type;
            cred.session_id = meta.session_id;
            cred.logon_time = meta.logon_time;
            if cred.username.is_empty() && !meta.username.is_empty() {
                cred.username.clone_from(&meta.username);
            }
            if cred.domain.is_empty() && !meta.domain.is_empty() {
                cred.domain.clone_from(&meta.domain);
            }
        }
    }
}

struct SessionMeta {
    logon_type: u32,
    session_id: u32,
    logon_time: u64,
    username: String,
    domain: String,
}

use crate::lsass::types::fill_wellknown_luid;

/// Validate and extract session metadata from a candidate entry.
/// `chunk` is the full 1MB scan chunk containing the entry, `entry_off_in_chunk` is the
/// entry's offset within that chunk. Used to attempt same-chunk string resolution.
fn validate_session_entry(
    entry: &[u8],
    layout: &SessionLayout,
    chunk: &[u8],
    entry_off_in_chunk: usize,
    chunk_base_phys: u64,
) -> Option<SessionMeta> {
    if entry.len() < layout.min_size {
        return None;
    }

    // Read inline fields
    let logon_type = u32::from_le_bytes(
        entry[layout.logon_type..layout.logon_type + 4]
            .try_into()
            .ok()?,
    );
    if logon_type > 13 {
        return None;
    }

    let logon_time = u64::from_le_bytes(
        entry[layout.logon_time..layout.logon_time + 8]
            .try_into()
            .ok()?,
    );
    // LogonTime must be in a plausible range, OR zero (for SYSTEM/special accounts)
    if logon_time != 0 && !(FT_2000..=FT_2100).contains(&logon_time) {
        return None;
    }

    let session_id = u32::from_le_bytes(
        entry[layout.session_id..layout.session_id + 4]
            .try_into()
            .ok()?,
    );
    if session_id > 100 {
        return None;
    }

    // Validate LIST_ENTRY at entry start (Flink/Blink must be plausible kernel-user pointers)
    let flink = u64::from_le_bytes(entry[0..8].try_into().ok()?);
    let blink = u64::from_le_bytes(entry[8..16].try_into().ok()?);
    if flink == 0 || blink == 0 {
        return None;
    }
    // Both pointers should be in user-mode range (< 0x0000800000000000)
    if (flink >> 47) != 0 || (blink >> 47) != 0 {
        return None;
    }

    // Validate UNICODE_STRING for username and domain (structure plausibility)
    let uname_meta = read_unicode_string_meta(entry, layout.username);
    let domain_meta = read_unicode_string_meta(entry, layout.domain);

    // At least username OR domain should have a valid UNICODE_STRING
    if uname_meta.is_none() && domain_meta.is_none() {
        return None;
    }

    // Try to resolve strings from the same chunk (same-heap-segment heuristic).
    // The Buffer VA points to LSASS virtual memory, but if the string was allocated
    // near the session struct, the physical page may be in our 1MB chunk.
    // We use the Flink VA to compute the entry's virtual base, then calculate the
    // expected physical offset for the string buffer.
    let entry_va = flink.wrapping_sub(0); // Flink points to next entry, but entry VA ≈ blink of next
    // More reliable: entry_va is what Blink of the NEXT entry points to,
    // i.e. the VA of this entry's LIST_ENTRY. We can estimate it from Flink/Blink neighborhood.
    // But simpler: use the entry's physical offset + Buffer VA page-offset approach.
    let entry_phys = chunk_base_phys + entry_off_in_chunk as u64;
    let username =
        resolve_string_from_chunk(uname_meta, entry_phys, entry_va, chunk, chunk_base_phys);
    let domain =
        resolve_string_from_chunk(domain_meta, entry_phys, entry_va, chunk, chunk_base_phys);

    Some(SessionMeta {
        logon_type,
        session_id,
        logon_time,
        username: username.unwrap_or_default(),
        domain: domain.unwrap_or_default(),
    })
}

/// Try to resolve a UNICODE_STRING from the scan chunk, given the entry's physical address.
/// Returns decoded string if the buffer is likely on the same physical page or nearby in the chunk.
fn resolve_string_from_chunk(
    meta: Option<(usize, u64)>,
    entry_phys: u64,
    _entry_va: u64,
    chunk: &[u8],
    chunk_base: u64,
) -> Option<String> {
    let (len_bytes, buf_va) = meta?;
    if len_bytes == 0 || len_bytes > 254 {
        return None;
    }

    // Strategy: the Buffer VA has a page offset (lower 12 bits).
    // The string's physical page might be near the entry's physical page.
    // Try each page within ±16 pages of the entry, using the VA's page offset.
    let buf_page_off = (buf_va & 0xFFF) as usize;
    if buf_page_off + len_bytes > 4096 {
        return None; // String would cross page boundary
    }

    // Only check the same physical page as the entry. Adjacent pages produce too many
    // false positives from unrelated strings (log fragments, debug text, etc.).
    // This works when LSASS allocated the string buffer on the same heap page as the struct.
    let entry_page_phys = entry_phys & !0xFFF;
    if entry_page_phys < chunk_base {
        return None;
    }
    let page_off_in_chunk = (entry_page_phys - chunk_base) as usize;
    if page_off_in_chunk + 4096 > chunk.len() {
        return None;
    }

    let str_start = page_off_in_chunk + buf_page_off;
    let str_end = str_start + len_bytes;
    if str_end > chunk.len() {
        return None;
    }

    try_decode_utf16le_strict(&chunk[str_start..str_end])
}

/// Decode UTF-16LE bytes to a String, validating as a Windows username/domain.
/// Allows any script (Latin, CJK, Cyrillic, Arabic, etc.) but rejects control chars,
/// private-use area, and common garbage indicators (brackets, pipes, slashes, etc.).
fn try_decode_utf16le_strict(data: &[u8]) -> Option<String> {
    if data.len() < 2 || !data.len().is_multiple_of(2) {
        return None;
    }
    // Strict UTF-16LE decode (no replacement chars — invalid surrogates = garbage)
    let s: String = char::decode_utf16(
        data.chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]])),
    )
    .collect::<std::result::Result<_, _>>()
    .ok()?;

    // Basic length check (byte length — 64 bytes covers ~21 CJK chars or 64 ASCII chars)
    if s.is_empty() || s.len() > 192 {
        return None;
    }
    // Reject control characters, private-use area (garbage), and common non-username chars.
    // Allow: alphanumeric (any script), spaces, hyphens, underscores, dots, @, apostrophes.
    if !s
        .chars()
        .all(|c| c.is_alphanumeric() || " -_.@'".contains(c))
    {
        return None;
    }
    // Must start with alphanumeric (any script)
    if !s.starts_with(|c: char| c.is_alphanumeric()) {
        return None;
    }
    // Must contain at least 2 alphanumeric characters (any script)
    if s.chars().filter(|c| c.is_alphanumeric()).count() < 2 {
        return None;
    }
    Some(s)
}

/// Extract UNICODE_STRING metadata (Length, Buffer VA) from a session entry.
/// Returns (len_bytes, buffer_va) if the UNICODE_STRING looks valid.
fn read_unicode_string_meta(entry: &[u8], offset: usize) -> Option<(usize, u64)> {
    if offset + 16 > entry.len() {
        return None;
    }

    let len = u16::from_le_bytes(entry[offset..offset + 2].try_into().ok()?) as usize;
    let max_len = u16::from_le_bytes(entry[offset + 2..offset + 4].try_into().ok()?) as usize;

    // Validate: len must be even (UTF-16), > 0, <= 254 bytes, max_len >= len
    if len == 0 || len > 254 || !len.is_multiple_of(2) || max_len < len || max_len > 512 {
        return None;
    }

    let buf_ptr = u64::from_le_bytes(entry[offset + 8..offset + 16].try_into().ok()?);
    if buf_ptr == 0 || (buf_ptr >> 47) != 0 {
        return None;
    }

    Some((len, buf_ptr))
}

/// Scan a memory chunk for plausible session structures and add them to candidates.
/// This is called during the combined_scan_pass to avoid a second full memory pass.
fn scan_chunk_for_sessions(data: &[u8], base: u64, candidates: &mut HashMap<u64, SessionMeta>) {
    let luid_offset = 0x70usize;

    // Scan for 8-byte aligned positions where a non-trivial LUID could be at +0x70
    for off in (0..data.len().saturating_sub(8)).step_by(8) {
        let val = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());

        // Quick filter: LUIDs are non-zero, typically < 0x10000000, and > 0x100
        // (skip very common values like 0, 1, 2 that cause too many false hits)
        if !(0x100..=0x0FFF_FFFF).contains(&val) {
            continue;
        }

        // Skip if we already have a high-confidence match for this LUID
        if candidates
            .get(&val)
            .is_some_and(|m| m.logon_time != 0 && !m.username.is_empty())
        {
            continue;
        }

        // This could be a LUID at offset 0x70 within a session entry
        let Some(entry_off) = off.checked_sub(luid_offset) else {
            continue;
        };

        // Try each session layout variant
        for layout in SESSION_LAYOUTS {
            if entry_off + layout.min_size > data.len() {
                continue;
            }

            if let Some(meta) =
                validate_session_entry(&data[entry_off..], layout, data, entry_off, base)
            {
                // Prefer entries with more metadata (LogonTime + username)
                let dominated = candidates.get(&val).is_some_and(|existing| {
                    let existing_score = u8::from(existing.logon_time != 0)
                        + u8::from(!existing.username.is_empty());
                    let new_score =
                        u8::from(meta.logon_time != 0) + u8::from(!meta.username.is_empty());
                    existing_score > new_score
                });
                if !dominated {
                    candidates.insert(val, meta);
                }
                break;
            }
        }
    }
}

/// Verify that a 07 00 08 00 signature is likely a real Primary credential ANSI_STRING.
/// Check for "Primary" ASCII text at a reasonable offset after the signature.
fn verify_primary_signature(page: &[u8], off: usize) -> bool {
    // In memory, the ANSI_STRING {Length=7, MaxLength=8} is followed by padding (4 bytes)
    // then a pointer to the "Primary" string buffer, OR the string may be inline.
    // Check: is "Primary" within ±64 bytes?
    let primary = b"Primary";
    let search_start = off.saturating_sub(64);
    let search_end = (off + 128).min(page.len().saturating_sub(primary.len()));
    for i in search_start..search_end {
        if page.get(i..i + primary.len()) == Some(primary) {
            return true;
        }
    }
    false
}

/// Collect IV candidates from a page containing MSSK structures.
/// IV is 16 bytes, 8-byte aligned, non-zero, not pointer-shaped, ≥4 unique bytes.
fn collect_iv_candidates(page: &[u8], page_addr: u64, candidates: &mut Vec<(u64, [u8; 16])>) {
    // Cap total candidates
    if candidates.len() >= 64 {
        return;
    }

    for off in (0..4096 - 16).step_by(8) {
        let candidate = &page[off..off + 16];

        // Must be non-zero
        if candidate.iter().all(|&b| b == 0) {
            continue;
        }

        // First 8 bytes should not look like a pointer
        let val = super::types::read_u64_le(candidate, 0).unwrap_or(0);
        if val > 0x10000 && (val >> 48 == 0 || val >> 48 == 0xFFFF) && val & 0x7 == 0 {
            continue;
        }

        // Second 8 bytes should not look like a pointer
        let val2 = super::types::read_u64_le(candidate, 8).unwrap_or(0);
        if val2 > 0x10000 && (val2 >> 48 == 0 || val2 >> 48 == 0xFFFF) && val2 & 0x7 == 0 {
            continue;
        }

        // Need ≥4 unique bytes for entropy
        if super::crypto::count_unique_bytes(candidate) < 4 {
            continue;
        }

        // Skip if it's a tag we already know (MSSK, UUUR, etc.)
        let tag = super::types::read_u32_le(candidate, 4).unwrap_or(0);
        if tag == 0x4D53_534B || tag == 0x5555_5552 {
            continue;
        }

        let mut iv = [0u8; 16];
        iv.copy_from_slice(candidate);
        candidates.push((page_addr + off as u64, iv));

        if candidates.len() >= 64 {
            return;
        }
    }
}

/// Resolve crypto keys: try LSASS-specific keys first, fall back to all scan keys.
fn resolve_crypto_keys<P: PhysicalMemory>(
    phys: &P,
    lsass_dtb: Option<u64>,
    scan_keys: &[(u64, Vec<u8>)],
) -> Option<(Vec<u8>, Vec<u8>)> {
    if let Some(dtb) = lsass_dtb {
        let lsass_keys = find_lsass_mssk_keys(phys, dtb);
        if lsass_keys.is_empty() {
            println!("[*] Carve L2: no MSSK keys in LSASS pages, using physical scan keys");
        } else {
            println!(
                "[+] Carve L2: found {} MSSK keys in LSASS pages",
                lsass_keys.len()
            );
            if let Some(keys) = extract_crypto_keys(&lsass_keys) {
                return Some(keys);
            }
            println!("[!] Carve L2: LSASS keys insufficient, trying all keys");
        }
    }
    extract_crypto_keys(scan_keys)
}

/// Enumerate LSASS present pages and extract MSSK keys from them.
/// Only returns keys from pages that are in the LSASS address space.
fn find_lsass_mssk_keys<P: PhysicalMemory>(phys: &P, dtb: u64) -> Vec<(u64, Vec<u8>)> {
    let walker = PageTableWalker::new(phys);
    let mut keys = Vec::new();

    walker.enumerate_present_pages(dtb, |mapping| {
        if mapping.size != 0x1000 {
            return;
        }
        let mut page = [0u8; 4096];
        if phys.read_phys(mapping.paddr, &mut page).is_err() {
            return;
        }
        for off in (0..4096 - 8).step_by(8) {
            if let Some(key) = crypto::extract_key_from_bcrypt_data(&page, off) {
                log::info!(
                    "Carve: LSASS MSSK at PA=0x{:x}+0x{:x} (VA=0x{:x}): {} bytes",
                    mapping.paddr,
                    off,
                    mapping.vaddr + off as u64,
                    key.len()
                );
                keys.push((mapping.paddr + off as u64, key));
            }
        }
    });

    keys
}

/// Build all (3DES, AES) key pair combinations from MSSK scan results.
/// Used as fallback when the primary key pair doesn't validate.
fn build_key_pairs(mssk_keys: &[(u64, Vec<u8>)]) -> Vec<(Vec<u8>, Vec<u8>)> {
    static DUMMY_3DES: [u8; 24] = [0u8; 24];
    // Collect key refs — needed for nested iteration (can't borrow twice from iterator)
    let des_keys: Vec<&[u8]> = mssk_keys
        .iter()
        .filter_map(|(_, k)| {
            if k.len() == 24 {
                Some(k.as_slice())
            } else {
                None
            }
        })
        .collect();
    let aes_keys: Vec<&[u8]> = mssk_keys
        .iter()
        .filter_map(|(_, k)| {
            if k.len() == 16 || k.len() == 32 {
                Some(k.as_slice())
            } else {
                None
            }
        })
        .collect();

    let max_pairs = des_keys.len() * aes_keys.len() + aes_keys.len();
    let mut pairs = Vec::with_capacity(max_pairs.min(32));

    // Real key pairs (3DES + AES)
    'outer: for dk in &des_keys {
        for ak in &aes_keys {
            pairs.push((dk.to_vec(), ak.to_vec()));
            if pairs.len() >= 32 {
                break 'outer;
            }
        }
    }
    // AES-only pairs (dummy 3DES)
    for ak in &aes_keys {
        if pairs.len() >= 32 {
            break;
        }
        pairs.push((DUMMY_3DES.to_vec(), ak.to_vec()));
    }
    pairs
}

/// Extract 3DES (24B) and AES (16/32B) keys from MSSK scan results.
/// Returns (des_key, aes_key) where either may be a dummy zero-filled key
/// if only one type was found. The decrypt function selects by data alignment.
fn extract_crypto_keys(mssk_keys: &[(u64, Vec<u8>)]) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut des_key: Option<Vec<u8>> = None;
    let mut aes_key: Option<Vec<u8>> = None;

    for (addr, key) in mssk_keys {
        log::info!(
            "Carve: MSSK key candidate at 0x{:x}: {} bytes: {}",
            addr,
            key.len(),
            hex::encode(&key[..key.len().min(8)])
        );
        if key.len() == 24 && des_key.is_none() {
            des_key = Some(key.clone());
        } else if (key.len() == 16 || key.len() == 32) && aes_key.is_none() {
            aes_key = Some(key.clone());
        }
        if des_key.is_some() && aes_key.is_some() {
            break;
        }
    }

    match (des_key, aes_key) {
        (Some(d), Some(a)) => Some((d, a)),
        (None, Some(a)) => {
            log::info!("Carve: no 3DES key found, using dummy (AES-only mode)");
            Some((vec![0u8; 24], a))
        }
        (Some(d), None) => {
            log::info!("Carve: no AES key found, using dummy (3DES-only mode)");
            Some((d, vec![0u8; 16]))
        }
        (None, None) => None,
    }
}

/// Resolve the IV by back-computing from a known decryption.
///
/// Strategy: decrypt a Primary blob with zero IV (hash validation works because
/// hash fields are past the first CBC block). Then back-compute IV from:
///   IV = AES_ECB_decrypt(ciphertext_block0) XOR plaintext_block0_expected
///
/// Since we don't know plaintext_block0, we use an alternative: collect IV
/// candidates from all pages that also contain lsasrv.dll-like structures,
/// and validate by checking that the first block decodes to a plausible
/// UNICODE_STRING (the LogonDomainName at offset 0 of the decrypted Primary blob).
fn resolve_iv<P: PhysicalMemory>(
    phys: &P,
    scan: &ScanResults,
    des_key: &[u8],
    aes_key: &[u8],
    lsass_dtb: Option<u64>,
) -> Option<[u8; 16]> {
    if scan.iv_candidates.is_empty() {
        log::info!("Carve: no IV candidates found");
        return None;
    }

    // Try IV candidates × known blobs (with SHA1 + first-block validation)
    for (primary_addr, _) in &scan.primary_hits {
        let blob_size = match read_primary_blob_size(phys, *primary_addr) {
            Some(s) if (0x40..=0x400).contains(&s) => s as usize,
            _ => continue,
        };

        // Read blob via DTB
        let enc_data = if let Some(dtb) = lsass_dtb {
            read_blob_via_dtb_only(phys, *primary_addr, blob_size, dtb)
        } else {
            None
        };
        let Some(enc_data) = enc_data else { continue };

        for (iv_idx, (_, iv)) in scan.iv_candidates.iter().enumerate().take(64) {
            let keys = CryptoKeys {
                iv: *iv,
                des_key: des_key.to_vec(),
                aes_key: aes_key.to_vec(),
            };

            if let Ok(decrypted) = crypto::decrypt_credential(&keys, &enc_data) {
                // Require SHA1 validation + valid first-block UNICODE_STRING
                if validate_primary_decryption(&decrypted) && validate_first_block(&decrypted) {
                    log::info!(
                        "Carve: IV validated (candidate #{}) at phys=0x{:x}: {}",
                        iv_idx,
                        primary_addr,
                        hex::encode(iv)
                    );
                    return Some(*iv);
                }
            }
        }
    }

    log::info!("Carve: IV resolution failed — no validated IV found");
    None
}

/// Validate that the first block of a decrypted Primary blob looks like a valid UNICODE_STRING.
/// The first field is LogonDomainName: Length(u16) + MaxLength(u16) + padding(u32) + Buffer(u64).
fn validate_first_block(decrypted: &[u8]) -> bool {
    if decrypted.len() < 16 {
        return false;
    }
    let length = u16::from_le_bytes([decrypted[0], decrypted[1]]) as usize;
    let max_length = u16::from_le_bytes([decrypted[2], decrypted[3]]) as usize;
    // Domain name: even length, reasonable size, max >= length
    if length == 0 || length > 128 || !length.is_multiple_of(2) || max_length < length {
        return false;
    }
    // Padding should be 0
    let padding = u32::from_le_bytes([decrypted[4], decrypted[5], decrypted[6], decrypted[7]]);
    if padding != 0 {
        return false;
    }
    // Buffer should be a valid user-mode pointer
    let buf_ptr = super::types::read_u64_le(decrypted, 8).unwrap_or(0);
    if !(0x10000..0x0000_8000_0000_0000).contains(&buf_ptr) {
        return false;
    }
    true
}

/// Read encrypted blob via DTB-based VA→PA translation only.
fn read_blob_via_dtb_only<P: PhysicalMemory>(
    phys: &P,
    primary_addr: u64,
    blob_size: usize,
    dtb: u64,
) -> Option<Vec<u8>> {
    let blob_vptr = read_primary_blob_vptr(phys, primary_addr)?;
    let walker = PageTableWalker::new(phys);
    let blob_paddr = walker.translate(dtb, blob_vptr).ok()?;
    let mut buf = vec![0u8; blob_size];
    if phys.read_phys(blob_paddr, &mut buf).is_ok() && buf.iter().any(|&b| b != 0) {
        log::info!(
            "Carve: blob via DTB: VA=0x{blob_vptr:x} → PA=0x{blob_paddr:x}, {blob_size} bytes"
        );
        Some(buf)
    } else {
        None
    }
}

/// Read the encrypted blob size from a Primary credential structure.
///
/// The ANSI_STRING signature (07 00 08 00) is at struct+0x08, so primary_addr = struct+0x08.
/// The encrypted Credentials UNICODE_STRING Length is at struct+0x18 = primary_addr+0x10.
fn read_primary_blob_size<P: PhysicalMemory>(phys: &P, primary_addr: u64) -> Option<u16> {
    phys.read_phys_u16(primary_addr + 0x10).ok()
}

/// Read the virtual address of the encrypted blob from a Primary credential structure.
///
/// The Credentials UNICODE_STRING Buffer pointer is at struct+0x20 = primary_addr+0x18.
fn read_primary_blob_vptr<P: PhysicalMemory>(phys: &P, primary_addr: u64) -> Option<u64> {
    let ptr = phys.read_phys_u64(primary_addr + 0x18).ok()?;
    // Must be a valid user-mode canonical address
    if ptr == 0 || ptr < 0x10000 {
        return None;
    }
    let high = ptr >> 48;
    if high != 0 && high != 0xFFFF {
        return None;
    }
    // Must be in user-mode range
    if ptr >= 0x0000_8000_0000_0000 {
        return None;
    }
    Some(ptr)
}

/// Validate that a decrypted blob contains plausible Primary credential hashes.
/// Uses SHA1(NT_hash) == SHA1_field cross-validation.
fn validate_primary_decryption(decrypted: &[u8]) -> bool {
    for offsets in PRIMARY_CRED_OFFSETS {
        let nt_off = offsets.nt_hash;
        let sha1_off = offsets.sha1_hash;

        if decrypted.len() < sha1_off + 20 {
            continue;
        }

        let nt_hash = &decrypted[nt_off..nt_off + 16];
        let sha1_field = &decrypted[sha1_off..sha1_off + 20];

        // NT hash must be non-zero
        if nt_hash.iter().all(|&b| b == 0) {
            continue;
        }

        // Must look like a hash (has some entropy)
        if super::crypto::count_unique_bytes(nt_hash) < 4 {
            continue;
        }

        // Cross-validate: SHA1(NT_hash) should match the SHA1 field
        let computed_sha1 = sha1_hash(nt_hash);
        if computed_sha1 == sha1_field {
            return true;
        }
    }
    false
}

/// Carve MSV Primary credentials from physical memory.
/// Uses VA→PA translation (via lsass_dtb) when available, then a single combined
/// VA-offset scan for all targets, then nearby search as last resort.
fn carve_primary_credentials<P: PhysicalMemory>(
    phys: &P,
    primary_hits: &[(u64, u64)],
    keys: &CryptoKeys,
    lsass_dtb: Option<u64>,
) -> Vec<MsvCredential> {
    let mut results = Vec::new();
    let mut seen_nt_hashes = std::collections::HashSet::new();

    // Collect VA-offset targets for combined scan (avoid N separate full scans)
    let mut va_offset_targets: Vec<(usize, usize)> = Vec::new(); // (blob_size, page_offset)

    for (primary_addr, _page_base) in primary_hits {
        let blob_size = match read_primary_blob_size(phys, *primary_addr) {
            Some(s) if (0x40..=0x400).contains(&s) => s as usize,
            sz => {
                log::info!("Carve: Primary at 0x{primary_addr:x}: invalid blob size {sz:?}");
                continue;
            }
        };

        let blob_vptr_val = read_primary_blob_vptr(phys, *primary_addr);
        log::info!(
            "Carve: Primary at 0x{:x}: blob_size={}, blob_vptr={:?}",
            primary_addr,
            blob_size,
            blob_vptr_val.map(|v| format!("0x{v:x}"))
        );

        // Strategy 1: VA→PA translation (fastest, most reliable)
        if let Some(dtb) = lsass_dtb {
            if let Some(blob_vptr) = blob_vptr_val {
                let walker = PageTableWalker::new(phys);
                if let Ok(blob_paddr) = walker.translate(dtb, blob_vptr) {
                    let mut buf = vec![0u8; blob_size];
                    if phys.read_phys(blob_paddr, &mut buf).is_ok() && buf.iter().any(|&b| b != 0) {
                        if let Ok(decrypted) = crypto::decrypt_credential(keys, &buf) {
                            if let Some(msv) = extract_hashes_from_decrypted(&decrypted) {
                                if seen_nt_hashes.insert(msv.nt_hash) {
                                    log::info!(
                                        "Carve: MSV at Primary 0x{primary_addr:x} via DTB (VA=0x{blob_vptr:x}→PA=0x{blob_paddr:x})"
                                    );
                                    results.push(msv);
                                    continue;
                                }
                            }
                        }
                    }
                }
            }
        }

        // Collect for combined Strategy 2 scan (done after this loop)
        if let Some(blob_vptr) = blob_vptr_val {
            let page_offset = (blob_vptr & 0xFFF) as usize;
            if page_offset + blob_size <= 4096
                && !va_offset_targets.contains(&(blob_size, page_offset))
            {
                va_offset_targets.push((blob_size, page_offset));
            }
        } else {
            // Strategy 3: Nearby search (±4MB) — only when blob_vptr is unavailable
            if let Some(msv) = search_validated_blob(phys, *primary_addr, blob_size, keys, 1024) {
                if seen_nt_hashes.insert(msv.nt_hash) {
                    log::info!("Carve: MSV at Primary 0x{primary_addr:x} via nearby search (±4MB)");
                    results.push(msv);
                }
            }
        }
    }

    // Strategy 2: Single combined VA-offset scan for ALL targets at once.
    // Instead of N separate full-memory scans (one per Primary hit), read memory
    // once and test all page offsets.
    // Cap targets: 3DES is ~1300x slower than AES, so limit to 3 targets for 3DES
    // (each costs ~60s of CPU time per target on a 10GB file).
    if results.is_empty() && !va_offset_targets.is_empty() {
        let has_3des = va_offset_targets.iter().any(|(sz, _)| sz.is_multiple_of(8));
        if has_3des {
            va_offset_targets.truncate(3);
        }
        log::info!(
            "Carve: combined VA-offset scan for {} unique targets{}",
            va_offset_targets.len(),
            if has_3des { " (3DES)" } else { "" }
        );
        if let Some(msv) =
            search_blob_multi_keys(phys, &va_offset_targets, std::slice::from_ref(keys))
        {
            if seen_nt_hashes.insert(msv.nt_hash) {
                results.push(msv);
            }
        }
    }

    results
}

/// Maximum bytes needed for SHA1 cross-validation of Primary credential hashes.
/// Largest SHA1 offset (0x6C) + 20 bytes = 0x80 = 128 bytes, rounded to 16-byte AES block.
const VALIDATION_PREFIX_LEN: usize = 0x90; // 144 bytes = 9 AES blocks or 18 3DES blocks

/// Single-pass full-memory scan testing multiple (key, page_offset) combinations.
///
/// Instead of doing N separate full scans (one per key combo), reads each chunk
/// once and tests ALL key combos × ALL page offsets. This is O(1) I/O passes
/// regardless of how many key combos we try.
fn search_blob_multi_keys<P: PhysicalMemory>(
    phys: &P,
    targets: &[(usize, usize)], // (blob_size, page_offset)
    keys_list: &[CryptoKeys],
) -> Option<MsvCredential> {
    let phys_size = phys.phys_size();
    let mut chunk_buf = vec![0u8; SCAN_CHUNK_SIZE];
    let mut chunk_addr: u64 = 0;

    while chunk_addr < phys_size {
        let read_len = SCAN_CHUNK_SIZE.min((phys_size - chunk_addr) as usize);
        if phys
            .read_phys(chunk_addr, &mut chunk_buf[..read_len])
            .is_err()
        {
            chunk_addr += read_len as u64;
            continue;
        }

        let mut page_off = 0usize;
        while page_off + 4096 <= read_len {
            let page = &chunk_buf[page_off..page_off + 4096];

            for &(blob_size, page_offset) in targets {
                let enc_data = &page[page_offset..page_offset + blob_size];

                // Quick zero check
                if enc_data[0..8] == [0; 8] {
                    continue;
                }

                // Entropy pre-filter
                if !super::crypto::has_min_unique_bytes(&enc_data[..64.min(blob_size)], 22) {
                    continue;
                }

                // Try all key combinations on this candidate
                let use_3des = blob_size.is_multiple_of(8);
                for keys in keys_list {
                    let decrypted = if use_3des {
                        crypto::decrypt_prefix_3des(keys, enc_data, VALIDATION_PREFIX_LEN)
                    } else {
                        let [first, _] =
                            crypto::decrypt_prefix_both(keys, enc_data, VALIDATION_PREFIX_LEN);
                        first
                    };
                    if let Some(dec) = &decrypted {
                        if let Some(msv) = extract_hashes_from_decrypted(dec) {
                            log::info!(
                                "Carve: multi-key hit at phys=0x{:x}+0x{:x} ({})",
                                chunk_addr + page_off as u64,
                                page_offset,
                                if use_3des { "3DES" } else { "AES" }
                            );
                            return Some(msv);
                        }
                    }
                }
            }

            page_off += 4096;
        }

        chunk_addr += read_len as u64;
    }

    None
}

/// Search ±`radius` pages around a Primary hit, decrypt+validate each candidate blob.
/// Only returns SHA1-validated results (no false positives).
///
/// Uses 16-byte alignment (LSASS heap allocations are 16-byte aligned) and an
/// entropy pre-filter on the first 32 bytes to skip non-encrypted data quickly.
///
/// Tries both AES-CBC and 3DES-CBC for each candidate, decrypting only the first
/// 144 bytes (enough for all SHA1 validation offsets) instead of the full blob.
fn search_validated_blob<P: PhysicalMemory>(
    phys: &P,
    primary_addr: u64,
    blob_size: usize,
    keys: &CryptoKeys,
    radius: u64,
) -> Option<MsvCredential> {
    let search_start = primary_addr.saturating_sub(radius * 4096);
    let search_end = (primary_addr + radius * 4096).min(phys.phys_size());
    let mut chunk_buf = vec![0u8; SCAN_CHUNK_SIZE];
    let mut chunk_addr = search_start & !0xFFF; // page-align
    let max_blob_off = 4096usize.saturating_sub(blob_size);

    while chunk_addr < search_end {
        let read_len = SCAN_CHUNK_SIZE.min((search_end - chunk_addr) as usize);
        if phys
            .read_phys(chunk_addr, &mut chunk_buf[..read_len])
            .is_err()
        {
            chunk_addr += read_len as u64;
            continue;
        }

        let mut page_off = 0usize;
        while page_off + 4096 <= read_len {
            let page = &chunk_buf[page_off..page_off + 4096];
            let page_addr = chunk_addr + page_off as u64;

            // Skip zero pages
            if page[0..8] == [0; 8] && page[4088..4096] == [0; 8] && page.iter().all(|&b| b == 0) {
                page_off += 4096;
                continue;
            }

            for blob_off in (0..max_blob_off).step_by(16) {
                let enc_data = &page[blob_off..blob_off + blob_size];

                // Entropy pre-filter: AES/3DES ciphertext has near-uniform byte
                // distribution. Check first 64 bytes for ≥22 unique byte values.
                if !super::crypto::has_min_unique_bytes(&enc_data[..64.min(blob_size)], 22) {
                    continue;
                }

                // Select cipher based on blob size alignment (mimikatz logic):
                // blob_size % 8 == 0 → 3DES, else → AES
                let decrypted = if blob_size.is_multiple_of(8) {
                    crypto::decrypt_prefix_3des(keys, enc_data, VALIDATION_PREFIX_LEN)
                } else {
                    let [first, _] =
                        crypto::decrypt_prefix_both(keys, enc_data, VALIDATION_PREFIX_LEN);
                    first
                };
                if let Some(dec) = &decrypted {
                    if let Some(msv) = extract_hashes_from_decrypted(dec) {
                        log::info!(
                            "Carve: validated blob at phys=0x{:x}+0x{:x} ({})",
                            page_addr,
                            blob_off,
                            if blob_size.is_multiple_of(8) {
                                "3DES"
                            } else {
                                "AES"
                            }
                        );
                        return Some(msv);
                    }
                }
            }

            page_off += 4096;
        }

        chunk_addr += read_len as u64;
    }

    None
}

/// Extract NT/LM/SHA1 hashes from a decrypted Primary credential blob.
///
/// Only returns results validated by SHA1(NT_hash) == SHA1_field cross-check.
/// This eliminates false positives from random data in physical memory carving.
fn extract_hashes_from_decrypted(decrypted: &[u8]) -> Option<MsvCredential> {
    for offsets in PRIMARY_CRED_OFFSETS {
        let nt_off = offsets.nt_hash;
        let lm_off = offsets.lm_hash;
        let sha1_off = offsets.sha1_hash;

        if decrypted.len() < sha1_off + 20 {
            continue;
        }

        let mut nt_hash = [0u8; 16];
        let mut lm_hash = [0u8; 16];
        nt_hash.copy_from_slice(&decrypted[nt_off..nt_off + 16]);
        lm_hash.copy_from_slice(&decrypted[lm_off..lm_off + 16]);
        let sha1_field = &decrypted[sha1_off..sha1_off + 20];

        if nt_hash == [0u8; 16] {
            continue;
        }

        // Entropy check
        if super::crypto::count_unique_bytes(&nt_hash) < 4 {
            continue;
        }

        // SHA1 cross-validation — mandatory for carve mode to avoid false positives
        let computed_sha1 = sha1_hash(&nt_hash);
        if computed_sha1 == sha1_field {
            let mut sha1_hash_arr = [0u8; 20];
            sha1_hash_arr.copy_from_slice(sha1_field);
            return Some(MsvCredential {
                username: String::new(),
                domain: String::new(),
                lm_hash,
                nt_hash,
                sha1_hash: sha1_hash_arr,
            });
        }
    }

    None
}

/// Carve DPAPI master key entries from page snapshots.
fn carve_dpapi_entries(
    dpapi_hits: &[(u64, Vec<u8>)],
    keys: &CryptoKeys,
) -> Vec<(u64, DpapiCredential)> {
    let mut results = Vec::new();
    let mut seen_guids = std::collections::HashSet::new();

    for (entry_phys, page_data) in dpapi_hits {
        // Calculate the offset within the page
        let off = (*entry_phys % 4096) as usize;

        if let Some((luid, cred)) = dpapi::extract_dpapi_from_raw_page(page_data, off, keys) {
            if seen_guids.insert(cred.guid.clone()) {
                log::info!(
                    "Carve: DPAPI entry at phys=0x{:x}: GUID={}, LUID=0x{:x}",
                    entry_phys,
                    cred.guid,
                    luid
                );
                results.push((luid, cred));
            }
        }
    }

    results
}

use crate::utils::sha1_digest as sha1_hash;
