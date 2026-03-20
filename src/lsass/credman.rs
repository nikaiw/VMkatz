use crate::error::Result;
use crate::lsass::crypto::CryptoKeys;
use crate::lsass::types::{Arch, CredmanCredential, read_ptr, read_ustring, is_valid_user_ptr, read_data_section, read_ptr_from_buf};
use crate::memory::VirtualMemory;
use crate::pe::parser::PeHeaders;

/// MSV1_0_LIST entry offsets for the CredentialManager pointer.
struct CredmanMsvOffsets {
    flink: u64,
    luid: u64,
    username: u64,
    credman_ptr: u64,
}

const CREDMAN_MSV_OFFSET_VARIANTS: &[CredmanMsvOffsets] = &[
    // Win10 1607+ / Win11 (KIWI_MSV1_0_LIST_63)
    // CredentialManager is at the very end of the struct
    CredmanMsvOffsets {
        flink: 0x00,
        luid: 0x70,
        username: 0x90,
        credman_ptr: 0x158,
    },
    // Win8/8.1 (KIWI_MSV1_0_LIST_62, no waza[12])
    CredmanMsvOffsets {
        flink: 0x00,
        luid: 0x70,
        username: 0x80,
        credman_ptr: 0x148,
    },
    // Win7 SP1 (KIWI_MSV1_0_LIST_61)
    CredmanMsvOffsets {
        flink: 0x00,
        luid: 0x70,
        username: 0x80,
        credman_ptr: 0x100,
    },
    // Vista / Server 2008 (KIWI_MSV1_0_LIST_60)
    CredmanMsvOffsets {
        flink: 0x00,
        luid: 0x70,
        username: 0x80,
        credman_ptr: 0x108,
    },
];

// -- x86 offset variants --

/// x86 MSV entry offsets for CredentialManager pointer.
const CREDMAN_MSV_OFFSET_VARIANTS_X86: &[CredmanMsvOffsets] = &[
    // Win10 1607+ (LIST_63) x86
    CredmanMsvOffsets { flink: 0x00, luid: 0x3C, username: 0x48, credman_ptr: 0xB0 },
    // Win8/8.1 (LIST_62) x86
    CredmanMsvOffsets { flink: 0x00, luid: 0x3C, username: 0x44, credman_ptr: 0xA4 },
    // Win7 SP1 (LIST_61) x86
    CredmanMsvOffsets { flink: 0x00, luid: 0x3C, username: 0x44, credman_ptr: 0x80 },
    // Vista (LIST_60) x86
    CredmanMsvOffsets { flink: 0x00, luid: 0x3C, username: 0x44, credman_ptr: 0x84 },
];

/// KIWI_CREDMAN_LIST_ENTRY per-arch offsets.
/// Flink is mid-struct — subtract flink_offset to get base.
struct CredmanEntryOffsets {
    flink_offset: u64,
    cb_enc_password: u64,
    enc_password: u64,
    user: u64,     // UNICODE_STRING (display username)
    server1: u64,  // UNICODE_STRING (target)
    server2: u64,  // UNICODE_STRING (domain)
}

const CREDMAN_ENTRY_VARIANTS: &[CredmanEntryOffsets] = &[
    // Win7+ (KIWI_CREDMAN_LIST_ENTRY with unk4 LIST_ENTRY)
    CredmanEntryOffsets {
        flink_offset: 0x38,
        cb_enc_password: 0x00,
        enc_password: 0x08,
        user: 0xA8,
        server1: 0x70,
        server2: 0xC0,
    },
    // Win Vista / 2008 (KIWI_CREDMAN_LIST_ENTRY_60, no unk4 LIST_ENTRY)
    // Flink shifts back by 0x10 (no 16-byte unk4 LIST_ENTRY)
    CredmanEntryOffsets {
        flink_offset: 0x28,
        cb_enc_password: 0x00,
        enc_password: 0x08,
        user: 0x98,
        server1: 0x60,
        server2: 0xB0,
    },
];

/// x86 KIWI_CREDMAN_LIST_ENTRY offsets.
const CREDMAN_ENTRY_VARIANTS_X86: &[CredmanEntryOffsets] = &[
    // Win7+ x86 (with unk4 LIST_ENTRY)
    CredmanEntryOffsets {
        flink_offset: 0x20,
        cb_enc_password: 0x00,
        enc_password: 0x04,
        user: 0x58,
        server1: 0x3C,
        server2: 0x64,
    },
    // Vista x86 (no unk4 LIST_ENTRY)
    CredmanEntryOffsets {
        flink_offset: 0x18,
        cb_enc_password: 0x00,
        enc_password: 0x04,
        user: 0x50,
        server1: 0x34,
        server2: 0x5C,
    },
];

/// Extract Credential Manager saved credentials from MSV1_0 logon sessions.
///
/// Credman credentials are stored per-session inside MSV1_0 logon session entries.
/// Each entry has a CredentialManager pointer leading to a linked list of saved
/// credentials (RDP passwords, network share credentials, etc.).
///
/// Unified x64/x86 implementation: arch selects offset variants, pointer sizes,
/// and bucket sizes for hash table scanning.
pub fn extract_credman_credentials_arch(
    vmem: &dyn VirtualMemory,
    msv_base: u64,
    _msv_size: u32,
    keys: &CryptoKeys,
    arch: Arch,
) -> Result<Vec<(u64, CredmanCredential)>> {
    let msv_variants = match arch {
        Arch::X64 => CREDMAN_MSV_OFFSET_VARIANTS,
        Arch::X86 => CREDMAN_MSV_OFFSET_VARIANTS_X86,
    };

    let pe = PeHeaders::parse_from_memory(vmem, msv_base)?;
    let mut all_results = Vec::new();
    let mut validated = false;

    // Strategy 1: Try hash table walk (LogonSessionListCount hash table, most common)
    let tables = find_inline_hash_table(vmem, &pe, msv_base, arch)?;
    log::debug!("Credman {:?}: found {} hash table candidates", arch, tables.len());

    'ht: for (table_addr, bucket_count) in &tables {
        for offsets in msv_variants {
            if !validate_hash_table_variant(vmem, *table_addr, *bucket_count, offsets, arch) {
                continue;
            }
            log::debug!(
                "Credman {:?}: validated hash table at 0x{:x} ({} buckets) with variant luid=0x{:x}",
                arch,
                table_addr,
                bucket_count,
                offsets.luid
            );
            let results =
                walk_hash_table_for_credman(vmem, *table_addr, *bucket_count, offsets, keys, arch);
            all_results = results;
            validated = true;
            break 'ht;
        }
    }

    // Strategy 2: Fallback to single-list candidates (LogonSessionList)
    if !validated {
        let list_candidates = find_msv_list_candidates(vmem, &pe, msv_base, arch)?;
        log::debug!(
            "Credman {:?}: found {} single-list candidates",
            arch,
            list_candidates.len()
        );

        if !list_candidates.is_empty() {
            if let Some(results) = try_single_list_candidates(vmem, &list_candidates, keys, arch) {
                all_results = results;
            }
        }
    }

    log::info!("Credman {:?}: found {} entries", arch, all_results.len());
    Ok(all_results)
}

/// Try single-list candidates with each offset variant.
fn try_single_list_candidates(
    vmem: &dyn VirtualMemory,
    list_candidates: &[u64],
    keys: &CryptoKeys,
    arch: Arch,
) -> Option<Vec<(u64, CredmanCredential)>> {
    let msv_variants = match arch {
        Arch::X64 => CREDMAN_MSV_OFFSET_VARIANTS,
        Arch::X86 => CREDMAN_MSV_OFFSET_VARIANTS_X86,
    };

    for list_addr in list_candidates {
        for offsets in msv_variants {
            let head_flink = match read_ptr(vmem, *list_addr, arch) {
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
                let test_username = read_ustring(vmem, test_current + offsets.username, arch)
                    .unwrap_or_default();
                let test_luid = vmem.read_virt_u64(test_current + offsets.luid).unwrap_or(0);
                if !test_username.is_empty() && test_luid > 0 && test_luid < 0x100000 {
                    found_valid = true;
                    break;
                }
                test_current = match read_ptr(vmem, test_current + offsets.flink, arch) {
                    Ok(f) => f,
                    Err(_) => break,
                };
            }
            if !found_valid {
                continue;
            }

            log::debug!(
                "Credman {:?}: using single-list at 0x{:x} with variant (luid=0x{:x}, credman=0x{:x})",
                arch,
                list_addr,
                offsets.luid,
                offsets.credman_ptr
            );

            let results = walk_msv_for_credman(vmem, *list_addr, offsets, keys, arch);
            return Some(results);
        }
    }
    None
}

/// Validate that a hash table with given offsets produces readable usernames.
fn validate_hash_table_variant(
    vmem: &dyn VirtualMemory,
    table_addr: u64,
    bucket_count: usize,
    offsets: &CredmanMsvOffsets,
    arch: Arch,
) -> bool {
    let step = arch.list_entry_size() as usize;
    for bucket_idx in 0..bucket_count {
        let bucket_addr = table_addr + (bucket_idx * step) as u64;
        let flink = match read_ptr(vmem, bucket_addr, arch) {
            Ok(f) => f,
            Err(_) => continue,
        };
        if flink == bucket_addr || flink == 0 || !is_valid_user_ptr(flink, arch) {
            continue;
        }
        let username = read_ustring(vmem, flink + offsets.username, arch).unwrap_or_default();
        if !username.is_empty() {
            return true;
        }
    }
    false
}

/// Walk the MSV logon session list and extract Credman entries from each session.
fn walk_msv_for_credman(
    vmem: &dyn VirtualMemory,
    list_addr: u64,
    offsets: &CredmanMsvOffsets,
    keys: &CryptoKeys,
    arch: Arch,
) -> Vec<(u64, CredmanCredential)> {
    let mut results = Vec::new();
    let head_flink = match read_ptr(vmem, list_addr, arch) {
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
        let credman_ptr = read_ptr(vmem, current + offsets.credman_ptr, arch).unwrap_or(0);

        let username = read_ustring(vmem, current + offsets.username, arch).unwrap_or_default();
        log::debug!(
            "Credman {:?}: MSV entry at 0x{:x} LUID=0x{:x} user='{}' CredmanPtr=0x{:x}",
            arch,
            current,
            luid,
            username,
            credman_ptr
        );

        if is_valid_user_ptr(credman_ptr, arch) {
            extract_credman_from_ptr(vmem, credman_ptr, luid, keys, &mut results, arch);
        }

        current = match read_ptr(vmem, current + offsets.flink, arch) {
            Ok(f) => f,
            Err(_) => break,
        };
    }

    results
}

/// Walk all buckets in an inline hash table and extract Credman entries.
fn walk_hash_table_for_credman(
    vmem: &dyn VirtualMemory,
    table_addr: u64,
    bucket_count: usize,
    offsets: &CredmanMsvOffsets,
    keys: &CryptoKeys,
    arch: Arch,
) -> Vec<(u64, CredmanCredential)> {
    let mut results = Vec::new();
    let mut entries_found = 0u32;
    let step = arch.list_entry_size();

    for bucket_idx in 0..bucket_count {
        let bucket_addr = table_addr + (bucket_idx as u64) * step;
        let flink = match read_ptr(vmem, bucket_addr, arch) {
            Ok(f) => f,
            Err(_) => continue,
        };

        if flink == bucket_addr || flink == 0 || !is_valid_user_ptr(flink, arch) {
            continue;
        }

        let mut current = flink;
        let mut visited = std::collections::HashSet::new();

        loop {
            if current == bucket_addr || visited.contains(&current) || current == 0 {
                break;
            }
            visited.insert(current);

            let luid = vmem.read_virt_u64(current + offsets.luid).unwrap_or(0);
            let username = read_ustring(vmem, current + offsets.username, arch).unwrap_or_default();
            let credman_ptr = read_ptr(vmem, current + offsets.credman_ptr, arch).unwrap_or(0);

            if !username.is_empty() {
                entries_found += 1;
                log::debug!(
                    "Credman {:?}: hash bucket {} entry at 0x{:x} LUID=0x{:x} user='{}' CredmanPtr=0x{:x}",
                    arch, bucket_idx, current, luid, username, credman_ptr
                );

                if is_valid_user_ptr(credman_ptr, arch) {
                    extract_credman_from_ptr(vmem, credman_ptr, luid, keys, &mut results, arch);
                }
            }

            current = match read_ptr(vmem, current + offsets.flink, arch) {
                Ok(f) => f,
                Err(_) => break,
            };
        }
    }

    if entries_found > 0 {
        log::debug!(
            "Credman {:?}: hash table 0x{:x} ({} buckets): {} MSV entries, {} credman entries",
            arch,
            table_addr,
            bucket_count,
            entries_found,
            results.len()
        );
    }

    results
}

/// Extract Credman credentials from a CredentialManager pointer.
/// Follows: credman_ptr → SET_LIST_ENTRY → LIST_STARTER → first LIST_ENTRY.
fn extract_credman_from_ptr(
    vmem: &dyn VirtualMemory,
    credman_ptr: u64,
    luid: u64,
    keys: &CryptoKeys,
    results: &mut Vec<(u64, CredmanCredential)>,
    arch: Arch,
) {
    let set_list_entry_list1 = match arch { Arch::X64 => 0x18u64, Arch::X86 => 0x0C };
    let starter_start = match arch { Arch::X64 => 0x08u64, Arch::X86 => 0x04 };

    log::debug!(
        "Credman {:?}: LUID=0x{:x} CredentialManager=0x{:x}",
        arch,
        luid,
        credman_ptr
    );

    // credman_ptr -> KIWI_CREDMAN_SET_LIST_ENTRY
    // Read list1 pointer at SET_LIST_ENTRY + offset
    let list1_ptr = match read_ptr(vmem, credman_ptr + set_list_entry_list1, arch) {
        Ok(p) if is_valid_user_ptr(p, arch) => p,
        _ => {
            log::debug!("Credman {:?}: list1 pointer at 0x{:x}+0x{:x} invalid", arch, credman_ptr, set_list_entry_list1);
            return;
        }
    };

    // list1_ptr -> KIWI_CREDMAN_LIST_STARTER
    // The sentinel reference for list termination is &start (list1_ptr + offset)
    let sentinel = list1_ptr + starter_start;
    let first_flink = match read_ptr(vmem, sentinel, arch) {
        Ok(f) => f,
        Err(_) => return,
    };

    if first_flink == 0 || first_flink == sentinel || !is_valid_user_ptr(first_flink, arch) {
        log::debug!(
            "Credman {:?}: list at starter 0x{:x} is empty (flink=0x{:x})",
            arch,
            list1_ptr,
            first_flink
        );
        return;
    }

    let entries = walk_credman_list(vmem, sentinel, keys, arch);
    for entry in entries {
        results.push((luid, entry));
    }
}

/// Walk the Credman linked list and extract credentials.
fn walk_credman_list(
    vmem: &dyn VirtualMemory,
    sentinel: u64,
    keys: &CryptoKeys,
    arch: Arch,
) -> Vec<CredmanCredential> {
    let entry_variants = match arch {
        Arch::X64 => CREDMAN_ENTRY_VARIANTS,
        Arch::X86 => CREDMAN_ENTRY_VARIANTS_X86,
    };

    let mut results = Vec::new();
    let mut current_flink_addr = match read_ptr(vmem, sentinel, arch) {
        Ok(f) => f,
        Err(_) => return results,
    };
    let mut visited = std::collections::HashSet::new();

    loop {
        if current_flink_addr == sentinel
            || visited.contains(&current_flink_addr)
            || current_flink_addr == 0
        {
            break;
        }
        visited.insert(current_flink_addr);

        // Try each entry offset variant
        for entry_offsets in entry_variants {
            // Subtract flink_offset to get struct base
            let struct_base = current_flink_addr - entry_offsets.flink_offset;
            if let Some(cred) = try_extract_credman_entry(vmem, struct_base, entry_offsets, keys, arch) {
                results.push(cred);
                break;
            }
        }

        // Follow Flink (already at current_flink_addr, read the pointer there)
        current_flink_addr = match read_ptr(vmem, current_flink_addr, arch) {
            Ok(f) => f,
            Err(_) => break,
        };
    }

    results
}

/// Try to extract a single Credman entry using the given offsets.
/// `struct_base` is the start of the KIWI_CREDMAN_LIST_ENTRY (after flink_offset subtraction).
fn try_extract_credman_entry(
    vmem: &dyn VirtualMemory,
    struct_base: u64,
    offsets: &CredmanEntryOffsets,
    keys: &CryptoKeys,
    arch: Arch,
) -> Option<CredmanCredential> {
    // Read user (UNICODE_STRING at offsets.user) -- this is the display username
    let username = read_ustring(vmem, struct_base + offsets.user, arch).unwrap_or_default();
    if username.is_empty() {
        return None;
    }

    // Read server1 as target (UNICODE_STRING)
    let target = read_ustring(vmem, struct_base + offsets.server1, arch).unwrap_or_default();

    // Read server2 as domain (UNICODE_STRING)
    let domain = read_ustring(vmem, struct_base + offsets.server2, arch).unwrap_or_default();

    // Read encrypted password
    let cb_enc = vmem
        .read_virt_u32(struct_base + offsets.cb_enc_password)
        .ok()? as usize;
    let enc_ptr = read_ptr(vmem, struct_base + offsets.enc_password, arch).ok()?;

    let password = if cb_enc > 0 && cb_enc <= 0x400 && is_valid_user_ptr(enc_ptr, arch) {
        let enc_data = vmem.read_virt_bytes(enc_ptr, cb_enc).ok()?;
        match crate::lsass::crypto::decrypt_credential(keys, &enc_data) {
            Ok(dec) => crate::lsass::crypto::decode_utf16_le(&dec),
            Err(_) => String::new(),
        }
    } else {
        String::new()
    };

    log::debug!(
        "Credman entry: user='{}' target='{}' domain='{}' pwd_len={}",
        username,
        target,
        domain,
        password.len()
    );

    Some(CredmanCredential {
        username,
        domain,
        password,
        target,
    })
}

/// Find MSV logon session list candidates in msv1_0.dll .data section.
fn find_msv_list_candidates(
    vmem: &dyn VirtualMemory,
    pe: &PeHeaders,
    msv_base: u64,
    arch: Arch,
) -> Result<Vec<u64>> {
    let (data_base, data) = match read_data_section(vmem, pe, msv_base, 0x10000, "msv1_0.dll") {
        Ok(r) => r,
        Err(_) => return Ok(Vec::new()),
    };
    let data_size = data.len();

    let mut candidates = Vec::new();
    let step = arch.ptr_size() as usize;

    for off in (0..data_size.saturating_sub(step * 2)).step_by(step) {
        let flink = read_ptr_from_buf(&data, off, arch);
        let blink = read_ptr_from_buf(&data, off + step, arch);

        if !is_valid_user_ptr(flink, arch) || !is_valid_user_ptr(blink, arch) {
            continue;
        }
        if flink >= msv_base && flink < msv_base + 0x100000 {
            continue;
        }

        let list_addr = data_base + off as u64;

        // Verify: entry's blink points back to list_addr
        let entry_blink = match read_ptr(vmem, flink + step as u64, arch) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if entry_blink != list_addr {
            continue;
        }

        let entry_flink = match read_ptr(vmem, flink, arch) {
            Ok(f) => f,
            Err(_) => continue,
        };
        if entry_flink != list_addr && !is_valid_user_ptr(entry_flink, arch) {
            continue;
        }

        candidates.push(list_addr);
    }

    Ok(candidates)
}

/// Search the .data section for an inline LogonSessionList hash table.
fn find_inline_hash_table(
    vmem: &dyn VirtualMemory,
    pe: &PeHeaders,
    msv_base: u64,
    arch: Arch,
) -> Result<Vec<(u64, usize)>> {
    let msv_end = msv_base + 0x100000;
    let (data_base, data) = match read_data_section(vmem, pe, msv_base, 0x10000, "msv1_0.dll") {
        Ok(r) => r,
        Err(_) => return Ok(Vec::new()),
    };
    let data_size = data.len();

    let bucket_step = arch.list_entry_size() as usize;

    let mut tables = Vec::new();
    let mut run_start: Option<usize> = None;
    let mut run_count = 0usize;

    for off in (0..data_size.saturating_sub(bucket_step)).step_by(bucket_step) {
        let flink = read_ptr_from_buf(&data, off, arch);
        let blink = read_ptr_from_buf(&data, off + arch.ptr_size() as usize, arch);
        let self_addr = data_base + off as u64;

        let flink_is_self = flink == self_addr;
        let blink_is_self = blink == self_addr;
        let flink_is_dll = flink >= msv_base && flink < msv_end;
        let blink_is_dll = blink >= msv_base && blink < msv_end && !blink_is_self;

        let is_valid_bucket = (flink_is_self && blink_is_self)
            || (is_valid_user_ptr(flink, arch)
                && !flink_is_dll
                && (blink_is_self || (is_valid_user_ptr(blink, arch) && !blink_is_dll)));

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
