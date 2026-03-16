// Re-export crate-level safe read helpers for lsass submodules.
pub(super) use crate::utils::{read_u16_le, read_u32_le, read_u64_le};

use std::fmt::Write as _;

use crate::error::Result;
use crate::memory::VirtualMemory;

/// Target architecture for LSASS extraction.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Arch {
    X64,
    X86,
}

impl Arch {
    /// Pointer size in bytes.
    pub fn ptr_size(self) -> u64 {
        match self {
            Arch::X64 => 8,
            Arch::X86 => 4,
        }
    }

    /// UNICODE_STRING struct size in bytes.
    pub fn ustr_size(self) -> u64 {
        match self {
            Arch::X64 => 16,
            Arch::X86 => 8,
        }
    }

    /// LIST_ENTRY struct size (2 pointers).
    pub fn list_entry_size(self) -> u64 {
        self.ptr_size() * 2
    }
}

/// Read a pointer (4 or 8 bytes depending on arch).
pub fn read_ptr(vmem: &dyn VirtualMemory, addr: u64, arch: Arch) -> Result<u64> {
    match arch {
        Arch::X64 => Ok(vmem.read_virt_u64(addr)?),
        Arch::X86 => Ok(vmem.read_virt_u32(addr)? as u64),
    }
}

/// Read a UNICODE_STRING and return the string content.
pub fn read_ustring(vmem: &dyn VirtualMemory, addr: u64, arch: Arch) -> Result<String> {
    match arch {
        Arch::X64 => vmem.read_win_unicode_string(addr),
        Arch::X86 => vmem.read_win_unicode_string_32(addr),
    }
}

/// Validate a user-mode pointer for the given architecture.
pub fn is_valid_user_ptr(ptr: u64, arch: Arch) -> bool {
    match arch {
        Arch::X64 => ptr > 0x10000 && (ptr >> 48) == 0,
        Arch::X86 => ptr > 0x10000 && ptr < 0x8000_0000,
    }
}

/// Format a SID from its raw bytes: 8-byte header + sub-authority data.
/// SID header: Revision(1) + SubAuthorityCount(1) + IdentifierAuthority(6).
/// Sub-authority data: SubAuthorityCount × u32 LE values.
pub(super) fn format_sid_from_bytes(header: &[u8], sub_data: &[u8]) -> String {
    if header.len() < 8 {
        return String::new();
    }
    let revision = header[0];
    let sub_count = header[1] as usize;
    if revision != 1 || sub_count == 0 || sub_count > 15 || sub_data.len() < sub_count * 4 {
        return String::new();
    }
    let authority = u64::from_be_bytes([
        0, 0, header[2], header[3], header[4], header[5], header[6], header[7],
    ]);
    let mut s = format!("S-{}-{}", revision, authority);
    for i in 0..sub_count {
        let sub = u32::from_le_bytes([
            sub_data[i * 4],
            sub_data[i * 4 + 1],
            sub_data[i * 4 + 2],
            sub_data[i * 4 + 3],
        ]);
        write!(s, "-{}", sub).ok();
    }
    s
}

/// Convert Windows FILETIME (100-ns ticks since 1601-01-01) to a readable string.
pub fn filetime_to_string(ft: u64) -> String {
    if ft == 0 || ft == 0x7FFF_FFFF_FFFF_FFFF {
        return "N/A".to_string();
    }
    // Windows epoch (1601-01-01) to Unix epoch (1970-01-01) = 11644473600 seconds
    let unix_secs = (ft / 10_000_000).saturating_sub(11_644_473_600);
    let secs = unix_secs % 60;
    let mins = (unix_secs / 60) % 60;
    let hours = (unix_secs / 3600) % 24;
    let days = unix_secs / 86400;
    // Rough date from days since unix epoch
    let mut y = 1970u64;
    let mut rem = days;
    loop {
        let days_in_year =
            if y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400)) {
                366
            } else {
                365
            };
        if rem < days_in_year {
            break;
        }
        rem -= days_in_year;
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
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        y,
        m + 1,
        rem + 1,
        hours,
        mins,
        secs
    )
}

/// Human-readable Windows logon type.
pub fn logon_type_name(lt: u32) -> &'static str {
    match lt {
        0 => "UndefinedLogonType",
        2 => "Interactive",
        3 => "Network",
        4 => "Batch",
        5 => "Service",
        7 => "Unlock",
        8 => "NetworkCleartext",
        9 => "NewCredentials",
        10 => "RemoteInteractive",
        11 => "CachedInteractive",
        12 => "CachedRemoteInteractive",
        13 => "CachedUnlock",
        _ => "Unknown",
    }
}

/// Aggregated credential for a logon session.
#[derive(Debug, Default)]
pub struct Credential {
    pub luid: u64,
    pub username: String,
    pub domain: String,
    pub logon_type: u32,
    pub session_id: u32,
    pub logon_time: u64,
    pub logon_server: String,
    pub sid: String,
    pub msv: Option<MsvCredential>,
    pub wdigest: Option<WdigestCredential>,
    pub kerberos: Option<KerberosCredential>,
    pub tspkg: Option<TspkgCredential>,
    pub dpapi: Vec<DpapiCredential>,
    pub credman: Vec<CredmanCredential>,
    pub ssp: Option<SspCredential>,
    pub livessp: Option<LiveSspCredential>,
    pub cloudap: Option<CloudApCredential>,
}

/// MSV1_0 credential: NTLM hashes.
#[derive(Debug, Clone)]
pub struct MsvCredential {
    pub username: String,
    pub domain: String,
    pub lm_hash: [u8; 16],
    pub nt_hash: [u8; 16],
    pub sha1_hash: [u8; 20],
}

/// WDigest credential: plaintext password.
#[derive(Debug, Clone)]
pub struct WdigestCredential {
    pub username: String,
    pub domain: String,
    pub password: String,
}

/// Kerberos encryption key (AES128, AES256, RC4/NTLM, DES).
#[derive(Debug, Clone)]
pub struct KerberosKey {
    /// Kerberos encryption type (etype): 17=AES128, 18=AES256, 23=RC4, 3=DES
    pub etype: u32,
    /// Raw key bytes
    pub key: Vec<u8>,
}

impl KerberosKey {
    /// Human-readable encryption type name.
    pub fn etype_name(&self) -> &'static str {
        // Negative etypes are stored as u32, so -128 = 0xFFFFFF80, etc.
        match self.etype {
            1 => "DES_CBC_CRC",
            3 => "DES_CBC_MD5",
            17 => "AES128_HMAC",
            18 => "AES256_HMAC",
            23 => "RC4_HMAC",
            24 => "RC4_HMAC_EXP",
            0xFFFF_FF7B => "RC4_HMAC_OLD", // -133
            0xFFFF_FF80 => "RC4_HMAC_OLD_EXP", // -128
            0xFFFF_FF79 => "DES_PLAIN", // -135
            _ => "Unknown",
        }
    }
}

/// Kerberos credential.
#[derive(Debug, Clone)]
pub struct KerberosCredential {
    pub username: String,
    pub domain: String,
    pub password: String,
    pub keys: Vec<KerberosKey>,
    pub tickets: Vec<KerberosTicket>,
}

/// Kerberos ticket type (TGT, TGS, client).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KerberosTicketType {
    Tgt,
    Tgs,
    Client,
}

impl std::fmt::Display for KerberosTicketType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tgt => write!(f, "TGT"),
            Self::Tgs => write!(f, "TGS"),
            Self::Client => write!(f, "Client"),
        }
    }
}

/// Extracted Kerberos ticket (TGT/TGS).
#[derive(Debug, Clone)]
pub struct KerberosTicket {
    pub ticket_type: KerberosTicketType,
    pub service_name: Vec<String>,
    pub service_name_type: i16,
    pub client_name: Vec<String>,
    pub client_name_type: i16,
    pub domain_name: String,
    pub target_domain_name: String,
    pub ticket_flags: u32,
    pub key_type: u32,
    pub session_key: Vec<u8>,
    pub start_time: u64,
    pub end_time: u64,
    pub renew_until: u64,
    pub ticket_enc_type: u32,
    pub ticket_kvno: u32,
    pub ticket_blob: Vec<u8>,
    /// Pre-encoded .kirbi (KRB-CRED ASN.1 DER)
    pub kirbi: Vec<u8>,
}

/// TsPkg credential.
#[derive(Debug, Clone)]
pub struct TspkgCredential {
    pub username: String,
    pub domain: String,
    pub password: String,
}

/// DPAPI master key cache entry.
#[derive(Debug, Clone)]
pub struct DpapiCredential {
    pub guid: String,
    pub key: Vec<u8>,
    pub sha1_masterkey: [u8; 20],
}

/// Credential Manager saved credential.
#[derive(Debug, Clone)]
pub struct CredmanCredential {
    pub username: String,
    pub domain: String,
    pub password: String,
    pub target: String,
}

/// SSP credential (custom SSP).
#[derive(Debug, Clone)]
pub struct SspCredential {
    pub username: String,
    pub domain: String,
    pub password: String,
}

/// LiveSSP credential (Microsoft Account).
#[derive(Debug, Clone)]
pub struct LiveSspCredential {
    pub username: String,
    pub domain: String,
    pub password: String,
}

/// CloudAP credential (Azure AD).
#[derive(Debug, Clone)]
pub struct CloudApCredential {
    pub username: String,
    pub domain: String,
    pub dpapi_key: Vec<u8>,
    pub prt: String,
}

/// Well-known Windows logon session LUIDs (MS-DTYP / wininternl.h).
pub const LUID_SYSTEM: u64 = 0x3e7;
pub const LUID_NETWORK_SERVICE: u64 = 0x3e4;
pub const LUID_LOCAL_SERVICE: u64 = 0x3e5;
pub const LUID_IUSR: u64 = 0x3e3;

/// Fill username/domain for well-known Windows logon session LUIDs.
/// Only overwrites empty fields to avoid clobbering MSV/WDigest-discovered names.
pub fn fill_wellknown_luid(cred: &mut Credential) {
    if !cred.username.is_empty() {
        return;
    }
    match cred.luid {
        LUID_SYSTEM => {
            cred.username = "SYSTEM".to_string();
            cred.domain = "NT AUTHORITY".to_string();
        }
        LUID_NETWORK_SERVICE => {
            cred.username = "NETWORK SERVICE".to_string();
            cred.domain = "NT AUTHORITY".to_string();
        }
        LUID_LOCAL_SERVICE => {
            cred.username = "LOCAL SERVICE".to_string();
            cred.domain = "NT AUTHORITY".to_string();
        }
        LUID_IUSR => {
            cred.username = "IUSR".to_string();
            cred.domain = "NT AUTHORITY".to_string();
        }
        _ => {}
    }
}

impl Credential {
    pub fn new_empty(luid: u64, username: String, domain: String) -> Self {
        Credential {
            luid,
            username,
            domain,
            logon_type: 0,
            session_id: 0,
            logon_time: 0,
            logon_server: String::new(),
            sid: String::new(),
            msv: None,
            wdigest: None,
            kerberos: None,
            tspkg: None,
            dpapi: Vec::new(),
            credman: Vec::new(),
            ssp: None,
            livessp: None,
            cloudap: None,
        }
    }

    /// Returns true if this credential has any useful extracted data.
    pub fn has_credentials(&self) -> bool {
        self.msv.is_some()
            || self
                .wdigest
                .as_ref()
                .is_some_and(|w| !w.password.is_empty())
            || self
                .kerberos
                .as_ref()
                .is_some_and(|k| !k.password.is_empty() || !k.keys.is_empty() || !k.tickets.is_empty())
            || self.tspkg.as_ref().is_some_and(|t| !t.password.is_empty())
            || !self.dpapi.is_empty()
            || !self.credman.is_empty()
            || self.ssp.as_ref().is_some_and(|s| !s.password.is_empty())
            || self
                .livessp
                .as_ref()
                .is_some_and(|l| !l.password.is_empty())
            || self.cloudap.is_some()
    }
}

impl std::fmt::Display for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let luid_label = match self.luid {
            LUID_SYSTEM => " (SYSTEM)",
            LUID_NETWORK_SERVICE => " (NETWORK SERVICE)",
            LUID_LOCAL_SERVICE => " (LOCAL SERVICE)",
            LUID_IUSR => " (IUSER)",
            l if l >= 0x8000_0000_0000_0000 => " (physical scan)",
            _ => "",
        };
        writeln!(f, "  LUID: 0x{:x}{}", self.luid, luid_label)?;
        if self.session_id != 0 || self.logon_type != 0 {
            writeln!(
                f,
                "  Session: {} | LogonType: {}",
                self.session_id,
                logon_type_name(self.logon_type)
            )?;
        }
        writeln!(f, "  Username: {}", self.username)?;
        writeln!(f, "  Domain: {}", self.domain)?;
        if !self.logon_server.is_empty() {
            writeln!(f, "  LogonServer: {}", self.logon_server)?;
        }
        if self.logon_time != 0 {
            writeln!(f, "  LogonTime: {}", filetime_to_string(self.logon_time))?;
        }
        if !self.sid.is_empty() {
            writeln!(f, "  SID: {}", self.sid)?;
        }
        if !self.has_credentials() {
            writeln!(f, "  (no credentials extracted - paged out)")?;
            return Ok(());
        }
        if let Some(msv) = &self.msv {
            writeln!(f, "  [MSV1_0]")?;
            if msv.lm_hash != [0u8; 16] {
                writeln!(f, "    LM Hash : {}", hex::encode(msv.lm_hash))?;
            }
            writeln!(f, "    NT Hash : {}", hex::encode(msv.nt_hash))?;
            writeln!(f, "    SHA1    : {}", hex::encode(msv.sha1_hash))?;
            writeln!(f, "    DPAPI   : {}", hex::encode(msv.sha1_hash))?;
        }
        if let Some(wd) = &self.wdigest {
            if !wd.password.is_empty() {
                writeln!(f, "  [WDigest]")?;
                writeln!(f, "    Password: {}", wd.password)?;
            }
        }
        if let Some(krb) = &self.kerberos {
            writeln!(f, "  [Kerberos]")?;
            if !krb.password.is_empty() {
                writeln!(f, "    Password: {}", krb.password)?;
            }
            // Deduplicate keys by value — show each unique key once with primary etype
            let mut seen_keys: Vec<(&[u8], &str)> = Vec::new();
            for key in &krb.keys {
                if !seen_keys.iter().any(|(k, _)| *k == key.key.as_slice()) {
                    seen_keys.push((&key.key, key.etype_name()));
                }
            }
            for (key_bytes, etype_name) in &seen_keys {
                writeln!(
                    f,
                    "    {:11}: {}",
                    etype_name,
                    hex::encode(key_bytes)
                )?;
            }
            for ticket in &krb.tickets {
                writeln!(
                    f,
                    "    [{}] {}",
                    ticket.ticket_type,
                    ticket.service_name.join("/")
                )?;
                writeln!(f, "      Domain : {}", ticket.domain_name)?;
                writeln!(f, "      Client : {}", ticket.client_name.join("/"))?;
                writeln!(
                    f,
                    "      EncType: {} | KeyType: {} | Kvno: {}",
                    ticket.ticket_enc_type, ticket.key_type, ticket.ticket_kvno
                )?;
                writeln!(f, "      Flags  : 0x{:08x}", ticket.ticket_flags)?;
                writeln!(
                    f,
                    "      Start  : {}",
                    filetime_to_string(ticket.start_time)
                )?;
                writeln!(f, "      End    : {}", filetime_to_string(ticket.end_time))?;
                writeln!(
                    f,
                    "      Kirbi  : {} bytes (base64: {})",
                    ticket.kirbi.len(),
                    crate::lsass::crypto::base64_encode(&ticket.kirbi)
                )?;
            }
        }
        if let Some(ts) = &self.tspkg {
            writeln!(f, "  [TsPkg]")?;
            writeln!(f, "    Password: {}", ts.password)?;
        }
        for dk in &self.dpapi {
            writeln!(f, "  [DPAPI]")?;
            writeln!(f, "    GUID          : {}", dk.guid)?;
            writeln!(f, "    MasterKey     : {}", hex::encode(&dk.key))?;
            writeln!(f, "    SHA1 MasterKey: {}", hex::encode(dk.sha1_masterkey))?;
        }
        if !self.credman.is_empty() {
            writeln!(f, "  [CredMan]")?;
            for cm in &self.credman {
                writeln!(f, "    Target  : {}", cm.target)?;
                writeln!(f, "    Username: {}", cm.username)?;
                writeln!(f, "    Domain  : {}", cm.domain)?;
                writeln!(f, "    Password: {}", cm.password)?;
            }
        }
        if let Some(ssp) = &self.ssp {
            writeln!(f, "  [SSP]")?;
            writeln!(f, "    Username: {}", ssp.username)?;
            writeln!(f, "    Domain  : {}", ssp.domain)?;
            writeln!(f, "    Password: {}", ssp.password)?;
        }
        if let Some(live) = &self.livessp {
            writeln!(f, "  [LiveSSP]")?;
            writeln!(f, "    Username: {}", live.username)?;
            writeln!(f, "    Domain  : {}", live.domain)?;
            writeln!(f, "    Password: {}", live.password)?;
        }
        if let Some(cap) = &self.cloudap {
            writeln!(f, "  [CloudAP]")?;
            writeln!(f, "    Username : {}", cap.username)?;
            writeln!(f, "    Domain   : {}", cap.domain)?;
            if !cap.dpapi_key.is_empty() {
                writeln!(f, "    DPAPI Key: {}", hex::encode(&cap.dpapi_key))?;
            }
            if !cap.prt.is_empty() {
                writeln!(f, "    PRT      : {}", cap.prt)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arch_sizes() {
        assert_eq!(Arch::X64.ptr_size(), 8);
        assert_eq!(Arch::X86.ptr_size(), 4);
        assert_eq!(Arch::X64.ustr_size(), 16);
        assert_eq!(Arch::X86.ustr_size(), 8);
        assert_eq!(Arch::X64.list_entry_size(), 16);
        assert_eq!(Arch::X86.list_entry_size(), 8);
    }

    #[test]
    fn test_is_valid_user_ptr() {
        // x64
        assert!(!is_valid_user_ptr(0, Arch::X64));
        assert!(!is_valid_user_ptr(0x1000, Arch::X64));
        assert!(is_valid_user_ptr(0x7FFE_0000_0000, Arch::X64));
        assert!(!is_valid_user_ptr(0xFFFF_8000_0000_0000, Arch::X64)); // kernel
        // x86
        assert!(!is_valid_user_ptr(0, Arch::X86));
        assert!(!is_valid_user_ptr(0x1000, Arch::X86));
        assert!(is_valid_user_ptr(0x7FFE_0000, Arch::X86));
        assert!(!is_valid_user_ptr(0x8000_0000, Arch::X86)); // kernel
    }

    #[test]
    fn test_filetime_to_string() {
        assert_eq!(filetime_to_string(0), "N/A");
        assert_eq!(filetime_to_string(0x7FFF_FFFF_FFFF_FFFF), "N/A");
        // 2024-01-01 00:00:00 UTC
        assert_eq!(
            filetime_to_string(133_485_408_000_000_000),
            "2024-01-01 00:00:00 UTC"
        );
    }

    #[test]
    fn test_format_sid_from_bytes() {
        // S-1-5-18 (Local System)
        let header = [1, 1, 0, 0, 0, 0, 0, 5];
        let sub = 18u32.to_le_bytes();
        assert_eq!(format_sid_from_bytes(&header, &sub), "S-1-5-18");

        // S-1-5-21-xxx-yyy-zzz-1001
        let header = [1, 4, 0, 0, 0, 0, 0, 5];
        let mut sub = Vec::new();
        sub.extend_from_slice(&21u32.to_le_bytes());
        sub.extend_from_slice(&100u32.to_le_bytes());
        sub.extend_from_slice(&200u32.to_le_bytes());
        sub.extend_from_slice(&1001u32.to_le_bytes());
        assert_eq!(format_sid_from_bytes(&header, &sub), "S-1-5-21-100-200-1001");

        // Invalid: too short
        assert_eq!(format_sid_from_bytes(&[1, 1, 0], &[0; 4]), "");
    }

    #[test]
    fn test_logon_type_name() {
        assert_eq!(logon_type_name(2), "Interactive");
        assert_eq!(logon_type_name(3), "Network");
        assert_eq!(logon_type_name(10), "RemoteInteractive");
        assert_eq!(logon_type_name(99), "Unknown");
    }

    #[test]
    fn test_fill_wellknown_luid() {
        let mut cred = Credential { luid: 0x3e7, ..Default::default() };
        fill_wellknown_luid(&mut cred);
        assert_eq!(cred.username, "SYSTEM");
        assert_eq!(cred.domain, "NT AUTHORITY");

        let mut cred2 = Credential { luid: 0x3e4, ..Default::default() };
        fill_wellknown_luid(&mut cred2);
        assert_eq!(cred2.username, "NETWORK SERVICE");

        // Non-wellknown LUID: username stays empty
        let mut cred3 = Credential { luid: 0x12345, ..Default::default() };
        fill_wellknown_luid(&mut cred3);
        assert!(cred3.username.is_empty());
    }
}
