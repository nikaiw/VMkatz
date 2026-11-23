//! Shared offline secret records. Parsers populate these records; DPAPI consumers
//! can also use an empty set with explicitly supplied passwords or hashes.

/// A SAM user entry with RID, username, and NT/LM hashes.
#[derive(Debug)]
pub struct SamEntry {
    pub rid: u32,
    pub username: String,
    pub nt_hash: [u8; 16],
    pub lm_hash: [u8; 16],
    /// Account Control Bits from per-user F value (offset 0x38).
    pub acb_flags: u32,
}

// Account Control Bit flags (from SAM per-user F value).
impl SamEntry {
    /// Account is disabled (ACB_DISABLED).
    pub const fn is_disabled(&self) -> bool {
        self.acb_flags & 0x0001 != 0
    }

    /// Password not required (ACB_PWNOTREQ).
    pub const fn password_not_required(&self) -> bool {
        self.acb_flags & 0x0004 != 0
    }
}

/// Combined extraction result: SAM hashes + LSA secrets + cached credentials.
#[derive(Debug, Default)]
pub struct DiskSecrets {
    pub sam_entries: Vec<SamEntry>,
    pub lsa_secrets: Vec<LsaSecret>,
    pub cached_credentials: Vec<CachedCredential>,
    /// Account-domain (machine) SID from `SAM\Domains\Account\V`, if parsed.
    pub machine_sid: Option<String>,
}

/// A single LSA secret with its name, raw data, and parsed interpretation.
#[derive(Debug)]
pub struct LsaSecret {
    pub name: String,
    pub raw_data: Vec<u8>,
    pub parsed: LsaSecretType,
}

/// Parsed LSA secret types.
#[derive(Debug)]
pub enum LsaSecretType {
    /// DPAPI system keys (user + machine).
    DpapiSystem {
        user_key: [u8; 20],
        machine_key: [u8; 20],
    },
    /// DPAPI domain backup key — preferred key GUID pointer.
    DpapiBackupPreferred { guid: String },
    /// DPAPI domain backup key — RSA private key (can decrypt any domain user's master key).
    DpapiBackupKey {
        guid: String,
        version: u32,
        key_data: Vec<u8>,
        cert_data: Vec<u8>,
        pvk: Vec<u8>,
    },
    /// Machine account password (hex-encoded raw bytes).
    MachineAccount { password_hex: String },
    /// Default logon password (plaintext UTF-16LE decoded).
    DefaultPassword { password: String },
    /// Cached domain key (NL$KM).
    CachedDomainKey { key: Vec<u8> },
    /// Service account password (_SC_* secrets).
    ServicePassword { service: String, password: String },
    /// Unrecognized secret, shown as raw hex.
    Raw,
}

impl std::fmt::Display for LsaSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.parsed {
            LsaSecretType::DpapiSystem {
                user_key,
                machine_key,
            } => {
                write!(
                    f,
                    "  DPAPI_SYSTEM\n    user_key:    {}\n    machine_key: {}",
                    hex::encode(user_key),
                    hex::encode(machine_key)
                )
            }
            LsaSecretType::DpapiBackupPreferred { guid } => {
                write!(f, "  BCKUPKEY_P (Preferred Backup Key)\n    GUID: {guid}")
            }
            LsaSecretType::DpapiBackupKey {
                guid,
                version,
                key_data,
                cert_data,
                pvk,
            } => {
                write!(
                    f,
                    "  BCKUPKEY (Domain DPAPI Backup Key)\n    GUID    : {}\n    Version : {}\n    Key     : {} bytes\n    Cert    : {} bytes\n    PVK     : {} bytes",
                    guid,
                    version,
                    key_data.len(),
                    cert_data.len(),
                    pvk.len()
                )
            }
            LsaSecretType::MachineAccount { password_hex } => {
                write!(f, "  $MACHINE.ACC\n    password: {password_hex}")
            }
            LsaSecretType::DefaultPassword { password } => {
                write!(f, "  DefaultPassword\n    password: {password}")
            }
            LsaSecretType::CachedDomainKey { key } => {
                write!(f, "  NL$KM\n    key: {}", hex::encode(key))
            }
            LsaSecretType::ServicePassword { service, password } => {
                write!(f, "  _SC_{service}\n    password: {password}")
            }
            LsaSecretType::Raw => {
                let hex_str = hex::encode(&self.raw_data);
                let display = if hex_str.len() > 128 {
                    format!("{}...", &hex_str[..128])
                } else {
                    hex_str
                };
                write!(f, "  {}\n    raw: {}", self.name, display)
            }
        }
    }
}

/// A single domain cached credential entry.
#[derive(Debug)]
pub struct CachedCredential {
    pub username: String,
    pub domain: String,
    pub dns_domain: String,
    pub dcc2_hash: [u8; 16],
    pub iteration_count: u32,
}

impl std::fmt::Display for CachedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // hashcat mode 2100 format
        write!(
            f,
            "  {}/{}:$DCC2${}#{}#{}",
            if self.dns_domain.is_empty() {
                &self.domain
            } else {
                &self.dns_domain
            },
            self.username,
            self.iteration_count,
            self.username.to_lowercase(),
            hex::encode(self.dcc2_hash),
        )
    }
}
