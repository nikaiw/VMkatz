//! Firefox NSS (key4.db + logins.json) decrypt — scaffold.
//!
//! Supports modern key4.db (AES-256-CBC, PBKDF2-HMAC-SHA256). Legacy key3.db (3DES)
//! is out of scope. Full NSS PBES2 derive + 3DES login decrypt is a follow-up sub-task;
//! the scaffold here lands the data structures and the SQLite/JSON parsing so the
//! crypto can land independently.

use crate::chrome::sqlite::{walk_table, Pager, Value};
use crate::chrome::types::{Browser, BrowserProfile, ChromeSource, SavedPassword};
use crate::chrome::util::b64_decode;
use crate::error::{Result, VmkatzError as Error};
use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct FirefoxProfile {
    pub user: String,
    pub profile_name: String,
    pub path: String,
    pub key4_db: Vec<u8>,
    pub key4_db_wal: Option<Vec<u8>>,
    pub logins_json: String,
}

#[derive(Debug, Clone)]
pub(crate) struct LoginEntry {
    pub hostname: String,
    pub username_pkcs11: Vec<u8>,
    pub password_pkcs11: Vec<u8>,
}

/// Top-level: parse logins.json, derive NSS master key, decrypt each login.
/// Currently the decrypt step errors with a clear "not yet implemented" — callers
/// should treat this as "Firefox extraction is partial in this build".
pub fn extract_profile(p: &FirefoxProfile) -> Result<Vec<SavedPassword>> {
    let _master = derive_master_key(&p.key4_db, p.key4_db_wal.as_deref(), b"")?;
    let logins = parse_logins(&p.logins_json)?;
    let profile = BrowserProfile {
        browser: Browser::Firefox,
        user: p.user.clone(),
        profile_name: p.profile_name.clone(),
        path: p.path.clone(),
    };
    let mut out = Vec::new();
    for l in logins {
        if let (Some(u), Some(pw)) = (
            decrypt_login(&l.username_pkcs11, &_master),
            decrypt_login(&l.password_pkcs11, &_master),
        ) {
            out.push(SavedPassword {
                profile: profile.clone(),
                url: l.hostname,
                username: u,
                password: pw,
                source: ChromeSource::DiskDpapi, // TODO: introduce ChromeSource::Nss in Task 18
            });
        }
    }
    Ok(out)
}

pub(crate) fn parse_logins(json: &str) -> Result<Vec<LoginEntry>> {
    #[derive(Deserialize)]
    struct Login {
        hostname: String,
        #[serde(rename = "encryptedUsername")] encrypted_username: String,
        #[serde(rename = "encryptedPassword")] encrypted_password: String,
    }
    #[derive(Deserialize)]
    struct Root { logins: Vec<Login> }
    let r: Root = serde_json::from_str(json)
        .map_err(|e| Error::Parse(format!("logins.json: {}", e)))?;
    Ok(r.logins
        .into_iter()
        .filter_map(|l| {
            Some(LoginEntry {
                hostname: l.hostname,
                username_pkcs11: b64_decode(&l.encrypted_username)?,
                password_pkcs11: b64_decode(&l.encrypted_password)?,
            })
        })
        .collect())
}

/// Read the metadata table out of key4.db, derive the master AES key from the
/// (empty) master password. Currently errors with "NSS derive not yet implemented".
fn derive_master_key(key4_db: &[u8], wal: Option<&[u8]>, _master_password: &[u8]) -> Result<Vec<u8>> {
    let pager = match wal {
        Some(w) => Pager::open_with_wal(key4_db, w)?,
        None => Pager::open(key4_db)?,
    };
    // metadata: id TEXT, item1 BLOB (globalSalt), item2 BLOB (password_check)
    let meta_root = pager
        .root_of("metadata")?
        .ok_or_else(|| Error::Parse("key4.db: no metadata table".into()))?;
    let mut global_salt: Vec<u8> = Vec::new();
    let mut password_check: Vec<u8> = Vec::new();
    walk_table(&pager, meta_root, |_r, cols| {
        if cols.get(0).and_then(Value::as_text) == Some("password") {
            if let Some(b) = cols.get(1).and_then(Value::as_blob) { global_salt = b.to_vec(); }
            if let Some(b) = cols.get(2).and_then(Value::as_blob) { password_check = b.to_vec(); }
        }
        Ok(())
    })?;
    if global_salt.is_empty() {
        return Err(Error::Parse("key4.db: global_salt missing".into()));
    }
    let _ = password_check; // currently unused; will verify master password via PBES2 unwrap.
    // PBES2 / PBKDF2-HMAC-SHA256 derive + AES-256-CBC unwrap of nssPrivate.a11:
    // implementation is the Task 17 Step 6 follow-up.
    Err(Error::Parse("NSS derive not yet implemented".into()))
}

fn decrypt_login(_blob: &[u8], _master: &[u8]) -> Option<String> {
    // ASN.1: SEQUENCE { OID 3desCBC, IV, ciphertext }. 3DES-CBC decrypt with master key.
    // Strip PKCS#7 padding. Return UTF-8.
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_logins_json() {
        let json = r#"{"logins":[{"hostname":"https://x.test/","encryptedUsername":"YWJj","encryptedPassword":"ZGVm"}]}"#;
        let logins = parse_logins(json).unwrap();
        assert_eq!(logins.len(), 1);
        assert_eq!(logins[0].hostname, "https://x.test/");
        assert_eq!(logins[0].username_pkcs11, b"abc");
        assert_eq!(logins[0].password_pkcs11, b"def");
    }

    #[test]
    fn parse_logins_rejects_invalid_json() {
        let r = parse_logins(r#"{not json"#);
        assert!(r.is_err());
    }

    #[test]
    fn derive_master_key_errors_without_real_impl() {
        // We can't easily build a synthetic key4.db here; verify that with an empty/invalid
        // input we get a clean error (not a panic).
        let r = derive_master_key(&[], None, b"");
        assert!(r.is_err());
    }
}
