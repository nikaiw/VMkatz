//! Disk-side chrome orchestrator.
//!
//! Walks profile discovery, derives per-profile v10/v11 keys from `Local State`
//! using a caller-provided masterkey resolver, decrypts SQLite blobs.

use crate::chrome::blob::{classify, decrypt_v10, BlobScheme};
use crate::chrome::dpapi_decrypt::{decrypt_blob, parse_blob};
use crate::chrome::local_state;
use crate::chrome::profile::{discover_chromium, DiscoveredProfile, FileTree};
use crate::chrome::sqlite::{walk_table, Pager, Value};
use crate::chrome::types::{
    AutofillEntry, AutofillKind, BrowserProfile, ChromeFindings, ChromeSource, Cookie,
    SavedPassword,
};
use crate::chrome::util::chrome_time_to_unix;
use crate::error::Result;

/// Resolves a DPAPI masterkey GUID to its cleartext 64-byte value.
/// Implementations: in-memory LSASS cache, on-disk full-chain decrypt, test mocks.
pub trait MasterkeyResolver {
    fn resolve(&self, mk_guid: &str) -> Option<Vec<u8>>;
}

/// Convenience impl over an owned HashMap so tests and simple callers can just hand
/// in a `HashMap<String, Vec<u8>>`.
impl MasterkeyResolver for std::collections::HashMap<String, Vec<u8>> {
    fn resolve(&self, mk_guid: &str) -> Option<Vec<u8>> {
        self.get(mk_guid).cloned()
    }
}

/// Per-profile decryption keys, derived from `Local State`.
struct ProfileKeys {
    v10: [u8; 32],
}

/// Top-level entrypoint. Discovers profiles, derives per-profile keys via `mk_resolver`,
/// extracts passwords/cookies/autofill, returns ChromeFindings.
pub fn extract_from_disk<T: FileTree, R: MasterkeyResolver>(
    tree: &mut T,
    mk_resolver: &R,
) -> Result<ChromeFindings> {
    let mut out = ChromeFindings::default();
    let profiles = discover_chromium(tree)?;
    for p in profiles {
        match per_profile(&p, mk_resolver) {
            Ok(mut findings) => {
                out.passwords.append(&mut findings.passwords);
                out.cookies.append(&mut findings.cookies);
                out.autofill.append(&mut findings.autofill);
            }
            Err(e) => {
                log::debug!("chrome profile {} skipped: {}", p.profile.path, e);
            }
        }
    }
    Ok(out)
}

fn per_profile<R: MasterkeyResolver>(p: &DiscoveredProfile, mkr: &R) -> Result<ChromeFindings> {
    let mut out = ChromeFindings::default();
    let keys = match derive_keys(p, mkr) {
        Some(k) => k,
        None => return Ok(out),
    };

    if let Some(db) = &p.artifacts.login_data {
        extract_logins(
            db,
            p.artifacts.login_data_wal.as_deref(),
            &keys,
            &p.profile,
            ChromeSource::DiskDpapi,
            &mut out,
        )?;
    }
    if let Some(db) = &p.artifacts.cookies {
        extract_cookies(
            db,
            p.artifacts.cookies_wal.as_deref(),
            &keys,
            &p.profile,
            ChromeSource::DiskDpapi,
            &mut out,
        )?;
    }
    if let Some(db) = &p.artifacts.web_data {
        extract_autofill(
            db,
            p.artifacts.web_data_wal.as_deref(),
            &keys,
            &p.profile,
            ChromeSource::DiskDpapi,
            &mut out,
        )?;
    }
    Ok(out)
}

fn derive_keys<R: MasterkeyResolver>(p: &DiscoveredProfile, mkr: &R) -> Option<ProfileKeys> {
    let ls_bytes = p.artifacts.local_state.as_ref()?;
    let ls_str = std::str::from_utf8(ls_bytes).ok()?;
    let ls = local_state::parse(ls_str).ok()?;
    let v10 = derive_v10_key(ls.encrypted_key.as_deref()?, mkr)?;
    Some(ProfileKeys { v10 })
}

/// Strip "DPAPI" prefix, run the masterkey chain via the resolver, decrypt blob,
/// return 32-byte AES-GCM key.
fn derive_v10_key<R: MasterkeyResolver>(raw: &[u8], mkr: &R) -> Option<[u8; 32]> {
    if raw.len() < 5 || &raw[..5] != b"DPAPI" {
        return None;
    }
    let blob = parse_blob(&raw[5..]).ok()?;
    let mk = mkr.resolve(&blob.mk_guid_str)?;
    let pt = decrypt_blob(&blob, &mk).ok()?;
    if pt.len() < 32 {
        return None;
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&pt[..32]);
    Some(k)
}

fn extract_logins(
    db: &[u8],
    wal: Option<&[u8]>,
    keys: &ProfileKeys,
    profile: &BrowserProfile,
    src: ChromeSource,
    out: &mut ChromeFindings,
) -> Result<()> {
    let pager = match wal {
        Some(w) => Pager::open_with_wal(db, w)?,
        None => Pager::open(db)?,
    };
    let root = match pager.root_of("logins")? {
        Some(r) => r,
        None => return Ok(()),
    };
    walk_table(&pager, root, |_rid, cols| {
        // logins schema (positional, Chrome >= 90):
        //   0: origin_url TEXT, 1: action_url TEXT, 2: username_element TEXT,
        //   3: username_value TEXT, 4: password_element TEXT, 5: password_value BLOB, ...
        let url = cols.get(0).and_then(Value::as_text).unwrap_or("").to_string();
        let username = cols.get(3).and_then(Value::as_text).unwrap_or("").to_string();
        let blob = cols.get(5).and_then(Value::as_blob).unwrap_or(&[]);
        if matches!(classify(blob), BlobScheme::V10 | BlobScheme::V11) {
            if let Ok(pt) = decrypt_v10(blob, &keys.v10) {
                let password = String::from_utf8_lossy(&pt).into_owned();
                out.passwords.push(SavedPassword {
                    profile: profile.clone(),
                    url,
                    username,
                    password,
                    source: src.clone(),
                });
            }
        }
        Ok(())
    })
}

fn extract_cookies(
    db: &[u8],
    wal: Option<&[u8]>,
    keys: &ProfileKeys,
    profile: &BrowserProfile,
    src: ChromeSource,
    out: &mut ChromeFindings,
) -> Result<()> {
    let pager = match wal {
        Some(w) => Pager::open_with_wal(db, w)?,
        None => Pager::open(db)?,
    };
    let root = match pager.root_of("cookies")? {
        Some(r) => r,
        None => return Ok(()),
    };
    walk_table(&pager, root, |_rid, cols| {
        // Cookies schema varies by Chrome version; use heuristics:
        //   - host_key: first ASCII text col containing '.'
        //   - name: first text col that is short, non-host, not the path
        //   - value blob: the only Blob in the row
        //   - expires: the only int with chrome epoch-scale magnitude
        //   - path: the text col starting with '/'
        let host = cols
            .iter()
            .filter_map(Value::as_text)
            .find(|s| s.contains('.'))
            .map(str::to_string)
            .unwrap_or_default();
        let path = cols
            .iter()
            .filter_map(Value::as_text)
            .find(|s| s.starts_with('/'))
            .unwrap_or("/")
            .to_string();
        // name: first non-host, non-path, non-empty text col
        let name = cols
            .iter()
            .filter_map(Value::as_text)
            .find(|s| !s.is_empty() && !s.contains('.') && !s.starts_with('/'))
            .unwrap_or("")
            .to_string();
        let blob = cols.iter().find_map(Value::as_blob).unwrap_or(&[]);
        let exp_us = cols
            .iter()
            .filter_map(Value::as_int)
            .find(|n| *n > 10_000_000_000_000_000);
        if matches!(classify(blob), BlobScheme::V10 | BlobScheme::V11) {
            if let Ok(pt) = decrypt_v10(blob, &keys.v10) {
                let value = strip_cookie_prefix(&pt);
                out.cookies.push(Cookie {
                    profile: profile.clone(),
                    host,
                    name,
                    value,
                    path,
                    expires: exp_us.and_then(chrome_time_to_unix),
                    http_only: false,
                    secure: false,
                    source: src.clone(),
                });
            }
        }
        Ok(())
    })
}

/// Chrome >= v118 prefixes cookie plaintext with SHA-256(host) for integrity binding.
/// Heuristic: if pt[..32] is non-ASCII-ish and pt[32..] looks ASCII, strip 32 bytes.
fn strip_cookie_prefix(pt: &[u8]) -> String {
    if pt.len() > 32 {
        let head_binary = pt[..32].iter().any(|&b| b == 0 || b > 127);
        let tail_ascii = pt[32..].iter().all(|&b| b == 0 || (b >= 0x20 && b < 0x7F));
        if head_binary && tail_ascii {
            return String::from_utf8_lossy(&pt[32..]).into_owned();
        }
    }
    String::from_utf8_lossy(pt).into_owned()
}

fn extract_autofill(
    db: &[u8],
    wal: Option<&[u8]>,
    _keys: &ProfileKeys,
    profile: &BrowserProfile,
    src: ChromeSource,
    out: &mut ChromeFindings,
) -> Result<()> {
    let pager = match wal {
        Some(w) => Pager::open_with_wal(db, w)?,
        None => Pager::open(db)?,
    };
    // autofill table (form fields): name TEXT, value TEXT, value_lower TEXT, date_created INT, ...
    if let Some(root) = pager.root_of("autofill")? {
        walk_table(&pager, root, |_rid, cols| {
            let name = cols.get(0).and_then(Value::as_text).unwrap_or("").to_string();
            let value = cols.get(1).and_then(Value::as_text).unwrap_or("").to_string();
            if !name.is_empty() && !value.is_empty() {
                out.autofill.push(AutofillEntry {
                    profile: profile.clone(),
                    kind: AutofillKind::FormField,
                    fields: vec![("name".into(), name), ("value".into(), value)],
                    source: src.clone(),
                });
            }
            Ok(())
        })?;
    }
    // Credit cards + addresses contain encrypted blobs that would need the same v10 key.
    // Defer to a later sub-task.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chrome::profile::FileTree;
    use std::collections::HashMap;

    struct EmptyTree;
    impl FileTree for EmptyTree {
        fn list_dir(&mut self, p: &str) -> Result<Vec<String>> {
            if p == "Users" {
                Ok(vec!["alice".into()])
            } else {
                Ok(Vec::new())
            }
        }
        fn read_file(&mut self, _p: &str) -> Result<Option<Vec<u8>>> {
            Ok(None)
        }
    }

    #[test]
    fn empty_disk_yields_empty_findings() {
        let mut t = EmptyTree;
        let kr: HashMap<String, Vec<u8>> = HashMap::new();
        let f = extract_from_disk(&mut t, &kr).unwrap();
        assert!(f.is_empty());
    }

    #[test]
    fn derive_v10_key_rejects_missing_prefix() {
        let kr: HashMap<String, Vec<u8>> = HashMap::new();
        assert!(derive_v10_key(b"NOTDP", &kr).is_none());
    }

    #[test]
    fn masterkey_resolver_hashmap_impl_works() {
        let mut kr: HashMap<String, Vec<u8>> = HashMap::new();
        kr.insert("guid1".into(), vec![1, 2, 3]);
        assert_eq!(kr.resolve("guid1"), Some(vec![1, 2, 3]));
        assert_eq!(kr.resolve("guid2"), None);
    }
}
