//! Offline Credential Manager extraction: walk every Windows profile on an NTFS
//! volume, resolve each `Credentials` blob's DPAPI masterkey, decrypt, parse.
//!
//! Read-only. A per-file failure is recorded in [`CredmanReport::undecrypted`]
//! and never aborts the sweep; missing directories are skipped silently.

use std::collections::HashMap;
use std::io::{Read, Seek};

use super::DiskSecrets;
use super::credman_blob::{CredmanEntry, parse_credential_blob};
use super::dpapi_blob::{decrypt_blob, parse_blob};
use super::dpapi_masterkey::{decrypt_local_user_masterkey, decrypt_system_masterkey};
use super::lsa::{LsaSecret, LsaSecretType};
use crate::error::Result;

const SYSTEM_SID: &str = "S-1-5-18";
/// Max profiles / protect SID folders / credential files examined per directory.
const MAX_PROFILES: usize = 256;
const MAX_PROTECT_DIRS: usize = 16;
const MAX_CRED_FILES: usize = 512;
/// Max size of any single file read (Credentials blobs and masterkey files are tiny).
const MAX_FILE_LEN: u64 = 4 << 20;

/// A decrypted Credential Manager entry with its owning profile.
#[derive(Debug, Clone)]
pub struct ProfileCred {
    pub profile: String,
    pub sid: String,
    pub entry: CredmanEntry,
}

/// A Credentials file that could not be decrypted/parsed, with the reason.
#[derive(Debug, Clone)]
pub struct Undecrypted {
    pub profile: String,
    pub sid: String,
    pub file: String,
    pub reason: String,
}

/// Result of a credman sweep.
#[derive(Debug, Default)]
pub struct CredmanReport {
    pub entries: Vec<ProfileCred>,
    pub undecrypted: Vec<Undecrypted>,
}

/// Secrets available to unlock DPAPI masterkeys.
#[derive(Debug, Default, Clone)]
pub struct SecretTable {
    pub local_nt_by_sid: HashMap<String, [u8; 16]>,
    /// DPAPI_SYSTEM machine key.
    pub dpapi_system: Option<[u8; 20]>,
    pub domain_nt_by_sid: HashMap<String, [u8; 16]>,
    /// DPAPI_SYSTEM user key (for `S-1-5-18\User` masterkeys).
    pub dpapi_system_user: Option<[u8; 20]>,
}

/// The secret (if any) that applies to a SID.
#[derive(Debug, Clone, Copy)]
pub enum Secret {
    System {
        machine: Option<[u8; 20]>,
        user: Option<[u8; 20]>,
    },
    Nt([u8; 16]),
    None,
}

impl Secret {
    pub const fn is_system(&self) -> bool {
        matches!(self, Self::System { .. })
    }
    pub const fn is_nt(&self) -> bool {
        matches!(self, Self::Nt(_))
    }
    pub const fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }
}

impl SecretTable {
    /// Look up the secret for a profile SID.
    pub fn secret_for(&self, sid: &str) -> Secret {
        if sid.eq_ignore_ascii_case(SYSTEM_SID) {
            return Secret::System {
                machine: self.dpapi_system,
                user: self.dpapi_system_user,
            };
        }
        self.local_nt_by_sid
            .get(sid)
            .or_else(|| self.domain_nt_by_sid.get(sid))
            .map_or(Secret::None, |h| Secret::Nt(*h))
    }
}

/// Strip the trailing RID from a user SID, yielding the account-domain SID.
pub fn machine_sid_from_user_sid(user_sid: &str) -> Option<&str> {
    user_sid.rsplit_once('-').map(|(p, _)| p)
}

/// Build the secret table: local `machine_sid-RID` -> NT hash from the SAM,
/// DPAPI_SYSTEM from LSA, plus caller-supplied domain NT hashes.
pub fn build_secret_table(
    disk_secrets: &DiskSecrets,
    lsa: &[LsaSecret],
    machine_sid: &str,
    domain_nthashes: &[(String, [u8; 16])],
) -> SecretTable {
    let mut t = SecretTable::default();
    for e in &disk_secrets.sam_entries {
        // An all-zero hash means no hash was recovered for the account.
        if e.nt_hash != [0u8; 16] {
            t.local_nt_by_sid
                .insert(format!("{machine_sid}-{}", e.rid), e.nt_hash);
        }
    }
    for s in lsa {
        if let LsaSecretType::DpapiSystem {
            user_key,
            machine_key,
        } = &s.parsed
        {
            t.dpapi_system = Some(*machine_key);
            t.dpapi_system_user = Some(*user_key);
            break;
        }
    }
    for (sid, h) in domain_nthashes {
        t.domain_nt_by_sid.insert(sid.clone(), *h);
    }
    t
}

/// True if `name` looks like a SID folder (`S-1-...`); safe for non-ASCII names.
fn is_sid_dir_name(name: &str) -> bool {
    name.len() > 4
        && name
            .get(..4)
            .is_some_and(|p| p.eq_ignore_ascii_case("S-1-"))
}

/// A directory holding masterkey files for `sid`.
struct ProtectDir {
    path: String,
    sid: String,
}

struct Profile {
    name: String,
    cred_dirs: Vec<String>,
    protect: Vec<ProtectDir>,
}

struct Walker<'a, 'n, R: Read + Seek> {
    ntfs: &'n ntfs::Ntfs,
    root: &'a ntfs::NtfsFile<'n>,
    rd: &'a mut R,
    secrets: &'a SecretTable,
}

impl<R: Read + Seek> Walker<'_, '_, R> {
    /// List a directory (bounded); `None` if it does not exist.
    fn list(&mut self, path: &str, cap: usize) -> Option<Vec<(String, bool)>> {
        let dir = crate::fs::navigate_to_dir(self.ntfs, self.root, self.rd, path).ok()?;
        let mut v = crate::fs::list_directory(self.ntfs, &dir, self.rd).ok()?;
        v.truncate(cap);
        Some(v)
    }

    /// Read a file by directory path + name, refusing oversized files.
    fn read(&mut self, dir: &str, name: &str) -> Result<Vec<u8>> {
        let d = crate::fs::navigate_to_dir(self.ntfs, self.root, self.rd, dir)?;
        let f = crate::fs::find_entry(self.ntfs, &d, self.rd, name)?;
        let len = f
            .data(self.rd, "")
            .and_then(std::result::Result::ok)
            .and_then(|i| i.to_attribute().ok().map(|a| a.value_length()))
            .ok_or_else(|| crate::error::VmkatzError::Parse("unreadable data length".into()))?;
        if len > MAX_FILE_LEN {
            return Err(crate::error::VmkatzError::Parse(format!(
                "file too large: {len} bytes"
            )));
        }
        crate::fs::read_file_data(&f, self.rd)
    }

    /// Masterkey folders under `<base>\AppData\Roaming\Microsoft\Protect`.
    fn user_protect_dirs(&mut self, base: &str) -> Vec<ProtectDir> {
        let root = format!("{base}\\AppData\\Roaming\\Microsoft\\Protect");
        self.list(&root, MAX_PROTECT_DIRS * 4)
            .unwrap_or_default()
            .into_iter()
            .filter(|(n, is_dir)| *is_dir && is_sid_dir_name(n))
            .take(MAX_PROTECT_DIRS)
            .map(|(n, _)| ProtectDir {
                path: format!("{root}\\{n}"),
                sid: n,
            })
            .collect()
    }

    fn user_profile(&mut self, name: &str, base: &str) -> Profile {
        Profile {
            name: name.to_string(),
            cred_dirs: vec![
                format!("{base}\\AppData\\Local\\Microsoft\\Credentials"),
                format!("{base}\\AppData\\Roaming\\Microsoft\\Credentials"),
            ],
            protect: self.user_protect_dirs(base),
        }
    }

    fn system_profile() -> Profile {
        let base = "Windows\\System32\\config\\systemprofile";
        let prot = "Windows\\System32\\Microsoft\\Protect\\S-1-5-18";
        Profile {
            name: "SYSTEM".into(),
            cred_dirs: vec![
                format!("{base}\\AppData\\Local\\Microsoft\\Credentials"),
                format!("{base}\\AppData\\Roaming\\Microsoft\\Credentials"),
            ],
            protect: vec![
                ProtectDir {
                    path: format!("{prot}\\User"),
                    sid: SYSTEM_SID.into(),
                },
                ProtectDir {
                    path: prot.into(),
                    sid: SYSTEM_SID.into(),
                },
            ],
        }
    }

    /// Enumerate all profiles on the volume.
    fn profiles(&mut self) -> Vec<Profile> {
        let mut out = vec![Self::system_profile()];
        for (parent, skip_builtin) in [("Users", true), ("Windows\\ServiceProfiles", false)] {
            let names = self.list(parent, MAX_PROFILES).unwrap_or_default();
            for (name, is_dir) in names {
                let lower = name.to_lowercase();
                if !is_dir
                    || (skip_builtin
                        && matches!(
                            lower.as_str(),
                            "public" | "default" | "default user" | "all users"
                        ))
                {
                    continue;
                }
                let p = self.user_profile(&name, &format!("{parent}\\{name}"));
                out.push(p);
            }
        }
        out
    }

    /// Locate and decrypt the masterkey `guid`; returns (clear key, owning SID).
    fn resolve_masterkey(
        &mut self,
        prof: &Profile,
        guid: &str,
    ) -> std::result::Result<(Vec<u8>, String), (String, String)> {
        let default_sid = prof
            .protect
            .first()
            .map(|p| p.sid.clone())
            .unwrap_or_default();
        let mut last = (
            default_sid,
            format!("masterkey {guid} not found in Protect folders"),
        );
        for pd in &prof.protect {
            let Ok(mk_bytes) = self.read(&pd.path, guid) else {
                continue;
            };
            match unlock(self.secrets, &pd.sid, &mk_bytes) {
                Ok(k) => return Ok((k, pd.sid.clone())),
                Err(reason) => last = (pd.sid.clone(), reason),
            }
        }
        Err(last)
    }

    fn scan_profile(&mut self, prof: &Profile, report: &mut CredmanReport) {
        for dir in &prof.cred_dirs {
            let Some(files) = self.list(dir, MAX_CRED_FILES) else {
                continue;
            };
            for (fname, is_dir) in files {
                if is_dir {
                    continue;
                }
                match self.decrypt_one(prof, dir, &fname) {
                    Ok((sid, entry)) => report.entries.push(ProfileCred {
                        profile: prof.name.clone(),
                        sid,
                        entry,
                    }),
                    Err((sid, reason)) => report.undecrypted.push(Undecrypted {
                        profile: prof.name.clone(),
                        sid,
                        file: format!("{dir}\\{fname}"),
                        reason,
                    }),
                }
            }
        }
    }

    fn decrypt_one(
        &mut self,
        prof: &Profile,
        dir: &str,
        fname: &str,
    ) -> std::result::Result<(String, CredmanEntry), (String, String)> {
        let sid0 = prof
            .protect
            .first()
            .map(|p| p.sid.clone())
            .unwrap_or_default();
        let raw = self
            .read(dir, fname)
            .map_err(|e| (sid0.clone(), e.to_string()))?;
        let blob = parse_blob(&raw).map_err(|e| (sid0.clone(), format!("blob parse: {e}")))?;
        let (mk, sid) = self.resolve_masterkey(prof, &blob.mk_guid_str)?;
        let clear =
            decrypt_blob(&blob, &mk).map_err(|e| (sid.clone(), format!("blob decrypt: {e}")))?;
        let entry = parse_credential_blob(&clear)
            .map_err(|e| (sid.clone(), format!("credential parse: {e}")))?;
        Ok((sid, entry))
    }
}

/// Decrypt a masterkey file with whatever secret applies to `sid`.
fn unlock(
    secrets: &SecretTable,
    sid: &str,
    mk_bytes: &[u8],
) -> std::result::Result<Vec<u8>, String> {
    match secrets.secret_for(sid) {
        Secret::None => Err(format!("no secret for {sid}")),
        Secret::Nt(h) => decrypt_local_user_masterkey(mk_bytes, &h, sid)
            .map_err(|e| format!("masterkey decrypt: {e}")),
        Secret::System { machine, user } => {
            let mut last = format!("no DPAPI_SYSTEM secret for {sid}");
            for key in [machine, user].into_iter().flatten() {
                match decrypt_system_masterkey(mk_bytes, &key) {
                    Ok(k) => return Ok(k),
                    Err(e) => last = format!("masterkey decrypt: {e}"),
                }
            }
            Err(last)
        }
    }
}

/// Sweep every NTFS partition (or only `partition`) for Credential Manager blobs.
pub fn extract_credman_from_reader_scoped<R: Read + Seek>(
    reader: &mut R,
    partition: Option<u64>,
    secrets: &SecretTable,
) -> Result<CredmanReport> {
    let parts = crate::fs::select_partition(
        crate::fs::find_ntfs_partitions(reader).unwrap_or_default(),
        partition,
    )?;
    let mut report = CredmanReport::default();
    for &off in &parts {
        if crate::fs::is_bitlocker_partition(reader, off) {
            continue;
        }
        let mut part = crate::fs::PartitionReader::new(&mut *reader, off);
        let Ok(ntfs) = ntfs::Ntfs::new(&mut part) else {
            continue;
        };
        let Ok(root) = ntfs.root_directory(&mut part) else {
            continue;
        };
        let mut w = Walker {
            ntfs: &ntfs,
            root: &root,
            rd: &mut part,
            secrets,
        };
        for prof in w.profiles() {
            w.scan_profile(&prof, &mut report);
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sam::{DiskSecrets, SamEntry};

    fn disk_secrets_fixture() -> DiskSecrets {
        DiskSecrets {
            sam_entries: vec![SamEntry {
                rid: 500,
                username: "Administrator".into(),
                nt_hash: [7u8; 16],
                lm_hash: [0u8; 16],
                acb_flags: 0,
            }],
            ..Default::default()
        }
    }

    #[test]
    fn resolves_system_secret_and_reports_unavailable_domain() {
        let t = SecretTable {
            dpapi_system: Some([0u8; 20]),
            ..Default::default()
        };
        assert!(t.secret_for("S-1-5-18").is_system());
        assert!(t.secret_for("S-1-5-21-1-2-3-1106").is_none());
    }

    #[test]
    fn sid_dir_name_filter_no_panic_on_multibyte() {
        assert!(is_sid_dir_name("S-1-5-21-1-2-3-1001"));
        assert!(is_sid_dir_name("s-1-5-18"));
        // byte index 4 falls inside a multibyte char: must not panic
        assert!(!is_sid_dir_name("a\u{e9}\u{e9}\u{e9}xyz"));
        assert!(!is_sid_dir_name("S-1\u{e9}-5"));
        assert!(!is_sid_dir_name("S-1-"));
    }

    #[test]
    fn machine_sid_strips_rid() {
        assert_eq!(
            machine_sid_from_user_sid("S-1-5-21-1-2-3-1001"),
            Some("S-1-5-21-1-2-3")
        );
        assert_eq!(machine_sid_from_user_sid("nodash"), None);
    }

    #[test]
    fn zero_hash_and_domain_entries() {
        let mut ds = disk_secrets_fixture();
        ds.sam_entries.push(SamEntry {
            rid: 501,
            username: "Guest".into(),
            nt_hash: [0u8; 16],
            lm_hash: [0u8; 16],
            acb_flags: 0,
        });
        let dom = vec![("S-1-5-21-9-9-9-1106".to_string(), [3u8; 16])];
        let st = build_secret_table(&ds, &[], "S-1-5-21-1-2-3", &dom);
        assert!(!st.local_nt_by_sid.contains_key("S-1-5-21-1-2-3-501"));
        assert!(st.secret_for("S-1-5-21-9-9-9-1106").is_nt());
    }

    #[test]
    fn build_secret_table_maps_rid_to_sid() {
        let st = build_secret_table(&disk_secrets_fixture(), &[], "S-1-5-21-1-2-3", &[]);
        assert_eq!(
            st.local_nt_by_sid.get("S-1-5-21-1-2-3-500"),
            Some(&[7u8; 16])
        );
    }
}
