//! Offline Credential Manager extraction: walk every Windows profile on an NTFS
//! volume, resolve each `Credentials` blob's DPAPI masterkey, decrypt, parse.
//!
//! Read-only. A per-file failure is recorded in [`CredmanReport::undecrypted`]
//! and never aborts the sweep; missing directories are skipped silently.

use std::collections::HashMap;
use std::io::{Read, Seek};

use super::DiskSecrets;
use super::credhist;
use super::credman_blob::{CredmanEntry, parse_credential_blob};
use super::dpapi_blob::{decrypt_blob, parse_blob};
use super::dpapi_masterkey::{
    decrypt_local_user_masterkey, decrypt_local_user_masterkey_pw, decrypt_masterkey_with_prekey,
    decrypt_system_masterkey, prekey_from_hash, prekey_from_password,
};
use super::lsa::{LsaSecret, LsaSecretType};
use super::vault::{VaultCred, VaultKeys, parse_vault_keys, parse_vcrd, parse_vpol};
use crate::error::Result;

const SYSTEM_SID: &str = "S-1-5-18";
/// Max profiles / protect SID folders / credential files examined per directory.
const MAX_PROFILES: usize = 256;
const MAX_PROTECT_DIRS: usize = 16;
const MAX_CRED_FILES: usize = 512;
/// Max vault GUID folders per Vault root, and `.vcrd` files per vault folder.
const MAX_VAULT_DIRS: usize = 32;
const MAX_VCRD_FILES: usize = 512;
/// Max size of any single file read (Credentials blobs and masterkey files are tiny).
const MAX_FILE_LEN: u64 = 4 << 20;

/// A decrypted Credential Manager entry with its owning profile.
#[derive(Debug, Clone)]
pub struct ProfileCred {
    pub profile: String,
    pub sid: String,
    pub entry: CredmanEntry,
    /// Enumerated CREDENTIAL attributes (values stay encrypted).
    pub attributes: Vec<AttrInfo>,
}

/// An enumerated credential attribute: keyword + raw (encrypted) value as hex.
/// Entropy-bound blobs (e.g. WindowsLive SSO) cannot be decrypted offline.
#[derive(Debug, Clone)]
pub struct AttrInfo {
    pub keyword: String,
    pub value_hex: String,
}

/// A Credentials file that could not be decrypted/parsed, with the reason.
#[derive(Debug, Clone)]
pub struct Undecrypted {
    pub profile: String,
    pub sid: String,
    pub file: String,
    pub reason: String,
}

/// A decrypted Vault credential (resource / identity / authenticator).
#[derive(Debug, Clone)]
pub struct ProfileVaultCred {
    pub profile: String,
    /// SID whose masterkey opened this vault's `Policy.vpol`.
    pub sid: String,
    pub vault_guid: String,
    pub cred: VaultCred,
}

/// Result of a credman sweep.
#[derive(Debug, Default)]
pub struct CredmanReport {
    pub entries: Vec<ProfileCred>,
    pub undecrypted: Vec<Undecrypted>,
    pub vault: Vec<ProfileVaultCred>,
    /// Per-vault notes: `<profile>\<guid>: keys=<n> vcrd=<n>` for each unlocked vault.
    pub vault_notes: Vec<String>,
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
    /// Cleartext passwords by SID. A local (context-1) user masterkey is derived
    /// from the password, not the NT hash, so only this opens those.
    pub pw_by_sid: HashMap<String, String>,
    /// NT hashes keyed by lowercased profile name, for specs the CLI could not
    /// map to a SID (a domain user has no SAM entry and may have no masterkey
    /// hash to look the SID up from).
    pub nt_by_name: HashMap<String, Vec<[u8; 16]>>,
    /// Cleartext passwords keyed by lowercased profile name, same rationale.
    pub pw_by_name: HashMap<String, Vec<String>>,
}

/// One secret that may open a SID's masterkeys.
#[derive(Debug, Clone, Copy)]
pub enum Secret<'a> {
    System {
        machine: Option<[u8; 20]>,
        user: Option<[u8; 20]>,
    },
    Password(&'a str),
    Nt([u8; 16]),
}

impl Secret<'_> {
    pub const fn is_system(&self) -> bool {
        matches!(self, Self::System { .. })
    }
    pub const fn is_nt(&self) -> bool {
        matches!(self, Self::Nt(_))
    }
    pub const fn is_password(&self) -> bool {
        matches!(self, Self::Password(_))
    }
}

impl SecretTable {
    /// Every secret that may open a masterkey of `sid` (owned by `profile`), in
    /// the order they are tried: explicit/known passwords (by SID, then name),
    /// explicit/domain NT hashes by SID, the local SAM hash, then NT hashes by
    /// profile name (NTDS or unresolved `--dpapi-nthash`). Several are kept
    /// because one can shadow another: on a DC the SAM holds the DSRM hash
    /// under RID 500, which is not what the domain Administrator's keys use.
    /// `S-1-5-18` gets only the DPAPI_SYSTEM keys. Duplicates are dropped.
    pub fn candidates(&self, sid: &str, profile: &str) -> Vec<Secret<'_>> {
        if sid.eq_ignore_ascii_case(SYSTEM_SID) {
            return vec![Secret::System {
                machine: self.dpapi_system,
                user: self.dpapi_system_user,
            }];
        }
        let name = profile.to_lowercase();
        let mut out: Vec<Secret<'_>> = Vec::new();
        let pw_name = self.pw_by_name.get(&name).map_or(&[][..], Vec::as_slice);
        for pw in self.pw_by_sid.get(sid).into_iter().chain(pw_name) {
            if !out
                .iter()
                .any(|c| matches!(c, Secret::Password(p) if *p == pw.as_str()))
            {
                out.push(Secret::Password(pw));
            }
        }
        let nt_name = self.nt_by_name.get(&name).map_or(&[][..], Vec::as_slice);
        for h in self
            .domain_nt_by_sid
            .get(sid)
            .into_iter()
            .chain(self.local_nt_by_sid.get(sid))
            .chain(nt_name)
        {
            if !out.iter().any(|c| matches!(c, Secret::Nt(x) if x == h)) {
                out.push(Secret::Nt(*h));
            }
        }
        out
    }

    /// Pre-keys derived from every user secret for this profile (same order
    /// as [`Self::candidates`]), each a possible entry point of a CREDHIST walk.
    pub(crate) fn start_prekeys(&self, sid: &str, profile: &str) -> Vec<[u8; 20]> {
        self.candidates(sid, profile)
            .into_iter()
            .filter_map(|c| match c {
                Secret::Password(pw) => prekey_from_password(pw, sid).ok(),
                Secret::Nt(h) => prekey_from_hash(&h, sid).ok(),
                Secret::System { .. } => None,
            })
            .collect()
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
    machine_sid: Option<&str>,
    domain_nthashes: &[(String, [u8; 16])],
    passwords: &[(String, String)],
) -> SecretTable {
    let mut t = SecretTable::default();
    // Without the machine SID the SAM RIDs cannot be keyed: skip them rather
    // than invent `-<rid>` SIDs.
    if let Some(machine_sid) = machine_sid {
        for e in &disk_secrets.sam_entries {
            // An all-zero hash means no hash was recovered for the account.
            if e.nt_hash != [0u8; 16] {
                t.local_nt_by_sid
                    .insert(format!("{machine_sid}-{}", e.rid), e.nt_hash);
            }
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
    for (sid, pw) in passwords {
        t.pw_by_sid.insert(sid.clone(), pw.clone());
    }
    t
}

/// Strip the 12-byte `CredentialFile` header (version, blob size, unknown) and
/// return the inner DPAPI blob bytes.
fn credential_file_blob(file: &[u8]) -> Result<&[u8]> {
    const HDR: usize = 12;
    let size = file
        .get(4..8)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
        .filter(|_| file.len() >= HDR)
        .ok_or_else(|| {
            crate::error::VmkatzError::Parse("CredentialFile header truncated".into())
        })?;
    let end = HDR
        .checked_add(size)
        .filter(|&e| e <= file.len())
        .ok_or_else(|| {
            crate::error::VmkatzError::Parse(format!(
                "CredentialFile blob size {size} exceeds file length {}",
                file.len()
            ))
        })?;
    Ok(&file[HDR..end])
}

/// True if `name` looks like a SID folder (`S-1-...`); safe for non-ASCII names.
fn is_sid_dir_name(name: &str) -> bool {
    name.len() > 4
        && name
            .get(..4)
            .is_some_and(|p| p.eq_ignore_ascii_case("S-1-"))
}

/// A directory holding masterkey files for `sid`.
#[derive(Clone)]
struct ProtectDir {
    path: String,
    sid: String,
}

struct Profile {
    name: String,
    cred_dirs: Vec<String>,
    vault_roots: Vec<String>,
    protect: Vec<ProtectDir>,
}

struct Walker<'a, 'n, R: Read + Seek> {
    ntfs: &'n ntfs::Ntfs,
    root: &'a ntfs::NtfsFile<'n>,
    rd: &'a mut R,
    secrets: &'a SecretTable,
    /// SYSTEM Protect dirs, tried when a profile's own store lacks a masterkey.
    system_protect: Vec<ProtectDir>,
    /// Resolved (or failed) masterkeys by (profile, GUID), so a masterkey that
    /// cannot be opened is not re-derived (PBKDF2 + CREDHIST) for every file.
    mk_cache: HashMap<(String, String), MkResolution>,
    /// Walked CREDHIST chains by (parent dir, SID, start prekey); `None` = walk failed.
    chain_cache: HashMap<(String, String, [u8; 20]), Option<Vec<credhist::CredHistHashes>>>,
}

type MkResolution = std::result::Result<(Vec<u8>, String), (String, String)>;

/// The SYSTEM masterkey folders (`...\S-1-5-18\User` first, then `...\S-1-5-18`).
fn system_protect_dirs() -> Vec<ProtectDir> {
    let prot = "Windows\\System32\\Microsoft\\Protect\\S-1-5-18";
    vec![
        ProtectDir {
            path: format!("{prot}\\User"),
            sid: SYSTEM_SID.into(),
        },
        ProtectDir {
            path: prot.into(),
            sid: SYSTEM_SID.into(),
        },
    ]
}

/// SYSTEM fallback dirs for `prof_name`; empty for SYSTEM itself (already searched).
fn fallback_dirs<'a>(prof_name: &str, system: &'a [ProtectDir]) -> &'a [ProtectDir] {
    if prof_name == "SYSTEM" { &[] } else { system }
}

fn vault_roots(base: &str) -> Vec<String> {
    vec![
        format!("{base}\\AppData\\Local\\Microsoft\\Vault"),
        format!("{base}\\AppData\\Roaming\\Microsoft\\Vault"),
    ]
}

/// Keep the items matching `keep`, then cap to `cap`. A cap hit is recorded in
/// `notes` and logged so the truncation is never silent.
fn filter_cap<T>(
    items: Vec<T>,
    keep: impl Fn(&T) -> bool,
    cap: usize,
    what: &str,
    notes: &mut Vec<String>,
) -> Vec<T> {
    let mut v: Vec<T> = items.into_iter().filter(|i| keep(i)).collect();
    if v.len() > cap {
        let msg = format!("{what}: cap hit, scanned {cap} of {} entries", v.len());
        log::warn!("credman: {msg}");
        notes.push(msg);
        v.truncate(cap);
    }
    v
}

impl<R: Read + Seek> Walker<'_, '_, R> {
    /// List a directory (uncapped: callers filter first, then `filter_cap`);
    /// `None` if it does not exist.
    fn list(&mut self, path: &str) -> Option<Vec<(String, bool)>> {
        let dir = crate::fs::navigate_to_dir(self.ntfs, self.root, self.rd, path).ok()?;
        crate::fs::list_directory(self.ntfs, &dir, self.rd).ok()
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
    fn user_protect_dirs(&mut self, base: &str, notes: &mut Vec<String>) -> Vec<ProtectDir> {
        let root = format!("{base}\\AppData\\Roaming\\Microsoft\\Protect");
        let dirs = self.list(&root).unwrap_or_default();
        filter_cap(
            dirs,
            |(n, is_dir)| *is_dir && is_sid_dir_name(n),
            MAX_PROTECT_DIRS,
            &format!("{root} (SID folders)"),
            notes,
        )
        .into_iter()
        .map(|(n, _)| ProtectDir {
            path: format!("{root}\\{n}"),
            sid: n,
        })
        .collect()
    }

    fn user_profile(&mut self, name: &str, base: &str, notes: &mut Vec<String>) -> Profile {
        Profile {
            name: name.to_string(),
            cred_dirs: vec![
                format!("{base}\\AppData\\Local\\Microsoft\\Credentials"),
                format!("{base}\\AppData\\Roaming\\Microsoft\\Credentials"),
            ],
            vault_roots: vault_roots(base),
            protect: self.user_protect_dirs(base, notes),
        }
    }

    fn system_profile() -> Profile {
        let base = "Windows\\System32\\config\\systemprofile";
        Profile {
            name: "SYSTEM".into(),
            cred_dirs: vec![
                format!("{base}\\AppData\\Local\\Microsoft\\Credentials"),
                format!("{base}\\AppData\\Roaming\\Microsoft\\Credentials"),
            ],
            vault_roots: vault_roots(base),
            protect: system_protect_dirs(),
        }
    }

    /// Enumerate all profiles on the volume.
    fn profiles(&mut self, notes: &mut Vec<String>) -> Vec<Profile> {
        let mut out = vec![Self::system_profile()];
        for (parent, skip_builtin) in [("Users", true), ("Windows\\ServiceProfiles", false)] {
            let all = self.list(parent).unwrap_or_default();
            let names = filter_cap(
                all,
                |(name, is_dir)| {
                    let lower = name.to_lowercase();
                    *is_dir
                        && !(skip_builtin
                            && matches!(
                                lower.as_str(),
                                "public" | "default" | "default user" | "all users"
                            ))
                },
                MAX_PROFILES,
                &format!("{parent} (profiles)"),
                notes,
            );
            for (name, _) in names {
                let p = self.user_profile(&name, &format!("{parent}\\{name}"), notes);
                out.push(p);
            }
        }
        out
    }

    /// Locate and decrypt the masterkey `guid`; returns (clear key, owning SID).
    fn resolve_masterkey(&mut self, prof: &Profile, guid: &str) -> MkResolution {
        let key = (prof.name.clone(), guid.to_string());
        if let Some(hit) = self.mk_cache.get(&key) {
            return hit.clone();
        }
        let res = self.resolve_masterkey_uncached(prof, guid);
        self.mk_cache.insert(key, res.clone());
        res
    }

    fn resolve_masterkey_uncached(&mut self, prof: &Profile, guid: &str) -> MkResolution {
        let default_sid = prof
            .protect
            .first()
            .map(|p| p.sid.clone())
            .unwrap_or_default();
        let mut last = (
            default_sid,
            format!("masterkey {guid} not found in Protect folders"),
        );
        // Collect the search order up front: holding a borrow of
        // `self.system_protect` across `self.read` would conflict, and taking
        // it out would leave the cache empty if an early return ever crept in.
        let fallback: Vec<ProtectDir> = fallback_dirs(&prof.name, &self.system_protect).to_vec();
        let mut found = None;
        for pd in prof.protect.iter().chain(fallback.iter()) {
            let Ok(mk_bytes) = self.read(&pd.path, guid) else {
                continue;
            };
            match unlock(self.secrets, &pd.sid, &prof.name, &mk_bytes) {
                Ok(k) => {
                    found = Some((k, pd.sid.clone()));
                    break;
                }
                Err(reason) => {
                    // The masterkey may predate the current password; CREDHIST
                    // holds the older hashes that still open it.
                    if let Some(k) = self.try_credhist(pd, &prof.name, &mk_bytes) {
                        found = Some((k, pd.sid.clone()));
                        break;
                    }
                    last = (pd.sid.clone(), reason);
                }
            }
        }
        found.ok_or(last)
    }

    /// Walk `CREDHIST` (one level above the per-SID folder) for previous
    /// password hashes and retry the masterkey with each of them.
    fn try_credhist(&mut self, pd: &ProtectDir, profile: &str, mk_bytes: &[u8]) -> Option<Vec<u8>> {
        let starts = self.secrets.start_prekeys(&pd.sid, profile);
        if starts.is_empty() {
            return None;
        }
        let (parent, _) = pd.path.rsplit_once('\\')?;
        let mut file: Option<Vec<u8>> = None;
        for start in &starts {
            let key = (parent.to_string(), pd.sid.clone(), *start);
            if !self.chain_cache.contains_key(&key) {
                if file.is_none() {
                    file = Some(self.read(parent, "CREDHIST").ok()?);
                }
                let walked = file
                    .as_deref()
                    .and_then(|f| credhist::recover_previous_hashes(f, &pd.sid, start).ok());
                self.chain_cache.insert(key.clone(), walked);
            }
            let Some(chain) = self.chain_cache.get(&key).and_then(Option::as_ref) else {
                continue;
            };
            for h in chain {
                for key in [
                    prekey_from_hash(&h.sha1, &pd.sid),
                    prekey_from_hash(&h.ntlm, &pd.sid),
                ]
                .into_iter()
                .flatten()
                {
                    if let Ok(clear) = decrypt_masterkey_with_prekey(mk_bytes, &key) {
                        return Some(clear);
                    }
                }
            }
        }
        None
    }

    fn scan_profile(&mut self, prof: &Profile, report: &mut CredmanReport) {
        for dir in &prof.cred_dirs {
            let Some(all) = self.list(dir) else {
                continue;
            };
            let files = filter_cap(
                all,
                |(_, d)| !*d,
                MAX_CRED_FILES,
                &format!("{dir} (credential files)"),
                &mut report.vault_notes,
            );
            for (fname, _) in files {
                match self.decrypt_one(prof, dir, &fname) {
                    Ok((sid, entry, attributes)) => report.entries.push(ProfileCred {
                        profile: prof.name.clone(),
                        sid,
                        entry,
                        attributes,
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

    /// Scan `<base>\AppData\{Local,Roaming}\Microsoft\Vault\<GUID>\` folders.
    /// Failures go to `undecrypted`; nothing here aborts the walk.
    fn scan_vaults(&mut self, prof: &Profile, report: &mut CredmanReport) {
        for root in &prof.vault_roots {
            let Some(all) = self.list(root) else {
                continue;
            };
            let dirs = filter_cap(
                all,
                |(_, d)| *d,
                MAX_VAULT_DIRS,
                &format!("{root} (vault folders)"),
                &mut report.vault_notes,
            );
            for (guid, _) in dirs {
                let dir = format!("{root}\\{guid}");
                let all = self.list(&dir).unwrap_or_default();
                let vcrds: Vec<String> = filter_cap(
                    all,
                    |(n, d)| !*d && n.to_lowercase().ends_with(".vcrd"),
                    MAX_VCRD_FILES,
                    &format!("{dir} (.vcrd files)"),
                    &mut report.vault_notes,
                )
                .into_iter()
                .map(|(n, _)| n)
                .collect();
                let (keys, sid) = match self.vault_keys(prof, &dir) {
                    Ok(k) => k,
                    Err((sid, reason)) => {
                        // A folder without Policy.vpol and without records is not a vault.
                        if !vcrds.is_empty() || !reason.starts_with("Policy.vpol read") {
                            report.undecrypted.push(Undecrypted {
                                profile: prof.name.clone(),
                                sid,
                                file: format!("{dir}\\Policy.vpol"),
                                reason,
                            });
                        }
                        continue;
                    }
                };
                let mut n_ok = 0usize;
                for name in &vcrds {
                    let res = self.read(&dir, name).and_then(|b| parse_vcrd(&b, &keys));
                    match res {
                        Ok(cred) => {
                            n_ok += 1;
                            report.vault.push(ProfileVaultCred {
                                profile: prof.name.clone(),
                                sid: sid.clone(),
                                vault_guid: guid.clone(),
                                cred,
                            });
                        }
                        Err(e) => report.undecrypted.push(Undecrypted {
                            profile: prof.name.clone(),
                            sid: sid.clone(),
                            file: format!("{dir}\\{name}"),
                            reason: format!("vcrd: {e}"),
                        }),
                    }
                }
                report.vault_notes.push(format!(
                    "{}\\{guid}: keys={} vcrd={}/{}",
                    prof.name,
                    keys.count(),
                    n_ok,
                    vcrds.len()
                ));
            }
        }
    }

    /// Policy.vpol -> DPAPI blob -> masterkey -> clear -> AES keys.
    fn vault_keys(
        &mut self,
        prof: &Profile,
        dir: &str,
    ) -> std::result::Result<(VaultKeys, String), (String, String)> {
        let sid0 = prof
            .protect
            .first()
            .map(|p| p.sid.clone())
            .unwrap_or_default();
        let raw = self
            .read(dir, "Policy.vpol")
            .map_err(|e| (sid0.clone(), format!("Policy.vpol read: {e}")))?;
        let inner = parse_vpol(&raw).map_err(|e| (sid0.clone(), format!("vpol parse: {e}")))?;
        let blob =
            parse_blob(inner).map_err(|e| (sid0.clone(), format!("vpol blob parse: {e}")))?;
        let (mk, sid) = self.resolve_masterkey(prof, &blob.mk_guid_str)?;
        let clear = decrypt_blob(&blob, &mk)
            .map_err(|e| (sid.clone(), format!("vpol blob decrypt: {e}")))?;
        let keys =
            parse_vault_keys(&clear).map_err(|e| (sid.clone(), format!("vault keys: {e}")))?;
        Ok((keys, sid))
    }

    fn decrypt_one(
        &mut self,
        prof: &Profile,
        dir: &str,
        fname: &str,
    ) -> std::result::Result<(String, CredmanEntry, Vec<AttrInfo>), (String, String)> {
        let sid0 = prof
            .protect
            .first()
            .map(|p| p.sid.clone())
            .unwrap_or_default();
        let raw = self
            .read(dir, fname)
            .map_err(|e| (sid0.clone(), e.to_string()))?;
        let inner = credential_file_blob(&raw).map_err(|e| (sid0.clone(), e.to_string()))?;
        let blob = parse_blob(inner).map_err(|e| (sid0.clone(), format!("blob parse: {e}")))?;
        let (mk, sid) = self.resolve_masterkey(prof, &blob.mk_guid_str)?;
        let clear =
            decrypt_blob(&blob, &mk).map_err(|e| (sid.clone(), format!("blob decrypt: {e}")))?;
        let entry = parse_credential_blob(&clear)
            .map_err(|e| (sid.clone(), format!("credential parse: {e}")))?;
        let attrs = entry
            .attributes
            .iter()
            .map(|a| AttrInfo {
                keyword: a.keyword.clone(),
                value_hex: hex::encode(&a.value),
            })
            .collect();
        Ok((sid, entry, attrs))
    }
}

/// Decrypt a masterkey file with each secret that applies to `sid`, in
/// [`SecretTable::candidates`] order; the first that verifies wins.
fn unlock(
    secrets: &SecretTable,
    sid: &str,
    profile: &str,
    mk_bytes: &[u8],
) -> std::result::Result<Vec<u8>, String> {
    let mut last = None;
    for cand in secrets.candidates(sid, profile) {
        let res = match cand {
            // A local (context-1) user masterkey derives from the password,
            // which an NT hash cannot reproduce.
            Secret::Password(pw) => decrypt_local_user_masterkey_pw(mk_bytes, pw, sid)
                .map_err(|e| format!("masterkey decrypt (password): {e}")),
            Secret::Nt(h) => decrypt_local_user_masterkey(mk_bytes, &h, sid)
                .map_err(|e| format!("masterkey decrypt: {e}")),
            Secret::System { machine, user } => {
                let mut r = Err(format!("no DPAPI_SYSTEM secret for {sid}"));
                for key in [machine, user].into_iter().flatten() {
                    r = decrypt_system_masterkey(mk_bytes, &key)
                        .map_err(|e| format!("masterkey decrypt: {e}"));
                    if r.is_ok() {
                        break;
                    }
                }
                r
            }
        };
        match res {
            Ok(k) => return Ok(k),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| format!("no secret for {sid}")))
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
            system_protect: system_protect_dirs(),
            mk_cache: HashMap::new(),
            chain_cache: HashMap::new(),
        };
        for prof in w.profiles(&mut report.vault_notes) {
            w.scan_profile(&prof, &mut report);
            w.scan_vaults(&prof, &mut report);
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
        assert!(t.candidates("S-1-5-18", "SYSTEM")[0].is_system());
        assert!(t.candidates("S-1-5-21-1-2-3-1106", "bob").is_empty());
    }

    #[test]
    fn system_fallback_resolves() {
        let sys = system_protect_dirs();
        assert_eq!(sys.len(), 2);
        assert!(sys[0].path.ends_with("S-1-5-18\\User"));
        assert!(sys.iter().all(|p| p.sid == "S-1-5-18"));
        // Non-SYSTEM profiles fall back to the SYSTEM dirs, in order.
        let fb = fallback_dirs("NetworkService", &sys);
        assert_eq!(fb.len(), 2);
        assert_eq!(fb[0].path, sys[0].path);
        // SYSTEM itself is never re-searched.
        assert!(fallback_dirs("SYSTEM", &sys).is_empty());
        // The fallback SID is unlockable via DPAPI_SYSTEM.
        let t = SecretTable {
            dpapi_system: Some([0u8; 20]),
            ..Default::default()
        };
        assert!(t.candidates(&fb[0].sid, "NetworkService")[0].is_system());
        assert_eq!(
            Walker::<std::io::Cursor<Vec<u8>>>::system_profile().protect[0].sid,
            fb[0].sid
        );
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
    fn credential_file_header_is_stripped() {
        // Minimal DPAPI blob: 4+16+4+16+4 header, then empty description etc.
        let mut blob = Vec::new();
        blob.extend_from_slice(&1u32.to_le_bytes());
        blob.extend_from_slice(&[
            0xD0, 0x8C, 0x9D, 0xDF, 1, 0x15, 0xD1, 0x11, 0x8C, 0x7A, 0, 0xC0, 0x4F, 0xC2, 0x97,
            0xEB,
        ]);
        blob.extend_from_slice(&1u32.to_le_bytes());
        blob.extend_from_slice(&[0x11u8; 16]);
        blob.extend_from_slice(&0u32.to_le_bytes()); // flags
        blob.extend_from_slice(&0u32.to_le_bytes()); // desc len
        blob.extend_from_slice(&0x6610u32.to_le_bytes());
        blob.extend_from_slice(&256u32.to_le_bytes());
        blob.extend_from_slice(&0u32.to_le_bytes()); // salt len
        blob.extend_from_slice(&0u32.to_le_bytes()); // hmac_key len
        blob.extend_from_slice(&0x800Eu32.to_le_bytes());
        blob.extend_from_slice(&512u32.to_le_bytes());
        blob.extend_from_slice(&0u32.to_le_bytes()); // hmac len
        blob.extend_from_slice(&0u32.to_le_bytes()); // data len
        blob.extend_from_slice(&0u32.to_le_bytes()); // sign len
        let mut file = Vec::new();
        file.extend_from_slice(&1u32.to_le_bytes());
        file.extend_from_slice(&u32::try_from(blob.len()).unwrap().to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&blob);
        let inner = credential_file_blob(&file).unwrap();
        assert_eq!(inner, &blob[..]);
        assert!(parse_blob(inner).is_ok());
        // Whole-file parse (the old bug) must not be what succeeds.
        assert!(credential_file_blob(&file[..11]).is_err());
        assert!(credential_file_blob(&[]).is_err());
        // Declared size beyond the file.
        let mut bad = file.clone();
        bad[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(credential_file_blob(&bad).is_err());
    }

    #[test]
    fn cap_hit_is_reported() {
        let mut notes = Vec::new();
        // 5 noise entries must not eat the 3 cap slots (filter first).
        let items: Vec<(String, bool)> = (0..5)
            .map(|i| (format!("n{i}"), false))
            .chain((0..5).map(|i| (format!("d{i}"), true)))
            .collect();
        let kept = filter_cap(items.clone(), |(_, d)| *d, 3, "dir", &mut notes);
        assert_eq!(kept.len(), 3);
        assert!(kept.iter().all(|(n, _)| n.starts_with('d')));
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("cap hit") && notes[0].contains("3 of 5"));
        let mut quiet = Vec::new();
        let kept = filter_cap(items, |(_, d)| *d, 5, "dir", &mut quiet);
        assert_eq!(kept.len(), 5);
        assert!(quiet.is_empty());
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
        let st = build_secret_table(&ds, &[], Some("S-1-5-21-1-2-3"), &dom, &[]);
        assert!(!st.local_nt_by_sid.contains_key("S-1-5-21-1-2-3-501"));
        assert!(st.candidates("S-1-5-21-9-9-9-1106", "bob")[0].is_nt());
    }

    #[test]
    fn unlock_tries_every_candidate_explicit_first() {
        use crate::sam::dpapi_masterkey::fixture_mk_file;
        let sid = "S-1-5-21-1-2-3-500";
        let mk = [0x5Au8; 64];
        let good = [9u8; 16];
        let wrong = [7u8; 16];
        // DC case: the SAM (DSRM) hash for RID 500 is wrong, the domain hash opens it.
        let file = fixture_mk_file(&prekey_from_hash(&good, sid).unwrap(), &mk);
        let mut t = SecretTable::default();
        t.local_nt_by_sid.insert(sid.into(), wrong);
        t.domain_nt_by_sid.insert(sid.into(), good);
        assert_eq!(unlock(&t, sid, "Administrator", &file).unwrap(), mk);
        // Same with the domain hash known only by profile name (NTDS).
        let mut t = SecretTable::default();
        t.local_nt_by_sid.insert(sid.into(), wrong);
        t.nt_by_name.insert("administrator".into(), vec![good]);
        assert_eq!(unlock(&t, sid, "Administrator", &file).unwrap(), mk);
        // An explicit password beats a (wrong) SAM hash.
        let pw_file = fixture_mk_file(&prekey_from_password("P@ss", sid).unwrap(), &mk);
        let mut t = SecretTable::default();
        t.local_nt_by_sid.insert(sid.into(), wrong);
        t.pw_by_sid.insert(sid.into(), "P@ss".into());
        assert_eq!(unlock(&t, sid, "Administrator", &pw_file).unwrap(), mk);
        // Order: explicit password, then explicit/domain hash, then SAM, then NTDS.
        t.domain_nt_by_sid.insert(sid.into(), good);
        t.nt_by_name.insert("administrator".into(), vec![[1u8; 16]]);
        let c = t.candidates(sid, "Administrator");
        assert!(matches!(c[0], Secret::Password("P@ss")));
        assert!(matches!(c[1], Secret::Nt(h) if h == good));
        assert!(matches!(c[2], Secret::Nt(h) if h == wrong));
        assert!(matches!(c[3], Secret::Nt(h) if h == [1u8; 16]));
        assert_eq!(c.len(), 4);
        // Every candidate failing reports a decrypt failure, not "no secret".
        let mut t = SecretTable::default();
        t.local_nt_by_sid.insert(sid.into(), wrong);
        assert!(unlock(&t, sid, "Administrator", &file).is_err());
    }

    #[test]
    fn by_name_tries_explicit_then_ntds() {
        use crate::sam::dpapi_masterkey::fixture_mk_file;
        let sid = "S-1-5-21-1-2-3-500";
        let mk = [0x5Au8; 64];
        let good = [9u8; 16];
        let stale = [7u8; 16];
        let file = fixture_mk_file(&prekey_from_hash(&good, sid).unwrap(), &mk);
        let mut t = SecretTable::default();
        // Explicit (stale) pushed first, NTDS (good) second.
        t.nt_by_name
            .entry("administrator".into())
            .or_default()
            .extend([stale, good]);
        let c = t.candidates(sid, "Administrator");
        assert_eq!(c.len(), 2);
        assert!(matches!(c[0], Secret::Nt(h) if h == stale));
        assert!(matches!(c[1], Secret::Nt(h) if h == good));
        assert_eq!(unlock(&t, sid, "Administrator", &file).unwrap(), mk);
        // Same for passwords: explicit first, both tried.
        let pw_file = fixture_mk_file(&prekey_from_password("P@ss", sid).unwrap(), &mk);
        let mut t = SecretTable::default();
        t.pw_by_name
            .entry("administrator".into())
            .or_default()
            .extend(["wrong".to_string(), "P@ss".to_string()]);
        let c = t.candidates(sid, "Administrator");
        assert!(matches!(c[0], Secret::Password("wrong")));
        assert!(matches!(c[1], Secret::Password("P@ss")));
        assert_eq!(unlock(&t, sid, "Administrator", &pw_file).unwrap(), mk);
    }

    #[test]
    fn system_sid_gets_no_user_secrets() {
        let mut t = SecretTable {
            dpapi_system: Some([0u8; 20]),
            ..Default::default()
        };
        t.pw_by_name.insert("system".into(), vec!["x".into()]);
        t.nt_by_name.insert("system".into(), vec![[1u8; 16]]);
        let c = t.candidates(SYSTEM_SID, "SYSTEM");
        assert_eq!(c.len(), 1);
        assert!(c[0].is_system());
        assert!(t.start_prekeys(SYSTEM_SID, "SYSTEM").is_empty());
    }

    #[test]
    fn build_secret_table_without_machine_sid_skips_sam() {
        let st = build_secret_table(&disk_secrets_fixture(), &[], None, &[], &[]);
        assert!(st.local_nt_by_sid.is_empty());
    }

    #[test]
    fn build_secret_table_maps_rid_to_sid() {
        let st = build_secret_table(
            &disk_secrets_fixture(),
            &[],
            Some("S-1-5-21-1-2-3"),
            &[],
            &[],
        );
        assert_eq!(
            st.local_nt_by_sid.get("S-1-5-21-1-2-3-500"),
            Some(&[7u8; 16])
        );
    }
}
