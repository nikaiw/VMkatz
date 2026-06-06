//! Top-level entrypoint for the chrome module's CLI wiring.
//!
//! Today this only performs *discovery* on disk — enumerating Chromium profiles
//! and reporting which artifacts (Local State / Login Data / Cookies / Web Data)
//! are present. Decryption requires DPAPI masterkey derivation from the user's
//! NTLM hash, which is a follow-up sub-task. Until then, `findings` stays empty.
//!
//! Memory orchestration is also a follow-up — wiring `PhysicalMemory` to a
//! `ProcessSource` is non-trivial and not in this task.

use std::collections::HashMap;
use std::path::Path;

use crate::chrome::abe_keys::BrowserKeyMap;
use crate::chrome::hybrid::HybridKeyring;
use crate::chrome::output::{render, Format};
use crate::chrome::profile::{discover_chromium, DiscoveredProfile};
use crate::chrome::types::ChromeFindings;
use crate::error::Result;

/// What was found on disk. Once masterkey decryption lands, `findings` will populate.
pub struct DiscoverySummary {
    pub profiles: Vec<DiscoveredProfile>,
    pub findings: ChromeFindings,
}

/// Discover Chromium profiles on `disk_path` and produce findings.
///
/// Opens the disk image (any format supported by `disk::open_disk`), locates the
/// first non-BitLocker NTFS partition, and walks the standard Windows user-profile
/// paths to enumerate browser profiles. Returns the discovery summary; callers
/// pretty-print or JSON-serialize via [`render_summary`].
/// Reader-based variant for callers that already have a disk reader open (e.g.
/// the VMFS-backed flat-VMDK flow on ESXi). Skips the `disk::open_disk` call and
/// uses caller-supplied SAM/LSA secrets instead of re-extracting them.
///
/// `extra_passwords` are tried in addition to every LSA-recovered plaintext when
/// decrypting user DPAPI masterkey files.
pub fn run_reader<R: std::io::Read + std::io::Seek>(
    reader: &mut R,
    secrets: &crate::sam::DiskSecrets,
    extra_passwords: &[String],
) -> Result<DiscoverySummary> {
    let (profiles, key_map) = discover_profiles_in_reader(reader)?;
    let (user_kr, system_kr) = build_keyrings_with_secrets(reader, secrets, extra_passwords);
    log::info!(
        "[chrome] disk MK decrypt: {} user MKs, {} system MKs",
        user_kr.len(),
        system_kr.len()
    );
    let mut tree = ArtifactsTree { profiles: &profiles };
    let findings =
        crate::chrome::disk::extract_from_disk(&mut tree, &user_kr, Some(&system_kr), &key_map)
            .unwrap_or_default();
    Ok(DiscoverySummary { profiles, findings })
}

pub fn run_disk(disk_path: &Path) -> Result<DiscoverySummary> {
    run_disk_with_passwords(disk_path, &[])
}

/// Same as `run_disk` but supplies extra password candidates to try when
/// decrypting user MK files (in addition to LSA-recovered plaintext).
pub fn run_disk_with_passwords(
    disk_path: &Path,
    extra_passwords: &[String],
) -> Result<DiscoverySummary> {
    let (profiles, key_map) = discover_profiles(disk_path)?;
    let (user_kr, system_kr) = match build_keyrings_from_disk_with_passwords(
        disk_path,
        extra_passwords,
    ) {
        Ok(p) => p,
        Err(e) => {
            log::info!("[chrome] disk-only keyrings unavailable: {}", e);
            return Ok(DiscoverySummary {
                profiles,
                findings: ChromeFindings::default(),
            });
        }
    };
    log::info!(
        "[chrome] disk MK decrypt: {} user MKs, {} system MKs",
        user_kr.len(),
        system_kr.len()
    );
    let mut tree = ArtifactsTree { profiles: &profiles };
    let findings =
        crate::chrome::disk::extract_from_disk(&mut tree, &user_kr, Some(&system_kr), &key_map)
            .unwrap_or_default();
    Ok(DiscoverySummary { profiles, findings })
}

/// Same as `run_disk` but takes a `MasterkeyResolver` to actually decrypt blobs.
/// Returns ChromeFindings populated with decrypted passwords/cookies/autofill.
pub fn run_disk_with_keyring<U, S>(
    disk_path: &Path,
    user_resolver: &U,
    system_resolver: Option<&S>,
) -> Result<DiscoverySummary>
where
    U: crate::chrome::disk::MasterkeyResolver,
    S: crate::chrome::disk::MasterkeyResolver,
{
    let (profiles, key_map) = discover_profiles(disk_path)?;
    let mut tree = ArtifactsTree { profiles: &profiles };
    let findings = crate::chrome::disk::extract_from_disk(
        &mut tree,
        user_resolver,
        system_resolver,
        &key_map,
    )
    .unwrap_or_default();
    Ok(DiscoverySummary { profiles, findings })
}

/// Reader-based variant: caller owns the disk handle, we only borrow it. Used
/// by the hybrid path (lsass mem + disk) so the same File handle services both
/// keyring building and chrome discovery, avoiding a second `open()` that can
/// race against external filesystem locks (e.g. ESXi system datastores).
pub fn run_reader_with_keyring<R, U, S>(
    reader: &mut R,
    user_resolver: &U,
    system_resolver: Option<&S>,
) -> Result<DiscoverySummary>
where
    R: std::io::Read + std::io::Seek,
    U: crate::chrome::disk::MasterkeyResolver,
    S: crate::chrome::disk::MasterkeyResolver,
{
    let (profiles, key_map) = discover_profiles_in_reader(reader)?;
    let mut tree = ArtifactsTree { profiles: &profiles };
    let findings = crate::chrome::disk::extract_from_disk(
        &mut tree,
        user_resolver,
        system_resolver,
        &key_map,
    )
    .unwrap_or_default();
    Ok(DiscoverySummary { profiles, findings })
}

/// Reader-based variant of `build_keyrings_from_disk_with_passwords` — the
/// caller already has a disk reader and pre-extracted secrets. Used by the
/// hybrid path so we open the disk once and share the handle.
pub fn build_keyrings_from_reader<R: std::io::Read + std::io::Seek>(
    reader: &mut R,
    secrets: &crate::sam::DiskSecrets,
    extra_passwords: &[String],
) -> (HybridKeyring, HybridKeyring) {
    build_keyrings_with_secrets(reader, secrets, extra_passwords)
}

/// Build a `HybridKeyring` from any iterator of `(guid, masterkey_bytes)` pairs —
/// typically sourced from LSASS DPAPI extraction (`Credential.dpapi`).
pub fn keyring_from_pairs<I, S>(pairs: I) -> crate::chrome::hybrid::HybridKeyring
where
    I: IntoIterator<Item = (S, Vec<u8>)>,
    S: Into<String>,
{
    let mut kr = crate::chrome::hybrid::HybridKeyring::new();
    for (g, k) in pairs {
        kr.insert(g.into(), k);
    }
    kr
}

/// In-memory FileTree backed by already-discovered ProfileArtifacts. Lets the
/// orchestrator (`extract_from_disk`) decrypt without re-walking NTFS.
struct ArtifactsTree<'a> {
    profiles: &'a [DiscoveredProfile],
}

impl<'a> crate::chrome::profile::FileTree for ArtifactsTree<'a> {
    fn list_dir(&mut self, p: &str) -> Result<Vec<String>> {
        if p == "Users" {
            let mut users: Vec<String> = self.profiles.iter().map(|d| d.profile.user.clone()).collect();
            users.sort();
            users.dedup();
            return Ok(users);
        }
        for d in self.profiles {
            let browser_root = d.profile.path.rsplit_once('\\').map(|(parent, _)| parent).unwrap_or("");
            if p == browser_root {
                return Ok(vec![d.profile.profile_name.clone()]);
            }
        }
        Ok(Vec::new())
    }

    fn read_file(&mut self, p: &str) -> Result<Option<Vec<u8>>> {
        for d in self.profiles {
            let prof_path = &d.profile.path;
            let browser_root = prof_path.rsplit_once('\\').map(|(parent, _)| parent).unwrap_or("");
            if p == format!("{}\\Local State", browser_root) {
                return Ok(d.artifacts.local_state.clone());
            }
            if p == format!("{}\\Login Data", prof_path) { return Ok(d.artifacts.login_data.clone()); }
            if p == format!("{}\\Login Data-wal", prof_path) { return Ok(d.artifacts.login_data_wal.clone()); }
            if p == format!("{}\\Network\\Cookies", prof_path) { return Ok(d.artifacts.cookies.clone()); }
            if p == format!("{}\\Network\\Cookies-wal", prof_path) { return Ok(d.artifacts.cookies_wal.clone()); }
            if p == format!("{}\\Cookies", prof_path) { return Ok(d.artifacts.cookies.clone()); }
            if p == format!("{}\\Cookies-wal", prof_path) { return Ok(d.artifacts.cookies_wal.clone()); }
            if p == format!("{}\\Web Data", prof_path) { return Ok(d.artifacts.web_data.clone()); }
            if p == format!("{}\\Web Data-wal", prof_path) { return Ok(d.artifacts.web_data_wal.clone()); }
        }
        Ok(None)
    }
}

fn discover_profiles(disk_path: &Path) -> Result<(Vec<DiscoveredProfile>, BrowserKeyMap)> {
    let mut disk = crate::disk::open_disk(disk_path)?;
    discover_profiles_in_reader(&mut disk)
}

fn discover_profiles_in_reader<R: std::io::Read + std::io::Seek>(
    disk: &mut R,
) -> Result<(Vec<DiscoveredProfile>, BrowserKeyMap)> {
    let partitions = crate::sam::find_ntfs_partitions(disk).unwrap_or_default();
    if partitions.is_empty() {
        return Err(crate::error::VmkatzError::Parse(
            "no NTFS partitions found on disk".into(),
        ));
    }

    let mut last_err: Option<String> = None;
    for &part_offset in &partitions {
        if crate::sam::is_bitlocker_partition(disk, part_offset) {
            log::info!(
                "[chrome] partition at 0x{:x} is BitLocker, skipping",
                part_offset
            );
            continue;
        }
        let mut part_reader = crate::sam::PartitionReader::new(disk, part_offset);
        let ntfs = match ntfs::Ntfs::new(&mut part_reader) {
            Ok(n) => n,
            Err(e) => {
                last_err = Some(format!("ntfs parse at 0x{:x}: {}", part_offset, e));
                continue;
            }
        };
        let profiles = {
            let mut tree = crate::chrome::profile::NtfsTree {
                ntfs: &ntfs,
                reader: &mut part_reader,
            };
            match discover_chromium(&mut tree) {
                Ok(p) => p,
                Err(e) => {
                    last_err = Some(format!("discover at 0x{:x}: {}", part_offset, e));
                    continue;
                }
            }
        };
        if profiles.is_empty() {
            log::info!(
                "[chrome] no profiles on NTFS partition at 0x{:x}",
                part_offset
            );
            continue;
        }
        let key_map = build_keymap_from_partition(&ntfs, &mut part_reader);
        return Ok((profiles, key_map));
    }

    if let Some(msg) = last_err {
        log::info!("[chrome] discovery: {}", msg);
    }
    Ok((Vec::new(), BrowserKeyMap::fallback()))
}

/// Browser-specific elevation_service.exe locations to probe. Each tuple is
/// `(browser_label, parent_dir, exe_filename)`. The `Application` subdirectory
/// under `parent_dir` holds versioned subdirs (e.g. `135.0.7049.115`); we walk
/// each version subdir looking for `exe_filename`.
const ELEVATION_PATHS: &[(&str, &str, &str)] = &[
    (
        "chrome",
        r"Program Files\Google\Chrome\Application",
        "elevation_service.exe",
    ),
    (
        "chrome",
        r"Program Files (x86)\Google\Chrome\Application",
        "elevation_service.exe",
    ),
    (
        "brave",
        r"Program Files\BraveSoftware\Brave-Browser\Application",
        "brave_browser_elevation_service.exe",
    ),
    (
        "brave",
        r"Program Files (x86)\BraveSoftware\Brave-Browser\Application",
        "brave_browser_elevation_service.exe",
    ),
    (
        "vivaldi",
        r"Program Files\Vivaldi\Application",
        "elevation_service.exe",
    ),
    (
        "vivaldi",
        r"Program Files (x86)\Vivaldi\Application",
        "elevation_service.exe",
    ),
    (
        "opera",
        r"Program Files\Opera",
        "elevation_service.exe",
    ),
    (
        "opera",
        r"Program Files (x86)\Opera",
        "elevation_service.exe",
    ),
];

/// Walk known browser install dirs on an already-open NTFS partition, looking
/// for `elevation_service.exe` (or Brave's variant). Returns a merged keymap.
/// Falls back to Chrome 135 hardcoded keys if no binary is found.
fn build_keymap_from_partition<R: std::io::Read + std::io::Seek>(
    ntfs: &ntfs::Ntfs,
    reader: &mut R,
) -> BrowserKeyMap {
    let root = match ntfs.root_directory(reader) {
        Ok(r) => r,
        Err(_) => return BrowserKeyMap::fallback(),
    };
    let mut merged = BrowserKeyMap {
        entries: Vec::new(),
        fallback: false,
    };
    for (browser, parent_dir, exe_name) in ELEVATION_PATHS {
        let app_dir = match crate::sam::navigate_to_dir(ntfs, &root, reader, parent_dir) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let version_entries = match crate::sam::list_directory(ntfs, &app_dir, reader) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for (ver_name, is_dir) in version_entries {
            if !is_dir || !is_version_dir(&ver_name) {
                continue;
            }
            let ver_dir = match crate::sam::find_entry(ntfs, &app_dir, reader, &ver_name) {
                Ok(d) => d,
                Err(_) => continue,
            };
            let exe_file = match crate::sam::find_entry(ntfs, &ver_dir, reader, exe_name) {
                Ok(f) => f,
                Err(_) => continue,
            };
            let exe_bytes = match crate::sam::read_file_data(&exe_file, reader) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let parsed = BrowserKeyMap::from_pe_or_fallback(&exe_bytes);
            if parsed.fallback {
                log::info!(
                    "[chrome] {} {}\\{} parse miss (using fallback)",
                    browser,
                    parent_dir,
                    ver_name
                );
                continue;
            }
            log::info!(
                "[chrome] extracted {} ABE keys from {} {}\\{}\\{}",
                parsed.entries.len(),
                browser,
                parent_dir,
                ver_name,
                exe_name
            );
            let pre = merged.entries.len();
            let added = merged.merge(parsed);
            if !added && pre > 0 {
                log::info!(
                    "[chrome] {} keys overlap existing slots, keeping first match",
                    browser
                );
            }
        }
    }
    if merged.entries.is_empty() {
        log::info!("[chrome] no elevation_service.exe found, using Chrome 135 fallback keys");
        return BrowserKeyMap::fallback();
    }
    merged
}

/// Is `name` a dotted-decimal version directory like `135.0.7049.115`?
fn is_version_dir(name: &str) -> bool {
    !name.is_empty()
        && name.contains('.')
        && name
            .chars()
            .all(|c| c.is_ascii_digit() || c == '.')
}

/// Walk the disk, decrypt every accessible DPAPI masterkey file using SAM- and
/// LSA-derived pre-keys, and return `(user_keyring, system_keyring)`. Logs the
/// count of master keys decrypted from each context.
///
/// This is the "no memory snapshot" path: we extract SAM hashes + LSA secrets
/// (`extract_disk_secrets`), then walk every user's Protect directory and the
/// `S-1-5-18` Protect directory, decrypting each MK file with the matching
/// pre-key. Failed MKs are skipped with an info log so a single bad file
/// doesn't abort the whole walk.
pub fn build_keyrings_from_disk(
    disk_path: &Path,
) -> Result<(HybridKeyring, HybridKeyring)> {
    build_keyrings_from_disk_with_passwords(disk_path, &[])
}

pub fn build_keyrings_from_disk_with_passwords(
    disk_path: &Path,
    extra_passwords: &[String],
) -> Result<(HybridKeyring, HybridKeyring)> {
    let secrets = crate::sam::extract_disk_secrets(disk_path)?;
    let mut disk = crate::disk::open_disk(disk_path)?;
    Ok(build_keyrings_with_secrets(&mut disk, &secrets, extra_passwords))
}

/// Reader-based + already-extracted-secrets variant of `build_keyrings_from_disk`.
/// Use this when SAM/LSA were extracted from the same reader (e.g. VMFS path).
/// `extra_passwords` are tried in addition to LSA-recovered plaintext.
/// Never errors; returns empty keyrings on any failure.
fn build_keyrings_with_secrets<R: std::io::Read + std::io::Seek>(
    disk: &mut R,
    secrets: &crate::sam::DiskSecrets,
    extra_passwords: &[String],
) -> (HybridKeyring, HybridKeyring) {
    let mut nt_hash_by_rid: HashMap<u32, [u8; 16]> = HashMap::new();
    for entry in &secrets.sam_entries {
        nt_hash_by_rid.insert(entry.rid, entry.nt_hash);
    }

    // DPAPI_SYSTEM halves used per subpath:
    //  - `Protect\S-1-5-18\<GUID>` (machine-context)  → user_key
    //  - `Protect\S-1-5-18\User\<GUID>` (user-context) → machine_key
    let dpapi_system = secrets.lsa_secrets.iter().find_map(|s| match &s.parsed {
        crate::sam::lsa::LsaSecretType::DpapiSystem { user_key, machine_key } => {
            Some((*user_key, *machine_key))
        }
        _ => None,
    });

    // Collect every plaintext password available in LSA — `DefaultPassword`
    // (auto-logon) plus every `_SC_*` service-account password — plus any
    // caller-supplied candidates (`--chrome-password`).
    let mut password_candidates: Vec<String> = extra_passwords.to_vec();
    for s in &secrets.lsa_secrets {
        match &s.parsed {
            crate::sam::lsa::LsaSecretType::DefaultPassword { password } => {
                password_candidates.push(password.clone());
            }
            crate::sam::lsa::LsaSecretType::ServicePassword { password, .. } => {
                password_candidates.push(password.clone());
            }
            _ => {}
        }
    }
    password_candidates.sort();
    password_candidates.dedup();

    log::info!(
        "[chrome] disk secrets: {} SAM entries, DPAPI_SYSTEM={} password_candidates={}",
        secrets.sam_entries.len(),
        dpapi_system.is_some(),
        password_candidates.len()
    );

    let partitions = crate::sam::find_ntfs_partitions(disk).unwrap_or_default();

    let mut user_kr = HybridKeyring::new();
    let mut system_kr = HybridKeyring::new();

    for &part_offset in &partitions {
        if crate::sam::is_bitlocker_partition(disk, part_offset) {
            continue;
        }
        let mut part_reader = crate::sam::PartitionReader::new(disk, part_offset);
        let ntfs = match ntfs::Ntfs::new(&mut part_reader) {
            Ok(n) => n,
            Err(_) => continue,
        };
        let root = match ntfs.root_directory(&mut part_reader) {
            Ok(r) => r,
            Err(_) => continue,
        };

        // System masterkeys live in Windows\System32\Microsoft\Protect\S-1-5-18\
        // (machine-context, pre-key = DPAPI_SYSTEM.user_key) and a `User\` subdir
        // (user-context for SYSTEM, pre-key = DPAPI_SYSTEM.machine_key — confusing
        // but verified empirically on Win10).
        if let Some((user_key, machine_key)) = &dpapi_system {
            decrypt_mks_in_protect(
                &ntfs,
                &root,
                &mut part_reader,
                "Windows\\System32\\Microsoft\\Protect",
                |sid, sub, file_bytes| {
                    if sid != "S-1-5-18" {
                        return None;
                    }
                    let pre_key = if sub.is_empty() { user_key } else { machine_key };
                    crate::sam::dpapi_masterkey::decrypt_system_masterkey(file_bytes, pre_key).ok()
                },
                &mut system_kr,
                "system",
            );
        }

        // User masterkeys: Users\<user>\AppData\Roaming\Microsoft\Protect\<SID>\<guid>
        let users_dir =
            match crate::sam::find_entry(&ntfs, &root, &mut part_reader, "Users") {
                Ok(d) => d,
                Err(_) => continue,
            };
        let user_entries =
            match crate::sam::list_directory(&ntfs, &users_dir, &mut part_reader) {
                Ok(e) => e,
                Err(_) => continue,
            };

        for (user_name, is_dir) in user_entries {
            if !is_dir {
                continue;
            }
            let lower = user_name.to_lowercase();
            if matches!(
                lower.as_str(),
                "public" | "default" | "default user" | "all users" | "desktop.ini"
            ) {
                continue;
            }
            let protect_path =
                format!("{}\\AppData\\Roaming\\Microsoft\\Protect", user_name);

            decrypt_mks_in_protect(
                &ntfs,
                &users_dir,
                &mut part_reader,
                &protect_path,
                |sid, _sub, file_bytes| {
                    // Try every plaintext password from LSA (Win10+ local user chain).
                    for pw in &password_candidates {
                        if let Ok(k) = crate::sam::dpapi_masterkey::decrypt_local_user_masterkey_pw(
                            file_bytes, pw, sid,
                        ) {
                            return Some(k);
                        }
                    }
                    // Fallback: NT-hash direct chain (works for DOMAIN users).
                    let rid: u32 = sid.rsplit('-').next()?.parse().ok()?;
                    let nt_hash = nt_hash_by_rid.get(&rid)?;
                    crate::sam::dpapi_masterkey::decrypt_local_user_masterkey(
                        file_bytes, nt_hash, sid,
                    )
                    .ok()
                },
                &mut user_kr,
                &user_name,
            );
        }

        // First partition that yielded any MKs wins; stop scanning.
        if !user_kr.is_empty() || !system_kr.is_empty() {
            break;
        }
    }

    (user_kr, system_kr)
}

/// Walk `Protect\<SID>\<GUID>` under `base_dir`. For each MK file, call
/// `decrypt_fn(sid, bytes)`; on success, insert the cleartext key into `out`
/// under its file-name GUID. Failures log at info level and continue.
fn decrypt_mks_in_protect<'n, R, F>(
    ntfs: &'n ntfs::Ntfs,
    base_dir: &ntfs::NtfsFile<'n>,
    reader: &mut R,
    protect_path: &str,
    mut decrypt_fn: F,
    out: &mut HybridKeyring,
    label: &str,
) where
    R: std::io::Read + std::io::Seek,
    F: FnMut(&str, &str, &[u8]) -> Option<Vec<u8>>,
{
    let protect_dir = match crate::sam::navigate_to_dir(ntfs, base_dir, reader, protect_path) {
        Ok(d) => d,
        Err(_) => return,
    };
    let sids = match crate::sam::list_directory(ntfs, &protect_dir, reader) {
        Ok(e) => e,
        Err(_) => return,
    };
    for (sid, is_sid_dir) in sids {
        if !is_sid_dir || !sid.starts_with("S-1-5-") {
            continue;
        }
        let sid_dir = match crate::sam::find_entry(ntfs, &protect_dir, reader, &sid) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let mk_entries = match crate::sam::list_directory(ntfs, &sid_dir, reader) {
            Ok(e) => e,
            Err(_) => continue,
        };
        // Collect MK files in this SID dir AND in its optional `User\` subdir.
        // The `User\` subdir under S-1-5-18 holds user-context MKs used by SYSTEM
        // processes — Chrome's elevation_service.exe wraps the v20 key with one.
        let mut mks_to_try: Vec<(String, String)> = Vec::new();
        for (name, is_dir) in &mk_entries {
            if !is_dir && is_mk_guid(name) {
                mks_to_try.push((name.clone(), String::new()));
            }
        }
        if let Ok(user_sub) = crate::sam::find_entry(ntfs, &sid_dir, reader, "User") {
            if let Ok(user_entries) = crate::sam::list_directory(ntfs, &user_sub, reader) {
                for (name, is_dir) in user_entries {
                    if !is_dir && is_mk_guid(&name) {
                        mks_to_try.push((name, "User".to_string()));
                    }
                }
            }
        }
        for (mk_name, sub) in mks_to_try {
            let mk_file = if sub.is_empty() {
                match crate::sam::find_entry(ntfs, &sid_dir, reader, &mk_name) {
                    Ok(f) => f,
                    Err(_) => continue,
                }
            } else {
                let user_sub = match crate::sam::find_entry(ntfs, &sid_dir, reader, &sub) {
                    Ok(d) => d,
                    Err(_) => continue,
                };
                match crate::sam::find_entry(ntfs, &user_sub, reader, &mk_name) {
                    Ok(f) => f,
                    Err(_) => continue,
                }
            };
            let mk_data = match crate::sam::read_file_data(&mk_file, reader) {
                Ok(d) => d,
                Err(_) => continue,
            };
            match decrypt_fn(&sid, &sub, &mk_data) {
                Some(clear) => {
                    log::info!(
                        "[chrome] decrypted {} MK: SID={}{} GUID={}",
                        label,
                        sid,
                        if sub.is_empty() { "".into() } else { format!("/{}", sub) },
                        mk_name
                    );
                    out.insert(mk_name.to_lowercase(), clear);
                }
                None => {
                    log::info!(
                        "[chrome] MK decrypt failed: ctx={} SID={}{} GUID={}",
                        label,
                        sid,
                        if sub.is_empty() { "".into() } else { format!("/{}", sub) },
                        mk_name
                    );
                }
            }
        }
    }
}

/// 36-char `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` GUID filename check.
fn is_mk_guid(name: &str) -> bool {
    if name.len() != 36 {
        return false;
    }
    let b = name.as_bytes();
    b[8] == b'-'
        && b[13] == b'-'
        && b[18] == b'-'
        && b[23] == b'-'
        && b.iter()
            .enumerate()
            .all(|(i, &c)| matches!(i, 8 | 13 | 18 | 23) || c.is_ascii_hexdigit())
}

/// Render a discovery summary for stdout / JSON.
pub fn render_summary(summary: &DiscoverySummary, json: bool) -> String {
    if json {
        let mut obj = serde_json::Map::new();
        let mut profiles_json = Vec::new();
        for p in &summary.profiles {
            let mut pj = serde_json::Map::new();
            pj.insert("user".into(), p.profile.user.clone().into());
            pj.insert("profile_name".into(), p.profile.profile_name.clone().into());
            pj.insert("browser".into(), format!("{}", p.profile.browser).into());
            pj.insert("path".into(), p.profile.path.clone().into());
            pj.insert(
                "has_local_state".into(),
                p.artifacts.local_state.is_some().into(),
            );
            pj.insert(
                "has_login_data".into(),
                p.artifacts.login_data.is_some().into(),
            );
            pj.insert("has_cookies".into(), p.artifacts.cookies.is_some().into());
            pj.insert("has_web_data".into(), p.artifacts.web_data.is_some().into());
            profiles_json.push(serde_json::Value::Object(pj));
        }
        obj.insert("profiles".into(), profiles_json.into());
        obj.insert(
            "findings".into(),
            serde_json::to_value(&summary.findings).unwrap_or(serde_json::Value::Null),
        );
        serde_json::to_string_pretty(&serde_json::Value::Object(obj))
            .unwrap_or_else(|_| "{}".into())
    } else {
        let mut s = String::new();
        if summary.profiles.is_empty() {
            s.push_str("[Chrome] no profiles found\n");
        } else {
            for p in &summary.profiles {
                s.push_str(&format!(
                    "[Chrome] {}/{} ({})\n  artifacts: local_state={} login_data={} cookies={} web_data={}\n  path: {}\n",
                    p.profile.user,
                    p.profile.profile_name,
                    p.profile.browser,
                    p.artifacts.local_state.as_ref().map(|v| v.len()).unwrap_or(0),
                    p.artifacts.login_data.as_ref().map(|v| v.len()).unwrap_or(0),
                    p.artifacts.cookies.as_ref().map(|v| v.len()).unwrap_or(0),
                    p.artifacts.web_data.as_ref().map(|v| v.len()).unwrap_or(0),
                    p.profile.path,
                ));
            }
        }
        // Append any decrypted findings via the standard formatter (empty until
        // masterkey decryption lands; will become non-empty once it does).
        let extra = render(&summary.findings, Format::Pretty);
        if !extra.trim().is_empty() {
            s.push_str(&extra);
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chrome::profile::ProfileArtifacts;
    use crate::chrome::types::{Browser, BrowserProfile};

    fn fake_profile(user: &str, browser: Browser) -> DiscoveredProfile {
        DiscoveredProfile {
            profile: BrowserProfile {
                browser,
                user: user.into(),
                profile_name: "Default".into(),
                path: format!(r"Users\{}\AppData\Local\...\Default", user),
            },
            artifacts: ProfileArtifacts {
                local_state: Some(b"{}".to_vec()),
                login_data: Some(vec![0u8; 4096]),
                login_data_wal: None,
                cookies: None,
                cookies_wal: None,
                web_data: Some(vec![0u8; 1024]),
                web_data_wal: None,
            },
        }
    }

    #[test]
    fn render_pretty_empty() {
        let s = render_summary(
            &DiscoverySummary {
                profiles: Vec::new(),
                findings: ChromeFindings::default(),
            },
            false,
        );
        assert!(s.contains("no profiles found"));
    }

    #[test]
    fn render_pretty_with_profile() {
        let s = render_summary(
            &DiscoverySummary {
                profiles: vec![fake_profile("alice", Browser::Chrome)],
                findings: ChromeFindings::default(),
            },
            false,
        );
        assert!(s.contains("[Chrome] alice/Default (Chrome)"));
        assert!(s.contains("login_data=4096"));
        assert!(s.contains("web_data=1024"));
        assert!(s.contains("cookies=0"));
    }

    #[test]
    fn render_json_shape() {
        let s = render_summary(
            &DiscoverySummary {
                profiles: vec![fake_profile("alice", Browser::Edge)],
                findings: ChromeFindings::default(),
            },
            true,
        );
        // Valid JSON
        let v: serde_json::Value = serde_json::from_str(&s).expect("valid JSON");
        assert!(v.get("profiles").is_some());
        assert!(v.get("findings").is_some());
        let profs = v["profiles"].as_array().unwrap();
        assert_eq!(profs.len(), 1);
        assert_eq!(profs[0]["user"], "alice");
        assert_eq!(profs[0]["browser"], "Edge");
        assert_eq!(profs[0]["has_login_data"], true);
        assert_eq!(profs[0]["has_cookies"], false);
    }
}
