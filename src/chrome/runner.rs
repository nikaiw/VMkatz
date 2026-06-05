//! Top-level entrypoint for the chrome module's CLI wiring.
//!
//! Today this only performs *discovery* on disk — enumerating Chromium profiles
//! and reporting which artifacts (Local State / Login Data / Cookies / Web Data)
//! are present. Decryption requires DPAPI masterkey derivation from the user's
//! NTLM hash, which is a follow-up sub-task. Until then, `findings` stays empty.
//!
//! Memory orchestration is also a follow-up — wiring `PhysicalMemory` to a
//! `ProcessSource` is non-trivial and not in this task.

use std::path::Path;

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
pub fn run_disk(disk_path: &Path) -> Result<DiscoverySummary> {
    let profiles = discover_profiles(disk_path)?;
    Ok(DiscoverySummary {
        profiles,
        findings: ChromeFindings::default(),
    })
}

/// Same as `run_disk` but takes a `MasterkeyResolver` to actually decrypt blobs.
/// Returns ChromeFindings populated with decrypted passwords/cookies/autofill.
pub fn run_disk_with_keyring<R: crate::chrome::disk::MasterkeyResolver>(
    disk_path: &Path,
    user_resolver: &R,
    system_resolver: Option<&R>,
) -> Result<DiscoverySummary> {
    let profiles = discover_profiles(disk_path)?;
    let mut tree = ArtifactsTree { profiles: &profiles };
    let findings = crate::chrome::disk::extract_from_disk(&mut tree, user_resolver, system_resolver)
        .unwrap_or_default();
    Ok(DiscoverySummary { profiles, findings })
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

fn discover_profiles(disk_path: &Path) -> Result<Vec<DiscoveredProfile>> {
    let mut disk = crate::disk::open_disk(disk_path)?;

    // Reuse the sam partition scanner: handles MBR + GPT + BitLocker detection.
    let partitions = crate::sam::find_ntfs_partitions(&mut disk).unwrap_or_default();
    if partitions.is_empty() {
        return Err(crate::error::VmkatzError::Parse(
            "no NTFS partitions found on disk".into(),
        ));
    }

    let mut last_err: Option<String> = None;
    for &part_offset in &partitions {
        if crate::sam::is_bitlocker_partition(&mut disk, part_offset) {
            log::info!(
                "[chrome] partition at 0x{:x} is BitLocker, skipping",
                part_offset
            );
            continue;
        }
        let mut part_reader = crate::sam::PartitionReader::new(&mut disk, part_offset);
        let ntfs = match ntfs::Ntfs::new(&mut part_reader) {
            Ok(n) => n,
            Err(e) => {
                last_err = Some(format!("ntfs parse at 0x{:x}: {}", part_offset, e));
                continue;
            }
        };
        let mut tree = crate::chrome::profile::NtfsTree {
            ntfs: &ntfs,
            reader: &mut part_reader,
        };
        match discover_chromium(&mut tree) {
            Ok(profiles) if !profiles.is_empty() => return Ok(profiles),
            Ok(_) => {
                // NTFS parsed but no Chromium profiles on this partition; try next.
                log::info!(
                    "[chrome] no profiles on NTFS partition at 0x{:x}",
                    part_offset
                );
            }
            Err(e) => {
                last_err = Some(format!("discover at 0x{:x}: {}", part_offset, e));
            }
        }
    }

    if let Some(msg) = last_err {
        log::info!("[chrome] discovery: {}", msg);
    }
    // No profiles found is not an error — return empty list so the caller can
    // print a friendly "no profiles found" message.
    Ok(Vec::new())
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
                let mk_guid = p
                    .artifacts
                    .local_state
                    .as_ref()
                    .and_then(|b| std::str::from_utf8(b).ok())
                    .and_then(|s| crate::chrome::local_state::parse(s).ok())
                    .and_then(|ls| ls.encrypted_key)
                    .and_then(|raw| {
                        if raw.len() < 5 || &raw[..5] != b"DPAPI" {
                            return None;
                        }
                        crate::chrome::dpapi_decrypt::parse_blob(&raw[5..])
                            .ok()
                            .map(|b| b.mk_guid_str)
                    })
                    .unwrap_or_else(|| "?".into());
                s.push_str(&format!(
                    "[Chrome] {}/{} ({})\n  artifacts: local_state={} login_data={} cookies={} web_data={}\n  mk_guid: {}\n  path: {}\n",
                    p.profile.user,
                    p.profile.profile_name,
                    p.profile.browser,
                    p.artifacts.local_state.as_ref().map(|v| v.len()).unwrap_or(0),
                    p.artifacts.login_data.as_ref().map(|v| v.len()).unwrap_or(0),
                    p.artifacts.cookies.as_ref().map(|v| v.len()).unwrap_or(0),
                    p.artifacts.web_data.as_ref().map(|v| v.len()).unwrap_or(0),
                    mk_guid,
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
