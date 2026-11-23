//! Browser profile discovery on NTFS (Chromium family).
//!
//! Walks `Users\<user>\AppData\...\User Data\<profile>\...` and gathers the
//! artifacts (Local State, Login Data, Cookies, Web Data) needed for downstream
//! decryption.

use crate::chrome::types::{Browser, BrowserProfile};
use crate::error::Result;

/// Profile artifacts we want to read from disk.
#[derive(Debug, Clone, Default)]
pub struct ProfileArtifacts {
    /// `<browser>/User Data/Local State` (JSON)
    pub local_state: Option<Vec<u8>>,
    /// `<profile>/Login Data` (SQLite)
    pub login_data: Option<Vec<u8>>,
    pub login_data_wal: Option<Vec<u8>>,
    /// `<profile>/Network/Cookies` (modern) or `<profile>/Cookies` (legacy)
    pub cookies: Option<Vec<u8>>,
    pub cookies_wal: Option<Vec<u8>>,
    /// `<profile>/Web Data` (SQLite)
    pub web_data: Option<Vec<u8>>,
    pub web_data_wal: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct DiscoveredProfile {
    pub profile: BrowserProfile,
    pub artifacts: ProfileArtifacts,
}

const CHROMIUM_PATHS: &[(Browser, &str)] = &[
    (Browser::Chrome, r"AppData\Local\Google\Chrome\User Data"),
    (Browser::Edge, r"AppData\Local\Microsoft\Edge\User Data"),
    (
        Browser::Brave,
        r"AppData\Local\BraveSoftware\Brave-Browser\User Data",
    ),
    (Browser::Vivaldi, r"AppData\Local\Vivaldi\User Data"),
    (
        Browser::Opera,
        r"AppData\Roaming\Opera Software\Opera Stable",
    ),
];

/// Trait abstracting the NTFS reader so we can unit-test with an in-memory fake.
pub trait FileTree {
    /// List directory entries (file/dir names only, no metadata). Should NOT error
    /// when the directory is missing — return Ok(empty) instead.
    fn list_dir(&mut self, path: &str) -> Result<Vec<String>>;

    /// Read a file by absolute path. Returns Ok(None) if the file does not exist.
    /// Errors include I/O failures and resource limits.
    fn read_file(&mut self, path: &str) -> Result<Option<Vec<u8>>>;
}

pub fn discover_chromium<T: FileTree>(tree: &mut T) -> Result<Vec<DiscoveredProfile>> {
    let users = tree.list_dir(r"Users")?;
    let mut out = Vec::new();
    for user in users {
        if matches!(
            user.as_str(),
            "Public" | "Default" | "Default User" | "All Users" | "desktop.ini"
        ) {
            continue;
        }
        for (browser, sub) in CHROMIUM_PATHS {
            let root = format!(r"Users\{user}\{sub}");
            let Ok(profiles) = tree.list_dir(&root) else {
                continue;
            };
            let local_state = tree.read_file(&format!(r"{root}\Local State"))?;
            for prof in profiles {
                if prof != "Default" && !prof.starts_with("Profile ") {
                    continue;
                }
                let pdir = format!(r"{root}\{prof}");
                let art = ProfileArtifacts {
                    local_state: local_state.clone(),
                    login_data: tree.read_file(&format!(r"{pdir}\Login Data"))?,
                    login_data_wal: tree.read_file(&format!(r"{pdir}\Login Data-wal"))?,
                    // Modern Chromium stores Cookies under <profile>\Network\
                    cookies: match tree.read_file(&format!(r"{pdir}\Network\Cookies"))? {
                        Some(bytes) => Some(bytes),
                        None => tree.read_file(&format!(r"{pdir}\Cookies"))?,
                    },
                    cookies_wal: match tree.read_file(&format!(r"{pdir}\Network\Cookies-wal"))? {
                        Some(bytes) => Some(bytes),
                        None => tree.read_file(&format!(r"{pdir}\Cookies-wal"))?,
                    },
                    web_data: tree.read_file(&format!(r"{pdir}\Web Data"))?,
                    web_data_wal: tree.read_file(&format!(r"{pdir}\Web Data-wal"))?,
                };
                if art.login_data.is_none() && art.cookies.is_none() && art.web_data.is_none() {
                    continue;
                }
                out.push(DiscoveredProfile {
                    profile: BrowserProfile {
                        browser: browser.clone(),
                        user: user.clone(),
                        profile_name: prof,
                        path: pdir,
                    },
                    artifacts: art,
                });
            }
        }
    }
    Ok(out)
}

// Real NTFS-backed FileTree

use std::io::{Read, Seek};

use crate::fs::{find_entry, list_directory, navigate_to_dir, read_file_data};

/// FileTree backed by NTFS, with complete file reads limited to 128 MiB.
///
/// We hold the parsed `Ntfs` and the mutable reader by reference; the root
/// directory is re-resolved per call to keep lifetimes simple (NtfsFile borrows
/// from `Ntfs` and we don't want to thread its lifetime through `FileTree`).
pub struct NtfsTree<'a, R: Read + Seek> {
    pub ntfs: &'a ntfs::Ntfs,
    pub reader: &'a mut R,
}

impl<'a, R: Read + Seek> NtfsTree<'a, R> {
    pub const fn new(ntfs: &'a ntfs::Ntfs, reader: &'a mut R) -> Self {
        Self { ntfs, reader }
    }
}

impl<R: Read + Seek> FileTree for NtfsTree<'_, R> {
    fn list_dir(&mut self, path: &str) -> Result<Vec<String>> {
        let Ok(root) = self.ntfs.root_directory(self.reader) else {
            return Ok(Vec::new());
        };
        let Ok(dir) = navigate_to_dir(self.ntfs, &root, self.reader, path) else {
            return Ok(Vec::new());
        };
        match list_directory(self.ntfs, &dir, self.reader) {
            Ok(entries) => Ok(entries.into_iter().map(|(name, _is_dir)| name).collect()),
            Err(_) => Ok(Vec::new()),
        }
    }

    fn read_file(&mut self, path: &str) -> Result<Option<Vec<u8>>> {
        let Some((dir_part, file_part)) = path.rsplit_once(['\\', '/']) else {
            return Ok(None);
        };
        let Ok(root) = self.ntfs.root_directory(self.reader) else {
            return Ok(None);
        };
        let Ok(dir) = navigate_to_dir(self.ntfs, &root, self.reader, dir_part) else {
            return Ok(None);
        };
        let Ok(file) = find_entry(self.ntfs, &dir, self.reader, file_part) else {
            return Ok(None);
        };
        match read_file_data(&file, self.reader) {
            Ok(buf) => Ok(Some(buf)),
            Err(error) if error.is_resource_limit() => Err(error),
            Err(_) => Ok(None),
        }
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct FakeTree {
        files: HashMap<String, Vec<u8>>,
        dirs: HashMap<String, Vec<String>>,
    }
    impl FileTree for FakeTree {
        fn list_dir(&mut self, p: &str) -> Result<Vec<String>> {
            Ok(self.dirs.get(p).cloned().unwrap_or_default())
        }
        fn read_file(&mut self, p: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.files.get(p).cloned())
        }
    }

    #[test]
    fn discover_finds_chrome_default() {
        let mut dirs = HashMap::new();
        dirs.insert(r"Users".to_string(), vec!["alice".into(), "Public".into()]);
        dirs.insert(
            r"Users\alice\AppData\Local\Google\Chrome\User Data".into(),
            vec!["Default".into(), "Profile 1".into()],
        );
        let mut files = HashMap::new();
        files.insert(
            r"Users\alice\AppData\Local\Google\Chrome\User Data\Local State".into(),
            br#"{"os_crypt":{}}"#.to_vec(),
        );
        files.insert(
            r"Users\alice\AppData\Local\Google\Chrome\User Data\Default\Login Data".into(),
            b"SQLite format 3\x00".to_vec(),
        );
        let mut t = FakeTree { files, dirs };
        let found = discover_chromium(&mut t).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].profile.user, "alice");
        assert_eq!(found[0].profile.browser, Browser::Chrome);
        assert!(found[0].artifacts.login_data.is_some());
    }

    struct OversizedArtifact(&'static str);

    impl FileTree for OversizedArtifact {
        fn list_dir(&mut self, path: &str) -> Result<Vec<String>> {
            Ok(match path {
                "Users" => vec!["alice".into()],
                r"Users\alice\AppData\Local\Google\Chrome\User Data" => vec!["Default".into()],
                _ => Vec::new(),
            })
        }

        fn read_file(&mut self, path: &str) -> Result<Option<Vec<u8>>> {
            if path.ends_with(self.0) {
                let limit = crate::fs::ntfs::MAX_BUFFERED_BYTES;
                return Err(crate::error::VmkatzError::AllocTooLarge {
                    what: "test browser artifact",
                    requested: limit + 1,
                    limit,
                });
            }
            Ok(None)
        }
    }

    #[test]
    fn discovery_propagates_artifact_resource_limits() {
        for path in [
            r"User Data\Local State",
            r"Default\Login Data",
            r"Default\Login Data-wal",
            r"Default\Network\Cookies",
            r"Default\Network\Cookies-wal",
            r"Default\Cookies",
            r"Default\Cookies-wal",
            r"Default\Web Data",
            r"Default\Web Data-wal",
        ] {
            assert!(matches!(
                discover_chromium(&mut OversizedArtifact(path)),
                Err(crate::error::VmkatzError::AllocTooLarge { .. })
            ));
        }
    }
}
