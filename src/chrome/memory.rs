//! chrome.exe / msedge.exe / brave.exe in-memory secret scan.

use crate::chrome::heuristic::{scan_heap_for_cookies, scan_heap_for_passwords};
use crate::chrome::types::{
    Browser, BrowserProfile, ChromeFindings, ChromeSource, Cookie, SavedPassword,
};
use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChromeRole {
    Browser,
    Network,
    Other,
}

#[derive(Debug, Clone)]
pub struct ChromeProc {
    pub pid: u32,
    pub image: String,
    pub role: ChromeRole,
}

pub fn classify_cmdline(cmdline: &str) -> ChromeRole {
    if cmdline.contains("--type=utility") && cmdline.contains("network.mojom.NetworkService") {
        return ChromeRole::Network;
    }
    if !cmdline.contains("--type=") {
        return ChromeRole::Browser;
    }
    ChromeRole::Other
}

pub fn is_chromium_image(image: &str) -> bool {
    let lower = image.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "chrome.exe" | "msedge.exe" | "brave.exe" | "opera.exe" | "vivaldi.exe"
    )
}

/// Abstracts the source of chromium-process memory. Implementations: live VAD-walk
/// (Task 19), test mocks. Keeps memory.rs decoupled from PhysicalMemory + page table
/// walkers.
pub trait ProcessSource {
    fn list_chromium_processes(&mut self) -> Result<Vec<ChromeProc>>;
    /// Returns the concatenated heap pages for the process. Implementations cap at a
    /// sane size (typical chrome.exe browser process has < 500 MiB resident).
    fn read_process_heap(&mut self, pid: u32) -> Result<Vec<u8>>;
}

fn browser_from_image(image: &str) -> Browser {
    let lower = image.to_ascii_lowercase();
    match lower.as_str() {
        "msedge.exe" => Browser::Edge,
        "brave.exe" => Browser::Brave,
        "opera.exe" => Browser::Opera,
        "vivaldi.exe" => Browser::Vivaldi,
        _ => Browser::Chrome,
    }
}

fn memory_profile(pid: u32, image: &str) -> BrowserProfile {
    BrowserProfile {
        browser: browser_from_image(image),
        user: String::new(),
        profile_name: String::new(),
        path: format!("memory:pid={}", pid),
    }
}

/// Walks chromium processes via the provided source, scans heap for credentials, returns
/// heuristic-recovered passwords + cookies tagged with `ChromeSource::Memory`.
pub fn extract_from_memory<S: ProcessSource>(source: &mut S) -> Result<ChromeFindings> {
    let mut out = ChromeFindings::default();
    let procs = source.list_chromium_processes()?;
    for p in procs {
        match p.role {
            ChromeRole::Browser => {
                let mem = match source.read_process_heap(p.pid) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                let profile = memory_profile(p.pid, &p.image);
                for t in scan_heap_for_passwords(&mem) {
                    out.passwords.push(SavedPassword {
                        profile: profile.clone(),
                        url: t.url,
                        username: t.username,
                        password: t.password,
                        source: ChromeSource::Memory { pid: p.pid, process: p.image.clone() },
                    });
                }
            }
            ChromeRole::Network => {
                let mem = match source.read_process_heap(p.pid) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                let profile = memory_profile(p.pid, &p.image);
                for c in scan_heap_for_cookies(&mem) {
                    out.cookies.push(Cookie {
                        profile: profile.clone(),
                        host: c.host,
                        name: c.name,
                        value: c.value,
                        path: "/".into(),
                        expires: None,
                        http_only: false,
                        secure: false,
                        source: ChromeSource::Memory { pid: p.pid, process: p.image.clone() },
                    });
                }
            }
            ChromeRole::Other => {}
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_browser_no_type() {
        assert_eq!(classify_cmdline("\"chrome.exe\" --foo"), ChromeRole::Browser);
    }

    #[test]
    fn classify_network() {
        assert_eq!(
            classify_cmdline("chrome.exe --type=utility --utility-sub-type=network.mojom.NetworkService --xx"),
            ChromeRole::Network
        );
    }

    #[test]
    fn classify_renderer() {
        assert_eq!(classify_cmdline("chrome.exe --type=renderer"), ChromeRole::Other);
    }

    #[test]
    fn image_filter() {
        assert!(is_chromium_image("chrome.exe"));
        assert!(is_chromium_image("MSEDGE.EXE"));
        assert!(!is_chromium_image("explorer.exe"));
    }

    struct FakeSource {
        procs: Vec<ChromeProc>,
        heaps: std::collections::HashMap<u32, Vec<u8>>,
    }

    impl ProcessSource for FakeSource {
        fn list_chromium_processes(&mut self) -> Result<Vec<ChromeProc>> {
            Ok(self.procs.clone())
        }
        fn read_process_heap(&mut self, pid: u32) -> Result<Vec<u8>> {
            Ok(self.heaps.get(&pid).cloned().unwrap_or_default())
        }
    }

    fn utf16(s: &str) -> Vec<u8> {
        let mut v = Vec::new();
        for u in s.encode_utf16() {
            v.extend_from_slice(&u.to_le_bytes());
        }
        v.extend_from_slice(&[0, 0]);
        v
    }

    #[test]
    fn memory_extract_finds_password_in_browser_process() {
        let mut heap = vec![0u8; 64];
        heap.extend(utf16("https://t.example/login"));
        heap.extend(vec![0u8; 16]);
        heap.extend(utf16("alice"));
        heap.extend(vec![0u8; 16]);
        heap.extend(utf16("S3cr3t!"));
        heap.extend(vec![0u8; 64]);
        let mut heaps = std::collections::HashMap::new();
        heaps.insert(4288u32, heap);
        let mut src = FakeSource {
            procs: vec![ChromeProc {
                pid: 4288,
                image: "chrome.exe".into(),
                role: ChromeRole::Browser,
            }],
            heaps,
        };
        let f = extract_from_memory(&mut src).unwrap();
        assert_eq!(f.passwords.len(), 1);
        assert_eq!(f.passwords[0].url, "https://t.example/login");
        assert_eq!(f.passwords[0].username, "alice");
        assert_eq!(f.passwords[0].password, "S3cr3t!");
        match &f.passwords[0].source {
            ChromeSource::Memory { pid, process } => {
                assert_eq!(*pid, 4288);
                assert_eq!(process, "chrome.exe");
            }
            _ => panic!("expected Memory source"),
        }
    }

    #[test]
    fn memory_extract_finds_cookie_in_network_process() {
        let mut heap = vec![0u8; 16];
        heap.extend_from_slice(b".t.com\0");
        heap.extend_from_slice(b"SESSION\0");
        heap.extend_from_slice(b"AbCdEf012345\0");
        heap.extend(vec![0u8; 16]);
        let mut heaps = std::collections::HashMap::new();
        heaps.insert(4290u32, heap);
        let mut src = FakeSource {
            procs: vec![ChromeProc {
                pid: 4290,
                image: "chrome.exe".into(),
                role: ChromeRole::Network,
            }],
            heaps,
        };
        let f = extract_from_memory(&mut src).unwrap();
        assert_eq!(f.cookies.len(), 1);
        assert_eq!(f.cookies[0].host, ".t.com");
        assert_eq!(f.cookies[0].name, "SESSION");
    }
}
