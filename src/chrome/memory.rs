//! chrome.exe / msedge.exe / brave.exe in-memory secret scan.
//!
//! Per design doc section "Vector 1 — Memory":
//! - The network-service process holds cookies in network::CookieMonster
//! - The browser process holds the password manager's cached PasswordForm entries

use crate::chrome::types::ChromeFindings;
use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChromeRole {
    Browser,  // no --type=, holds password manager
    Network,  // --type=utility --utility-sub-type=network.mojom.NetworkService, holds cookies
    Other,    // renderer, gpu-process, etc. -> skip
}

#[derive(Debug, Clone)]
pub struct ChromeProc {
    pub pid: u32,
    pub image: String,           // "chrome.exe", "msedge.exe", ...
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
    matches!(lower.as_str(), "chrome.exe" | "msedge.exe" | "brave.exe" | "opera.exe" | "vivaldi.exe")
}

/// Memory-vector entrypoint stub. Implemented across Tasks 13-16; this returns empty for now.
pub fn extract_from_memory<L>(_layer: &L) -> Result<ChromeFindings> {
    Ok(ChromeFindings::default())
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
}
