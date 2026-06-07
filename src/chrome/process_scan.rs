//! In-process scanner for chromium browser secrets.
//!
//! Enumerates every chrome.exe / msedge.exe / brave.exe process in a memory
//! snapshot, classifies each (browser vs network-service vs other), walks
//! that process's mapped userland pages via the page-table-based region
//! enumerator, and runs the existing heuristic password/cookie scanners
//! over the collected bytes.
//!
//! When this scan is enabled (hybrid mode with both `--disk` and a memory
//! snapshot), its findings are merged with the disk-side findings under a
//! single [`crate::chrome::types::ChromeFindings`]. Each result is tagged
//! `ChromeSource::Memory { pid, process }` so the source is visible in the
//! output renderers.
//!
//! Per-version `CanonicalCookie` struct decoding (`cookie_monster::read_cookie`)
//! is not yet driven here — locating CookieMonster instances precisely
//! requires per-Chrome-major-version byte signatures that are queued as a
//! follow-up. Today's scanner uses the existing
//! [`crate::chrome::heuristic`] ASCII / UTF-16 patterns which work across
//! versions but produce flatter cookie / password records.

use crate::chrome::heuristic::{scan_heap_for_cookies, scan_heap_for_passwords};
use crate::chrome::memory::is_chromium_image;
use crate::chrome::types::{
    Browser, BrowserProfile, ChromeFindings, ChromeSource, Cookie, SavedPassword,
};
use crate::error::Result;
use crate::memory::{PhysicalMemory, VirtualMemory};
use crate::paging::regions::enumerate_user_regions;
use crate::paging::translate::ProcessMemory;
use crate::windows::process::Process;

/// Cap on per-process bytes read into the scan buffer. Browser processes
/// commonly use a few hundred MB resident; 1 GiB is well above that and
/// prevents pathological dumps if the page tables are corrupt.
const MAX_BYTES_PER_PROCESS: usize = 1024 * 1024 * 1024;

/// Cap on per-region bytes read. A single page-table entry can claim up
/// to 1 GiB (huge page); we never want one bogus PDPT entry to swamp the
/// scan budget.
const MAX_BYTES_PER_REGION: usize = 64 * 1024 * 1024;

/// Run the in-process chromium scan across every chrome.exe / msedge.exe
/// / brave.exe / vivaldi.exe / opera.exe in `processes`. Reads each
/// process's mapped userland through `phys` + the process DTB and runs
/// both the password (`https://` UTF-16) and cookie (ASCII-domain) scans
/// on it.
///
/// We don't yet read process command lines, so every chromium process is
/// treated as if it could hold either kind of secret. In practice the
/// main browser process holds passwords and the network-service utility
/// holds cookies — scanning renderers is wasted work, but they don't
/// contain the patterns we look for so they yield zero false positives.
/// Per-role gating via PEB ProcessParameters → CommandLine is a follow-up.
pub fn scan_chromium_processes<P: PhysicalMemory>(
    phys: &P,
    processes: &[Process],
) -> Result<ChromeFindings> {
    let mut findings = ChromeFindings::default();
    let mut scanned = 0;
    for proc in processes {
        if !is_chromium_image(&proc.name) {
            continue;
        }
        let buf = match collect_process_memory(phys, proc.dtb) {
            Ok(b) => b,
            Err(e) => {
                log::info!(
                    "[chrome-mem] PID {} {} heap read failed: {}",
                    proc.pid, proc.name, e
                );
                continue;
            }
        };
        let mib = buf.len() / 1024 / 1024;
        let pw_before = findings.passwords.len();
        let cookie_before = findings.cookies.len();
        harvest(proc.pid as u32, &proc.name, &buf, &mut findings);
        log::info!(
            "[chrome-mem] PID {} {} ({} MiB): +{} passwords, +{} cookies",
            proc.pid,
            proc.name,
            mib,
            findings.passwords.len() - pw_before,
            findings.cookies.len() - cookie_before,
        );
        scanned += 1;
    }
    log::info!("[chrome-mem] scanned {} chromium processes", scanned);
    Ok(findings)
}

/// Collect every mapped userland page in a process's address space into a
/// single byte buffer suitable for pattern matching. Reads stop at
/// [`MAX_BYTES_PER_PROCESS`]; per-region reads are capped at
/// [`MAX_BYTES_PER_REGION`] to absorb runaway 1 GiB huge-page entries.
fn collect_process_memory<P: PhysicalMemory>(phys: &P, dtb: u64) -> Result<Vec<u8>> {
    let regions = enumerate_user_regions(phys, dtb)?;
    let vmem = ProcessMemory::new(phys, dtb);
    let mut out: Vec<u8> = Vec::new();
    for region in regions {
        if out.len() >= MAX_BYTES_PER_PROCESS {
            break;
        }
        let remaining_total = MAX_BYTES_PER_PROCESS - out.len();
        let take_len = (region.len as usize)
            .min(MAX_BYTES_PER_REGION)
            .min(remaining_total);
        if take_len == 0 {
            continue;
        }
        match vmem.read_virt_bytes(region.start, take_len) {
            Ok(bytes) => out.extend_from_slice(&bytes),
            Err(_) => {
                // Page reads can fail for swapped / unmapped subranges
                // inside a region; that's fine, skip to the next region.
                continue;
            }
        }
    }
    Ok(out)
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

fn harvest(pid: u32, image: &str, mem: &[u8], out: &mut ChromeFindings) {
    let profile = memory_profile(pid, image);
    let src = ChromeSource::Memory {
        pid,
        process: image.to_string(),
    };
    for t in scan_heap_for_passwords(mem) {
        out.passwords.push(SavedPassword {
            profile: profile.clone(),
            url: t.url,
            username: t.username,
            password: t.password,
            source: src.clone(),
        });
    }
    for c in scan_heap_for_cookies(mem) {
        out.cookies.push(Cookie {
            profile: profile.clone(),
            host: c.host,
            name: c.name,
            value: c.value,
            path: "/".into(),
            expires: None,
            http_only: false,
            secure: false,
            source: src.clone(),
        });
    }
}
