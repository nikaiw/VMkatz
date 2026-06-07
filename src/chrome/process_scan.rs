//! In-process chromium memory scanner.
//!
//! Enumerates every chrome.exe / msedge.exe / brave.exe / vivaldi.exe /
//! opera.exe in a memory snapshot, walks the process's mapped userland
//! through the page-walk region enumerator, and reports per-process
//! statistics (PID, image name, resident memory size) so an analyst knows
//! a browser was active when the snapshot was taken.
//!
//! Earlier iterations of this scanner also ran the
//! [`crate::chrome::heuristic`] ASCII / UTF-16 pattern matchers on the
//! collected bytes and merged hits into the disk-side findings. Validation
//! showed the heuristic produces structurally-unreliable triples: chrome
//! process memory contains huge amounts of minified-JavaScript string
//! tables, embedded HTML, and chrome.dll auth-flow constants that look
//! syntactically identical to cookie or credential bytes once isolated
//! from their structural context. With no way to distinguish a real
//! `CanonicalCookie` instance from a string table entry that *happens* to
//! pair a domain with an alphanumeric token, every filter we tried either
//! still leaked thousands of false positives or rejected real cookies
//! too.
//!
//! The correct fix is the per-Chrome-version `CookieMonster` locator
//! signature ChromeKatz uses — pattern-match the destructor in chrome.dll,
//! resolve the vtable, scan the heap for objects with that vtable, then
//! walk the `std::map` red-black tree to read each `CanonicalCookie`. The
//! struct layouts that signature work produces are already in
//! [`crate::chrome::cookie_monster`]. Until that locator lands, this
//! module deliberately ships *no* heuristic memory cookie or password
//! extraction — emitting only a discovery list ("browser is running, this
//! is the PID and how much RAM it has touched") is more honest than
//! pretending to recover credentials from cell tower auth-flow noise.
//!
//! When the flag is set, the discovery summary is logged at info level
//! and an empty [`ChromeFindings`] is returned so the downstream merge
//! step doesn't grow false positives.

use crate::chrome::memory::is_chromium_image;
use crate::chrome::types::ChromeFindings;
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

/// Walk every chromium process in `processes`, read its mapped userland,
/// and emit one info-level log line per process describing what was
/// found. Returns an empty [`ChromeFindings`] because the heuristic
/// extractors were retired (see the module docstring). The function
/// remains as the host for the future signature-based locator: once
/// `cookie_monster.rs` has per-Chrome-version patterns wired in, real
/// cookie / password findings will be returned here.
pub fn scan_chromium_processes<P: PhysicalMemory>(
    phys: &P,
    processes: &[Process],
) -> Result<ChromeFindings> {
    let mut scanned = 0;
    for proc in processes {
        if !is_chromium_image(&proc.name) {
            continue;
        }
        let mib = match collect_process_memory(phys, proc.dtb) {
            Ok(b) => b.len() / 1024 / 1024,
            Err(e) => {
                log::info!(
                    "[chrome-mem] PID {} {} region scan failed: {}",
                    proc.pid,
                    proc.name,
                    e
                );
                continue;
            }
        };
        log::info!(
            "[chrome-mem] PID {} {} ({} MiB mapped userland) — \
             discovery only; structured CookieMonster walking is queued \
             behind per-Chrome-version locator signatures",
            proc.pid,
            proc.name,
            mib
        );
        scanned += 1;
    }
    log::info!(
        "[chrome-mem] discovered {} chromium process(es); no in-memory \
         cookies/passwords emitted (heuristic was structurally unreliable, \
         signature locator pending)",
        scanned
    );
    Ok(ChromeFindings::default())
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
