//! In-process chromium memory scanner.
//!
//! Enumerates every chrome.exe / msedge.exe / brave.exe / vivaldi.exe /
//! opera.exe in a memory snapshot and walks each one's `net::CookieMonster`
//! instances directly out of process memory via the
//! [`crate::chrome::cookie_monster`] locator signature.
//!
//! ## Current state
//!
//! The full pipeline (region enumeration → pattern scan → tree walk →
//! variant-aware cookie decode) is wired and runs end-to-end. Validation
//! on a VMware Win10 snapshot with Edge 135 finds 8 `CookieMonster`
//! instances in the main browser process but every one reports
//! `size = 0` — the cookie maps are empty. ChromeKatz's own source notes
//! that the first instance "seems to always be empty" and one usually
//! has to walk multiple to find populated stores. The 152-byte signature
//! was derived against Chrome 124/130; Chrome 135's destructor / data
//! layout may have drifted enough that we're only matching the
//! always-empty internal instance. Per-Chrome-major-version pattern
//! tuning (and possibly a fresh chrome.dll RE pass) is the path to
//! real-data extraction.
//!
//! Pipeline:
//! 1. [`crate::paging::regions::enumerate_user_regions`] walks the process's
//!    page tables top-down and emits every mapped 4 KiB region in the
//!    canonical low half.
//! 2. For each region we re-patch the 152-byte
//!    [`cookie_monster::COOKIE_MONSTER_SIG`] with the high 4 bytes of that
//!    region's base address (`patch_module_high_half`), then scan the
//!    region buffer for matches. Every match is a candidate CookieMonster
//!    instance.
//! 3. From each instance address we read the [`cookie_monster::RbRoot`] at
//!    `instance + COOKIE_MAP_OFFSET` (0x30) and call
//!    [`cookie_monster::walk_cookie_tree`]; each leaf's `value_address`
//!    points at a `CanonicalCookie`.
//! 4. We try each [`cookie_monster::CookieVariant`] in turn (Chrome 130 ↔
//!    Edge 130, with and without `ProcessBoundString` value encryption,
//!    plus the legacy Chrome 124 layout) and keep the first decode whose
//!    fields all pass plausibility checks. The variant is per-process,
//!    not per-cookie, so the first matching choice sticks for the rest
//!    of that process's cookies.
//!
//! Findings are tagged `ChromeSource::Memory { pid, process }` and
//! merged into the same [`crate::chrome::types::ChromeFindings`] the
//! disk path produces.

use crate::chrome::cookie_monster::{
    patch_module_high_half, read_cookie, scan_for_cookie_monster, walk_cookie_tree,
    CookieVariant, COOKIE_MAP_OFFSET, COOKIE_MONSTER_SIG,
};
use crate::chrome::memory::is_chromium_image;
use crate::chrome::types::{
    Browser, BrowserProfile, ChromeFindings, ChromeSource, Cookie,
};
use crate::error::Result;
use crate::memory::{PhysicalMemory, VirtualMemory};
use crate::paging::regions::{enumerate_user_regions_filtered, RegionFilter};
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

/// Cap on `CookieMonster` instance hits we accept per process. Filtered
/// to writable user pages the signature is tight enough that real Edge /
/// Chrome processes produce on the order of 4-12 instances (per-profile,
/// per-incognito-window, per-partition). The cap is a safety net rather
/// than a working limit.
const MAX_INSTANCES_PER_PROCESS: usize = 256;

/// Cap on cookies decoded per `CookieMonster` instance. A real cookie
/// store rarely holds more than a few thousand entries; bound at 50k as
/// a safety net for corrupt tree traversal.
const MAX_COOKIES_PER_INSTANCE: usize = 50_000;

/// Try each `CookieVariant` against the candidate `CanonicalCookie*`
/// address; return the first one whose decoded fields look real.
const VARIANT_TRY_ORDER: &[CookieVariant] = &[
    CookieVariant::Chrome130,
    CookieVariant::Chrome130Pb,
    CookieVariant::Edge130,
    CookieVariant::Edge130Pb,
    CookieVariant::Chrome124,
];

/// Walk every chromium process in `processes`, locate every
/// `CookieMonster` instance via the locator signature, and harvest cookies
/// from the matching `std::map` red-black tree.
pub fn scan_chromium_processes<P: PhysicalMemory>(
    phys: &P,
    processes: &[Process],
) -> Result<ChromeFindings> {
    let mut findings = ChromeFindings::default();
    let mut total_processes = 0;
    let mut total_instances = 0;
    for proc in processes {
        if !is_chromium_image(&proc.name) {
            continue;
        }
        match harvest_process(phys, proc, &mut findings) {
            Ok(instances) => {
                if instances > 0 {
                    log::info!(
                        "[chrome-mem] PID {} {} — {} CookieMonster instance(s), {} cookies harvested so far",
                        proc.pid, proc.name, instances, findings.cookies.len()
                    );
                } else {
                    log::info!(
                        "[chrome-mem] PID {} {} — no CookieMonster instances found",
                        proc.pid, proc.name
                    );
                }
                total_instances += instances;
            }
            Err(e) => log::info!(
                "[chrome-mem] PID {} {} harvest failed: {}",
                proc.pid, proc.name, e
            ),
        }
        total_processes += 1;
    }
    log::info!(
        "[chrome-mem] scanned {} chromium process(es), located {} CookieMonster instance(s), {} cookies total",
        total_processes, total_instances, findings.cookies.len()
    );
    Ok(findings)
}

fn harvest_process<P: PhysicalMemory>(
    phys: &P,
    proc: &Process,
    out: &mut ChromeFindings,
) -> Result<usize> {
    // Writable user pages only — chrome.dll's text section and rodata
    // would otherwise produce thousands of pattern hits whose first
    // qword matches the chrome.dll high half (since the pattern's
    // patched bytes describe "any pointer pointing into the heap
    // region we're scanning"). The R/W bit filter is roughly the
    // page-table-side equivalent of VirtualQuery's `PAGE_READWRITE`.
    let regions = enumerate_user_regions_filtered(phys, proc.dtb, RegionFilter::WritableUser)?;
    let vmem = ProcessMemory::new(phys, proc.dtb);

    // First pass: locate CookieMonster instance addresses.
    let mut instances: Vec<u64> = Vec::new();
    let mut total_read: usize = 0;
    for region in regions {
        if total_read >= MAX_BYTES_PER_PROCESS || instances.len() >= MAX_INSTANCES_PER_PROCESS {
            break;
        }
        let take = (region.len as usize)
            .min(MAX_BYTES_PER_REGION)
            .min(MAX_BYTES_PER_PROCESS - total_read);
        if take < COOKIE_MONSTER_SIG.len() {
            continue;
        }
        let buf = match vmem.read_virt_bytes(region.start, take) {
            Ok(b) => b,
            Err(_) => continue,
        };
        total_read += buf.len();

        // Patch the signature with the high 4 bytes of THIS region's base.
        // The pattern requires pointer fields inside the candidate object
        // to point into the same memory region (which on x64 Windows
        // happens to share its high 4 bytes with chrome.dll's heap-side
        // allocations).
        let mut sig = COOKIE_MONSTER_SIG;
        patch_module_high_half(&mut sig, region.start);

        let mut hits = scan_for_cookie_monster(&buf, region.start, &sig);
        if hits.is_empty() {
            continue;
        }
        let remaining = MAX_INSTANCES_PER_PROCESS - instances.len();
        if hits.len() > remaining {
            hits.truncate(remaining);
        }
        instances.extend_from_slice(&hits);
    }

    if instances.is_empty() {
        return Ok(0);
    }

    // Second pass: for each instance, follow the cookie map and decode
    // every CanonicalCookie. We auto-detect the variant from the first
    // instance and reuse it for the rest of this process.
    let mut variant: Option<CookieVariant> = None;
    for instance_addr in &instances {
        let map_root = instance_addr + COOKIE_MAP_OFFSET;
        let begin_node = vmem.read_virt_u64(map_root).unwrap_or(0);
        let map_size = vmem.read_virt_u64(map_root + 16).unwrap_or(0);
        log::debug!(
            "[chrome-mem] PID {} instance=0x{:x} map_root=0x{:x} begin_node=0x{:x} size={}",
            proc.pid, instance_addr, map_root, begin_node, map_size
        );
        let v = match variant {
            Some(v) => v,
            None => match detect_variant(&vmem, map_root) {
                Some(v) => {
                    log::info!(
                        "[chrome-mem] PID {} {} — using variant {:?}",
                        proc.pid, proc.name, v
                    );
                    variant = Some(v);
                    v
                }
                None => {
                    log::debug!(
                        "[chrome-mem] PID {} instance=0x{:x} — no variant matched, skipping",
                        proc.pid, instance_addr
                    );
                    continue;
                }
            },
        };
        if let Err(e) = harvest_tree(&vmem, map_root, v, proc, out) {
            log::debug!(
                "[chrome-mem] PID {} {} — instance 0x{:x} tree walk error: {}",
                proc.pid, proc.name, instance_addr, e
            );
        }
    }
    Ok(instances.len())
}

/// Attempt every known [`CookieVariant`] on the first cookie under
/// `map_root`; return the first variant whose decoded fields all pass
/// the validity checks in [`cookie_looks_real`]. `None` means either
/// the tree was empty or unreadable, or no variant decoded a plausible
/// cookie.
fn detect_variant<V: VirtualMemory>(vmem: &V, map_root: u64) -> Option<CookieVariant> {
    let first_cookie = first_cookie_address(vmem, map_root)?;
    for v in VARIANT_TRY_ORDER {
        if let Ok(c) = read_cookie(vmem, first_cookie, *v) {
            if cookie_looks_real(&c) {
                return Some(*v);
            }
        }
    }
    None
}

/// Read the first cookie's `CanonicalCookie*` from the leftmost real
/// node of the `std::map` under `map_root`.
fn first_cookie_address<V: VirtualMemory>(vmem: &V, map_root: u64) -> Option<u64> {
    let begin_node = vmem.read_virt_u64(map_root).ok()?;
    if begin_node == 0 {
        return None;
    }
    // RbNode { left:8, right:8, parent:8, is_black:1, pad:7, key:24, value_address:8 }
    // value_address is at offset 56.
    let value_addr = vmem.read_virt_u64(begin_node + 56).ok()?;
    if value_addr == 0 {
        None
    } else {
        Some(value_addr)
    }
}

fn harvest_tree<V: VirtualMemory>(
    vmem: &V,
    map_root: u64,
    variant: CookieVariant,
    proc: &Process,
    out: &mut ChromeFindings,
) -> Result<()> {
    let mut count = 0usize;
    walk_cookie_tree(vmem, map_root, |value_addr| {
        if count >= MAX_COOKIES_PER_INSTANCE {
            return false;
        }
        match read_cookie(vmem, value_addr, variant) {
            Ok(c) if cookie_looks_real(&c) => {
                out.cookies.push(Cookie {
                    profile: memory_profile(proc.pid as u32, &proc.name),
                    host: c.domain,
                    name: c.name,
                    value: c.value,
                    path: c.path,
                    expires: None,
                    http_only: c.http_only,
                    secure: c.secure,
                    source: ChromeSource::Memory {
                        pid: proc.pid as u32,
                        process: proc.name.clone(),
                    },
                });
                count += 1;
                true
            }
            _ => false,
        }
    })?;
    Ok(())
}

/// Sanity-check that a decoded cookie's fields look like a real one.
/// Rejects entries where any field is empty, the domain has no dot, or
/// the name contains characters outside the RFC 6265 token set.
fn cookie_looks_real(c: &crate::chrome::cookie_monster::InProcessCookie) -> bool {
    if c.domain.is_empty() || c.name.is_empty() || c.value.is_empty() {
        return false;
    }
    if c.domain.len() > 256 || c.name.len() > 256 || c.value.len() > 8192 {
        return false;
    }
    if !c.domain.contains('.') {
        return false;
    }
    // Domain should be mostly ASCII; the heuristic-grade UTF-8 lossy
    // decode will produce replacement chars for binary noise.
    if c.domain.contains('\u{FFFD}') || c.name.contains('\u{FFFD}') {
        return false;
    }
    // Cookie names per RFC 6265 are token chars.
    if !c
        .name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b" !#$%&'*+-.^_`|~".contains(&b))
    {
        return false;
    }
    true
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
