//! Reconstruct registry hives (SAM / SYSTEM / SECURITY) from a guest physical
//! memory image and extract on-disk credentials from them.
//!
//! Why this exists: Credential Guard isolates the in-memory LSA logon-secret cache
//! (NTLM hashes, Kerberos keys) in VTL1, so they can't be read from the normal
//! LSASS process memory. But the registry SAM database is NOT Cred-Guard-protected,
//! and the hives live in kernel memory. Reconstructing them from RAM yields local
//! NT hashes (and LSA secrets) even on a Credential Guard machine, without the disk.
//!
//! Reconstruction: a loaded hive mirrors the on-disk `regf` format (a 4 KB base
//! block followed by `hbin` cell bins), but the Configuration Manager scatters the
//! bins across paged pool — they are NOT contiguous, in physical OR in a single
//! virtual view we can find without the CM cell map. Every `hbin` header records
//! its own hive-file offset and size, so a scan of physical memory locates all
//! bins and indexes them by the offsets they cover ([`RunIndex`]).
//!
//! The parser navigates a hive purely by cell offset from the root, so we don't
//! need a contiguous image — only the cells actually reached from the root, placed
//! at their recorded offsets in a zero-filled buffer. `walk_children` walks the
//! tree from a base block's root, resolving each cell against the bins covering its
//! offset; several stale copies of a hive share the offset space, so the physically
//! nearest candidate to the parent is chosen to keep the walk within one copy, and
//! each copy is scored by real extraction so the freshest wins.
//!
//! The bootkey is instead read by locating the SYSTEM `Control\Lsa` NK cell
//! physically and reading its `JD`/`Skew1`/`GBG`/`Data` class names by proximity:
//! the SYSTEM hive is too large and multi-copy for whole-hive reassembly to
//! disambiguate its deep bootkey path. No kernel struct offsets or page tables are
//! required for any of this.


use std::collections::HashMap;

use crate::memory::PhysicalMemory;
use crate::sam::SamEntry;
use crate::sam::hashes::extract_hashes;
use crate::sam::lsa::{LsaSecret, LsaSecretType, extract_lsa_secrets};

const PAGE: u64 = 0x1000;
const BASE_BLOCK: u64 = 0x1000;
const MAX_HIVE: u64 = 512 * 1024 * 1024;
const MAX_BIN: u64 = 16 * 1024 * 1024;
/// The registry hives we care about, matched against the base block's file name.
const WANTED: [&str; 3] = ["SAM", "SYSTEM", "SECURITY"];

/// A physically-located NK cell: its head bytes (payload) and its GPA.
type NkAnchor = (Vec<u8>, u64);
/// Child (offset, name-hash) entries decoded from a subkey-list cell.
type SubkeyEntries = Vec<(u32, SkHash)>;

/// A located hive base block in physical (GPA) space.
struct HiveLoc {
    name: String,
    gpa: u64,
    length: u64,
    sequence_ok: bool,
}

/// An `hbin` cell-bin block found in physical memory.
#[derive(Clone, Copy)]
struct Hbin {
    gpa: u64,
    file_offset: u64,
    size: u64,
}

/// A maximal run of `hbin` bins that are contiguous BOTH physically and in
/// hive-file offset — i.e. one allocation the Configuration Manager wrote in order.
/// Runs are large, distinctive units, so chaining them by offset is far less
/// ambiguous than picking individual bins (which collide across hives).
struct Run {
    start_gpa: u64,
    start_off: u64,
    total: u64,
}

/// Credentials recovered from in-memory registry hives.
#[derive(Default)]
pub struct MemoryHiveCreds {
    pub bootkey: Option<[u8; 16]>,
    pub sam_hashes: Vec<SamEntry>,
    pub lsa_secrets: Vec<LsaSecret>,
}

/// Scan guest physical memory once for both hive base blocks ("regf") and cell
/// bins ("hbin"), which are page-aligned. Returns the wanted base blocks and a
/// map of hive-file-offset -> candidate bins.
fn scan_memory(phys: &impl PhysicalMemory) -> (Vec<HiveLoc>, Vec<Hbin>, Vec<NkAnchor>) {
    // SIMD search for the "Lsa" key name; the NK header sits 0x4C bytes before it.
    let finder = memchr::memmem::Finder::new(b"Lsa");
    let locs = std::sync::Mutex::new(Vec::new());
    let bins = std::sync::Mutex::new(Vec::new());
    let lsa = std::sync::Mutex::new(Vec::new());
    let collect = |gpa: u64, buf: &[u8]| -> bool {
        let (l, b, a) = scan_chunk(buf, gpa, &finder);
        let has_bins = !b.is_empty();
        if !l.is_empty() {
            locs.lock().unwrap().extend(l);
        }
        if has_bins {
            bins.lock().unwrap().extend(b);
        }
        if !a.is_empty() {
            lsa.lock().unwrap().extend(a);
        }
        // Keep blocks that hold hive bins cached: reassembly re-reads exactly these.
        has_bins
    };

    // Prefer the layer's parallel sweep (VMRS decompresses each block on its own
    // core); fall back to a sequential 1 MB read sweep for flat/mmap layers.
    if !phys.par_scan(&collect) {
        let ps = phys.phys_size();
        let mut buf = vec![0u8; 1024 * 1024];
        let mut base = 0u64;
        while base < ps {
            let n = ((ps - base) as usize).min(buf.len());
            if phys.read_phys(base, &mut buf[..n]).is_ok() {
                collect(base, &buf[..n]);
            }
            base += buf.len() as u64;
        }
    }

    let mut locs = locs.into_inner().unwrap();
    let bins = bins.into_inner().unwrap();
    let mut lsa = lsa.into_inner().unwrap();
    lsa.truncate(256);
    locs.sort_by_key(|h| !h.sequence_ok); // clean copies first
    (locs, bins, lsa)
}

/// Scan one memory chunk starting at guest physical `base_gpa` for hive base
/// blocks (`regf`), cell bins (`hbin`, page-aligned) and Control\Lsa NK anchor
/// cells. Pure over `buf`, so it runs on the sequential sweep or on a worker
/// thread of a parallel [`PhysicalMemory::par_scan`] alike.
fn scan_chunk(
    buf: &[u8],
    base_gpa: u64,
    finder: &memchr::memmem::Finder,
) -> (Vec<HiveLoc>, Vec<Hbin>, Vec<NkAnchor>) {
    let n = buf.len();
    let mut locs = Vec::new();
    let mut bins = Vec::new();
    let mut lsa = Vec::new();

    // Control\Lsa NK cells (name "Lsa", 0x4C bytes past the "nk" header) with a
    // sane subkey count and a subkey list (excludes leaf "Lsa" keys).
    for p in finder.find_iter(buf) {
        let Some(j) = p.checked_sub(0x4C) else { continue };
        if j + 0x80 > n
            || &buf[j..j + 2] != b"nk"
            || u16::from_le_bytes([buf[j + 0x48], buf[j + 0x49]]) != 3
        {
            continue;
        }
        let subs = u32::from_le_bytes(buf[j + 0x14..j + 0x18].try_into().unwrap());
        let list = u32::from_le_bytes(buf[j + 0x1C..j + 0x20].try_into().unwrap());
        if (4..=64).contains(&subs) && list != 0xFFFF_FFFF {
            lsa.push((buf[j..j + 0x80].to_vec(), base_gpa + j as u64));
        }
    }

    let mut off = 0usize;
    while off + 0x20 <= n {
        let gpa = base_gpa + off as u64;
        match &buf[off..off + 4] {
            b"regf" => {
                let seq1 = u32::from_le_bytes(buf[off + 4..off + 8].try_into().unwrap());
                let seq2 = u32::from_le_bytes(buf[off + 8..off + 12].try_into().unwrap());
                let length = u64::from(u32::from_le_bytes(
                    buf[off + 0x28..off + 0x2c].try_into().unwrap(),
                ));
                if off + 0x30 + 64 <= n && (BASE_BLOCK..=MAX_HIVE).contains(&(length + BASE_BLOCK)) {
                    let name: String = buf[off + 0x30..off + 0x30 + 64]
                        .chunks(2)
                        .map(|c| u16::from_le_bytes([c[0], *c.get(1).unwrap_or(&0)]))
                        .take_while(|&u| u != 0)
                        .filter_map(|u| char::from_u32(u32::from(u)))
                        .collect();
                    let basename = name.rsplit(['\\', '/']).next().unwrap_or("");
                    if WANTED.iter().any(|w| basename.eq_ignore_ascii_case(w)) {
                        locs.push(HiveLoc {
                            name: basename.to_ascii_uppercase(),
                            gpa,
                            length,
                            sequence_ok: seq1 == seq2,
                        });
                    }
                }
            }
            b"hbin" => {
                let file_offset =
                    u64::from(u32::from_le_bytes(buf[off + 4..off + 8].try_into().unwrap()));
                let size = u64::from(u32::from_le_bytes(buf[off + 8..off + 12].try_into().unwrap()));
                if (PAGE..=MAX_BIN).contains(&size)
                    && size.is_multiple_of(PAGE)
                    && file_offset.is_multiple_of(PAGE)
                    && file_offset < MAX_HIVE
                {
                    bins.push(Hbin {
                        gpa,
                        file_offset,
                        size,
                    });
                }
            }
            _ => {}
        }
        off += PAGE as usize; // regf/hbin blocks are page-aligned
    }
    (locs, bins, lsa)
}

/// Coalesce bins into runs contiguous in both physical address and hive offset.
fn build_runs(mut bins: Vec<Hbin>) -> Vec<Run> {
    bins.sort_by_key(|b| b.gpa);
    let mut runs = Vec::new();
    let mut i = 0usize;
    while i < bins.len() {
        let start = bins[i];
        let mut end_gpa = start.gpa + start.size;
        let mut end_off = start.file_offset + start.size;
        let mut j = i + 1;
        while j < bins.len()
            && bins[j].gpa == end_gpa
            && bins[j].file_offset == end_off
        {
            end_gpa += bins[j].size;
            end_off += bins[j].size;
            j += 1;
        }
        runs.push(Run {
            start_gpa: start.gpa,
            start_off: start.file_offset,
            total: end_gpa - start.gpa,
        });
        i = j;
    }
    runs
}

/// Runs plus a page → covering-run-indices index, so a cell's covering runs are
/// found in O(1) instead of scanning every run (there can be tens of thousands).
struct RunIndex {
    runs: Vec<Run>,
    by_page: HashMap<u64, Vec<usize>>,
}

impl RunIndex {
    fn new(runs: Vec<Run>) -> Self {
        let mut by_page: HashMap<u64, Vec<usize>> = HashMap::new();
        for (i, r) in runs.iter().enumerate() {
            let first = r.start_off >> 12;
            let last = (r.start_off + r.total - 1) >> 12;
            for p in first..=last {
                by_page.entry(p).or_default().push(i);
            }
        }
        Self { runs, by_page }
    }

    const fn len(&self) -> usize {
        self.runs.len()
    }

    /// Runs that cover hive offset `off`.
    fn covering(&self, off: u64) -> impl Iterator<Item = &Run> {
        self.by_page
            .get(&(off >> 12))
            .into_iter()
            .flatten()
            .map(move |&i| &self.runs[i])
            .filter(move |r| off >= r.start_off && off < r.start_off + r.total)
    }
}

/// Place the cell at hive-offset `off` into `buf`, choosing among the runs that
/// cover it. When `want` sigs are given, only a cell starting with one is accepted
/// (this disambiguates the structural backbone — nk / lf / lh / li / ri / vk —
/// across the several hive copies in memory); otherwise the run physically nearest
/// `anchor` wins. Returns the cell payload (after the size prefix) and the chosen
/// run's start GPA (used as the anchor for its children).
fn place_cell(
    phys: &impl PhysicalMemory,
    ix: &RunIndex,
    buf: &mut [u8],
    off: u64,
    want: &[&[u8]],
    anchor: u64,
) -> Option<(Vec<u8>, u64)> {
    let mut best: Option<(u64, Vec<u8>, u64)> = None; // (dist, cell bytes, run gpa)
    for run in ix.covering(off) {
        let poff = off - run.start_off;
        let addr = run.start_gpa + poff;
        let Ok(szb) = phys.read_phys_bytes(addr, 4) else {
            continue;
        };
        let abs = u64::from(i32::from_le_bytes(szb.try_into().unwrap()).unsigned_abs());
        if !(8..=0x10000).contains(&abs) || poff + abs > run.total {
            continue;
        }
        let Ok(cell) = phys.read_phys_bytes(addr, abs as usize) else {
            continue;
        };
        if !want.is_empty() && !want.iter().any(|w| cell.len() >= 4 + w.len() && &cell[4..4 + w.len()] == *w) {
            continue;
        }
        let dist = run.start_gpa.abs_diff(anchor);
        if best.as_ref().is_none_or(|(d, _, _)| dist < *d) {
            best = Some((dist, cell, run.start_gpa));
        }
    }
    let (_, cell, gpa) = best?;
    let dst = (BASE_BLOCK + off) as usize;
    if dst + cell.len() <= buf.len() {
        buf[dst..dst + cell.len()].copy_from_slice(&cell);
    }
    Some((cell[4..].to_vec(), gpa))
}

/// Place the NK cell at `off` whose name matches `hk` (disambiguating identically-
/// offset NK cells from other hive copies), writing it into `buf`.
fn place_nk(
    phys: &impl PhysicalMemory,
    ix: &RunIndex,
    buf: &mut [u8],
    off: u64,
    hk: SkHash,
    anchor: u64,
) -> Option<(Vec<u8>, u64)> {
    let mut best: Option<(u64, Vec<u8>, u64)> = None;
    for run in ix.covering(off) {
        let poff = off - run.start_off;
        let addr = run.start_gpa + poff;
        let Ok(szb) = phys.read_phys_bytes(addr, 4) else {
            continue;
        };
        let abs = u64::from(i32::from_le_bytes(szb.try_into().unwrap()).unsigned_abs());
        if !(0x50..=0x10000).contains(&abs) || poff + abs > run.total {
            continue;
        }
        let Ok(cell) = phys.read_phys_bytes(addr, abs as usize) else {
            continue;
        };
        if &cell[4..6] != b"nk" || !nk_matches(&cell[4..], hk) {
            continue;
        }
        let dist = run.start_gpa.abs_diff(anchor);
        if best.as_ref().is_none_or(|(d, _, _)| dist < *d) {
            best = Some((dist, cell, run.start_gpa));
        }
    }
    let (_, cell, gpa) = best?;
    let dst = (BASE_BLOCK + off) as usize;
    if dst + cell.len() <= buf.len() {
        buf[dst..dst + cell.len()].copy_from_slice(&cell);
    }
    Some((cell[4..].to_vec(), gpa))
}

/// Recursively walk a key's subtree, placing every reachable cell into `buf`.
/// NK children are disambiguated by the subkey-list name hash; the structural
/// backbone by signature; leaf data by proximity. Only visited cells are filled,
/// which is all the SAM/SECURITY parsers need.
fn walk_key(
    phys: &impl PhysicalMemory,
    runs: &RunIndex,
    buf: &mut [u8],
    off: u64,
    hk: SkHash,
    anchor: u64,
    visited: &mut std::collections::HashSet<u64>,
) {
    if !visited.insert(off) || visited.len() > 200_000 {
        return;
    }
    let Some((nk, run_gpa)) = place_nk(phys, runs, buf, off, hk, anchor) else {
        return;
    };
    walk_children(phys, runs, buf, &nk, run_gpa, visited);
}

/// Place the values, class and subkeys of an already-placed NK cell.
fn walk_children(
    phys: &impl PhysicalMemory,
    runs: &RunIndex,
    buf: &mut [u8],
    nk: &[u8],
    run_gpa: u64,
    visited: &mut std::collections::HashSet<u64>,
) {
    if nk.len() < 0x50 {
        return;
    }
    // Values: a VK-offset array (no signature). Among candidate arrays at this
    // offset choose the one physically NEAREST the parent (same hive copy) that is
    // large enough and whose entries resolve to "vk" cells, then place it and each
    // VK's data. Proximity keeps the whole subtree within one consistent copy.
    let vcount = u32_at(nk, 0x24) as usize;
    let vlist_off = u32_at(nk, 0x28);
    if vcount > 0 && vcount < 0x10000 && vlist_off != 0xFFFF_FFFF {
        let want = vcount * 4;
        let best = cells_with_gpa(phys, runs, u64::from(vlist_off))
            .into_iter()
            .filter(|(c, _)| c.len() >= want)
            .filter(|(c, _)| {
                (0..vcount).any(|i| {
                    let vk = u32_at(c, i * 4);
                    vk != 0xFFFF_FFFF
                        && cells_with_gpa(phys, runs, u64::from(vk))
                            .iter()
                            .any(|(d, _)| d.len() >= 2 && &d[0..2] == b"vk")
                })
            })
            .min_by_key(|(_, g)| g.abs_diff(run_gpa))
            .map(|(c, _)| c);
        if let Some(vlist) = best {
            let dst = (BASE_BLOCK + u64::from(vlist_off)) as usize;
            let cell_len = (4 + vlist.len()) as i32;
            if dst + 4 + vlist.len() <= buf.len() {
                buf[dst..dst + 4].copy_from_slice(&(-cell_len).to_le_bytes());
                buf[dst + 4..dst + 4 + vlist.len()].copy_from_slice(&vlist);
            }
            for i in 0..vcount {
                let vk_off = u32_at(&vlist, i * 4);
                if vk_off == 0xFFFF_FFFF {
                    continue;
                }
                if let Some((vk, vk_gpa)) =
                    place_cell(phys, runs, buf, u64::from(vk_off), &[b"vk"], run_gpa)
                {
                    let dsize = u32_at(&vk, 0x04);
                    let doff = u32_at(&vk, 0x08);
                    if dsize & 0x8000_0000 == 0 && dsize > 0 && doff != 0xFFFF_FFFF {
                        place_cell(phys, runs, buf, u64::from(doff), &[], vk_gpa);
                    }
                }
            }
        }
    }
    // Class name cell (holds bootkey nibbles for Lsa subkeys).
    let class_off = u32_at(nk, 0x30);
    if class_off != 0xFFFF_FFFF {
        place_cell(phys, runs, buf, u64::from(class_off), &[], run_gpa);
    }
    // Subkeys. The subkey-list cell has no name to disambiguate copies, so among the
    // candidate list cells (that resolve to at least one name-matched child NK)
    // choose the one physically NEAREST the parent, then place it and recurse.
    let scount = u32_at(nk, 0x14);
    let slist_off = u32_at(nk, 0x1C);
    if scount > 0 && slist_off != 0xFFFF_FFFF {
        let mut best: Option<(u64, Vec<u8>, SubkeyEntries)> = None; // (dist, list, entries)
        for (list, lgpa) in cells_with_gpa(phys, runs, u64::from(slist_off)) {
            if list.len() < 4 || !matches!(&list[0..2], b"lf" | b"lh" | b"li" | b"ri") {
                continue;
            }
            let entries = subkey_list_entries(phys, runs, &list, 0);
            let score = entries
                .iter()
                .filter(|(off, hk)| {
                    cells_with_gpa(phys, runs, u64::from(*off))
                        .iter()
                        .any(|(c, _)| c.len() >= 0x50 && &c[0..2] == b"nk" && nk_matches(c, *hk))
                })
                .count();
            if score == 0 {
                continue;
            }
            let dist = lgpa.abs_diff(run_gpa);
            if best.as_ref().is_none_or(|(d, _, _)| dist < *d) {
                best = Some((dist, list, entries));
            }
        }
        if let Some((_, list, entries)) = best {
            let dst = (BASE_BLOCK + u64::from(slist_off)) as usize;
            let cell_len = (4 + list.len()) as i32;
            if dst + 4 + list.len() <= buf.len() {
                buf[dst..dst + 4].copy_from_slice(&(-cell_len).to_le_bytes());
                buf[dst + 4..dst + 4 + list.len()].copy_from_slice(&list);
            }
            for (child, chash) in entries {
                walk_key(phys, runs, buf, u64::from(child), chash, run_gpa, visited);
            }
        }
    }
}

/// Recover only the bootkey from physical memory (no page tables needed).
///
/// Scans for hive bins + the `Control\Lsa` NK cell and reads its `JD/Skew1/GBG/Data`
/// class-name nibbles by physical proximity. More robust than reading a mapped SYSTEM
/// hive whose bins may be paged out, so the CM hive-map walk falls back to this.
pub fn recover_bootkey(phys: &impl PhysicalMemory) -> Option<[u8; 16]> {
    let (locs, bins, lsa_cands) = scan_memory(phys);
    if locs.is_empty() {
        return None;
    }
    let runs = RunIndex::new(build_runs(bins));
    guided_bootkey(phys, &runs, &lsa_cands)
}

/// Reconstruct SAM/SYSTEM/SECURITY hives from memory and extract credentials.
/// Requires no page tables or kernel symbols — purely physical.
pub fn extract_from_memory(phys: &impl PhysicalMemory) -> MemoryHiveCreds {
    let mut creds = MemoryHiveCreds::default();
    let (locs, bins, lsa_cands) = scan_memory(phys);
    if locs.is_empty() {
        log::debug!("mem_hive: no SAM/SYSTEM/SECURITY base blocks in memory");
        return creds;
    }
    let n_bins = bins.len();
    let runs = RunIndex::new(build_runs(bins));
    log::info!(
        "mem_hive: {} base block(s), {n_bins} bins in {} runs, {} Lsa cand(s)",
        locs.len(),
        runs.len(),
        lsa_cands.len()
    );

    // Bootkey: anchor on a physically-located Control\Lsa NK cell and read its
    // JD/Skew1/GBG/Data class names by proximity. This is robust to the many stale
    // SYSTEM copies, whose per-copy hive offsets make root-down navigation land on
    // uncaptured bins.
    let Some(bk) = guided_bootkey(phys, &runs, &lsa_cands) else {
        log::debug!("mem_hive: could not recover bootkey from SYSTEM in memory");
        return creds;
    };
    creds.bootkey = Some(bk);
    log::info!("mem_hive: recovered bootkey from memory");

    // SAM and SECURITY: reassemble from each base-block copy's root and keep the
    // reassembly yielding the most records. Copies differ (transaction logs, stale
    // snapshots); only the freshest complete copy holds every SAM user, so the
    // highest-scoring reassembly — not the first that parses — is kept.
    let sam_roots = root_candidates(phys, &runs, &locs, "SAM", "SAM");
    if let Some((buf, n)) = best_reassembly(phys, &runs, &sam_roots, hive_total(&locs, "SAM"), |b| {
        extract_hashes(b, &bk).map_or(0, |h| h.len())
    }) {
        if let Ok(h) = extract_hashes(&buf, &bk) {
            log::info!("mem_hive: extracted {} SAM account(s) (score {n})", h.len());
            creds.sam_hashes = h;
        }
    }
    // SECURITY: score reassemblies by LSA-secret CORRECTNESS, not just count.
    // Several stale/partial SECURITY copies share the bin pool; a reassembly that
    // mixes cells across copies decrypts every secret with a wrong LSA key, yielding
    // the right-length-but-garbage output that used to be printed as mojibake.
    // `lsa_reassembly_score` rejects those (DPAPI_SYSTEM is a shared-key anchor), and
    // the final gate drops the result rather than emit garbage when no copy verifies
    // (e.g. a partial memory dump that doesn't contain a consistent SECURITY hive).
    let sec_roots = root_candidates(phys, &runs, &locs, "SECURITY", "Policy");
    if let Some((buf, _)) = best_reassembly(phys, &runs, &sec_roots, hive_total(&locs, "SECURITY"), |b| {
        lsa_reassembly_score(&extract_lsa_secrets(b, &bk).unwrap_or_default())
    }) {
        if let Ok(s) = extract_lsa_secrets(&buf, &bk) {
            if lsa_secrets_verified(&s) {
                log::info!("mem_hive: extracted {} LSA secret(s)", s.len());
                creds.lsa_secrets = s;
            } else {
                log::info!(
                    "mem_hive: SECURITY reassembly failed the DPAPI_SYSTEM validity check \
                     (stale/partial copy) — not reporting garbage LSA secrets"
                );
            }
        }
    }
    creds
}

/// DPAPI_SYSTEM always decrypts to 44 bytes whose first dword (version) is 1. All
/// LSA secrets share one LSA key, so a wrong key (from a mixed/stale SECURITY
/// reassembly) corrupts DPAPI_SYSTEM too — making it a reliable correctness anchor.
/// Returns `None` when no DPAPI_SYSTEM secret is present (can't judge).
fn dpapi_system_valid(secrets: &[LsaSecret]) -> Option<bool> {
    secrets.iter().find_map(|s| match &s.parsed {
        LsaSecretType::DpapiSystem { .. } => Some(
            s.raw_data.len() == 44
                && u32::from_le_bytes(s.raw_data[0..4].try_into().unwrap()) == 1,
        ),
        _ => None,
    })
}

/// Score a SECURITY reassembly by LSA-secret correctness. A DPAPI_SYSTEM that
/// fails the version check means the LSA key is wrong → reject (score 0). A valid
/// DPAPI_SYSTEM strongly outranks a copy without one.
fn lsa_reassembly_score(secrets: &[LsaSecret]) -> usize {
    match dpapi_system_valid(secrets) {
        Some(false) => 0,
        Some(true) => 1000 + secrets.len(),
        None => secrets.len(),
    }
}

/// Accept a SECURITY reassembly's secrets only if it has some and its DPAPI_SYSTEM
/// (when present) verifies — i.e. never surface garbage decrypted with a wrong key.
fn lsa_secrets_verified(secrets: &[LsaSecret]) -> bool {
    !secrets.is_empty() && dpapi_system_valid(secrets) != Some(false)
}

/// The root NK cells of every base block matching `hive`, as (root offset, root
/// cell, root GPA) — one per copy resident in memory. Deduplicated by (offset, GPA).
/// A base block's root offset (~0x20) collides with the root of every other hive
/// copy in the bin pool, so only roots that actually have the expected top-level
/// child (`top_child`: "SAM" or "Policy") are kept — a cheap one-level probe that
/// prunes the dozens of unrelated roots before the expensive whole-tree walk.
fn root_candidates(
    phys: &impl PhysicalMemory,
    runs: &RunIndex,
    locs: &[HiveLoc],
    hive: &str,
    top_child: &str,
) -> Vec<(u64, Vec<u8>, u64)> {
    let mut out: Vec<(u64, Vec<u8>, u64)> = Vec::new();
    let mut seen: std::collections::HashSet<(u64, u64)> = std::collections::HashSet::new();
    let mut add = |off: u64, cell: Vec<u8>, gpa: u64| {
        if cell.len() >= 0x50 - 4
            && &cell[0..2] == b"nk"
            && root_has_child(phys, runs, &cell, top_child)
            && seen.insert((off, gpa))
        {
            out.push((off, cell, gpa));
        }
    };
    for loc in locs.iter().filter(|l| hive_key(&l.name) == hive) {
        if let Ok(head) = phys.read_phys_bytes(loc.gpa, BASE_BLOCK as usize) {
            let root_off = u64::from(u32_at(&head, 0x24));
            for (cell, gpa) in cells_with_gpa(phys, runs, root_off) {
                add(root_off, cell, gpa);
            }
        }
    }
    out
}

/// Cheap one-level probe: does `root`'s subkey list resolve to at least one child
/// NK named `name` (in any resident copy)? Used to reject unrelated hive roots
/// before the expensive whole-tree reassembly walk.
fn root_has_child(phys: &impl PhysicalMemory, runs: &RunIndex, root: &[u8], name: &str) -> bool {
    if root.len() < 0x50 || &root[0..2] != b"nk" {
        return false;
    }
    let list_off = u32_at(root, 0x1C);
    if list_off == 0xFFFF_FFFF {
        return false;
    }
    for (list, _) in cells_with_gpa(phys, runs, u64::from(list_off)) {
        if !matches!(list.get(0..2), Some(b"lf" | b"lh" | b"li" | b"ri")) {
            continue;
        }
        for (coff, _) in subkey_list_entries(phys, runs, &list, 0) {
            if cells_with_gpa(phys, runs, u64::from(coff)).iter().any(|(c, _)| {
                c.len() >= 0x50 && &c[0..2] == b"nk" && nk_name(c).eq_ignore_ascii_case(name)
            }) {
                return true;
            }
        }
    }
    false
}

/// Buffer size for reassembling a hive: the largest matching base-block length,
/// floored to a sane minimum.
fn hive_total(locs: &[HiveLoc], hive: &str) -> usize {
    let len = locs
        .iter()
        .filter(|l| hive_key(&l.name) == hive)
        .map(|l| l.length)
        .max()
        .unwrap_or(0x40_0000)
        .max(0x2_0000);
    (BASE_BLOCK + len) as usize
}


/// Reassemble the hive from each candidate root and return the buffer with the
/// highest `score` (0 = unusable).
fn best_reassembly<S: Fn(&[u8]) -> usize>(
    phys: &impl PhysicalMemory,
    runs: &RunIndex,
    roots: &[(u64, Vec<u8>, u64)],
    total: usize,
    score: S,
) -> Option<(Vec<u8>, usize)> {
    let mut best: Option<(Vec<u8>, usize)> = None;
    for (root_off, root_cell, root_gpa) in roots {
        let dst = (BASE_BLOCK + root_off) as usize;
        if dst + 4 + root_cell.len() > total {
            continue;
        }
        let mut buf = vec![0u8; total];
        // Synthetic base block: the hive parser only reads the "regf" magic and the
        // root cell offset at 0x24, so a copied real base block is not needed.
        buf[0..4].copy_from_slice(b"regf");
        buf[0x24..0x28].copy_from_slice(&(*root_off as u32).to_le_bytes());
        let cell_len = (4 + root_cell.len()) as i32;
        buf[dst..dst + 4].copy_from_slice(&(-cell_len).to_le_bytes());
        buf[dst + 4..dst + 4 + root_cell.len()].copy_from_slice(root_cell);
        let mut visited = std::collections::HashSet::new();
        visited.insert(*root_off);
        walk_children(phys, runs, &mut buf, root_cell, *root_gpa, &mut visited);
        let s = score(&buf);
        if s > 0 && best.as_ref().is_none_or(|(_, bs)| s > *bs) {
            best = Some((buf, s));
        }
    }
    best
}

// --- Guided bootkey navigation ---------------------------------------------
//
// The SYSTEM hive is large and several copies (plus transaction logs) share the
// bin pool, so root-down navigation lands on bins from the wrong copy (each copy
// stores the bootkey path at a different hive offset). Instead we locate the
// Control\Lsa NK cell physically (see scan_memory) and read its
// {JD,Skew1,GBG,Data} subkeys' class names by physical-proximity anchoring, so
// the whole read stays inside one copy without needing the bin tiling to align.

const PBOX: [usize; 16] = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7];

fn u32_at(d: &[u8], o: usize) -> u32 {
    d.get(o..o + 4)
        .map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()))
}
fn u16_at(d: &[u8], o: usize) -> u16 {
    d.get(o..o + 2)
        .map_or(0, |b| u16::from_le_bytes(b.try_into().unwrap()))
}

/// All cell payloads (bytes after the 4-byte size prefix) at a hive-relative
/// offset, one per run that covers it.
fn cell_candidates(phys: &impl PhysicalMemory, ix: &RunIndex, hive_off: u64) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for run in ix.covering(hive_off) {
        let poff = hive_off - run.start_off;
        let addr = run.start_gpa + poff;
        let Ok(szb) = phys.read_phys_bytes(addr, 4) else {
            continue;
        };
        let abs = u64::from(i32::from_le_bytes(szb.try_into().unwrap()).unsigned_abs());
        if !(8..=0x10000).contains(&abs) || poff + abs > run.total {
            continue;
        }
        if let Ok(data) = phys.read_phys_bytes(addr + 4, (abs - 4) as usize) {
            out.push(data);
        }
        if out.len() >= 16 {
            break;
        }
    }
    out
}

/// A subkey-list entry: child NK offset plus the name key used to disambiguate the
/// correct child NK among candidates from other hives at the same offset.
#[derive(Clone, Copy)]
enum SkHash {
    None,
    Lf(u32), // first 4 chars of the name, packed LE
    Lh(u32), // 37*acc + uppercase(char) hash
}

/// Windows lh subkey-name hash.
fn lh_hash(name: &str) -> u32 {
    let mut h = 0u32;
    for c in name.chars() {
        h = h
            .wrapping_mul(37)
            .wrapping_add(c.to_ascii_uppercase() as u32);
    }
    h
}

/// Does an NK cell's name match the subkey-list hash?
fn nk_matches(nk: &[u8], hk: SkHash) -> bool {
    match hk {
        SkHash::None => true,
        SkHash::Lf(h) => {
            let name = nk_name(nk);
            let want = h.to_le_bytes();
            let nb = name.as_bytes();
            (0..4).all(|i| want[i] == 0 || nb.get(i).copied() == Some(want[i]))
        }
        SkHash::Lh(h) => lh_hash(&nk_name(nk)) == h,
    }
}

/// Child NK (offset, name-hash) entries referenced by a subkey-list cell.
fn subkey_list_entries(
    phys: &impl PhysicalMemory,
    runs: &RunIndex,
    list: &[u8],
    depth: u8,
) -> Vec<(u32, SkHash)> {
    if list.len() < 4 || depth > 4 {
        return Vec::new();
    }
    let count = u16_at(list, 2) as usize;
    let mut out = Vec::new();
    match &list[0..2] {
        b"lf" => {
            for i in 0..count.min(4096) {
                let o = 4 + i * 8;
                if o + 8 <= list.len() {
                    out.push((u32_at(list, o), SkHash::Lf(u32_at(list, o + 4))));
                }
            }
        }
        b"lh" => {
            for i in 0..count.min(4096) {
                let o = 4 + i * 8;
                if o + 8 <= list.len() {
                    out.push((u32_at(list, o), SkHash::Lh(u32_at(list, o + 4))));
                }
            }
        }
        b"li" => {
            for i in 0..count.min(4096) {
                let o = 4 + i * 4;
                if o + 4 <= list.len() {
                    out.push((u32_at(list, o), SkHash::None));
                }
            }
        }
        b"ri" => {
            for i in 0..count.min(1024) {
                let o = 4 + i * 4;
                if o + 4 > list.len() {
                    break;
                }
                for sub in cell_candidates(phys, runs, u64::from(u32_at(list, o))) {
                    out.extend(subkey_list_entries(phys, runs, &sub, depth + 1));
                }
            }
        }
        _ => {}
    }
    out
}

fn nk_name(nk: &[u8]) -> String {
    let nl = u16_at(nk, 0x48) as usize;
    nk.get(0x4C..0x4C + nl)
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .unwrap_or_default()
}

/// All (cell payload, cell GPA) pairs at a hive-relative offset, one per run that
/// covers it. Unlike [`cell_candidates`], this exposes each candidate's physical
/// address so navigation can pick the copy physically nearest an anchor. Not
/// capped: a low, common offset is covered by every hive copy (tens of runs), and
/// dropping candidates could hide the one nearest the anchor.
fn cells_with_gpa(phys: &impl PhysicalMemory, ix: &RunIndex, hive_off: u64) -> Vec<(Vec<u8>, u64)> {
    let mut out = Vec::new();
    for run in ix.covering(hive_off) {
        let poff = hive_off - run.start_off;
        let addr = run.start_gpa + poff;
        let Ok(szb) = phys.read_phys_bytes(addr, 4) else {
            continue;
        };
        let abs = u64::from(i32::from_le_bytes(szb.try_into().unwrap()).unsigned_abs());
        if !(8..=0x10000).contains(&abs) || poff + abs > run.total {
            continue;
        }
        if let Ok(data) = phys.read_phys_bytes(addr + 4, (abs - 4) as usize) {
            out.push((data, addr));
        }
    }
    out
}

/// The child NK named `name` whose cell is physically nearest `anchor`, plus its
/// GPA. Anchoring on proximity keeps a multi-step navigation inside ONE hive copy:
/// the several stale SYSTEM copies in memory each store the same key at a
/// different hive offset, so resolving by offset+name alone jumps between copies
/// and lands on offsets whose bins were never captured. A copy's bins cluster in
/// physical memory, so the nearest name-matching child is the in-copy one.
fn child_by_name(
    phys: &impl PhysicalMemory,
    ix: &RunIndex,
    nk: &[u8],
    name: &str,
    anchor: u64,
) -> Option<(Vec<u8>, u64)> {
    if nk.len() < 0x50 || &nk[0..2] != b"nk" {
        return None;
    }
    let list_off = u32_at(nk, 0x1C);
    if list_off == 0xFFFF_FFFF {
        return None;
    }
    let mut best: Option<(u64, Vec<u8>, u64)> = None; // (dist, payload, gpa)
    for (list, _) in cells_with_gpa(phys, ix, u64::from(list_off)) {
        if !matches!(list.get(0..2), Some(b"lf" | b"lh" | b"li" | b"ri")) {
            continue;
        }
        for (coff, _) in subkey_list_entries(phys, ix, &list, 0) {
            for (child, cgpa) in cells_with_gpa(phys, ix, u64::from(coff)) {
                if child.len() >= 0x50
                    && &child[0..2] == b"nk"
                    && nk_name(&child).eq_ignore_ascii_case(name)
                {
                    let d = cgpa.abs_diff(anchor);
                    if best.as_ref().is_none_or(|(bd, _, _)| d < *bd) {
                        best = Some((d, child, cgpa));
                    }
                }
            }
        }
    }
    best.map(|(_, c, g)| (c, g))
}

/// The class-name hex bytes of an NK cell, choosing the class cell physically
/// nearest `anchor` that decodes as hex (the Lsa `JD`/`Skew1`/`GBG`/`Data` keys
/// carry bootkey nibbles as their class name).
fn class_hex(
    phys: &impl PhysicalMemory,
    ix: &RunIndex,
    nk: &[u8],
    anchor: u64,
) -> Option<Vec<u8>> {
    let class_off = u32_at(nk, 0x30);
    let class_len = u16_at(nk, 0x4A) as usize;
    if class_off == 0xFFFF_FFFF || class_len == 0 {
        return None;
    }
    let mut best: Option<(u64, Vec<u8>)> = None;
    for (cell, cgpa) in cells_with_gpa(phys, ix, u64::from(class_off)) {
        if class_len <= cell.len() {
            let s = crate::utils::utf16le_decode(&cell[..class_len]);
            if let Ok(b) = hex::decode(&s) {
                let d = cgpa.abs_diff(anchor);
                if best.as_ref().is_none_or(|(bd, _)| d < *bd) {
                    best = Some((d, b));
                }
            }
        }
    }
    best.map(|(_, b)| b)
}

/// Extract the bootkey from a physically-located Control\Lsa NK cell. For each
/// candidate we read its `JD`/`Skew1`/`GBG`/`Data` subkeys' class names — the four
/// bootkey nibble groups — resolving each child and its class cell by physical
/// proximity to the Lsa cell, so the whole read stays inside one hive copy. This
/// avoids root-down navigation, which lands on uncaptured bins because the several
/// stale SYSTEM copies each store the path at a different hive offset.
fn guided_bootkey(
    phys: &impl PhysicalMemory,
    runs: &RunIndex,
    lsa_cands: &[(Vec<u8>, u64)],
) -> Option<[u8; 16]> {
    for (lsa, g3) in lsa_cands {
        let mut raw = Vec::with_capacity(16);
        for kn in ["JD", "Skew1", "GBG", "Data"] {
            match child_by_name(phys, runs, lsa, kn, *g3)
                .and_then(|(sub, g4)| class_hex(phys, runs, &sub, g4))
            {
                Some(b) if raw.len() + b.len() <= 16 => raw.extend_from_slice(&b),
                _ => {
                    raw.clear();
                    break;
                }
            }
        }
        if raw.len() == 16 {
            let mut bk = [0u8; 16];
            for (i, &p) in PBOX.iter().enumerate() {
                bk[i] = raw[p];
            }
            log::debug!("guided_bootkey: assembled from Lsa@{g3:#x}");
            return Some(bk);
        }
    }
    None
}

fn hive_key(name: &str) -> &'static str {
    match name {
        "SAM" => "SAM",
        "SECURITY" => "SECURITY",
        _ => "SYSTEM",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dpapi_secret(version: u32) -> LsaSecret {
        let mut raw = vec![0u8; 44];
        raw[0..4].copy_from_slice(&version.to_le_bytes());
        LsaSecret {
            name: "DPAPI_SYSTEM".into(),
            raw_data: raw,
            parsed: LsaSecretType::DpapiSystem {
                user_key: [0u8; 20],
                machine_key: [0u8; 20],
            },
        }
    }

    fn text_secret(name: &str) -> LsaSecret {
        LsaSecret {
            name: name.into(),
            raw_data: b"whatever".to_vec(),
            parsed: LsaSecretType::DefaultPassword {
                password: "x".into(),
            },
        }
    }

    #[test]
    fn valid_dpapi_system_is_accepted_and_outranks() {
        let good = vec![dpapi_secret(1), text_secret("DefaultPassword")];
        assert_eq!(dpapi_system_valid(&good), Some(true));
        assert!(lsa_secrets_verified(&good));
        assert!(lsa_reassembly_score(&good) >= 1000);
    }

    #[test]
    fn wrong_lsa_key_dpapi_system_is_rejected() {
        // A wrong LSA key corrupts DPAPI_SYSTEM's version dword → reject the whole
        // reassembly, so mojibake secrets are never surfaced.
        let garbage = vec![dpapi_secret(0x8ab21f9c), text_secret("_SC_thing")];
        assert_eq!(dpapi_system_valid(&garbage), Some(false));
        assert!(!lsa_secrets_verified(&garbage));
        assert_eq!(lsa_reassembly_score(&garbage), 0);
    }

    #[test]
    fn no_dpapi_system_keeps_count_based_behavior() {
        let secrets = vec![text_secret("DefaultPassword")];
        assert_eq!(dpapi_system_valid(&secrets), None);
        assert!(lsa_secrets_verified(&secrets));
        assert_eq!(lsa_reassembly_score(&secrets), 1);
    }
}
