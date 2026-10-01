//! Recover SAM / SYSTEM / SECURITY from a memory image via the Configuration
//! Manager hive map (`_HHIVE` / `_HMAP`).
//!
//! Unlike the signature carve ([`crate::sam::mem_hive`]), the map gives an
//! unambiguous per-hive offset -> page translation, so it works even when a hive is
//! fragmented into scattered pages. Bins are mapped in the Registry process (Win10
//! 1803+), so translation uses its DTB; the map structures are kernel VAs and resolve
//! in any DTB. Field offsets are self-calibrated per hive (see [`calibrate`]), so it
//! is version-agnostic. Needs page tables, so it runs after System/Registry are found.

use std::collections::HashMap;

use crate::memory::PhysicalMemory;
use crate::paging::translate::PageTableWalker;
use crate::sam::bootkey::extract_bootkey;
use crate::sam::hashes::extract_hashes;
use crate::sam::lsa::extract_lsa_secrets;
use crate::sam::mem_hive::MemoryHiveCreds;

const HHIVE_SIG: u32 = 0xBEE0_BEE0;
const BASE_BLOCK: usize = 0x1000;
/// Hives we materialize (matched against the base block's embedded file name).
const WANTED: [&str; 3] = ["SAM", "SYSTEM", "SECURITY"];
/// Cap a hive image so a corrupt length can't drive a huge allocation.
const MAX_HIVE: usize = 256 << 20;

fn u32at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn u64at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
fn is_kernel_va(v: u64) -> bool {
    (0xFFFF_8000_0000_0000..u64::MAX).contains(&v)
}

/// How an `_HMAP_ENTRY` encodes its 4 KB block address (self-calibrated).
#[derive(Clone, Copy)]
enum EntryScheme {
    /// Win8.1+: block = (PermanentBinAddress@+8 & ~0xF) + BlockOffset@+0.
    PermBin,
    /// Win7/Vista: BlockAddress@+0 is the block VA directly.
    BlockAddr,
}

/// Calibrated `_HMAP` layout: the `_HMAP_DIRECTORY` VA, the `_HMAP_TABLE` entry
/// stride, and how entries encode their block address.
struct MapLayout {
    map_va: u64,
    stride: u64,
    scheme: EntryScheme,
}

/// Recover bootkey + SAM hashes + LSA secrets by materializing the hives via the CM map.
///
/// Translates with `dtb` (the Registry process DTB on Win10 1803+, else the System
/// DTB). Returns empty creds if no usable SYSTEM hive is found.
pub fn extract_from_cm_map<L: PhysicalMemory>(layer: &L, dtb: u64) -> MemoryHiveCreds {
    let mut creds = MemoryHiveCreds::default();
    let walker = PageTableWalker::new(layer);
    let rv = |va: u64, n: usize| -> Option<Vec<u8>> {
        layer
            .read_phys_bytes(walker.translate(dtb, va).ok()?, n)
            .ok()
    };

    let hives = scan_hives(layer, &rv);
    // Prefer the mapped SYSTEM hive; fall back to a physical Lsa-cell scan when its
    // bins are paged out, so SAM/SECURITY still decrypt if their blocks are resident.
    let bk = hives
        .get("SYSTEM")
        .and_then(|s| extract_bootkey(s).ok())
        .or_else(|| {
            log::info!(
                "cm_hive: bootkey from mapped SYSTEM unavailable — trying physical bootkey scan"
            );
            crate::sam::mem_hive::recover_bootkey(layer)
        });
    let Some(bk) = bk else {
        log::debug!("cm_hive: bootkey unrecoverable (mapped SYSTEM + physical scan)");
        return creds;
    };
    creds.bootkey = Some(bk);
    match hives.get("SAM").map(|sam| extract_hashes(sam, &bk)) {
        Some(Ok(h)) => {
            log::info!("cm_hive: extracted {} SAM account(s) via CM map", h.len());
            creds.sam_hashes = h;
        }
        Some(Err(e)) => log::info!("cm_hive: SAM parse failed: {e}"),
        None => log::info!("cm_hive: no SAM hive found via CM map"),
    }
    match hives
        .get("SECURITY")
        .map(|sec| extract_lsa_secrets(sec, &bk))
    {
        Some(Ok(s)) => {
            log::info!("cm_hive: extracted {} LSA secret(s) via CM map", s.len());
            creds.lsa_secrets = s;
        }
        Some(Err(e)) => log::info!("cm_hive: SECURITY parse failed: {e}"),
        None => log::info!("cm_hive: no SECURITY hive found via CM map"),
    }
    creds
}

/// Scan physical memory for `_HHIVE` signatures and materialize each wanted hive.
/// Keeps the largest image seen per hive name (freshest/most-complete copy).
fn scan_hives<L: PhysicalMemory>(
    layer: &L,
    rv: &dyn Fn(u64, usize) -> Option<Vec<u8>>,
) -> HashMap<String, Vec<u8>> {
    let mut hives: HashMap<String, Vec<u8>> = HashMap::new();
    let ps = layer.phys_size();
    let mut buf = vec![0u8; 1024 * 1024];
    let mut base = 0u64;
    while base < ps {
        let n = ((ps - base) as usize).min(buf.len());
        if layer.read_phys(base, &mut buf[..n]).is_ok() {
            let mut i = 0;
            while i + 4 <= n {
                if u32::from_le_bytes(buf[i..i + 4].try_into().unwrap()) == HHIVE_SIG {
                    if let Some((name, img)) = materialize(layer, rv, base + i as u64) {
                        // Keep the largest (most-complete) image seen per hive name.
                        if hives.get(&name).is_none_or(|e| img.len() > e.len()) {
                            hives.insert(name, img);
                        }
                    }
                }
                i += 8; // _HHIVE is 8-aligned
            }
        }
        // Release the window just swept: on an mmap-backed layer this is the only
        // thing keeping a full-RAM scan from leaving the whole image resident.
        layer.advise_scanned(base, n as u64);
        base += buf.len() as u64;
    }
    hives
}

/// Materialize a contiguous `[base block][bins]` hive image for the `_HHIVE` at
/// physical `hhive_phys`, or `None` if it isn't a wanted hive or can't be resolved.
fn materialize<L: PhysicalMemory>(
    layer: &L,
    rv: &dyn Fn(u64, usize) -> Option<Vec<u8>>,
    hhive_phys: u64,
) -> Option<(String, Vec<u8>)> {
    let hh = layer.read_phys_bytes(hhive_phys, 0x200).ok()?;

    // BaseBlock: the first kernel-VA pointer whose target begins with "regf".
    let base_block = (8..0x100)
        .step_by(8)
        .map(|o| u64at(&hh, o))
        .filter(|&va| is_kernel_va(va))
        .find_map(|va| rv(va, BASE_BLOCK).filter(|b| &b[0..4] == b"regf"))?;
    let length = u32at(&base_block, 0x28) as usize;
    let name = crate::utils::utf16le_decode(&base_block[0x30..0x70]);
    let base = name
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or("")
        .to_ascii_uppercase();
    if !WANTED.contains(&base.as_str()) || length == 0 || length > MAX_HIVE {
        return None;
    }

    let Some(layout) = calibrate(rv, &hh, length) else {
        // Base block resident but no bin resolves to "hbin" — this hive's views are
        // paged out of the image.
        log::info!("cm_hive: {base} present but its bins are not resident — skipping");
        return None;
    };
    let mut img = vec![0u8; BASE_BLOCK + length];
    img[..BASE_BLOCK].copy_from_slice(&base_block);
    let mut off = 0usize;
    let mut filled = 0usize;
    while off < length {
        if let Some(block) = read_block(rv, &layout, off) {
            // Clamp to the image tail and block length so a non-4K-aligned hive
            // `length` (or a short block) can't overrun the buffer.
            let dst = BASE_BLOCK + off;
            let w = img.len().saturating_sub(dst).min(block.len());
            img[dst..dst + w].copy_from_slice(&block[..w]);
            filled += 1;
        }
        off += 0x1000;
    }
    log::info!(
        "cm_hive: {base}: mapped {filled}/{} blocks (len {length:#x})",
        length.div_ceil(0x1000)
    );
    Some((base, img))
}

/// Find the `Storage[Stable]` map layout structurally: try every kernel-VA pointer
/// in the `_HHIVE` as the `Map`, with each candidate stride and entry scheme, and
/// keep the one whose `dir -> table -> entry -> bin` chain resolves the MOST probe
/// blocks to "hbin".
///
/// Scoring (not first-match) is essential: a wrong stride can still resolve a few
/// early blocks by coincidence — e.g. on Win7 the real `_HMAP_ENTRY` stride is 0x20,
/// but 0x18 aligns on every other entry, so first-match picked 0x18 and mapped only
/// ~half the hive (incomplete → parse fails). Genuinely paged-out blocks miss under
/// every candidate, so they don't change which stride scores highest.
fn calibrate(
    rv: &dyn Fn(u64, usize) -> Option<Vec<u8>>,
    hh: &[u8],
    length: usize,
) -> Option<MapLayout> {
    let probes = (length / 0x1000).min(64);
    let mut best: Option<(usize, MapLayout)> = None;
    for o in (0x40..hh.len().saturating_sub(8)).step_by(8) {
        let map_va = u64at(hh, o);
        if !is_kernel_va(map_va) {
            continue;
        }
        for stride in [0x18u64, 0x10, 0x20, 0x28, 0x30] {
            for scheme in [EntryScheme::PermBin, EntryScheme::BlockAddr] {
                let layout = MapLayout {
                    map_va,
                    stride,
                    scheme,
                };
                let score = (0..=probes)
                    .filter(|&i| {
                        read_block(rv, &layout, i * 0x1000).is_some_and(|b| &b[0..4] == b"hbin")
                    })
                    .count();
                if score == 0 {
                    continue;
                }
                // Perfect resolution of every probe — no better layout exists.
                if score == probes + 1 {
                    return Some(layout);
                }
                if best.as_ref().is_none_or(|(bs, _)| score > *bs) {
                    best = Some((score, layout));
                }
            }
        }
    }
    best.map(|(_, l)| l)
}

/// Read the 4 KB hive block for cell offset `off` (which is 4 KB-aligned here):
/// `Directory[off>>21] -> Table[(off>>12)&0x1FF]`, decoded per the entry scheme.
fn read_block(
    rv: &dyn Fn(u64, usize) -> Option<Vec<u8>>,
    layout: &MapLayout,
    off: usize,
) -> Option<Vec<u8>> {
    let dir = rv(layout.map_va + ((off >> 21) as u64) * 8, 8)?;
    let table_va = u64at(&dir, 0);
    if !is_kernel_va(table_va) {
        return None;
    }
    let ent_va = table_va + (((off >> 12) & 0x1FF) as u64) * layout.stride;
    let ent = rv(ent_va, 0x18)?;
    let block_va = match layout.scheme {
        // (PermanentBinAddress & ~0xF) + BlockOffset. The block VA is user-range in
        // the Registry process (Win10 1803+); the caller's DTB maps it.
        EntryScheme::PermBin => (u64at(&ent, 8) & !0xF).checked_add(u64at(&ent, 0))?,
        // BlockAddress is the 4 KB block VA directly (Win7/Vista, System space).
        EntryScheme::BlockAddr => u64at(&ent, 0) & !0xFFF,
    };
    if block_va == 0 {
        return None;
    }
    rv(block_va, 0x1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Region-addressed fake memory serving both physical (the `_HHIVE` window) and
    /// VA reads (base block, map, table, bins) — no real page tables needed.
    struct Fake {
        regions: Vec<(u64, Vec<u8>)>,
    }
    impl Fake {
        fn read(&self, addr: u64, n: usize) -> Option<Vec<u8>> {
            for (start, data) in &self.regions {
                if addr >= *start && addr + n as u64 <= start + data.len() as u64 {
                    let o = (addr - start) as usize;
                    return Some(data[o..o + n].to_vec());
                }
            }
            None
        }
    }
    impl PhysicalMemory for Fake {
        fn read_phys(&self, addr: u64, buf: &mut [u8]) -> crate::error::Result<()> {
            match self.read(addr, buf.len()) {
                Some(d) => {
                    buf.copy_from_slice(&d);
                    Ok(())
                }
                None => Err(crate::error::VmkatzError::Parse("mock oob".into())),
            }
        }
        fn phys_size(&self) -> u64 {
            0
        }
    }

    fn put_u32(b: &mut [u8], o: usize, v: u32) {
        b[o..o + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put_u64(b: &mut [u8], o: usize, v: u64) {
        b[o..o + 8].copy_from_slice(&v.to_le_bytes());
    }

    /// materialize() must self-calibrate the map layout (Length@+0x118, Map@+0x120,
    /// stride 0x18, PermanentBinAddress@+8) and assemble the two bins into a
    /// contiguous image — including a bin whose VA is user-range (Registry process).
    #[test]
    fn materialize_walks_cm_map_and_assembles_image() {
        const BB_VA: u64 = 0xFFFF_F000_0001_0000;
        const MAP_VA: u64 = 0xFFFF_F000_0002_0000;
        const TABLE_VA: u64 = 0xFFFF_F000_0003_0000;
        const BIN0_VA: u64 = 0x0000_0000_0100_0000; // user-range (Registry) VA
        const BIN1_VA: u64 = 0x0000_0000_0100_1000;
        let len = 0x2000u32; // two 4 KB bins

        // _HHIVE window (read from phys 0): BaseBlock@+0x40, Length@+0x118, Map@+0x120.
        let mut hh = vec![0u8; 0x200];
        put_u64(&mut hh, 0x40, BB_VA);
        put_u32(&mut hh, 0x118, len);
        put_u64(&mut hh, 0x120, MAP_VA);

        // Base block: regf, root@0x24=0x20, len@0x28, name "SAM" (UTF-16) @0x30.
        let mut bb = vec![0u8; 0x1000];
        bb[0..4].copy_from_slice(b"regf");
        put_u32(&mut bb, 0x24, 0x20);
        put_u32(&mut bb, 0x28, len);
        for (i, ch) in "SAM".encode_utf16().enumerate() {
            bb[0x30 + i * 2..0x30 + i * 2 + 2].copy_from_slice(&ch.to_le_bytes());
        }

        // Map directory: dir[0] -> table.
        let mut map = vec![0u8; 0x40];
        put_u64(&mut map, 0, TABLE_VA);

        // Table: two _HMAP_ENTRY (stride 0x18): { BlockOffset=0, PermBinAddr, size }.
        let mut table = vec![0u8; 0x40];
        put_u64(&mut table, 0x00, 0); // entry0 BlockOffset
        put_u64(&mut table, 0x08, BIN0_VA | 1); // entry0 PermanentBinAddress (flag bit)
        put_u64(&mut table, 0x10, 0x1000);
        put_u64(&mut table, 0x18, 0); // entry1 BlockOffset
        put_u64(&mut table, 0x20, BIN1_VA | 1); // entry1 PermanentBinAddress

        // Bins: both start "hbin"; bin0 has the root NK cell at hive offset 0x20.
        let mut bin0 = vec![0u8; 0x1000];
        bin0[0..4].copy_from_slice(b"hbin");
        bin0[0x20..0x24].copy_from_slice(&(-0x50i32).to_le_bytes()); // cell size
        bin0[0x24..0x26].copy_from_slice(b"nk");
        let mut bin1 = vec![0u8; 0x1000];
        bin1[0..4].copy_from_slice(b"hbin");

        let fake = Fake {
            regions: vec![
                (0, hh),
                (BB_VA, bb),
                (MAP_VA, map),
                (TABLE_VA, table),
                (BIN0_VA, bin0),
                (BIN1_VA, bin1),
            ],
        };
        let rv = |va: u64, n: usize| fake.read(va, n);
        let (name, img) = materialize(&fake, &rv, 0).expect("materialize");
        assert_eq!(name, "SAM");
        assert_eq!(img.len(), BASE_BLOCK + len as usize);
        assert_eq!(&img[0..4], b"regf"); // base block preserved
        assert_eq!(&img[BASE_BLOCK..BASE_BLOCK + 4], b"hbin"); // bin0 @ offset 0
        assert_eq!(&img[BASE_BLOCK + 0x24..BASE_BLOCK + 0x26], b"nk"); // root cell
        assert_eq!(&img[BASE_BLOCK + 0x1000..BASE_BLOCK + 0x1004], b"hbin"); // bin1
    }
}
