//! Recover SAM / SYSTEM / SECURITY from a live memory image via the Configuration
//! Manager hive map (`_HHIVE` / `_HMAP`).
//!
//! Robust where the signature-scan reassembly ([`crate::sam::mem_hive`]) fails: the
//! CM map gives an unambiguous, per-hive-instance translation from a hive-cell
//! offset to the memory page holding it, so there is no cross-hive offset collision
//! and no need to guess which scattered page belongs to which hive.
//!
//! Mechanics: scan physical memory for the `_HHIVE` signature (`0xBEE0BEE0`); for a
//! wanted hive, follow `Storage[Stable].Map` (a directory of `_HMAP_TABLE`s) to get
//! each 4 KB block's address and materialize a contiguous hive image, which the
//! existing `regf` parser + extractors consume. On Win10 1803+ the hive bins are
//! mapped into the **Registry** minimal process's address space (user-range VAs),
//! so translation uses that process's DTB (kernel VAs for the map structures resolve
//! in any DTB, since the kernel half is shared).
//!
//! Struct field offsets vary by build, so they are **self-calibrated** per hive:
//! `BaseBlock` is the pointer whose target is `regf`, and the `(Map, entry-stride)`
//! pair is the one for which hive offset 0 translates to a page starting `hbin`.
//! Needs page tables (a DTB), unlike the signature carve — so it runs only once the
//! System (and Registry) process has been located.

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
fn utf16(b: &[u8]) -> String {
    b.chunks(2)
        .map(|c| u16::from_le_bytes([c[0], *c.get(1).unwrap_or(&0)]))
        .take_while(|&u| u != 0)
        .filter_map(|u| char::from_u32(u32::from(u)))
        .collect()
}

/// Calibrated map layout for one hive: the `_HMAP_DIRECTORY` VA and the
/// `_HMAP_TABLE` entry stride. `PermanentBinAddress` is at entry+0x8, `BlockOffset`
/// at entry+0 (validated against a live "hbin").
struct MapLayout {
    map_va: u64,
    stride: u64,
}

/// Recover bootkey + SAM hashes + LSA secrets by materializing the hives via the CM map.
///
/// Translates with `dtb` (the Registry process DTB on Win10 1803+, else the System
/// DTB). Returns empty creds if no usable SYSTEM hive is found.
pub fn extract_from_cm_map<L: PhysicalMemory>(layer: &L, dtb: u64) -> MemoryHiveCreds {
    let mut creds = MemoryHiveCreds::default();
    let walker = PageTableWalker::new(layer);
    let rv = |va: u64, n: usize| -> Option<Vec<u8>> {
        layer.read_phys_bytes(walker.translate(dtb, va).ok()?, n).ok()
    };

    let hives = scan_hives(layer, &rv);
    let Some(system) = hives.get("SYSTEM") else {
        log::debug!("cm_hive: no SYSTEM hive materialized via CM map");
        return creds;
    };
    let Ok(bk) = extract_bootkey(system) else {
        log::debug!("cm_hive: bootkey extraction from mapped SYSTEM failed");
        return creds;
    };
    creds.bootkey = Some(bk);
    if let Some(sam) = hives.get("SAM") {
        if let Ok(h) = extract_hashes(sam, &bk) {
            log::info!("cm_hive: extracted {} SAM account(s) via CM map", h.len());
            creds.sam_hashes = h;
        }
    }
    if let Some(sec) = hives.get("SECURITY") {
        if let Ok(s) = extract_lsa_secrets(sec, &bk) {
            log::info!("cm_hive: extracted {} LSA secret(s) via CM map", s.len());
            creds.lsa_secrets = s;
        }
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
    let name = utf16(&base_block[0x30..0x70]);
    let base = name.rsplit(['\\', '/']).next().unwrap_or("").to_ascii_uppercase();
    if !WANTED.contains(&base.as_str()) || length == 0 || length > MAX_HIVE {
        return None;
    }

    let layout = calibrate(rv, &hh, length)?;
    let mut img = vec![0u8; BASE_BLOCK + length];
    img[..BASE_BLOCK].copy_from_slice(&base_block);
    let mut off = 0usize;
    let mut filled = 0usize;
    while off < length {
        if let Some(block) = read_block(rv, &layout, off) {
            img[BASE_BLOCK + off..BASE_BLOCK + off + 0x1000].copy_from_slice(&block);
            filled += 1;
        }
        off += 0x1000;
    }
    log::debug!(
        "cm_hive: {base}: {filled}/{} blocks via CM map (len {length:#x})",
        length / 0x1000
    );
    Some((base, img))
}

/// Find the `Storage[Stable]` map layout by validating that hive offset 0 resolves
/// to a page starting with "hbin". Tries each u32 field equal to the hive length as
/// `Length` (so `Map` is the following qword) and each plausible entry stride.
fn calibrate(
    rv: &dyn Fn(u64, usize) -> Option<Vec<u8>>,
    hh: &[u8],
    length: usize,
) -> Option<MapLayout> {
    for o in (0x40..hh.len().saturating_sub(0x10)).step_by(4) {
        if u32at(hh, o) as usize != length {
            continue;
        }
        let map_va = u64at(hh, o + 8); // _DUAL: Length @ +0, Map @ +8
        if !is_kernel_va(map_va) {
            continue;
        }
        for stride in [0x18u64, 0x10, 0x20] {
            let layout = MapLayout { map_va, stride };
            if read_block(rv, &layout, 0).is_some_and(|b| &b[0..4] == b"hbin") {
                return Some(layout);
            }
        }
    }
    None
}

/// Read the 4 KB hive block covering cell offset `off` through the map:
/// `Directory[off>>21] -> Table[(off>>12)&0x1FF] -> BlockOffset + PermanentBinAddress`.
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
    let block_off = u64at(&ent, 0); // this block's offset within its bin
    let bin = u64at(&ent, 8) & !0xF; // PermanentBinAddress (low bits are flags)
    if bin == 0 {
        return None;
    }
    // `bin` is a user-range VA in the Registry process; the caller's DTB maps it.
    rv(bin + block_off, 0x1000)
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
