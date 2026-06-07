//! In-process `CanonicalCookie` struct layouts, locator signature, and
//! `std::map` red-black tree walker.
//!
//! Ported from Meckazin/ChromeKatz (`CookieKatz/Memory.h`,
//! `CookieKatz/Main.cpp`, `CookieKatz/Memory.cpp`).
//!
//! ## Locator pipeline
//!
//! 1. For every mapped userland memory region in a chromium process,
//!    re-patch [`COOKIE_MONSTER_SIG`] with the high 4 bytes of the
//!    region's base address (via [`patch_module_high_half`]). On x64
//!    Windows `chrome.dll` / `msedge.dll` and the heap that holds the
//!    CookieMonster instances share their high 4 bytes, so this acts as
//!    a "pointer-points-into-the-same-region" structural test.
//! 2. Scan the region buffer for the patched pattern. Every match
//!    (8-byte aligned) is a candidate `net::CookieMonster` instance.
//! 3. The cookie map root is at `instance + COOKIE_MAP_OFFSET` (0x30
//!    bytes past the instance start, per ChromeKatz's `Main.cpp`).
//! 4. Read the [`RbRoot`] there and call [`walk_cookie_tree`]; each
//!    leaf's `value_address` points at a `CanonicalCookie` struct whose
//!    layout depends on Chrome/Edge major version (see [`CookieVariant`]).
//!
//! The same 152-byte structural signature works across multiple Chrome
//! and Edge versions because the wildcard bytes (`0xAA`, `0xCC`) leave
//! room for build-to-build drift in the non-pointer data fields. The
//! variant choice for [`read_cookie`] still matters for `partition_key`
//! / `ProcessBoundString` layout differences.

use crate::error::Result;
use crate::memory::VirtualMemory;

// ============================================================================
// Locator signature
// ============================================================================

/// 152-byte structural signature of a `net::CookieMonster` instance's
/// first members. Wildcards: `0xAA`, `0xCC`. The `0xBB` bytes at the six
/// fixed offsets [`PATCH_OFFSETS`] get replaced via [`patch_module_high_half`]
/// before each per-region scan — they represent the high 4 bytes of
/// pointer fields that must point back into the same chrome.dll / heap
/// region we're scanning.
pub const COOKIE_MONSTER_SIG: [u8; 152] = [
    0xAA, 0xAA, 0xAA, 0xAA, 0xCC, 0xCC, 0xCC, 0xCC, 0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB,
    0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB,
    0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00,
    0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00,
    0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB,
];

/// One past each of the six 4-byte `0xBB` windows in
/// [`COOKIE_MONSTER_SIG`]. [`patch_module_high_half`] writes the four
/// bytes ending at each position; cf ChromeKatz `Memory.cpp::PatchPattern`
/// which writes `pattern[offset-1..offset-4]` from the high half of an
/// `uintptr_t`.
const PATCH_OFFSETS: [usize; 6] = [16, 24, 56, 64, 88, 152];

/// Byte offset from a `CookieMonster` instance to the `std::map`
/// `RbRoot` head. Fixed at 0x30 (`0x28` + `sizeof(uintptr_t)` per
/// `Main.cpp`'s `CookieMapOffset` calculation) across observed Chrome
/// / Edge versions.
pub const COOKIE_MAP_OFFSET: u64 = 0x30;

/// Replace the four bytes ending at each [`PATCH_OFFSETS`] position with
/// the high half (bytes 4..8) of `region_base` in little-endian form. On
/// x64 Windows this turns the otherwise-wildcard pointer-high-half
/// windows into a fixed match for "the high 4 bytes of any pointer that
/// targets the same memory region we're scanning."
pub fn patch_module_high_half(sig: &mut [u8; 152], region_base: u64) {
    let bytes = region_base.to_le_bytes();
    // High 4 bytes are bytes[4..8]; they want to land at sig[offset-4..offset]
    // with the highest byte (bytes[7]) at sig[offset-1] going down. Looking
    // at ChromeKatz's loop the writes match a direct copy of bytes[4..8].
    for &offset in &PATCH_OFFSETS {
        let dst = &mut sig[offset - 4..offset];
        dst.copy_from_slice(&bytes[4..8]);
    }
}

/// Scan `mem` (mapped at virtual address `base_va`) for every offset
/// where the (already module-half-patched) [`COOKIE_MONSTER_SIG`]
/// matches. Returns absolute virtual addresses by adding `base_va`.
/// Matches are 8-byte aligned (the candidate object always starts on a
/// pointer-aligned boundary).
pub fn scan_for_cookie_monster(mem: &[u8], base_va: u64, sig: &[u8; 152]) -> Vec<u64> {
    let mut hits = Vec::new();
    if mem.len() < sig.len() {
        return hits;
    }
    let last_start = mem.len() - sig.len();
    let mut i = 0usize;
    while i <= last_start {
        let window = &mem[i..i + sig.len()];
        if matches_signature(sig, window) {
            hits.push(base_va + i as u64);
        }
        i += 8;
    }
    hits
}

/// Match a window against the signature: wildcards (`0xAA`/`0xCC`)
/// always pass; everything else must match byte-for-byte.
fn matches_signature(sig: &[u8; 152], window: &[u8]) -> bool {
    for (s, w) in sig.iter().zip(window.iter()) {
        match *s {
            0xAA | 0xCC => continue,
            other => {
                if other != *w {
                    return false;
                }
            }
        }
    }
    true
}

// ============================================================================
// In-process C++ struct layouts (MSVC x64)
// ============================================================================


/// `std::string` short-string-optimization layout (MSVC x64): a 23-byte
/// inline buffer with the length stored in byte 23. When `len > 22`, byte
/// 23 holds 23 and the first 8 bytes of `buf` are reinterpreted as a
/// pointer to a heap-allocated character buffer.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OptimizedString {
    pub buf: [u8; 23],
    pub len: u8,
}

/// Cookie value variant introduced in Chrome 130 / Edge 130 for
/// "ProcessBoundEncryption". Holds either plaintext bytes or
/// `CryptProtectMemory`-encrypted bytes. We can't decrypt the latter
/// offline — when `encrypted == 1` we report the value as `<encrypted>`
/// rather than corrupt bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessBoundString {
    pub data_ptr: u64,
    pub data_size: u64,
    pub data_capacity: u64,
    pub original_size: u64,
    pub _unk: [u8; 8],
    pub encrypted: u8,
    pub _pad: [u8; 7],
}

/// `_Tree_node` in MSVC's `std::map` red-black tree. The cookie-map nodes
/// keyed on cookie name carry the address of the `CanonicalCookie` in
/// `value_address`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RbNode {
    pub left: u64,
    pub right: u64,
    pub parent: u64,
    pub is_black: u8,
    pub _pad: [u8; 7],
    pub key: OptimizedString,
    pub value_address: u64,
}

/// `_Tree` head in MSVC's `std::map`: pointer to the sentinel "header"
/// node (whose `left` is the leftmost real node = `begin()`) and the tree
/// size.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RbRoot {
    pub begin_node: u64,
    pub first_node: u64,
    pub size: u64,
}

/// Read an [`OptimizedString`] into a Rust `String`. Handles both the
/// inline-23-byte and heap-allocated paths.
pub fn read_optimized_string(vmem: &dyn VirtualMemory, addr: u64) -> Result<String> {
    let buf = vmem.read_virt_bytes(addr, 24)?;
    let len = buf[23] as usize;
    if len <= 22 {
        Ok(String::from_utf8_lossy(&buf[..len]).into_owned())
    } else {
        // Heap-allocated: bytes 0..8 are a pointer to the char buffer, and
        // the real length lives at offset 0x10 of the std::string struct.
        // Cap at 8 KiB to bound a corrupt-pointer scenario.
        let str_ptr = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let str_len_raw = vmem.read_virt_u64(addr + 16).unwrap_or(len as u64);
        let str_len = (str_len_raw as usize).min(8192);
        if str_ptr == 0 || str_len == 0 {
            return Ok(String::new());
        }
        let bytes = vmem.read_virt_bytes(str_ptr, str_len)?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }
}

/// One decoded cookie from an in-process struct walk.
#[derive(Debug, Clone)]
pub struct InProcessCookie {
    pub name: String,
    pub domain: String,
    pub path: String,
    pub value: String,
    pub secure: bool,
    pub http_only: bool,
}

/// Browser-variant `CanonicalCookie` layouts. Selected at the call site
/// based on the browser image + Chromium major version. Field-offset
/// sources are `ChromeKatz/CookieKatz/Memory.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookieVariant {
    /// Chrome ≥ 130 with `ProcessBoundString` value.
    Chrome130Pb,
    /// Chrome ≥ 130 with `OptimizedString` value (post-PB rollback).
    Chrome130,
    /// Chrome 124 (legacy 120-byte partition_key).
    Chrome124,
    /// Edge ≥ 130 with `ProcessBoundString` value.
    Edge130Pb,
    /// Edge ≥ 130 with `OptimizedString` value.
    Edge130,
    /// Pre-vfptr legacy layout: four `OptimizedString`s + timestamps only.
    Legacy,
}

impl CookieVariant {
    fn name_offset(self) -> usize {
        match self {
            CookieVariant::Legacy => 0,
            _ => 8, // skip vfptr
        }
    }

    fn domain_offset(self) -> usize {
        match self {
            CookieVariant::Legacy => 24 * 2,
            _ => 8 + 24,
        }
    }

    fn path_offset(self) -> usize {
        match self {
            CookieVariant::Legacy => 24 * 3,
            _ => 8 + 24 * 2,
        }
    }

    /// `(secure_offset, http_only_offset)`. `None` for the legacy layout
    /// which stores neither in the same struct.
    fn flags_offset(self) -> Option<(usize, usize)> {
        match self {
            CookieVariant::Legacy => None,
            _ => Some((8 + 24 * 3 + 8, 8 + 24 * 3 + 8 + 1)),
        }
    }

    /// Offset of the cookie value field. ChromeKatz layouts:
    ///   8 vfptr + 24 name + 24 domain + 24 path + 8 creation_date +
    ///   1 secure + 1 http_only + 4 same_site +
    ///   partition_key{120|128|136} + 4 source_scheme + 4 source_port
    /// then the value.
    fn value_offset(self) -> usize {
        let header = 8 + 24 * 3 + 8 + 1 + 1 + 4;
        let pk = match self {
            CookieVariant::Chrome124 => 120,
            CookieVariant::Chrome130Pb | CookieVariant::Chrome130 => 128,
            CookieVariant::Edge130Pb | CookieVariant::Edge130 => 136,
            CookieVariant::Legacy => return 24, // second OptimizedString
        };
        header + pk + 4 + 4
    }

    fn is_process_bound(self) -> bool {
        matches!(self, CookieVariant::Chrome130Pb | CookieVariant::Edge130Pb)
    }
}

/// Decode one `CanonicalCookie` struct at `addr` according to `variant`.
pub fn read_cookie(
    vmem: &dyn VirtualMemory,
    addr: u64,
    variant: CookieVariant,
) -> Result<InProcessCookie> {
    let name = read_optimized_string(vmem, addr + variant.name_offset() as u64)?;
    let domain = read_optimized_string(vmem, addr + variant.domain_offset() as u64)?;
    let path = read_optimized_string(vmem, addr + variant.path_offset() as u64)?;
    let (secure, http_only) = match variant.flags_offset() {
        Some((s_off, h_off)) => (
            vmem.read_virt_bytes(addr + s_off as u64, 1)?[0] != 0,
            vmem.read_virt_bytes(addr + h_off as u64, 1)?[0] != 0,
        ),
        None => (false, false),
    };
    let value = if variant.is_process_bound() {
        read_process_bound_value(vmem, addr + variant.value_offset() as u64)
    } else {
        read_optimized_string(vmem, addr + variant.value_offset() as u64)?
    };
    Ok(InProcessCookie {
        name,
        domain,
        path,
        value,
        secure,
        http_only,
    })
}

fn read_process_bound_value(vmem: &dyn VirtualMemory, pb_addr: u64) -> String {
    let pb_buf = match vmem.read_virt_bytes(pb_addr, 48) {
        Ok(b) if b.len() == 48 => b,
        _ => return String::new(),
    };
    let encrypted = pb_buf[40] != 0;
    if encrypted {
        return String::from("<encrypted in-process>");
    }
    let data_ptr = u64::from_le_bytes(pb_buf[0..8].try_into().unwrap());
    let data_size = u64::from_le_bytes(pb_buf[8..16].try_into().unwrap()).min(8192);
    if data_ptr == 0 || data_size == 0 {
        return String::new();
    }
    match vmem.read_virt_bytes(data_ptr, data_size as usize) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(_) => String::new(),
    }
}

/// Walk an MSVC `std::map`-style red-black tree rooted at `root_addr` (a
/// pointer to an [`RbRoot`] struct). For each leaf node, call `visit` with
/// the `value_address` (which points at a `CanonicalCookie`). Returns the
/// number of nodes for which `visit` returned `true`.
pub fn walk_cookie_tree(
    vmem: &dyn VirtualMemory,
    root_addr: u64,
    mut visit: impl FnMut(u64) -> bool,
) -> Result<usize> {
    let begin_node = vmem.read_virt_u64(root_addr)?;
    let size = vmem.read_virt_u64(root_addr + 16).unwrap_or(0);
    if begin_node == 0 {
        return Ok(0);
    }
    let cap = (size as usize).clamp(256, 100_000);
    let mut count = 0usize;
    let mut stack = vec![begin_node];
    let mut visited: std::collections::HashSet<u64> = std::collections::HashSet::new();
    while let Some(node_addr) = stack.pop() {
        if node_addr == 0 || !visited.insert(node_addr) || visited.len() > cap {
            continue;
        }
        let node_buf = match vmem.read_virt_bytes(node_addr, std::mem::size_of::<RbNode>()) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if node_buf.len() < std::mem::size_of::<RbNode>() {
            continue;
        }
        let left = u64::from_le_bytes(node_buf[0..8].try_into().unwrap());
        let right = u64::from_le_bytes(node_buf[8..16].try_into().unwrap());
        // value_address is at offset 56: left(8) + right(8) + parent(8) +
        // is_black(1) + pad(7) + key OptimizedString(24) = 56.
        let value_addr = u64::from_le_bytes(node_buf[56..64].try_into().unwrap());
        if value_addr != 0 && visit(value_addr) {
            count += 1;
        }
        stack.push(left);
        stack.push(right);
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variant_offsets_chrome130() {
        let v = CookieVariant::Chrome130;
        assert_eq!(v.name_offset(), 8);
        assert_eq!(v.domain_offset(), 8 + 24);
        assert_eq!(v.path_offset(), 8 + 48);
        // 8 vfptr + 72 strings + 8 creation + 6 (1+1+4) + 128 pk + 8 (4+4) = 230
        assert_eq!(v.value_offset(), 230);
    }

    #[test]
    fn variant_offsets_edge130_pb() {
        let v = CookieVariant::Edge130Pb;
        // Edge partition_key is 136 bytes (8 more than Chrome).
        assert_eq!(v.value_offset(), 230 + 8);
        assert!(v.is_process_bound());
    }

    #[test]
    fn legacy_layout_has_no_flags() {
        assert!(CookieVariant::Legacy.flags_offset().is_none());
        // Value is the second OptimizedString after the cookie name.
        assert_eq!(CookieVariant::Legacy.value_offset(), 24);
    }
}
