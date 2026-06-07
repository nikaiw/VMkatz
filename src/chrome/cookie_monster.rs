//! In-process `CanonicalCookie` struct layouts and helpers.
//!
//! Ported from Meckazin/ChromeKatz (`CookieKatz/Memory.h`). These structs
//! describe how Chrome / Edge store cookies in their browser-process heap.
//!
//! Locating the cookies via per-version code patterns (ChromeKatz's
//! 152-byte destructor-bytes signature) requires reverse-engineering each
//! Chrome major release in IDA. Until those signatures are committed,
//! [`crate::chrome::process_scan`] falls back to the heuristic ASCII /
//! UTF-16 scan in [`crate::chrome::heuristic`] for first-cut memory
//! extraction. The structs in this file are the precise targets the
//! signature work eventually unwraps; exposing them now means the
//! signature implementation only adds the locator, not the readers.

use crate::error::Result;
use crate::memory::VirtualMemory;

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
        let value_addr = u64::from_le_bytes(node_buf[48..56].try_into().unwrap());
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
