//! HybridKeyring — a MasterkeyResolver backed by cleartext DPAPI master keys
//! collected from LSASS memory, with optional disk fallback.
//!
//! Populate `from_memory` by GUID -> cleartext masterkey bytes. The keyring implements
//! `MasterkeyResolver` so it can be passed directly to `chrome::disk::extract_from_disk`.
//! When a GUID is found in memory, downstream tags the source as
//! `ChromeSource::HybridMemKey`. Disk-fallback resolution is the caller's responsibility
//! (compose with a second resolver).

use std::collections::HashMap;

use crate::chrome::disk::MasterkeyResolver;

#[derive(Default, Debug, Clone)]
pub struct HybridKeyring {
    /// MK GUID (lowercase, mixed-endian formatted) -> cleartext masterkey bytes
    pub from_memory: HashMap<String, Vec<u8>>,
    /// PID lsass was extracted from; informational.
    pub mem_source_pid: Option<u32>,
}

impl HybridKeyring {
    pub fn new() -> Self { Self::default() }

    pub fn insert(&mut self, mk_guid: impl Into<String>, masterkey: Vec<u8>) {
        self.from_memory.insert(mk_guid.into(), masterkey);
    }

    pub fn len(&self) -> usize { self.from_memory.len() }
    pub fn is_empty(&self) -> bool { self.from_memory.is_empty() }
}

impl MasterkeyResolver for HybridKeyring {
    fn resolve(&self, mk_guid: &str) -> Option<Vec<u8>> {
        self.from_memory.get(mk_guid).cloned()
    }
}

/// Compose two resolvers: try `primary` first, fall back to `fallback`. Returns the
/// matched bytes regardless of which resolver supplied them. Source-tagging is the
/// orchestrator's responsibility (currently always `DiskDpapi` from disk.rs — Task 18
/// can refine this).
pub struct ComposedResolver<'a, A: MasterkeyResolver, B: MasterkeyResolver> {
    pub primary: &'a A,
    pub fallback: &'a B,
}

impl<'a, A: MasterkeyResolver, B: MasterkeyResolver> MasterkeyResolver for ComposedResolver<'a, A, B> {
    fn resolve(&self, mk_guid: &str) -> Option<Vec<u8>> {
        self.primary.resolve(mk_guid).or_else(|| self.fallback.resolve(mk_guid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_hit() {
        let mut hk = HybridKeyring::new();
        hk.insert("guid1", vec![1, 2, 3]);
        assert_eq!(hk.resolve("guid1"), Some(vec![1, 2, 3]));
    }

    #[test]
    fn lookup_miss() {
        let hk = HybridKeyring::new();
        assert!(hk.resolve("nope").is_none());
    }

    #[test]
    fn composed_falls_back() {
        let mut a = HybridKeyring::new();
        a.insert("a", vec![10]);
        let mut b = HybridKeyring::new();
        b.insert("b", vec![20]);
        let c = ComposedResolver { primary: &a, fallback: &b };
        assert_eq!(c.resolve("a"), Some(vec![10]));
        assert_eq!(c.resolve("b"), Some(vec![20]));
        assert_eq!(c.resolve("c"), None);
    }

    #[test]
    fn composed_primary_wins() {
        let mut a = HybridKeyring::new();
        a.insert("k", vec![1]);
        let mut b = HybridKeyring::new();
        b.insert("k", vec![2]);
        let c = ComposedResolver { primary: &a, fallback: &b };
        assert_eq!(c.resolve("k"), Some(vec![1]));
    }
}
