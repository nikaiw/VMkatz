use std::collections::BTreeMap;

use crate::error::{Result, VmkatzError};

const BITMAP_BYTES: usize = 4096;
const PAGES_PER_BITMAP: u32 = (BITMAP_BYTES * 8) as u32;
const MAX_BITMAP_BYTES: usize = 8 * 1024 * 1024;
const MAX_PENDING_PAGES: usize = 1 << 20;

/// Allocate visited bits only for page-number ranges actually reached.
pub(super) struct Walk {
    page_count: u64,
    visited: BTreeMap<u32, Vec<u8>>,
    pending: Vec<u32>,
}

impl Walk {
    pub(super) fn new(root: u32, page_count: u64) -> Result<Self> {
        let mut walk = Self {
            page_count,
            visited: BTreeMap::new(),
            pending: Vec::new(),
        };
        walk.push(root)?;
        Ok(walk)
    }

    pub(super) fn push(&mut self, page: u32) -> Result<()> {
        if page == 0 || u64::from(page) + 1 >= self.page_count {
            return Ok(());
        }
        let group = page / PAGES_PER_BITMAP;
        if !self.visited.contains_key(&group) {
            if self.visited.len() >= MAX_BITMAP_BYTES / BITMAP_BYTES {
                return Err(VmkatzError::AllocTooLarge {
                    what: "ESE visited pages",
                    requested: MAX_BITMAP_BYTES + BITMAP_BYTES,
                    limit: MAX_BITMAP_BYTES,
                });
            }
            self.visited
                .insert(group, crate::utils::zeroed_buffer(BITMAP_BYTES)?);
        }
        let bits = self
            .visited
            .get_mut(&group)
            .ok_or_else(|| std::io::Error::other("Missing ESE visited bitmap"))?;
        let bit = (page % PAGES_PER_BITMAP) as usize;
        let mask = 1 << (bit % 8);
        if bits[bit / 8] & mask != 0 {
            return Ok(());
        }
        if self.pending.len() >= MAX_PENDING_PAGES {
            return Err(VmkatzError::AllocTooLarge {
                what: "ESE pending pages",
                requested: (MAX_PENDING_PAGES + 1) * 4,
                limit: MAX_PENDING_PAGES * 4,
            });
        }
        self.pending
            .try_reserve(1)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::OutOfMemory, e))?;
        bits[bit / 8] |= mask;
        self.pending.push(page);
        Ok(())
    }

    pub(super) fn pop(&mut self) -> Option<u32> {
        self.pending.pop()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn huge_sparse_databases_only_allocate_reached_bitmap_ranges() -> Result<()> {
        let mut walk = Walk::new(4, (8u64 << 40) / 4096)?;
        let far = (1 << 31) - 2;
        walk.push(far)?;
        walk.push(far)?;
        walk.push(0)?;
        walk.push(u32::MAX)?;
        assert_eq!(walk.visited.len(), 2);
        assert_eq!(walk.pop(), Some(far));
        assert_eq!(walk.pop(), Some(4));
        walk.push(4)?;
        assert_eq!(walk.pop(), None);
        Ok(())
    }

    #[test]
    fn scattered_page_numbers_cannot_grow_bitmaps_past_the_budget() -> Result<()> {
        let mut walk = Walk::new(1, u64::from(u32::MAX))?;
        for group in 1..(MAX_BITMAP_BYTES / BITMAP_BYTES) as u32 {
            walk.push(group * PAGES_PER_BITMAP)?;
        }
        assert!(matches!(
            walk.push((MAX_BITMAP_BYTES / BITMAP_BYTES) as u32 * PAGES_PER_BITMAP),
            Err(VmkatzError::AllocTooLarge { .. })
        ));
        assert_eq!(walk.visited.len() * BITMAP_BYTES, MAX_BITMAP_BYTES);
        Ok(())
    }
}
