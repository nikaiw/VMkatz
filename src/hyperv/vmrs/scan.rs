//! Parallel RAM scans with a shared worker/cache budget.

use std::sync::{
    Mutex, PoisonError,
    atomic::{AtomicBool, Ordering},
};

use super::compression::vm_compress_unpack;
use super::{BlockCache, RAM_BLOCK_SIZE, VmrsLayer, budget, metadata};

impl VmrsLayer {
    /// Decompress and scan every RAM block in parallel. Workers pull locations
    /// from the immutable key/object tables. Retained blocks and worker
    /// buffers share a fixed budget; callbacks may allocate their own memory.
    pub(super) fn scan_ram(&self, visit: &(dyn Fn(u64, &[u8]) -> bool + Sync)) -> bool {
        if self.ram_block_count == 0 {
            return false;
        }
        let mut pending = metadata::ram_jobs(
            &self.key_values,
            &self.object_entries,
            self.ram_block_count,
            self.mmio_gap_base,
            self.mmio_gap_size,
        )
        .peekable();
        if pending.peek().is_none() {
            return false;
        }
        let jobs = Mutex::new(pending);
        let job_bound = self
            .key_values
            .len()
            .saturating_add(self.object_entries.len());
        let block_budget = self.inner.borrow().cache.limit.min(budget::cache_blocks());
        self.inner.borrow_mut().cache.set_limit(block_budget);
        let processors =
            std::thread::available_parallelism().map_or(4, std::num::NonZeroUsize::get);
        let Some(scan_budget) = budget::ScanBudget::new(block_budget, processors, job_bound) else {
            return false;
        };
        // Keep reading the opened snapshot even if its path is renamed or replaced.
        let file = match self.inner.borrow().file.try_clone() {
            Ok(file) => file,
            Err(error) => {
                log::warn!("VMRS: cannot clone scan handle ({error}); using sequential reads");
                return false;
            }
        };
        let failed = AtomicBool::new(false);
        let mut retained = Vec::new();
        if let Err(error) = retained.try_reserve_exact(scan_budget.retained_blocks) {
            log::warn!("VMRS: cannot allocate scan cache ({error}); using sequential reads");
            return false;
        }
        let keep = Mutex::new(retained);
        // Release the previous cache before retaining scanned blocks.
        self.inner.borrow_mut().cache = BlockCache::with_limit(block_budget);
        let started = std::thread::scope(|scope| {
            let mut started = 0;
            for _ in 0..scan_budget.workers {
                let worker = std::thread::Builder::new()
                    .stack_size(budget::WORKER_STACK_BYTES)
                    .spawn_scoped(scope, || {
                        loop {
                            let job = jobs.lock().unwrap_or_else(PoisonError::into_inner).next();
                            let Some((block_index, gpa, file_offset, compressed_size)) = job else {
                                break;
                            };
                            let mut raw =
                                match crate::utils::zeroed_buffer(compressed_size as usize) {
                                    Ok(raw) => raw,
                                    Err(error) => {
                                        log::warn!("VMRS worker allocation failed: {error}");
                                        failed.store(true, Ordering::Relaxed);
                                        break;
                                    }
                                };
                            if crate::utils::read_exact_at(&file, &mut raw, file_offset).is_err() {
                                failed.store(true, Ordering::Relaxed);
                                continue;
                            }
                            let block = if compressed_size as usize == RAM_BLOCK_SIZE {
                                raw
                            } else {
                                vm_compress_unpack(&raw)
                            };
                            if visit(gpa, &block) {
                                let mut retained_blocks =
                                    keep.lock().unwrap_or_else(PoisonError::into_inner);
                                if retained_blocks.len() < scan_budget.retained_blocks {
                                    retained_blocks.push((block_index, block));
                                }
                            }
                        }
                    });
                if let Err(error) = worker {
                    log::warn!("VMRS: cannot start scan worker ({error})");
                    break;
                }
                started += 1;
            }
            started
        });
        if started == 0 {
            return false;
        }

        // Transfer the retained buffers without growing the cache budget.
        let kept = keep.into_inner().unwrap_or_else(PoisonError::into_inner);
        let mut inner = self.inner.borrow_mut();
        for (block_index, block) in kept {
            inner.cache.insert(block_index, block);
        }
        if failed.into_inner() {
            log::warn!("VMRS: incomplete parallel scan; retrying sequentially");
            return false;
        }
        true
    }
}
