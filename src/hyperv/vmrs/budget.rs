use super::RAM_BLOCK_SIZE;

const MAX_CACHE_BLOCKS: usize = 128;
const MAX_WORKERS: usize = 8;
pub(super) const WORKER_STACK_BYTES: usize = 2 * RAM_BLOCK_SIZE;
// Compressed input, decompressed output and the explicitly sized thread stack.
const BLOCKS_PER_WORKER: usize = 2 + WORKER_STACK_BYTES / RAM_BLOCK_SIZE;

pub(super) fn cache_blocks() -> usize {
    crate::utils::cache_budget_bytes().map_or(MAX_CACHE_BLOCKS, |bytes| {
        usize::try_from(bytes / RAM_BLOCK_SIZE as u64)
            .unwrap_or(usize::MAX)
            .min(MAX_CACHE_BLOCKS)
    })
}

pub(super) struct ScanBudget {
    pub workers: usize,
    pub retained_blocks: usize,
}

impl ScanBudget {
    pub fn new(blocks: usize, processors: usize, jobs: usize) -> Option<Self> {
        let workers = processors
            .min(jobs)
            .min(MAX_WORKERS)
            .min(blocks / BLOCKS_PER_WORKER);
        if workers == 0 {
            return None;
        }
        Some(Self {
            workers,
            retained_blocks: blocks - workers * BLOCKS_PER_WORKER,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workers_and_retention_share_the_budget() {
        for blocks in [0, 1, 3, 4, 8, 16, 128] {
            for processors in [0, 1, 8, 256] {
                for jobs in [0, 1, 10_000] {
                    let budget = ScanBudget::new(blocks, processors, jobs);
                    if blocks < BLOCKS_PER_WORKER || processors == 0 || jobs == 0 {
                        assert!(budget.is_none());
                        continue;
                    }
                    let budget = budget.expect("at least one worker fits");
                    assert!(budget.workers <= MAX_WORKERS);
                    assert!(budget.workers <= processors.min(jobs));
                    assert_eq!(
                        budget.retained_blocks + budget.workers * BLOCKS_PER_WORKER,
                        blocks
                    );
                }
            }
        }
    }
}
