//! Compact page mappings with last-write-wins updates and bounded fragmentation.

use std::collections::BTreeMap;
use std::io;

const PAGE_SIZE: u64 = 4096;
// Includes headroom for BTreeMap nodes: below 16 MiB on 64-bit targets.
const MAX_RUNS: usize = 131_072;

/// `end` is an exclusive page number; offsets and strides are measured in bytes.
#[derive(Clone, Copy, Debug)]
struct Run {
    end: u64,
    offset: Option<u64>,
    stride: u64,
}

impl Run {
    fn at(self, delta: u64) -> Option<u64> {
        self.offset.map(|offset| offset + delta * self.stride)
    }

    fn joined(self, start: u64, next: Self) -> Option<Self> {
        let stride = match (self.offset, next.offset) {
            (None, None) => 0,
            (Some(a), Some(b)) => {
                let stride = if self.end - start == 1 {
                    b.checked_sub(a)?
                } else {
                    self.stride
                };
                if a.checked_add((self.end - start).checked_mul(stride)?)? != b
                    || (next.end - self.end > 1 && next.stride != stride)
                {
                    return None;
                }
                a.checked_add((next.end - start - 1).checked_mul(stride)?)?;
                stride
            }
            _ => return None,
        };
        Some(Self {
            end: next.end,
            stride,
            ..self
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageLocation {
    Zero,
    File(u64),
}

impl PageLocation {
    #[cfg(feature = "qemu")]
    pub(crate) const fn offset(self) -> Option<u64> {
        match self {
            Self::Zero => None,
            Self::File(offset) => Some(offset),
        }
    }
}

#[derive(Default)]
pub struct PageIndex {
    runs: BTreeMap<u64, Run>,
    page_count: u64,
}

impl PageIndex {
    #[cfg(feature = "qemu")]
    pub(crate) fn remove(&mut self, gpa: u64) -> io::Result<()> {
        let page = gpa / PAGE_SIZE;
        let Some((&start, &run)) = self.runs.range(..=page).next_back() else {
            return Ok(());
        };
        if page >= run.end {
            return Ok(());
        }
        if start < page && page + 1 < run.end && self.runs.len() == MAX_RUNS {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "Snapshot page index is too fragmented (131072-run metadata budget)",
            ));
        }
        self.runs.remove(&start);
        if start < page {
            self.runs.insert(start, Run { end: page, ..run });
        }
        if page + 1 < run.end {
            self.runs.insert(
                page + 1,
                Run {
                    offset: run.at(page + 1 - start),
                    ..run
                },
            );
        }
        self.page_count -= 1;
        Ok(())
    }

    /// `None` records an explicit zero page; an absent mapping remains distinct.
    pub(crate) fn insert(&mut self, gpa: u64, offset: Option<u64>) -> io::Result<()> {
        if !gpa.is_multiple_of(PAGE_SIZE)
            || gpa.checked_add(PAGE_SIZE).is_none()
            || offset.is_some_and(|offset| offset.checked_add(PAGE_SIZE).is_none())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid snapshot page address",
            ));
        }
        let page = gpa / PAGE_SIZE;
        let previous = self.runs.range(..=page).next_back().map(|(&k, &v)| (k, v));
        let containing = previous.filter(|(_, run)| page < run.end);
        if containing.is_some_and(|(start, run)| run.at(page - start) == offset) {
            return Ok(());
        }
        let replacement = Run {
            end: page + 1,
            offset,
            stride: 0,
        };
        if self.extend_previous(page, previous, replacement) {
            return Ok(());
        }
        let left = containing.map_or(previous, |(start, _)| {
            self.runs.range(..start).next_back().map(|(&k, &v)| (k, v))
        });
        let right = self.runs.range(page + 1..).next().map(|(&k, &v)| (k, v));
        let prefix = containing
            .filter(|(start, _)| *start < page)
            .map(|(start, run)| (start, Run { end: page, ..run }));
        let suffix = containing
            .filter(|(_, run)| page + 1 < run.end)
            .map(|(start, run)| {
                (
                    page + 1,
                    Run {
                        offset: run.at(page + 1 - start),
                        ..run
                    },
                )
            });

        // Merge on the stack before checking the budget or changing the index.
        let mut runs: [Option<(u64, Run)>; 5] = [None; 5];
        let mut count = 0;
        for (start, run) in [left, prefix, Some((page, replacement)), suffix, right]
            .into_iter()
            .flatten()
        {
            if count > 0
                && let Some((prev_start, prev)) = runs[count - 1]
                && prev.end == start
                && let Some(joined) = prev.joined(prev_start, run)
            {
                runs[count - 1] = Some((prev_start, joined));
                continue;
            }
            runs[count] = Some((start, run));
            count += 1;
        }
        let removed = [left, containing, right];
        let removed_count = removed.iter().flatten().count();
        if self.runs.len() - removed_count + count > MAX_RUNS {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "Snapshot page index is too fragmented (131072-run metadata budget)",
            ));
        }
        for (start, _) in removed.into_iter().flatten() {
            self.runs.remove(&start);
        }
        for (start, run) in runs.into_iter().flatten() {
            self.runs.insert(start, run);
        }
        if containing.is_none() {
            self.page_count += 1;
        }
        Ok(())
    }

    /// Extend a consecutive run without allocating a tree node.
    fn extend_previous(
        &mut self,
        page: u64,
        previous: Option<(u64, Run)>,
        replacement: Run,
    ) -> bool {
        let Some((start, prev)) = previous.filter(|(_, run)| run.end == page) else {
            return false;
        };
        let Some(mut joined) = prev.joined(start, replacement) else {
            return false;
        };
        if let Some(&next) = self.runs.get(&(page + 1))
            && let Some(both) = joined.joined(start, next)
        {
            joined = both;
            self.runs.remove(&(page + 1));
        }
        self.runs.insert(start, joined);
        self.page_count += 1;
        true
    }

    pub(crate) fn get(&self, gpa: u64) -> Option<PageLocation> {
        let page = gpa / PAGE_SIZE;
        let (&start, &run) = self.runs.range(..=page).next_back()?;
        (page < run.end).then(|| {
            run.at(page - start)
                .map_or(PageLocation::Zero, PageLocation::File)
        })
    }

    pub(crate) const fn page_count(&self) -> u64 {
        self.page_count
    }

    #[cfg(feature = "vbox")]
    pub(crate) fn phys_end(&self) -> Option<u64> {
        self.runs
            .last_key_value()
            .map(|(_, run)| run.end * PAGE_SIZE)
    }
}

#[cfg(test)]
mod tests;
