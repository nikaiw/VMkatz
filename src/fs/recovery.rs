//! Fixed budgets for automatic recovery of damaged disks. Limits are errors,
//! never successful partial results. A blocked kernel read cannot be interrupted
//! by these cooperative checks.
use std::time::{Duration, Instant};

use crate::error::{Result, VmkatzError};

#[cfg(feature = "sam")]
pub const MAX_RAW_DISK_BYTES: u64 = 1024 * 1024 * 1024;
#[cfg(any(feature = "sam", test))]
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_CANDIDATES: usize = 65_536;
const MAX_SCAN_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SCAN_RECORDS: u64 = 65_536;
const MAX_DURATION: Duration = Duration::from_secs(30);

pub struct ScanBudget {
    started: Instant,
    bytes: u64,
    records: u64,
}

impl ScanBudget {
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            bytes: 0,
            records: 0,
        }
    }

    pub fn check_time(&self) -> Result<()> {
        if self.started.elapsed() >= MAX_DURATION {
            return Err(VmkatzError::RecoveryLimit(
                "30-second recovery deadline reached",
            ));
        }
        Ok(())
    }

    /// Charge attempted work, including failed reads and seeks.
    pub fn charge(&mut self, bytes: u64, records: u64) -> Result<()> {
        self.check_time()?;
        self.bytes = self.bytes.saturating_add(bytes);
        self.records = self.records.saturating_add(records);
        if self.bytes > MAX_SCAN_BYTES || self.records > MAX_SCAN_RECORDS {
            return Err(VmkatzError::RecoveryLimit(
                "MFT scan budget reached (64 MiB / 65536 records)",
            ));
        }
        Ok(())
    }
}

#[cfg(feature = "sam")]
pub const fn check_raw_size(size: u64) -> Result<()> {
    if size > MAX_RAW_DISK_BYTES {
        return Err(VmkatzError::RecoveryLimit(
            "automatic whole-disk recovery disabled above 1 GiB; NTFS lookup remains available",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deadline_is_checked_without_sleeping() {
        let mut budget = ScanBudget::new();
        budget.started -= MAX_DURATION;
        assert!(matches!(
            budget.charge(1, 1),
            Err(VmkatzError::RecoveryLimit(_))
        ));
    }
}
