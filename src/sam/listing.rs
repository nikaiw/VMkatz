//! Directory listing orchestrator: healthy NTFS index first, degraded MFT scan as fallback.

use std::io::{Read, Seek};

use super::ntfs_fallback;
use crate::error::{Result, VmkatzError};
use crate::fs::ntfs::{finalize, list_index, navigate_to_dir};
use crate::fs::{DirEntry, PartitionReader};

/// Result of listing a path on an NTFS partition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListOutcome {
    /// Directory listed; `degraded` is true when the MFTMirr scan was used.
    Listed {
        entries: Vec<DirEntry>,
        degraded: bool,
    },
    /// The NTFS index is healthy and the path does not exist.
    PathNotFound,
    /// The index is unusable and the degraded scan could not resolve the path.
    PathUnresolvableDegraded,
}

/// List `path` on the NTFS partition at `partition_offset`.
///
/// A `DiskFormatError` from path navigation means the index is readable and the
/// entry is absent (`PathNotFound`, no fallback). Any other failure, including
/// NTFS bootstrap errors, falls back to the degraded MFT scan.
pub fn list_path<R: Read + Seek>(
    reader: &mut R,
    partition_offset: u64,
    path: &str,
) -> Result<ListOutcome> {
    match list_healthy(reader, partition_offset, path) {
        Ok(outcome) => return Ok(outcome),
        Err(e) => log::info!("healthy NTFS listing failed ({e}), trying MFT fallback"),
    }
    Ok(
        match ntfs_fallback::list_path_degraded(reader, partition_offset, path)? {
            Some(entries) => ListOutcome::Listed {
                entries,
                degraded: true,
            },
            None => ListOutcome::PathUnresolvableDegraded,
        },
    )
}

/// Healthy attempt; `Err` means "fall back" (never a `DiskFormatError` from navigation).
fn list_healthy<R: Read + Seek>(
    reader: &mut R,
    partition_offset: u64,
    path: &str,
) -> Result<ListOutcome> {
    let mut part = PartitionReader::new(reader, partition_offset);
    let ntfs = ntfs::Ntfs::new(&mut part)
        .map_err(|e| VmkatzError::DecryptionError(format!("NTFS parse error: {e}")))?;
    let root = ntfs
        .root_directory(&mut part)
        .map_err(|e| VmkatzError::DecryptionError(format!("NTFS root error: {e}")))?;
    let dir = match navigate_to_dir(&ntfs, &root, &mut part, path) {
        Ok(d) => d,
        Err(VmkatzError::DiskFormatError(_)) => return Ok(ListOutcome::PathNotFound),
        Err(e) => return Err(e),
    };
    let raw = list_index(&ntfs, &dir, &mut part)?;
    Ok(ListOutcome::Listed {
        entries: finalize(raw, true),
        degraded: false,
    })
}

#[cfg(test)]
mod tests {
    use super::super::ntfs_fallback::tests::{PART_OFF, build_volume};
    use super::*;
    use std::io::Cursor;

    fn volume() -> Cursor<Vec<u8>> {
        Cursor::new(build_volume(8, 7, true, false))
    }

    #[test]
    fn list_path_degrades_on_unparseable_index() {
        let mut r = volume();
        {
            let mut pr = PartitionReader::new(&mut r, PART_OFF);
            let ok = ntfs::Ntfs::new(&mut pr)
                .and_then(|n| n.root_directory(&mut pr).map(|_| ()))
                .is_ok();
            assert!(!ok, "precondition: synthetic volume must be unparseable");
        }
        match list_path(&mut r, PART_OFF, "").unwrap() {
            ListOutcome::Listed { entries, degraded } => {
                assert!(degraded);
                assert!(entries.iter().any(|e| e.name == "Users"));
                assert!(entries.iter().any(|e| e.name == "pagefile.sys"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn list_path_empty_dir_is_not_error() {
        let mut r = volume();
        match list_path(&mut r, PART_OFF, "Users").unwrap() {
            ListOutcome::Listed { entries, .. } => assert!(entries.is_empty()),
            other => panic!("unexpected {other:?}"),
        }
    }
}
