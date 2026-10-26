//! SAM/SYSTEM/SECURITY hive + NTDS artifact extraction from an NTFS
//! partition, built on the generic primitives in `crate::fs`.

use std::io::{Read, Seek};

use super::ntfs_fallback;
use crate::error::{Result, VmkatzError};
use crate::fs::{PartitionReader, find_entry, read_file_data};

/// Read SAM, SYSTEM, and (optionally) SECURITY hive files from NTFS filesystem.
/// On I/O errors during directory traversal, falls back to MFTMirr approach.
pub(super) fn read_hive_files<R: Read + Seek>(
    reader: &mut R,
    partition_offset: u64,
) -> Result<super::HiveFiles> {
    // Wrap reader with partition offset
    let mut part_reader = PartitionReader::new(reader, partition_offset);

    let ntfs = match ntfs::Ntfs::new(&mut part_reader) {
        Ok(n) => n,
        Err(e) => {
            log::info!("NTFS parse error: {e}, trying MFTMirr fallback");
            return ntfs_fallback::try_mftmirr_fallback(part_reader.inner_mut(), partition_offset);
        }
    };

    match ntfs.root_directory(&mut part_reader) {
        Ok(root) => {
            // Navigate: Windows/System32/config/
            // Wrap the entire traversal to catch I/O errors mid-way
            let result = (|| -> Result<super::HiveFiles> {
                let windows = find_entry(&ntfs, &root, &mut part_reader, "Windows")?;
                let system32 = find_entry(&ntfs, &windows, &mut part_reader, "System32")?;
                let config = find_entry(&ntfs, &system32, &mut part_reader, "config")?;

                let sam_file = find_entry(&ntfs, &config, &mut part_reader, "SAM")?;
                let system_file = find_entry(&ntfs, &config, &mut part_reader, "SYSTEM")?;

                let sam_data = read_file_data(&sam_file, &mut part_reader)?;
                let system_data = read_file_data(&system_file, &mut part_reader)?;

                // SECURITY hive is optional
                let security_data = find_entry(&ntfs, &config, &mut part_reader, "SECURITY")
                    .ok()
                    .and_then(|f| read_file_data(&f, &mut part_reader).ok());

                Ok((sam_data, system_data, security_data))
            })();

            match result {
                Ok(hives) => Ok(hives),
                // A clean "entry not found" means the directory index was fully
                // enumerated — the file is genuinely absent from this partition
                // (a WinRE/OEM partition has no \Windows). The MFTMirr scan
                // cannot find what the index does not list; report and let the
                // caller move on to the next partition.
                Err(e) if matches!(e, VmkatzError::DiskFormatError(_)) => {
                    log::info!("Partition at 0x{partition_offset:x}: {e}");
                    Err(e)
                }
                Err(e) => {
                    log::info!("NTFS traversal error: {e}, trying MFTMirr fallback");
                    drop(ntfs);
                    ntfs_fallback::try_mftmirr_fallback(part_reader.inner_mut(), partition_offset)
                }
            }
        }
        Err(e) => {
            log::info!("NTFS root dir error: {e}, trying MFTMirr fallback");
            drop(ntfs);
            ntfs_fallback::try_mftmirr_fallback(part_reader.inner_mut(), partition_offset)
        }
    }
}

/// Read NTDS.dit + SYSTEM hive from NTFS filesystem.
/// Uses resilient file reads — I/O errors on individual clusters are zero-filled.
/// On I/O/parse errors falls back to the MFTMirr scan; a clean "entry not found"
/// (no \Windows\NTDS on this partition) is returned as-is so the caller can
/// move on to the next partition without a full MFT scan.
pub(super) fn read_ntds_artifacts<R: Read + Seek>(
    reader: &mut R,
    partition_offset: u64,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut part_reader = PartitionReader::new(reader, partition_offset);

    let ntfs = match ntfs::Ntfs::new(&mut part_reader) {
        Ok(n) => n,
        Err(e) => {
            log::info!("NTFS parse error: {e}, trying MFTMirr fallback for NTDS");
            return ntfs_fallback::try_mftmirr_fallback_ntds(
                part_reader.inner_mut(),
                partition_offset,
            );
        }
    };

    let root = match ntfs.root_directory(&mut part_reader) {
        Ok(r) => r,
        Err(e) => {
            log::info!("NTFS root dir error: {e}, trying MFTMirr fallback for NTDS");
            drop(ntfs);
            return ntfs_fallback::try_mftmirr_fallback_ntds(
                part_reader.inner_mut(),
                partition_offset,
            );
        }
    };

    let result = (|| -> Result<(Vec<u8>, Vec<u8>)> {
        let windows = find_entry(&ntfs, &root, &mut part_reader, "Windows")?;
        let ntds_dir = find_entry(&ntfs, &windows, &mut part_reader, "NTDS")?;
        let ntds_file = find_entry(&ntfs, &ntds_dir, &mut part_reader, "ntds.dit")?;
        let ntds_data = read_file_data(&ntds_file, &mut part_reader)?;

        let system32 = find_entry(&ntfs, &windows, &mut part_reader, "System32")?;
        let config = find_entry(&ntfs, &system32, &mut part_reader, "config")?;
        let system_file = find_entry(&ntfs, &config, &mut part_reader, "SYSTEM")?;
        let system_data = read_file_data(&system_file, &mut part_reader)?;

        Ok((ntds_data, system_data))
    })();

    match result {
        Ok(data) => Ok(data),
        Err(e) if matches!(e, VmkatzError::DiskFormatError(_)) => {
            log::info!("Partition at 0x{partition_offset:x}: {e}");
            Err(e)
        }
        Err(e) => {
            log::info!("NTFS traversal error: {e}, trying MFTMirr fallback for NTDS");
            drop(ntfs);
            ntfs_fallback::try_mftmirr_fallback_ntds(part_reader.inner_mut(), partition_offset)
        }
    }
}
