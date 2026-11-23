//! Streaming SAM/SYSTEM/SECURITY and NTDS reads from an NTFS partition.

use std::io::{Cursor, Read, Seek};

use crate::error::{Result, VmkatzError};
use crate::fs::ntfs::{ReadSeek, ResilientReader};
use crate::fs::{PartitionReader, find_entry, ntfs_fallback, with_file_data};

mod hives;
pub(super) use hives::read_secrets;

/// The inner result belongs to the consumer: parser errors must not cause MFT recovery.
fn consume_ntfs<R: Read + Seek, S, T>(
    reader: &mut R,
    prepare: &impl Fn(&mut dyn ReadSeek, u64) -> Result<S>,
    consume: &impl Fn(&mut dyn ReadSeek, S) -> Result<T>,
) -> Result<(Result<T>, u64)> {
    let ntfs = ntfs::Ntfs::new(reader)
        .map_err(|e| VmkatzError::DecryptionError(format!("NTFS parse error: {e}")))?;
    let root = ntfs
        .root_directory(reader)
        .map_err(|e| VmkatzError::DecryptionError(format!("NTFS root error: {e}")))?;
    let windows = find_entry(&ntfs, &root, reader, "Windows")?;
    let ntds_dir = find_entry(&ntfs, &windows, reader, "NTDS")?;
    let ntds_file = find_entry(&ntfs, &ntds_dir, reader, "ntds.dit")?;
    let system32 = find_entry(&ntfs, &windows, reader, "System32")?;
    let config = find_entry(&ntfs, &system32, reader, "config")?;
    let system_file = find_entry(&ntfs, &config, reader, "SYSTEM")?;
    let prepared = with_file_data(&system_file, reader, |stream, len| {
        Ok((prepare(&mut ResilientReader::new(stream, len), len), len))
    })?;
    let (system, system_len) = prepared;
    let system = match system {
        Ok(system) => system,
        Err(error) => return Ok((Err(error), system_len)),
    };
    with_file_data(&ntds_file, reader, |stream, len| {
        let result = consume(&mut ResilientReader::new(stream, len), system);
        Ok((result, system_len))
    })
}

pub(super) fn with_ntds_reader<R: Read + Seek, S, T>(
    reader: &mut R,
    partition_offset: u64,
    prepare: &impl Fn(&mut dyn ReadSeek, u64) -> Result<S>,
    consume: &impl Fn(&mut dyn ReadSeek, S) -> Result<T>,
) -> Result<(Result<T>, u64)> {
    let result = consume_ntfs(
        &mut PartitionReader::new(reader, partition_offset),
        prepare,
        consume,
    );
    match result {
        Ok(result) => Ok(result),
        Err(error)
            if error.is_resource_limit() || matches!(error, VmkatzError::NtfsEntryNotFound(_)) =>
        {
            Err(error)
        }
        Err(error) => {
            log::info!("NTFS traversal error: {error}, trying bounded MFTMirr recovery for NTDS");
            let (ntds, system) =
                ntfs_fallback::try_mftmirr_fallback_ntds(reader, partition_offset)?;
            let system_len = system.len() as u64;
            let result = prepare(&mut Cursor::new(system), system_len)
                .and_then(|system| consume(&mut Cursor::new(ntds), system));
            Ok((result, system_len))
        }
    }
}
