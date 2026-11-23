use std::io::{Read, Seek};

use crate::error::{Result, VmkatzError};
use crate::fs::ntfs::ReadSeek;
use crate::fs::{find_ntfs_partitions, is_bitlocker_partition, select_partition};
use crate::lsass::bitlocker::BitLockerKey;

/// Consumer output and metadata, without retaining a complete NTDS file.
pub struct NtdsReadResult<T> {
    pub output: T,
    pub system_size: u64,
    pub partition_offset: u64,
}

/// Read SYSTEM with a bounded cache, then consume NTDS with its bootkey.
/// `output` carries SYSTEM/parser errors separately from filesystem lookup failures.
pub fn with_ntds_bootkey<R: Read + Seek, T>(
    reader: &mut R,
    partition_filter: Option<u64>,
    fvek_keys: &[BitLockerKey],
    consume: impl Fn(&mut dyn ReadSeek, &[u8; 16]) -> Result<T>,
) -> Result<NtdsReadResult<Result<T>>> {
    let prepare =
        |system: &mut dyn ReadSeek, _| super::bootkey::extract_bootkey_from_reader(system);
    let consume_with_key = |stream: &mut dyn ReadSeek, key: [u8; 16]| consume(stream, &key);
    let partitions = select_partition(find_ntfs_partitions(reader)?, partition_filter)?;
    let mut bitlocker_found = false;
    for partition_offset in partitions {
        if is_bitlocker_partition(reader, partition_offset) {
            bitlocker_found = true;
            if let Some(result) = super::try_bitlocker_fvek_candidates(
                reader,
                partition_offset,
                fvek_keys,
                |reader, offset| {
                    super::ntfs_reader::with_ntds_reader(reader, 0, &prepare, &consume_with_key)
                        .map(|(output, system_size)| NtdsReadResult {
                            output,
                            system_size,
                            partition_offset: offset,
                        })
                },
            )? {
                return Ok(result);
            }
            continue;
        }
        match super::ntfs_reader::with_ntds_reader(
            reader,
            partition_offset,
            &prepare,
            &consume_with_key,
        ) {
            Ok((output, system_size)) => {
                return Ok(NtdsReadResult {
                    output,
                    system_size,
                    partition_offset,
                });
            }
            Err(error) if error.is_resource_limit() => return Err(error),
            Err(error) => log::info!("Partition at 0x{partition_offset:x}: {error}"),
        }
    }
    Err(VmkatzError::DecryptionError(if bitlocker_found {
        "NTDS.dit unavailable on BitLocker partitions; provide a working recovery key or FVEK"
            .into()
    } else {
        "NTDS.dit not found on readable NTFS partitions".into()
    }))
}
