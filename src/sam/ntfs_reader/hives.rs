use std::io::{Read, Seek};

use crate::error::{Result, VmkatzError};
use crate::fs::ntfs::ResilientReader;
use crate::fs::{PartitionReader, find_entry, with_file_data};
use crate::sam::{DiskSecrets, bootkey, hashes, hive::Hive};

pub fn read_secrets<R: Read + Seek>(reader: &mut R, offset: u64) -> Result<Result<DiskSecrets>> {
    match consume(&mut PartitionReader::new(reader, offset)) {
        Ok(parsed) => Ok(parsed),
        Err(error)
            if error.is_resource_limit() || matches!(error, VmkatzError::NtfsEntryNotFound(_)) =>
        {
            Err(error)
        }
        Err(error) => {
            log::info!("NTFS traversal error: {error}, trying bounded hive recovery");
            let (sam, system, security) =
                crate::fs::ntfs_fallback::try_mftmirr_fallback(reader, offset)?;
            Ok(crate::sam::process_hive_data(
                &sam,
                &system,
                security.as_deref(),
            ))
        }
    }
}

fn with_hive<R: Read + Seek, T>(
    file: &ntfs::NtfsFile<'_>,
    reader: &mut R,
    consume: impl FnOnce(&Hive<'_>) -> Result<T>,
) -> Result<Result<T>> {
    with_file_data(file, reader, |stream, len| {
        Ok(Hive::from_reader(ResilientReader::new(stream, len))
            .and_then(|hive| hive.finish(consume(&hive))))
    })
}

fn consume<R: Read + Seek>(reader: &mut R) -> Result<Result<DiskSecrets>> {
    let ntfs = ntfs::Ntfs::new(reader).map_err(std::io::Error::from)?;
    let root = ntfs.root_directory(reader).map_err(std::io::Error::from)?;
    let windows = find_entry(&ntfs, &root, reader, "Windows")?;
    let system32 = find_entry(&ntfs, &windows, reader, "System32")?;
    let config = find_entry(&ntfs, &system32, reader, "config")?;
    let sam_file = find_entry(&ntfs, &config, reader, "SAM")?;
    let system_file = find_entry(&ntfs, &config, reader, "SYSTEM")?;
    let boot_key = match with_hive(&system_file, reader, bootkey::extract_bootkey_from_hive)? {
        Ok(key) => key,
        Err(error) => return Ok(Err(error)),
    };
    let (sam_entries, machine_sid) = match with_hive(&sam_file, reader, |hive| {
        let entries = hashes::extract_hashes_from_hive(hive, &boot_key)?;
        Ok((entries, hashes::extract_machine_sid_from_hive(hive)))
    })? {
        Ok(parsed) => parsed,
        Err(error) => return Ok(Err(error)),
    };
    let (lsa_secrets, cached_credentials) = match find_entry(&ntfs, &config, reader, "SECURITY") {
        Ok(file) => match with_hive(&file, reader, |hive| {
            crate::sam::process_security_hive(hive, &boot_key)
        })
        .and_then(|parsed| parsed)
        {
            Ok(parsed) => parsed,
            Err(error) if error.is_resource_limit() || matches!(error, VmkatzError::Io(_)) => {
                return Ok(Err(error));
            }
            Err(error) => {
                log::warn!("SECURITY extraction failed: {error}");
                (Vec::new(), Vec::new())
            }
        },
        Err(error) if error.is_resource_limit() => return Err(error),
        Err(_) => (Vec::new(), Vec::new()),
    };
    Ok(Ok(DiskSecrets {
        sam_entries,
        lsa_secrets,
        cached_credentials,
        machine_sid,
    }))
}
