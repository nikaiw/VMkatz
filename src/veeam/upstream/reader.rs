use std::{fs::File, path::Path};

use crate::utils::read_exact_at;

use crate::veeam::{Result, VbkError};

pub(crate) const MAX_FIELD_ALLOCATION: u64 = 16 * 1024 * 1024;

#[derive(Debug)]
pub(crate) struct FileReader {
    file: File,
    length: u64,
}

impl FileReader {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        let file = File::open(path)?;
        let length = file.metadata()?.len();
        Ok(Self { file, length })
    }

    pub(crate) const fn length(&self) -> u64 {
        self.length
    }

    pub(crate) fn read_array<const SIZE: usize>(&self, offset: u64) -> Result<[u8; SIZE]> {
        let length = u64::try_from(SIZE).map_err(|error| VbkError::InvalidField {
            offset,
            field: "read_length",
            reason: error.to_string(),
        })?;
        self.validate_range(offset, length)?;

        let mut bytes = [0_u8; SIZE];
        read_exact_at(&self.file, &mut bytes, offset)?;
        Ok(bytes)
    }

    pub(crate) fn read_bytes(
        &self,
        offset: u64,
        length: u64,
        resource: &'static str,
    ) -> Result<Vec<u8>> {
        if length > MAX_FIELD_ALLOCATION {
            return Err(VbkError::LimitExceeded {
                resource,
                actual: length,
                limit: MAX_FIELD_ALLOCATION,
            });
        }
        self.validate_range(offset, length)?;
        let allocation = usize::try_from(length).map_err(|error| VbkError::InvalidField {
            offset,
            field: resource,
            reason: error.to_string(),
        })?;
        let mut bytes = vec![0_u8; allocation];
        read_exact_at(&self.file, &mut bytes, offset)?;
        Ok(bytes)
    }

    fn validate_range(&self, offset: u64, length: u64) -> Result<()> {
        let end = offset
            .checked_add(length)
            .ok_or(VbkError::OffsetOverflow { offset, length })?;
        if end > self.length {
            return Err(VbkError::RangeOutsideFile {
                offset,
                length,
                file_length: self.length,
            });
        }
        Ok(())
    }
}

pub(crate) fn read_u8(reader: &FileReader, offset: u64) -> Result<u8> {
    let bytes = reader.read_array::<1>(offset)?;
    bytes
        .first()
        .copied()
        .ok_or_else(|| VbkError::InvalidField {
            offset,
            field: "u8",
            reason: "empty fixed-size read".to_owned(),
        })
}

pub(crate) fn read_u32(reader: &FileReader, offset: u64) -> Result<u32> {
    let bytes = reader.read_array::<4>(offset)?;
    Ok(u32::from_le_bytes(bytes))
}

pub(crate) fn read_u64(reader: &FileReader, offset: u64) -> Result<u64> {
    let bytes = reader.read_array::<8>(offset)?;
    Ok(u64::from_le_bytes(bytes))
}
