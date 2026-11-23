//! Logical primary-bank pages, including transparent encrypted-segment decoding.

use std::collections::BTreeSet;

use crate::veeam::{
    Result, VbkError,
    encryption::{EncryptionInfo, recover_reader_keysets},
    reader::FileReader,
};

use super::{MetadataLayout, MetadataRegion, MetadataSegment};

const PAGE_SIZE: u64 = 4_096;
const PAGE_SIZE_USIZE: usize = 4_096;
const ALLOCATION_MAP_OFFSET: usize = 4;
const PAGE_ALLOCATED: u8 = 0;
const PAGE_FREE: u8 = 1;
const KEYSET_ID_OFFSET: usize = 0xc04;
const KEYSET_ID_SIZE: usize = 16;
const ENCRYPTED_SIZE_OFFSET: usize = 0xc14;
const ENCRYPTED_DATA_OFFSET: u64 = PAGE_SIZE;
const MAX_PRIMARY_BANK_SIZE: u64 = 256 * 1024 * 1024;
const PAGE_LOCATION_SIZE: usize = 8;
const PAGE_STACK_FIRST_LOCATION: usize = 16;
const INVALID_PAGE_LOCATION: u64 = u64::MAX;

/// One page in the logical, decrypted metadata address space.
#[derive(Clone, Debug)]
pub(crate) struct MetadataPage {
    pub(crate) offset: u64,
    pub(crate) location: Option<u64>,
    pub(crate) bytes: Vec<u8>,
}

/// Materialized pages for the first primary metadata region.
#[derive(Debug)]
pub(crate) struct MetadataBank {
    pages: Vec<MetadataPage>,
}

impl MetadataBank {
    pub(crate) fn open_primary(
        reader: &FileReader,
        layout: &MetadataLayout,
        encryption: &EncryptionInfo,
        password: Option<&str>,
    ) -> Result<Self> {
        let region = layout
            .regions
            .first()
            .ok_or_else(|| invalid_bank(0, "metadata layout has no primary region"))?;
        let segments = region_segments(layout, region)?;
        Self::open_segments(
            reader,
            segments,
            region.first_segment_index,
            encryption,
            password,
        )
    }

    pub(crate) fn open_all_primary(
        reader: &FileReader,
        layout: &MetadataLayout,
        encryption: &EncryptionInfo,
        password: Option<&str>,
    ) -> Result<Self> {
        Self::open_segments(reader, &layout.segments, 0, encryption, password)
    }

    fn open_segments(
        reader: &FileReader,
        segments: &[MetadataSegment],
        first_segment_index: u64,
        encryption: &EncryptionInfo,
        password: Option<&str>,
    ) -> Result<Self> {
        validate_materialized_size(segments)?;
        let keysets = if encryption.encrypted {
            let password = password.ok_or_else(|| password_required(encryption))?;
            Some(recover_reader_keysets(reader, encryption, password)?)
        } else {
            None
        };
        let mut pages = Vec::new();
        for (relative_index, segment) in segments.iter().enumerate() {
            let relative_index = u64::try_from(relative_index).map_err(invalid_size)?;
            let segment_index = checked_add(first_segment_index, relative_index)?;
            append_segment_pages(reader, segment, segment_index, keysets.as_ref(), &mut pages)?;
        }
        Ok(Self { pages })
    }

    pub(crate) fn pages(&self) -> &[MetadataPage] {
        &self.pages
    }

    pub(crate) fn page_at(&self, location: u64) -> Option<&MetadataPage> {
        self.pages
            .iter()
            .find(|page| page.location == Some(location))
    }

    pub(crate) fn page_at_offset(&self, offset: u64) -> Option<&MetadataPage> {
        self.pages.iter().find(|page| page.offset == offset)
    }

    pub(crate) fn table_pages(&self) -> Result<(Vec<&MetadataPage>, bool)> {
        let mut locations = BTreeSet::new();
        for page in &self.pages {
            collect_page_stack_locations(self, page, &mut locations)?;
        }
        if locations.is_empty() {
            let pages = self
                .pages
                .iter()
                .filter(|page| page.location.is_some())
                .collect();
            return Ok((pages, false));
        }
        let pages = self
            .pages
            .iter()
            .filter(|page| {
                page.location
                    .is_some_and(|location| locations.contains(&location))
            })
            .collect();
        Ok((pages, true))
    }
}

fn collect_page_stack_locations(
    bank: &MetadataBank,
    root: &MetadataPage,
    locations: &mut BTreeSet<u64>,
) -> Result<()> {
    let Some(root_location) = root.location else {
        return Ok(());
    };
    if read_optional_u64(&root.bytes, 0) != Some(INVALID_PAGE_LOCATION)
        || read_optional_u64(&root.bytes, 8) != Some(root_location)
    {
        return Ok(());
    }
    let mut candidate = Vec::new();
    let mut relative = PAGE_STACK_FIRST_LOCATION;
    while let Some(location) = read_optional_u64(&root.bytes, relative) {
        if location == INVALID_PAGE_LOCATION {
            break;
        }
        if location == root_location || bank.page_at(location).is_none() {
            return Ok(());
        }
        candidate.push(location);
        relative = relative
            .checked_add(PAGE_LOCATION_SIZE)
            .ok_or_else(|| invalid_bank(root.offset, "page-stack location offset overflow"))?;
    }
    locations.extend(candidate);
    Ok(())
}

fn read_optional_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    let slice = bytes.get(offset..end)?;
    let array = <[u8; 8]>::try_from(slice).ok()?;
    Some(u64::from_le_bytes(array))
}

fn append_segment_pages(
    reader: &FileReader,
    segment: &MetadataSegment,
    segment_index: u64,
    keysets: Option<&crate::veeam::encryption::RecoveredKeysets>,
    pages: &mut Vec<MetadataPage>,
) -> Result<()> {
    let header = reader.read_bytes(segment.offset, PAGE_SIZE, "metadata segment header")?;
    let Some(keysets) = keysets else {
        return append_raw_segment(reader, segment, segment_index, &header, pages);
    };
    let identifier = read_array::<KEYSET_ID_SIZE>(&header, KEYSET_ID_OFFSET, segment.offset)?;
    let encrypted_size = u64::from(read_u32(&header, ENCRYPTED_SIZE_OFFSET, segment.offset)?);
    if identifier.iter().all(|byte| *byte == 0) || encrypted_size == 0 {
        return append_raw_segment(reader, segment, segment_index, &header, pages);
    }
    let page_count = u64::from(read_u16(&header, 0, segment.offset)?);
    let plaintext_size = checked_multiply(page_count, PAGE_SIZE, segment.offset)?;
    validate_encrypted_sizes(segment, encrypted_size, plaintext_size)?;
    let identifier_offset = checked_add(
        segment.offset,
        u64::try_from(KEYSET_ID_OFFSET).map_err(invalid_size)?,
    )?;
    let keyset = keysets
        .get(identifier)
        .ok_or_else(|| invalid_bank(identifier_offset, "metadata keyset was not recovered"))?;
    let ciphertext_offset = checked_add(segment.offset, ENCRYPTED_DATA_OFFSET)?;
    let ciphertext = reader.read_bytes(
        ciphertext_offset,
        encrypted_size,
        "encrypted metadata pages",
    )?;
    let plaintext = keyset.decrypt_padded(&ciphertext, ciphertext_offset)?;
    if u64::try_from(plaintext.len()).map_err(invalid_size)? != plaintext_size {
        return Err(invalid_bank(
            ciphertext_offset,
            "decrypted metadata length does not match its page count",
        ));
    }
    pages.push(MetadataPage {
        offset: segment.offset,
        location: None,
        bytes: header.clone(),
    });
    append_plaintext_pages(segment.offset, segment_index, &header, &plaintext, pages)
}

fn append_raw_segment(
    reader: &FileReader,
    segment: &MetadataSegment,
    segment_index: u64,
    header: &[u8],
    pages: &mut Vec<MetadataPage>,
) -> Result<()> {
    pages.push(MetadataPage {
        offset: segment.offset,
        location: None,
        bytes: header.to_vec(),
    });
    let allocated = allocated_page_indices(header, segment.offset)?;
    validate_raw_page_capacity(segment, header)?;
    for page_index in allocated {
        let physical_page_index = checked_add(page_index, 1)?;
        let relative = checked_multiply(physical_page_index, PAGE_SIZE, segment.offset)?;
        let offset = checked_add(segment.offset, relative)?;
        pages.push(MetadataPage {
            offset,
            location: Some(page_location(segment_index, page_index, segment.offset)?),
            bytes: reader.read_bytes(offset, PAGE_SIZE, "metadata page")?,
        });
    }
    Ok(())
}

fn append_plaintext_pages(
    segment_offset: u64,
    segment_index: u64,
    header: &[u8],
    plaintext: &[u8],
    pages: &mut Vec<MetadataPage>,
) -> Result<()> {
    for page_index in allocated_page_indices(header, segment_offset)? {
        let page = plaintext_page(plaintext, page_index, segment_offset)?;
        let relative = checked_multiply(page_index, PAGE_SIZE, segment_offset)?;
        let data_relative = checked_add(ENCRYPTED_DATA_OFFSET, relative)?;
        pages.push(MetadataPage {
            offset: checked_add(segment_offset, data_relative)?,
            location: Some(page_location(segment_index, page_index, segment_offset)?),
            bytes: page.to_vec(),
        });
    }
    Ok(())
}

fn allocated_page_indices(header: &[u8], offset: u64) -> Result<Vec<u64>> {
    let page_count = usize::from(read_u16(header, 0, offset)?);
    let end = ALLOCATION_MAP_OFFSET
        .checked_add(page_count)
        .ok_or_else(|| invalid_bank(offset, "metadata allocation map offset overflow"))?;
    let states = header
        .get(ALLOCATION_MAP_OFFSET..end)
        .ok_or_else(|| invalid_bank(offset, "metadata allocation map is truncated"))?;
    let mut allocated = Vec::new();
    for (index, state) in states.iter().copied().enumerate() {
        match state {
            PAGE_ALLOCATED => allocated.push(u64::try_from(index).map_err(invalid_size)?),
            PAGE_FREE => {}
            invalid => {
                return Err(invalid_bank(
                    offset,
                    &format!("unsupported metadata page allocation state {invalid}"),
                ));
            }
        }
    }
    Ok(allocated)
}

fn validate_raw_page_capacity(segment: &MetadataSegment, header: &[u8]) -> Result<()> {
    let page_count = u64::from(read_u16(header, 0, segment.offset)?);
    let data_length = checked_multiply(page_count, PAGE_SIZE, segment.offset)?;
    let required = checked_add(PAGE_SIZE, data_length)?;
    if required > segment.length {
        return Err(invalid_bank(
            segment.offset,
            "metadata allocation map exceeds the raw segment",
        ));
    }
    Ok(())
}

fn plaintext_page(plaintext: &[u8], page_index: u64, offset: u64) -> Result<&[u8]> {
    let start =
        usize::try_from(checked_multiply(page_index, PAGE_SIZE, offset)?).map_err(invalid_size)?;
    let end = start
        .checked_add(PAGE_SIZE_USIZE)
        .ok_or_else(|| invalid_bank(offset, "metadata plaintext page range overflow"))?;
    plaintext
        .get(start..end)
        .ok_or_else(|| invalid_bank(offset, "metadata plaintext page is truncated"))
}

fn page_location(segment_index: u64, page_index: u64, offset: u64) -> Result<u64> {
    let segment =
        u32::try_from(segment_index).map_err(|error| invalid_bank(offset, &error.to_string()))?;
    let page =
        u32::try_from(page_index).map_err(|error| invalid_bank(offset, &error.to_string()))?;
    Ok((u64::from(segment) << 32) | u64::from(page))
}

fn region_segments<'a>(
    layout: &'a MetadataLayout,
    region: &MetadataRegion,
) -> Result<&'a [MetadataSegment]> {
    let start = usize::try_from(region.first_segment_index).map_err(invalid_size)?;
    let count = usize::try_from(region.segment_count).map_err(invalid_size)?;
    let end = start.checked_add(count).ok_or_else(|| {
        invalid_bank(
            region.primary_offset,
            "metadata region segment range overflow",
        )
    })?;
    layout.segments.get(start..end).ok_or_else(|| {
        invalid_bank(
            region.primary_offset,
            "metadata region segment range is invalid",
        )
    })
}

fn validate_materialized_size(segments: &[MetadataSegment]) -> Result<()> {
    let mut size = 0_u64;
    for segment in segments {
        size = checked_add(size, segment.length)?;
    }
    if size > MAX_PRIMARY_BANK_SIZE {
        return Err(VbkError::LimitExceeded {
            resource: "materialized primary metadata bank",
            actual: size,
            limit: MAX_PRIMARY_BANK_SIZE,
        });
    }
    Ok(())
}

fn validate_encrypted_sizes(
    segment: &MetadataSegment,
    ciphertext: u64,
    plaintext: u64,
) -> Result<()> {
    let expected_ciphertext = checked_add(plaintext, 16)?;
    let payload_end = checked_add(ENCRYPTED_DATA_OFFSET, ciphertext)?;
    if ciphertext != expected_ciphertext || payload_end > segment.length {
        return Err(invalid_bank(
            segment.offset,
            "encrypted metadata sizes do not match page count or segment allocation",
        ));
    }
    Ok(())
}

fn password_required(encryption: &EncryptionInfo) -> VbkError {
    let keyset_suffix = encryption
        .keyset_ids
        .first()
        .map_or_else(String::new, |identifier| format!(" (keyset {identifier})"));
    VbkError::PasswordRequired { keyset_suffix }
}

fn read_u16(bytes: &[u8], offset: usize, base: u64) -> Result<u16> {
    Ok(u16::from_le_bytes(read_array::<2>(bytes, offset, base)?))
}

fn read_u32(bytes: &[u8], offset: usize, base: u64) -> Result<u32> {
    Ok(u32::from_le_bytes(read_array::<4>(bytes, offset, base)?))
}

fn read_array<const SIZE: usize>(bytes: &[u8], offset: usize, base: u64) -> Result<[u8; SIZE]> {
    let end = offset
        .checked_add(SIZE)
        .ok_or_else(|| invalid_bank(base, "metadata header field offset overflow"))?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| invalid_bank(base, "metadata segment header is truncated"))?;
    <[u8; SIZE]>::try_from(slice).map_err(|error| invalid_bank(base, &error.to_string()))
}

fn checked_add(offset: u64, length: u64) -> Result<u64> {
    offset
        .checked_add(length)
        .ok_or(VbkError::OffsetOverflow { offset, length })
}

fn checked_multiply(value: u64, multiplier: u64, offset: u64) -> Result<u64> {
    value
        .checked_mul(multiplier)
        .ok_or(VbkError::OffsetOverflow {
            offset,
            length: value,
        })
}

fn invalid_size(error: std::num::TryFromIntError) -> VbkError {
    invalid_bank(0, &error.to_string())
}

fn invalid_bank(offset: u64, reason: &str) -> VbkError {
    VbkError::InvalidField {
        offset,
        field: "metadata_bank",
        reason: reason.to_owned(),
    }
}
