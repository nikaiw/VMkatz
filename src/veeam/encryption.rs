//! Discovery and recovery of Veeam encryption metadata.

mod hashcat;
mod keyset;

use std::{fmt::Write as _, path::Path};

use serde::Serialize;

use crate::veeam::{Result, VbkError, reader::FileReader};

pub use hashcat::{HASHCAT_VEEAM_VBK_MODE, hashcat_hashes};
pub(crate) use keyset::{RecoveredKeysets, recover_reader_keysets};

const SCAN_LIMIT: u64 = 16 * 1024 * 1024;
const KEYSET_MAGIC: [u8; 4] = [0x2e, 0xca, 0x10, 0xa1];
const RECORD_SENTINEL: [u8; 8] = [0xff; 8];
const STORAGE_PREFIX: &[u8] = b"Storage [Id:";
const SESSION_PREFIX: &[u8] = b"SessionId:";
const KEYSET_ID_SIZE: usize = 16;
const RECORD_HEADER_SIZE: usize = 0x30;
const MAX_RECORD_SIZE: u64 = 64 * 1024;
const MAX_HINT_LENGTH: usize = 0xfb;

/// Password-independent encryption information found in a backup.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct EncryptionInfo {
    /// Whether validated encryption records were found.
    pub encrypted: bool,
    /// Keyset identifiers referenced by storage or session descriptors, encoded as lowercase hexadecimal.
    pub keyset_ids: Vec<String>,
    /// Human-readable password hints stored by Veeam.
    pub password_hints: Vec<String>,
    /// Plaintext storage descriptions associated with keysets.
    pub storage_descriptors: Vec<String>,
    /// Wrapped-keyset record summaries; wrapped bytes are intentionally omitted.
    pub wrapped_keysets: Vec<WrappedKeysetInfo>,
}

/// Public fields of one password- or keyset-wrapped keyset record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WrappedKeysetInfo {
    /// Absolute record offset.
    pub record_offset: u64,
    /// KDF selector (`0`, `1`, or `2`).
    pub kdf_type: u32,
    /// PBKDF iteration count observed for this wrapper type.
    pub iterations: u32,
    /// Wrapped sub-keyset identifier as lowercase hexadecimal.
    pub sub_keyset_id: String,
    /// Wrapped payload size without exposing its bytes.
    pub payload_size: u64,
}

/// Inspect a backup for encryption metadata without requiring a password.
///
/// # Errors
///
/// Returns bounded IO, range, conversion, or malformed-record errors.
pub fn inspect_encryption(path: &Path) -> Result<EncryptionInfo> {
    let reader = FileReader::open(path)?;
    inspect_reader(&reader)
}

pub(crate) fn inspect_reader(reader: &FileReader) -> Result<EncryptionInfo> {
    let scan_length = reader.length().min(SCAN_LIMIT);
    let bytes = reader.read_bytes(0, scan_length, "encryption metadata scan")?;
    let (keyset_ids, storage_descriptors) = scan_storage_records(&bytes)?;
    let password_hints = scan_password_hints(&bytes);
    let wrapped_keysets = scan_wrapped_keysets(&bytes)?;
    let encrypted =
        !keyset_ids.is_empty() || !password_hints.is_empty() || !wrapped_keysets.is_empty();
    Ok(EncryptionInfo {
        encrypted,
        keyset_ids,
        password_hints,
        storage_descriptors,
        wrapped_keysets,
    })
}

fn scan_storage_records(bytes: &[u8]) -> Result<(Vec<String>, Vec<String>)> {
    let mut identifiers = Vec::new();
    let mut descriptors = Vec::new();
    let mut cursor = 0_usize;
    while let Some(position) = find_bytes(bytes, &KEYSET_MAGIC, cursor) {
        let window_end = position.saturating_add(512).min(bytes.len());
        let window = bytes
            .get(position..window_end)
            .ok_or_else(|| invalid_encryption(position, "keyset registry window is invalid"))?;
        parse_storage_window(window, &mut identifiers, &mut descriptors)?;
        cursor = position.saturating_add(KEYSET_MAGIC.len());
    }
    Ok((identifiers, descriptors))
}

fn parse_storage_window(
    window: &[u8],
    identifiers: &mut Vec<String>,
    descriptors: &mut Vec<String>,
) -> Result<()> {
    let descriptor_location = find_bytes(window, STORAGE_PREFIX, 0)
        .map(|offset| (offset, true))
        .or_else(|| find_bytes(window, SESSION_PREFIX, 0).map(|offset| (offset, false)));
    let Some((descriptor_offset, is_storage_descriptor)) = descriptor_location else {
        return Ok(());
    };
    if is_storage_descriptor
        && let Some((description, _length)) = printable_run(window, descriptor_offset, 256)
        && !descriptors.contains(&description)
    {
        descriptors.push(description);
    }
    let Some(identifier_offset) = descriptor_offset.checked_sub(20) else {
        return Ok(());
    };
    let Some(identifier) = fixed_identifier(window, identifier_offset) else {
        return Ok(());
    };
    let encoded = hex_identifier(identifier)?;
    if !identifiers.contains(&encoded) {
        identifiers.push(encoded);
    }
    Ok(())
}

fn scan_password_hints(bytes: &[u8]) -> Vec<String> {
    let mut hints = Vec::new();
    let mut offset = 0_usize;
    while offset.saturating_add(32) <= bytes.len() {
        if let Some(hint) = hint_at(bytes, offset)
            && !hints.contains(&hint)
        {
            hints.push(hint);
        }
        offset = offset.saturating_add(16);
    }
    hints
}

fn hint_at(bytes: &[u8], offset: usize) -> Option<String> {
    let identifier = fixed_identifier(bytes, offset)?;
    if !is_identifier(identifier) {
        return None;
    }
    let null_start = offset.checked_add(KEYSET_ID_SIZE)?;
    let null_end = null_start.checked_add(4)?;
    if bytes.get(null_start..null_end)? != [0_u8; 4] {
        return None;
    }
    let (hint, length) = printable_run(bytes, null_end, MAX_HINT_LENGTH)?;
    let terminator = null_end.checked_add(length)?;
    if length < 4 || bytes.get(terminator).copied()? != 0 || excluded_hint(&hint) {
        return None;
    }
    Some(hint)
}

fn excluded_hint(text: &str) -> bool {
    text.starts_with("Storage [Id:")
        || text.starts_with("SessionId:")
        || [".vmx", ".vmxf", ".vmdk", ".nvram"]
            .iter()
            .any(|extension| text.ends_with(extension))
}

fn scan_wrapped_keysets(bytes: &[u8]) -> Result<Vec<WrappedKeysetInfo>> {
    let mut records = Vec::new();
    let mut cursor = 0_usize;
    while let Some(position) = find_bytes(bytes, &RECORD_SENTINEL, cursor) {
        if let Some(record) = wrapped_record_at(bytes, position)? {
            let duplicate = records.iter().any(|existing| {
                wrapped_record_bytes(bytes, existing) == wrapped_record_bytes(bytes, &record)
            });
            if !duplicate {
                records.push(record);
            }
        }
        cursor = position.saturating_add(1);
    }
    Ok(records)
}

fn wrapped_record_bytes<'a>(bytes: &'a [u8], record: &WrappedKeysetInfo) -> Option<&'a [u8]> {
    let start = usize::try_from(record.record_offset).ok()?;
    let payload = usize::try_from(record.payload_size).ok()?;
    let end = start
        .checked_add(RECORD_HEADER_SIZE)?
        .checked_add(payload)?;
    bytes.get(start..end)
}

fn wrapped_record_at(bytes: &[u8], position: usize) -> Result<Option<WrappedKeysetInfo>> {
    if position.saturating_add(RECORD_HEADER_SIZE) > bytes.len() {
        return Ok(None);
    }
    let total_size = read_u64(bytes, position.saturating_add(8))?;
    let kdf_type = read_u32(bytes, position.saturating_add(0x10))?;
    let identifier_length = read_u32(bytes, position.saturating_add(0x14))?;
    if identifier_length != 16 || kdf_type > 2 || total_size > MAX_RECORD_SIZE {
        return Ok(None);
    }
    let identifier_offset = position.saturating_add(0x18);
    let Some(identifier) = fixed_identifier(bytes, identifier_offset) else {
        return Ok(None);
    };
    let payload_size = read_u64(bytes, position.saturating_add(0x28))?;
    if payload_size > MAX_RECORD_SIZE || !payload_fits(bytes, position, payload_size)? {
        return Ok(None);
    }
    Ok(Some(WrappedKeysetInfo {
        record_offset: u64::try_from(position).map_err(invalid_offset)?,
        kdf_type,
        iterations: kdf_iterations(kdf_type)?,
        sub_keyset_id: hex_identifier(identifier)?,
        payload_size,
    }))
}

fn payload_fits(bytes: &[u8], position: usize, payload_size: u64) -> Result<bool> {
    let payload_size = usize::try_from(payload_size).map_err(invalid_offset)?;
    let Some(end) = position
        .checked_add(RECORD_HEADER_SIZE)
        .and_then(|start| start.checked_add(payload_size))
    else {
        return Ok(false);
    };
    Ok(end <= bytes.len())
}

fn kdf_iterations(kdf_type: u32) -> Result<u32> {
    match kdf_type {
        0 => Ok(1),
        1 => Ok(10_000),
        2 => Ok(600_000),
        value => Err(VbkError::InvalidField {
            offset: 0,
            field: "keyset_kdf_type",
            reason: format!("unsupported value {value}"),
        }),
    }
}

fn fixed_identifier(bytes: &[u8], offset: usize) -> Option<&[u8]> {
    let end = offset.checked_add(KEYSET_ID_SIZE)?;
    let identifier = bytes.get(offset..end)?;
    is_identifier(identifier).then_some(identifier)
}

fn is_identifier(identifier: &[u8]) -> bool {
    identifier.iter().any(|byte| *byte != 0) && identifier.iter().any(|byte| *byte != 0xff)
}

fn printable_run(bytes: &[u8], start: usize, maximum: usize) -> Option<(String, usize)> {
    let mut end = start;
    let limit = start.saturating_add(maximum).min(bytes.len());
    while end < limit {
        let byte = bytes.get(end).copied()?;
        if !(0x20..0x7f).contains(&byte) {
            break;
        }
        end = end.saturating_add(1);
    }
    let slice = bytes.get(start..end)?;
    let text = std::str::from_utf8(slice).ok()?.to_owned();
    Some((text, end.saturating_sub(start)))
}

fn find_bytes(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    if needle.is_empty() || start >= haystack.len() {
        return None;
    }
    let mut position = start;
    while let Some(end) = position.checked_add(needle.len()) {
        if end > haystack.len() {
            return None;
        }
        if haystack.get(position..end) == Some(needle) {
            return Some(position);
        }
        position = position.saturating_add(1);
    }
    None
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(read_array::<4>(bytes, offset)?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(read_array::<8>(bytes, offset)?))
}

fn read_array<const SIZE: usize>(bytes: &[u8], offset: usize) -> Result<[u8; SIZE]> {
    let end = offset
        .checked_add(SIZE)
        .ok_or_else(|| invalid_encryption(offset, "record field offset overflow"))?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| invalid_encryption(offset, "truncated record field"))?;
    <[u8; SIZE]>::try_from(slice).map_err(|error| invalid_encryption(offset, &error.to_string()))
}

fn hex_identifier(identifier: &[u8]) -> Result<String> {
    let mut encoded = String::with_capacity(identifier.len().saturating_mul(2));
    for byte in identifier {
        write!(&mut encoded, "{byte:02x}")
            .map_err(|error| invalid_encryption(0, &error.to_string()))?;
    }
    Ok(encoded)
}

fn invalid_offset(error: std::num::TryFromIntError) -> VbkError {
    invalid_encryption(0, &error.to_string())
}

fn invalid_encryption(offset: usize, reason: &str) -> VbkError {
    let offset = u64::try_from(offset).unwrap_or(u64::MAX);
    VbkError::InvalidField {
        offset,
        field: "encryption_metadata",
        reason: reason.to_owned(),
    }
}
