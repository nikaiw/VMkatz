//! Typed property dictionaries attached to directory items.
//!
//! Every `DirItemRecord` reserves an `i64` slot at record offset `0x88` named
//! `PropsRootPage` in `dissect.archive`'s cstruct schema. When non-negative, the value
//! is the first page number of a `MetaBlob` that holds a stream of typed property
//! records. Each record on that stream is `PropertyType (u32) + NameLength (u32) +
//! Name (utf-8) + Value`, terminated by `PropertyType = 0xFFFFFFFF` (`-1`). Six value
//! shapes are defined and named after Extract.exe's `CDirElemPropsRW`:
//! `UInt32`, `UInt64`, `AString`, `WString`, `Binary`, and `Boolean`.
//!
//! `vbktool` does not (yet) consume properties during extraction, but the parser is
//! self-contained so a caller that already holds the dictionary bytes can decode the
//! typed entries without walking the whole backup.

use serde::Serialize;

use crate::veeam::{Result, VbkError};

/// Skip amount at the start of every `MetaBlob` payload — the 12-byte
/// `MetaBlobHeader { i64 NextPage, i32 Unk0 }`.
const META_BLOB_HEADER_SIZE: usize = 12;

/// Sentinel `PropertyType` marking the end of the dictionary stream.
const PROPERTY_TYPE_END: u32 = 0xFFFF_FFFF;

/// Largest name or binary value the reader will materialise. Guards against a malformed
/// length field that would otherwise ask us to allocate hundreds of megabytes on top of
/// an unrelated page. Real property names are short (`LogicalSectorSize`,
/// `DefinedBlocksMask`); real binary values are single-page bitmaps.
const MAX_PROPERTY_FIELD_SIZE: u32 = 64 * 1024;

/// Typed value carried by one property-dictionary entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "value")]
pub enum PropertyValue {
    /// `PropertyType::UInt32` (`= 1`).
    UInt32(u32),
    /// `PropertyType::UInt64` (`= 2`).
    UInt64(u64),
    /// `PropertyType::AString` (`= 3`) — length-prefixed UTF-8.
    AString(String),
    /// `PropertyType::WString` (`= 4`) — length-prefixed UTF-16 LE.
    WString(String),
    /// `PropertyType::Binary` (`= 5`) — length-prefixed opaque bytes.
    Binary(Vec<u8>),
    /// `PropertyType::Boolean` (`= 6`) — length-prefixed `u32` truthy value.
    Boolean(bool),
}

/// One entry in a `PropertiesDictionary`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Property {
    /// UTF-8 property name.
    pub name: String,
    /// Typed value the writer stored.
    pub value: PropertyValue,
}

/// Decode a `PropertiesDictionary` payload.
///
/// `payload` must be the concatenated bytes of every page in the `MetaBlob` addressed by
/// the directory item's `PropsRootPage`, with the leading `MetaBlobHeader` already
/// present (this function skips the first 12 bytes itself). Returns the parsed entries in
/// stream order.
///
/// # Errors
///
/// Returns an error if the stream is truncated, a length field exceeds
/// [`MAX_PROPERTY_FIELD_SIZE`], a name or `AString` value is not valid UTF-8, a `WString`
/// is not valid UTF-16 LE, or an unknown `PropertyType` is encountered.
pub fn read_properties_dictionary(payload: &[u8]) -> Result<Vec<Property>> {
    let mut cursor = META_BLOB_HEADER_SIZE;
    let mut entries = Vec::new();
    loop {
        let property_type = read_u32(payload, cursor)?;
        cursor = advance(cursor, 4)?;
        if property_type == PROPERTY_TYPE_END {
            return Ok(entries);
        }
        let name_length = read_u32(payload, cursor)?;
        cursor = advance(cursor, 4)?;
        let name = read_string_field(payload, &mut cursor, name_length, "property_name")?;
        let value = read_value(payload, &mut cursor, property_type)?;
        entries.push(Property { name, value });
    }
}

fn read_value(payload: &[u8], cursor: &mut usize, property_type: u32) -> Result<PropertyValue> {
    match property_type {
        1 => {
            let value = read_u32(payload, *cursor)?;
            *cursor = advance(*cursor, 4)?;
            Ok(PropertyValue::UInt32(value))
        }
        2 => {
            let value = read_u64(payload, *cursor)?;
            *cursor = advance(*cursor, 8)?;
            Ok(PropertyValue::UInt64(value))
        }
        3 => {
            let length = read_u32(payload, *cursor)?;
            *cursor = advance(*cursor, 4)?;
            let value = read_string_field(payload, cursor, length, "astring_value")?;
            Ok(PropertyValue::AString(value))
        }
        4 => {
            let length = read_u32(payload, *cursor)?;
            *cursor = advance(*cursor, 4)?;
            let value = read_wstring_field(payload, cursor, length)?;
            Ok(PropertyValue::WString(value))
        }
        5 => {
            let length = read_u32(payload, *cursor)?;
            *cursor = advance(*cursor, 4)?;
            let bytes = read_binary_field(payload, cursor, length)?;
            Ok(PropertyValue::Binary(bytes))
        }
        6 => {
            let value = read_u32(payload, *cursor)?;
            *cursor = advance(*cursor, 4)?;
            Ok(PropertyValue::Boolean(value != 0))
        }
        unknown => Err(VbkError::InvalidField {
            offset: u64::try_from(*cursor).unwrap_or(u64::MAX),
            field: "property_type",
            reason: format!("unknown property type {unknown}"),
        }),
    }
}

fn read_string_field(
    payload: &[u8],
    cursor: &mut usize,
    length: u32,
    field: &'static str,
) -> Result<String> {
    let bytes = read_binary_field(payload, cursor, length)?;
    String::from_utf8(bytes).map_err(|error| VbkError::InvalidField {
        offset: u64::try_from(*cursor).unwrap_or(u64::MAX),
        field,
        reason: error.to_string(),
    })
}

fn read_wstring_field(payload: &[u8], cursor: &mut usize, length: u32) -> Result<String> {
    let bytes = read_binary_field(payload, cursor, length)?;
    if bytes.len() % 2 != 0 {
        return Err(VbkError::InvalidField {
            offset: u64::try_from(*cursor).unwrap_or(u64::MAX),
            field: "wstring_value",
            reason: "wstring payload is not aligned to 16-bit code units".to_owned(),
        });
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .filter_map(|pair| {
            let array: [u8; 2] = pair.try_into().ok()?;
            Some(u16::from_le_bytes(array))
        })
        .collect();
    String::from_utf16(&units).map_err(|error| VbkError::InvalidField {
        offset: u64::try_from(*cursor).unwrap_or(u64::MAX),
        field: "wstring_value",
        reason: error.to_string(),
    })
}

fn read_binary_field(payload: &[u8], cursor: &mut usize, length: u32) -> Result<Vec<u8>> {
    if length > MAX_PROPERTY_FIELD_SIZE {
        return Err(VbkError::LimitExceeded {
            resource: "property field length",
            actual: u64::from(length),
            limit: u64::from(MAX_PROPERTY_FIELD_SIZE),
        });
    }
    let length = usize::try_from(length).map_err(|error| VbkError::InvalidField {
        offset: u64::try_from(*cursor).unwrap_or(u64::MAX),
        field: "property_field",
        reason: error.to_string(),
    })?;
    let end = advance(*cursor, length)?;
    let bytes = payload
        .get(*cursor..end)
        .ok_or_else(|| VbkError::InvalidField {
            offset: u64::try_from(*cursor).unwrap_or(u64::MAX),
            field: "property_field",
            reason: "value extends past the dictionary payload".to_owned(),
        })?
        .to_vec();
    *cursor = end;
    Ok(bytes)
}

fn read_u32(payload: &[u8], offset: usize) -> Result<u32> {
    let end = advance(offset, 4)?;
    let slice = payload
        .get(offset..end)
        .ok_or_else(|| VbkError::InvalidField {
            offset: u64::try_from(offset).unwrap_or(u64::MAX),
            field: "property_u32",
            reason: "dictionary payload is truncated".to_owned(),
        })?;
    let array = <[u8; 4]>::try_from(slice).map_err(|error| VbkError::InvalidField {
        offset: u64::try_from(offset).unwrap_or(u64::MAX),
        field: "property_u32",
        reason: error.to_string(),
    })?;
    Ok(u32::from_le_bytes(array))
}

fn read_u64(payload: &[u8], offset: usize) -> Result<u64> {
    let end = advance(offset, 8)?;
    let slice = payload
        .get(offset..end)
        .ok_or_else(|| VbkError::InvalidField {
            offset: u64::try_from(offset).unwrap_or(u64::MAX),
            field: "property_u64",
            reason: "dictionary payload is truncated".to_owned(),
        })?;
    let array = <[u8; 8]>::try_from(slice).map_err(|error| VbkError::InvalidField {
        offset: u64::try_from(offset).unwrap_or(u64::MAX),
        field: "property_u64",
        reason: error.to_string(),
    })?;
    Ok(u64::from_le_bytes(array))
}

fn advance(offset: usize, delta: usize) -> Result<usize> {
    offset
        .checked_add(delta)
        .ok_or_else(|| VbkError::InvalidField {
            offset: u64::try_from(offset).unwrap_or(u64::MAX),
            field: "property_cursor",
            reason: "property offset overflow".to_owned(),
        })
}
