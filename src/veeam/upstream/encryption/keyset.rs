//! Password-based and chained Veeam keyset recovery.

use std::{collections::BTreeMap, fmt};

use aes::Aes256;
use cbc::{
    Decryptor,
    cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7},
};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{
    EncryptionInfo, KEYSET_ID_SIZE, RECORD_HEADER_SIZE, SCAN_LIMIT, WrappedKeysetInfo,
    invalid_encryption, read_u32,
};
use crate::veeam::{Result, VbkError, reader::FileReader};

const WRAPPED_PAYLOAD_HEADER_SIZE: usize = 18;
const WRAPPED_PAYLOAD_TRAILER_SIZE: usize = 4;
const DERIVED_MATERIAL_SIZE: usize = 48;
const AES_KEY_SIZE: usize = 32;
const AES_IV_SIZE: usize = 16;
const SERIALIZED_KEYSET_HEADER_SIZE: usize = 34;
const SERIALIZED_KEYSET_VERSION: u32 = 2;
const SERIALIZED_KEYSET_BODY_SIZE: u32 = 74;
const MAX_WRAPPED_BLOB_SIZE: usize = 64 * 1024;

type Aes256CbcDecryptor = Decryptor<Aes256>;
type KeysetId = [u8; KEYSET_ID_SIZE];

/// Recovered secret keysets indexed by their on-disk identifiers.
#[derive(Default)]
pub(crate) struct RecoveredKeysets {
    keysets: BTreeMap<KeysetId, SecretKeyset>,
}

impl Drop for RecoveredKeysets {
    fn drop(&mut self) {
        for keyset in self.keysets.values_mut() {
            keyset.zeroize();
        }
        self.keysets.clear();
    }
}

impl fmt::Debug for RecoveredKeysets {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveredKeysets")
            .field("count", &self.keysets.len())
            .finish_non_exhaustive()
    }
}

impl RecoveredKeysets {
    pub(crate) fn get(&self, identifier: KeysetId) -> Option<&SecretKeyset> {
        self.keysets.get(&identifier)
    }

    #[cfg(all(test, feature = "fixture-tests"))]
    pub(crate) fn len(&self) -> usize {
        self.keysets.len()
    }

    fn insert(&mut self, identifier: KeysetId, keyset: SecretKeyset) {
        let _previous = self.keysets.insert(identifier, keyset);
    }
}

/// One recovered AES-256-CBC key and initialization vector.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct SecretKeyset {
    key: [u8; AES_KEY_SIZE],
    iv: [u8; AES_IV_SIZE],
}

impl fmt::Debug for SecretKeyset {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretKeyset([REDACTED])")
    }
}

impl SecretKeyset {
    pub(crate) fn key(&self) -> &[u8; AES_KEY_SIZE] {
        &self.key
    }

    pub(crate) fn iv(&self) -> &[u8; AES_IV_SIZE] {
        &self.iv
    }

    pub(crate) fn decrypt_padded(&self, ciphertext: &[u8], offset: u64) -> Result<Vec<u8>> {
        let decryptor = Aes256CbcDecryptor::new((&self.key).into(), (&self.iv).into());
        decryptor
            .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
            .map_err(|_error| VbkError::InvalidField {
                offset,
                field: "encrypted_payload",
                reason: "AES-256-CBC payload has invalid PKCS#7 padding".to_owned(),
            })
    }
}

pub(super) struct WrappedPayload<'a> {
    pub(super) ciphertext: &'a [u8],
    pub(super) auxiliary: &'a [u8],
    pub(super) salt: &'a [u8],
}

/// Recover all keysets whose wrappers form a resolvable password/keyset chain.
pub(crate) fn recover_reader_keysets(
    reader: &FileReader,
    encryption: &EncryptionInfo,
    password: &str,
) -> Result<RecoveredKeysets> {
    if encryption.wrapped_keysets.is_empty() {
        return Err(invalid_encryption(
            0,
            "encrypted backup has no wrapped keysets",
        ));
    }
    if encryption.keyset_ids.len() < encryption.wrapped_keysets.len() {
        return Err(invalid_encryption(
            0,
            "wrapped keyset has no matching registry identifier",
        ));
    }
    let scan_length = reader.length().min(SCAN_LIMIT);
    let bytes = reader.read_bytes(0, scan_length, "wrapped keyset recovery")?;
    let mut recovered = RecoveredKeysets::default();

    for (index, wrapper) in encryption.wrapped_keysets.iter().enumerate() {
        let payload = parse_wrapped_payload(&bytes, wrapper)?;
        let target_text = encryption
            .keyset_ids
            .get(index)
            .ok_or_else(|| invalid_encryption(index, "missing target keyset identifier"))?;
        let target = decode_identifier(target_text)?;
        let keyset = if payload.salt.is_empty() {
            recover_chained_keyset(wrapper, &payload, &recovered)?
        } else {
            recover_password_keyset(wrapper, &payload, password)?
        };
        recovered.insert(target, keyset);
    }
    Ok(recovered)
}

fn recover_password_keyset(
    wrapper: &WrappedKeysetInfo,
    payload: &WrappedPayload<'_>,
    password: &str,
) -> Result<SecretKeyset> {
    let mut password_bytes = utf16le(password);
    let mut derived = [0_u8; DERIVED_MATERIAL_SIZE];
    for iterations in iteration_candidates(wrapper.kdf_type) {
        pbkdf2_hmac::<Sha1>(&password_bytes, payload.salt, *iterations, &mut derived);
        let result = decrypt_serialized_keyset(
            payload.ciphertext,
            array_ref::<AES_KEY_SIZE>(&derived, 0)?,
            *array_ref::<AES_IV_SIZE>(&derived, AES_KEY_SIZE)?,
        );
        match result {
            Ok(keyset) => {
                password_bytes.zeroize();
                derived.zeroize();
                return Ok(keyset);
            }
            Err(_error) => {}
        }
        derived.zeroize();
    }
    password_bytes.zeroize();
    Err(VbkError::IncorrectPassword)
}

fn recover_chained_keyset(
    wrapper: &WrappedKeysetInfo,
    payload: &WrappedPayload<'_>,
    recovered: &RecoveredKeysets,
) -> Result<SecretKeyset> {
    let wrapping_identifier = decode_identifier(&wrapper.sub_keyset_id)?;
    let wrapping = recovered.get(wrapping_identifier).ok_or_else(|| {
        invalid_encryption(
            offset_as_usize(wrapper.record_offset),
            "wrapped keyset refers to a keyset that has not been recovered",
        )
    })?;
    decrypt_serialized_keyset(payload.ciphertext, wrapping.key(), *wrapping.iv())
}

fn decrypt_serialized_keyset(
    ciphertext: &[u8],
    key: &[u8; AES_KEY_SIZE],
    iv: [u8; AES_IV_SIZE],
) -> Result<SecretKeyset> {
    let wrapping = SecretKeyset { key: *key, iv };
    let plaintext = wrapping.decrypt_padded(ciphertext, 0)?;
    parse_serialized_keyset(&plaintext)
}

fn parse_serialized_keyset(plaintext: &[u8]) -> Result<SecretKeyset> {
    let version = read_u32(plaintext, 0)?;
    let body_size = read_u32(plaintext, 4)?;
    let key_size = read_u32(plaintext, 26)?;
    let iv_size = read_u32(plaintext, 30)?;
    if version != SERIALIZED_KEYSET_VERSION
        || body_size != SERIALIZED_KEYSET_BODY_SIZE
        || key_size != u32::try_from(AES_KEY_SIZE).map_err(invalid_size)?
        || iv_size != u32::try_from(AES_IV_SIZE).map_err(invalid_size)?
    {
        return Err(invalid_encryption(
            0,
            "decrypted keyset structure is invalid",
        ));
    }
    let expected_size = SERIALIZED_KEYSET_HEADER_SIZE
        .checked_add(AES_KEY_SIZE)
        .and_then(|size| size.checked_add(AES_IV_SIZE))
        .ok_or_else(|| invalid_encryption(0, "serialized keyset size overflow"))?;
    if plaintext.len() != expected_size {
        return Err(invalid_encryption(
            0,
            "decrypted keyset has an unexpected length",
        ));
    }
    Ok(SecretKeyset {
        key: *array_ref::<AES_KEY_SIZE>(plaintext, SERIALIZED_KEYSET_HEADER_SIZE)?,
        iv: *array_ref::<AES_IV_SIZE>(plaintext, SERIALIZED_KEYSET_HEADER_SIZE + AES_KEY_SIZE)?,
    })
}

pub(super) fn parse_wrapped_payload<'a>(
    bytes: &'a [u8],
    wrapper: &WrappedKeysetInfo,
) -> Result<WrappedPayload<'a>> {
    let record_offset = usize::try_from(wrapper.record_offset).map_err(invalid_size)?;
    let payload_start = record_offset
        .checked_add(RECORD_HEADER_SIZE)
        .ok_or_else(|| invalid_encryption(record_offset, "wrapped payload offset overflow"))?;
    let payload_size = usize::try_from(wrapper.payload_size).map_err(invalid_size)?;
    let payload_end = payload_start
        .checked_add(payload_size)
        .ok_or_else(|| invalid_encryption(payload_start, "wrapped payload size overflow"))?;
    let payload = bytes
        .get(payload_start..payload_end)
        .ok_or_else(|| invalid_encryption(payload_start, "wrapped payload is truncated"))?;
    let ciphertext_size = usize::from(read_u16(payload, 6)?);
    let auxiliary_size = usize::from(read_u16(payload, 10)?);
    let salt_size = usize::from(read_u16(payload, 14)?);
    validate_blob_size(ciphertext_size)?;
    validate_blob_size(auxiliary_size)?;
    validate_blob_size(salt_size)?;
    let ciphertext_start = WRAPPED_PAYLOAD_HEADER_SIZE;
    let auxiliary_start = checked_payload_add(ciphertext_start, ciphertext_size, payload_start)?;
    let salt_start = checked_payload_add(auxiliary_start, auxiliary_size, payload_start)?;
    let trailer_start = checked_payload_add(salt_start, salt_size, payload_start)?;
    let expected_end =
        checked_payload_add(trailer_start, WRAPPED_PAYLOAD_TRAILER_SIZE, payload_start)?;
    if expected_end != payload.len() || payload.get(trailer_start..expected_end) != Some(&[0_u8; 4])
    {
        return Err(invalid_encryption(
            payload_start,
            "wrapped payload framing is invalid",
        ));
    }
    let ciphertext = payload
        .get(ciphertext_start..auxiliary_start)
        .ok_or_else(|| invalid_encryption(payload_start, "wrapped ciphertext range is invalid"))?;
    if ciphertext.is_empty() || ciphertext.len() % AES_IV_SIZE != 0 {
        return Err(invalid_encryption(
            payload_start,
            "wrapped ciphertext is not AES block aligned",
        ));
    }
    Ok(WrappedPayload {
        ciphertext,
        auxiliary: payload.get(auxiliary_start..salt_start).ok_or_else(|| {
            invalid_encryption(payload_start, "wrapped auxiliary range is invalid")
        })?,
        salt: payload
            .get(salt_start..trailer_start)
            .ok_or_else(|| invalid_encryption(payload_start, "wrapped salt range is invalid"))?,
    })
}

fn iteration_candidates(kdf_type: u32) -> &'static [u32] {
    match kdf_type {
        0 => &[1, 10_000],
        1 => &[10_000, 310_000],
        2 => &[600_000, 10_000],
        _ => &[],
    }
}

fn utf16le(password: &str) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(password.len().saturating_mul(2));
    for unit in password.encode_utf16() {
        encoded.extend_from_slice(&unit.to_le_bytes());
    }
    encoded
}

fn decode_identifier(encoded: &str) -> Result<KeysetId> {
    if encoded.len() != KEYSET_ID_SIZE.saturating_mul(2) {
        return Err(invalid_encryption(
            0,
            "keyset identifier has an invalid encoded length",
        ));
    }
    let mut identifier = [0_u8; KEYSET_ID_SIZE];
    for (index, byte) in identifier.iter_mut().enumerate() {
        let start = index
            .checked_mul(2)
            .ok_or_else(|| invalid_encryption(index, "keyset identifier offset overflow"))?;
        let end = start
            .checked_add(2)
            .ok_or_else(|| invalid_encryption(start, "keyset identifier offset overflow"))?;
        let digits = encoded
            .get(start..end)
            .ok_or_else(|| invalid_encryption(start, "keyset identifier is truncated"))?;
        *byte = u8::from_str_radix(digits, 16).map_err(|error| {
            invalid_encryption(start, &format!("invalid keyset identifier: {error}"))
        })?;
    }
    Ok(identifier)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(*array_ref::<2>(bytes, offset)?))
}

fn array_ref<const SIZE: usize>(bytes: &[u8], offset: usize) -> Result<&[u8; SIZE]> {
    let end = offset
        .checked_add(SIZE)
        .ok_or_else(|| invalid_encryption(offset, "array field offset overflow"))?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| invalid_encryption(offset, "array field is truncated"))?;
    <&[u8; SIZE]>::try_from(slice).map_err(|error| invalid_encryption(offset, &error.to_string()))
}

fn checked_payload_add(offset: usize, length: usize, record_offset: usize) -> Result<usize> {
    offset
        .checked_add(length)
        .ok_or_else(|| invalid_encryption(record_offset, "wrapped payload length overflow"))
}

fn validate_blob_size(size: usize) -> Result<()> {
    if size > MAX_WRAPPED_BLOB_SIZE {
        return Err(VbkError::LimitExceeded {
            resource: "wrapped keyset blob size",
            actual: u64::try_from(size).map_err(invalid_size)?,
            limit: u64::try_from(MAX_WRAPPED_BLOB_SIZE).map_err(invalid_size)?,
        });
    }
    Ok(())
}

fn offset_as_usize(offset: u64) -> usize {
    match usize::try_from(offset) {
        Ok(value) => value,
        Err(_error) => usize::MAX,
    }
}

fn invalid_size(error: std::num::TryFromIntError) -> VbkError {
    invalid_encryption(0, &error.to_string())
}
