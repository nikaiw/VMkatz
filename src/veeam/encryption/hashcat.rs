//! Export of password-wrapped keysets for Hashcat mode 31200.

use std::{fmt::Write as _, path::Path};

use super::{SCAN_LIMIT, hex_identifier, inspect_reader, keyset::parse_wrapped_payload};
use crate::veeam::{Result, VbkError, reader::FileReader};

const HASHCAT_SALT_SIZE: usize = 64;
const HASHCAT_VERIFIER_SIZE: usize = 16;

/// Hashcat mode assigned to Veeam VBK password targets.
pub const HASHCAT_VEEAM_VBK_MODE: u32 = 31_200;

/// Extract password targets in Hashcat mode 31200 syntax.
///
/// Each returned string has the form `$vbk$*salt*iterations*verifier`. Chained keyset records
/// without password-derived material are intentionally omitted.
///
/// # Errors
///
/// Returns an error for malformed encryption records, IO failures, or backups without a
/// mode-31200-compatible password wrapper.
pub fn hashcat_hashes(path: &Path) -> Result<Vec<String>> {
    let reader = FileReader::open(path)?;
    let encryption = inspect_reader(&reader)?;
    let scan_length = reader.length().min(SCAN_LIMIT);
    let bytes = reader.read_bytes(0, scan_length, "Hashcat target extraction")?;
    let mut hashes = Vec::new();
    for wrapper in &encryption.wrapped_keysets {
        let payload = parse_wrapped_payload(&bytes, wrapper)?;
        if payload.salt.len() != HASHCAT_SALT_SIZE
            || payload.auxiliary.len() != HASHCAT_VERIFIER_SIZE
        {
            continue;
        }
        hashes.push(format_hashcat_line(
            payload.salt,
            wrapper.iterations,
            payload.auxiliary,
        )?);
    }
    if hashes.is_empty() {
        return Err(VbkError::HashcatTargetUnavailable);
    }
    Ok(hashes)
}

fn format_hashcat_line(salt: &[u8], iterations: u32, verifier: &[u8]) -> Result<String> {
    let salt = hex_identifier(salt)?;
    let verifier = hex_identifier(verifier)?;
    let mut line = String::with_capacity(7 + salt.len() + verifier.len() + 16);
    write!(&mut line, "$vbk$*{salt}*{iterations}*{verifier}").map_err(|error| {
        VbkError::InvalidField {
            offset: 0,
            field: "hashcat_target",
            reason: error.to_string(),
        }
    })?;
    Ok(line)
}
