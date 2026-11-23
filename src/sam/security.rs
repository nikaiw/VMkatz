use super::{cache, hive::Hive, lsa};
use crate::error::{Result, VmkatzError};

pub fn process_security_hive(
    hive: &Hive<'_>,
    boot_key: &[u8; 16],
) -> Result<(Vec<lsa::LsaSecret>, Vec<cache::CachedCredential>)> {
    let secrets = match lsa::extract_lsa_secrets_from_hive(hive, boot_key) {
        Ok(secrets) => secrets,
        Err(error) if error.is_resource_limit() || matches!(error, VmkatzError::Io(_)) => {
            return Err(error);
        }
        Err(error) => {
            log::warn!("LSA secrets extraction failed: {error}");
            Vec::new()
        }
    };
    let key = secrets.iter().find_map(|secret| match &secret.parsed {
        lsa::LsaSecretType::CachedDomainKey { key } if key.len() >= 32 => Some(key.as_slice()),
        _ => None,
    });
    let cached = if let Some(key) = key {
        match cache::extract_cached_credentials_from_hive(hive, key) {
            Ok(cached) => cached,
            Err(error) if error.is_resource_limit() || matches!(error, VmkatzError::Io(_)) => {
                return Err(error);
            }
            Err(error) => {
                log::warn!("DCC2 extraction failed: {error}");
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    Ok((secrets, cached))
}
