//! Offline Windows Credential Manager and Vault extraction.

mod blob;
mod disk;
mod vault;

pub use blob::{CredAttribute, CredmanEntry, parse_credential_blob};
pub use disk::{
    AttrInfo, CredmanReport, ProfileCred, Secret, SecretTable, Undecrypted, build_secret_table,
    extract_credman_from_reader_scoped, machine_sid_from_user_sid,
};
pub use vault::{VaultKeys, parse_vault_keys, parse_vpol};
