//! LSASS credential extraction from Windows memory snapshots.
//!
//! Architecture:
//! - `finder`   — Orchestrator: locates LSASS, extracts crypto keys, calls each SSP provider.
//! - `crypto`   — LSA decryption (AES-CFB-128, 3DES-CBC) and BCrypt key handle chain walking.
//! - `patterns` — Byte pattern scanning in PE .text sections to locate global variables.
//! - `types`    — Shared types: `Credential`, `Arch`, SSP-specific credential structs.
//!
//! SSP providers (each extracts one credential type from LSASS structures):
//! - `msv`      — NTLM hashes (NT/LM/SHA1) from MSV1_0_PRIMARY_CREDENTIAL.
//! - `wdigest`  — Plaintext passwords from WDigest logon session list.
//! - `kerberos` — Kerberos tickets and keys from AVL tree (KerbGlobalLogonSessionTable).
//! - `tspkg`    — Terminal Services plaintext credentials.
//! - `dpapi`    — DPAPI master keys from g_MasterKeyCacheList.
//! - `ssp`      — SSP credentials (SspCredentialList linked list).
//! - `livessp`  — Live account credentials (removed in Win10, livessp.dll).
//! - `credman`  — Credential Manager stored credentials (attached to MSV sessions).
//! - `cloudap`  — Azure AD / cloud credentials (PRT tokens, cache entries).
//!
//! - `carve`    — Degraded extraction for truncated/raw memory (no EPROCESS traversal).

pub mod bitlocker;
#[cfg(feature = "carve")]
pub mod carve;
pub(crate) mod cloudap;
pub(crate) mod credman;
pub(crate) mod crypto;
pub use crypto::base64_encode;
pub(crate) mod dpapi;
pub mod finder;
pub(crate) mod kerberos;
pub(crate) mod livessp;
pub(crate) mod msv;
pub(crate) mod patterns;
pub(crate) mod ssp;
pub(crate) mod tspkg;
pub mod types;
pub(crate) mod wdigest;
