//! DPAPI blob parse + decrypt primitives.
//!
//! The implementation lives in [`crate::dpapi::blob`] (available without the
//! `chrome` feature); re-exported here for existing callers.

pub use crate::dpapi::blob::{DpapiBlob, decrypt_blob, decrypt_blob_entropy, parse_blob};
