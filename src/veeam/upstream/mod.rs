//! Imported vbktool implementation, kept separate from the native disk adapter.

pub mod block;
pub mod catalog;
pub mod diskfs;
pub mod encryption;
pub mod error;
pub mod format;
pub mod metadata;
pub mod properties;
pub(super) mod reader;
pub mod reconstruct;
