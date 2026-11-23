//! DPAPI blobs, master keys and credential history, independent of SAM.

pub mod blob;
pub mod credhist;
#[cfg(feature = "disk")]
pub mod disk;
pub mod masterkey;
