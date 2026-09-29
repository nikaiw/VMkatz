//! Veeam VBK/VIB/VRB backup access, ported from the internal `vbktool` project
//! (read-only). Parses the backup format, enumerates stored disk images, and
//! exposes their reconstructed bytes so vmkatz's own disk/credential pipeline
//! can run on them. The CLI/TUI/preview/verify layers are not ported.
//!
//! This module is vendored verbatim from vbktool and kept close to upstream, so
//! it is exempted from vmkatz's own (pedantic/nursery) lint gate and its
//! not-yet-used helpers; only the thin `disk` adapter below is vmkatz code.
#![allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    dead_code,
    unexpected_cfgs
)]

pub mod block;
pub mod catalog;
pub mod disk;
pub mod diskfs;
pub mod encryption;
pub mod error;
pub mod format;
pub mod metadata;
pub mod properties;
mod reader;
pub mod reconstruct;

pub use block::{
    BlockDigestEngine, BlockFlags, BlockReference, Compression, Digest, FileBlockMap,
    IncrementRecovery, LogicalBlock, PhysicalBlock, build_file_maps, build_file_maps_with_password,
    build_increment_recovery_with_password, inspect_block_digest_engine,
};
pub use catalog::{
    Catalog, CatalogConfidence, StoredItem, StoredItemKind, list_items, list_items_with_password,
};
pub use disk::{VbkDisk, VeeamDiskEntry, is_veeam_path, list_disk_images};
pub use encryption::{
    EncryptionInfo, HASHCAT_VEEAM_VBK_MODE, WrappedKeysetInfo, hashcat_hashes, inspect_encryption,
};
pub use error::{Result, VbkError};
pub use format::{BackupHeader, FormatFamily, SupportLevel, parse_header};
pub use metadata::{
    MetadataLayout, MetadataMirrorReport, MetadataRegion, MetadataSegment, verify_metadata_mirror,
};
pub use properties::{Property, PropertyValue, read_properties_dictionary};
pub use reconstruct::{LogicalFileReader, LogicalImageReader};
