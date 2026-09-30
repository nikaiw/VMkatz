//! Veeam VBK/VIB/VRB backup access (read-only): parse the format, enumerate
//! stored disk images, and reconstruct their bytes for the credential pipeline.
//!
//! Vendored from the `vbktool` project and kept close to upstream, so it is
//! exempted from vmkatz's lint gate; only `disk` is vmkatz code.
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
pub use reconstruct::{
    ExtractionReport, LogicalFileReader, LogicalImageReader, extract_item_to_path_with_password,
};
