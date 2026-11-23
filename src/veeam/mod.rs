//! Veeam VBK/VIB/VRB backup access (read-only): parse the format, enumerate
//! stored disk images, and reconstruct their bytes for the credential pipeline.
//!
//! Vendored modules retain their upstream lint exceptions. The native `disk`
//! adapter and this module's public re-exports use the normal crate lint policy.

// Only the imported implementation receives these exceptions. The native disk
// adapter below remains subject to the crate's complete lint policy.
#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    dead_code,
    unexpected_cfgs,
    rustdoc::private_intra_doc_links,
    reason = "vbktool source kept close to upstream; native disk adapter is linted separately"
)]
mod upstream;

pub mod disk;
use upstream::reader;
pub use upstream::{
    block, catalog, diskfs, encryption, error, format, metadata, properties, reconstruct,
};

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
