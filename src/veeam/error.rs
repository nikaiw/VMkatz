//! Error types returned by the VBK reader.

use std::io;

use thiserror::Error;

/// Result type used by the VBK library.
pub type Result<T> = std::result::Result<T, VbkError>;

/// A bounded parsing, compatibility, or IO failure.
#[derive(Debug, Error)]
pub enum VbkError {
    /// The underlying file could not be read.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// The storage version is not recognized by this build.
    #[error("unsupported Veeam storage version {version}")]
    UnsupportedVersion {
        /// Version read at file offset zero.
        version: u32,
    },

    /// The file is a metadata sidecar or another non-storage file, not a backup container.
    #[error(
        "this is not a Veeam backup storage container: the file begins with '{preview}', which \
         looks like a .vbm metadata sidecar (an XML description of the backup chain). Point the \
         tool at the .vbk, .vib, or .vrb file the .vbm refers to"
    )]
    NotAStorageContainer {
        /// Short printable preview of the file's first bytes.
        preview: String,
    },

    /// The file is shorter than the length its own storage descriptor declares.
    #[error(
        "backup file is truncated or incomplete: its storage descriptor declares a full length of \
         {declared} bytes but only {actual} bytes are present ({present_percent:.1}% of the file). \
         Veeam stores the catalogue and block maps in a trailer near the end of the file, so the \
         metadata required to list or extract content is in the missing region. Re-copy the file \
         in full from the source repository"
    )]
    TruncatedFile {
        /// Full file length declared by the storage descriptor at 0x1010.
        declared: u64,
        /// Number of bytes actually present on disk.
        actual: u64,
        /// Percentage of the declared length that is present.
        present_percent: f64,
    },

    /// A requested range is outside the backup file.
    #[error("range at 0x{offset:x} with length {length} exceeds file length {file_length}")]
    RangeOutsideFile {
        /// Start offset of the requested range.
        offset: u64,
        /// Requested byte count.
        length: u64,
        /// Actual file length.
        file_length: u64,
    },

    /// Checked offset arithmetic overflowed.
    #[error("offset arithmetic overflow at 0x{offset:x} while adding {length} bytes")]
    OffsetOverflow {
        /// Base offset.
        offset: u64,
        /// Added byte count.
        length: u64,
    },

    /// An on-disk field failed validation.
    #[error("invalid field {field} at 0x{offset:x}: {reason}")]
    InvalidField {
        /// Field offset.
        offset: u64,
        /// Stable field name.
        field: &'static str,
        /// Human-readable validation failure.
        reason: String,
    },

    /// A stored checksum does not match the referenced bytes.
    #[error(
        "{resource} checksum mismatch at 0x{offset:x}: expected {expected:08x}, calculated {actual:08x}"
    )]
    ChecksumMismatch {
        /// Content protected by the checksum.
        resource: &'static str,
        /// Physical start offset of the protected content.
        offset: u64,
        /// Checksum read from metadata.
        expected: u32,
        /// Checksum calculated by this reader.
        actual: u32,
    },

    /// A defensive parser limit was exceeded.
    #[error("{resource} value {actual} exceeds parser limit {limit}")]
    LimitExceeded {
        /// Resource being limited.
        resource: &'static str,
        /// Value read from disk.
        actual: u64,
        /// Enforced limit.
        limit: u64,
    },

    /// The command depends on a decoder that has not been implemented yet.
    #[error("{feature} is not implemented yet for storage version {version}")]
    FeatureUnavailable {
        /// Requested capability.
        feature: &'static str,
        /// Parsed storage version.
        version: u32,
    },

    /// No catalogue file has the requested exact name.
    #[error("stored item {name:?} was not found")]
    ItemNotFound {
        /// Exact catalogue name requested by the caller.
        name: String,
    },

    /// More than one catalogue file has the requested exact name.
    #[error("stored item name {name:?} is ambiguous ({matches} matches)")]
    AmbiguousItem {
        /// Exact catalogue name requested by the caller.
        name: String,
        /// Number of matching file records.
        matches: usize,
    },

    /// A physical block uses a compression identifier not handled by this build.
    #[error("unsupported block compression {compression} at 0x{offset:x}")]
    UnsupportedCompression {
        /// Compression identifier from the physical record.
        compression: u16,
        /// Absolute stored-block offset.
        offset: u64,
    },

    /// A logical block refers to storage that is recognized but cannot yet be resolved.
    #[error("unsupported {kind} block reference at 0x{offset:x}")]
    UnsupportedBlockReference {
        /// Stable reference family name.
        kind: &'static str,
        /// Metadata offset of the reference when available.
        offset: u64,
    },

    /// A file is stored as an incremental (Patch/Increment) record; its unchanged regions live in
    /// the parent chain, so it cannot be fully reconstructed from this file alone.
    #[error(
        "stored file at 0x{record_offset:x} is an incremental record (a .vib/.vrb Patch/Increment): \
         its unchanged regions are not in this file but in the parent backup chain, so it cannot be \
         fully reconstructed from this file alone. Use `extract --allow-partial` to recover the \
         changed blocks this file does contain (unchanged regions are written as zeros), or open the \
         full backup chain"
    )]
    IncrementalRecordUnsupported {
        /// Absolute file offset of the incremental catalogue record.
        record_offset: u64,
    },

    /// A content digest is recognized but not supported by the active descriptor parser.
    #[error("unsupported digest algorithm {algorithm} at 0x{offset:x}")]
    UnsupportedDigest {
        /// Stable digest algorithm name.
        algorithm: &'static str,
        /// Metadata or physical-data offset identifying the content.
        offset: u64,
    },

    /// Reconstructed data does not match its on-disk digest.
    #[error("digest mismatch for {resource} at 0x{offset:x}")]
    DigestMismatch {
        /// Content being verified.
        resource: &'static str,
        /// Metadata or physical-data offset identifying the content.
        offset: u64,
    },

    /// Encrypted metadata cannot be traversed without recovering its keyset.
    #[error("backup metadata is encrypted; a password is required{keyset_suffix}")]
    PasswordRequired {
        /// Optional formatted keyset suffix included in the diagnostic.
        keyset_suffix: String,
    },

    /// The supplied password did not unwrap a structurally valid keyset.
    #[error("the supplied backup password is incorrect")]
    IncorrectPassword,

    /// No password wrapper can be serialized for Hashcat mode 31200.
    #[error("no Hashcat mode 31200 password target was found in this backup")]
    HashcatTargetUnavailable,
}
