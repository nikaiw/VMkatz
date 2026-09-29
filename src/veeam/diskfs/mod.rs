//! Read-only walking of disk images stored as catalogue files.
//!
//! A catalogue file such as a Veeam Agent disk image is a raw block device: a partition
//! table (GPT or MBR) that points at partitions, each holding a filesystem (FAT or NTFS).
//! This module descends that structure over any [`ByteReader`], so the same code drives both
//! the unit tests (over in-memory `&[u8]`) and the interactive browser (over a
//! reconstructed [`crate::veeam::LogicalFileReader`]).
//!
//! Everything here is read-only and bounded: every structure is size-checked before use and
//! traversal is capped, so a malformed image yields an error rather than an unbounded read.

mod fat;
mod ntfs;
mod partition;
mod source;

pub use fat::FatFileSystem;
pub use ntfs::NtfsFileSystem;
pub use partition::{Partition, PartitionKind, read_partitions};
pub use source::{ByteReader, SubReader, read_exact_at};

use std::fmt;

use serde::Serialize;

/// Error raised while walking a disk image or its filesystems.
#[derive(Debug)]
pub enum FsError {
    /// A read returned fewer bytes than required.
    Truncated {
        /// Offset the read started at.
        offset: u64,
        /// Number of bytes requested.
        length: usize,
    },
    /// A structure did not carry its expected signature or a field was out of range.
    Corrupt {
        /// What was being parsed.
        structure: &'static str,
        /// Why it was rejected.
        reason: String,
    },
    /// A recognised but not-yet-supported feature was encountered.
    Unsupported {
        /// The feature name.
        feature: &'static str,
    },
    /// The underlying reader failed.
    Io {
        /// A human description of the failure.
        message: String,
    },
}

impl fmt::Display for FsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { offset, length } => {
                write!(formatter, "short read of {length} bytes at offset {offset}")
            }
            Self::Corrupt { structure, reason } => {
                write!(formatter, "corrupt {structure}: {reason}")
            }
            Self::Unsupported { feature } => {
                write!(formatter, "unsupported filesystem feature: {feature}")
            }
            Self::Io { message } => write!(formatter, "disk image read failed: {message}"),
        }
    }
}

impl std::error::Error for FsError {}

/// Convenience result type for disk-image walking.
pub type FsResult<T> = Result<T, FsError>;

/// A directory entry inside a filesystem: a name plus enough state to descend or read it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FsEntry {
    /// Entry name (a single path component).
    pub name: String,
    /// Whether the entry is a directory.
    pub is_directory: bool,
    /// Logical byte length of a file (`0` for directories).
    pub size: u64,
    /// Opaque locator the owning filesystem uses to open this entry.
    pub locator: u64,
}

/// A filesystem the browser can list and read files from.
pub trait FileSystem {
    /// Human label for the filesystem kind (e.g. `FAT32`, `NTFS`).
    fn kind(&self) -> &'static str;
    /// Locator of the root directory.
    fn root(&self) -> u64;
    /// List the entries of the directory addressed by `locator`.
    ///
    /// # Errors
    ///
    /// Returns an error for a corrupt or unsupported directory structure or an IO failure.
    fn read_dir(&self, locator: u64) -> FsResult<Vec<FsEntry>>;
    /// Read the complete contents of the file addressed by `locator` into `output`.
    ///
    /// # Errors
    ///
    /// Returns an error for a corrupt run list, an oversized file, or an IO failure.
    fn read_file(&self, locator: u64, output: &mut Vec<u8>) -> FsResult<()>;
}

/// Largest file the disk-image browser will materialise, guarding against a corrupt size.
pub const MAX_FS_FILE_SIZE: u64 = 512 * 1024 * 1024;

/// Detect and open the filesystem in `partition`, or `None` if it is not FAT or NTFS.
///
/// # Errors
///
/// Returns an error when a recognised filesystem's superblock is corrupt.
pub fn open_filesystem<R: ByteReader + ?Sized>(
    partition: &R,
) -> FsResult<Option<Box<dyn FileSystem + '_>>> {
    if ntfs::is_ntfs(partition)? {
        return Ok(Some(Box::new(NtfsFileSystem::open(partition)?)));
    }
    if fat::is_fat(partition)? {
        return Ok(Some(Box::new(FatFileSystem::open(partition)?)));
    }
    Ok(None)
}
