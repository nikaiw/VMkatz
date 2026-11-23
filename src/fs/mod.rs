//! Generic NTFS filesystem + partition access over a disk image, shared by the
//! `sam` (hive/NTDS extraction), `chrome` and `paging` consumers.

pub mod listing;
pub(crate) mod ntfs_fallback;
pub(crate) mod recovery;
pub use listing::{ListOutcome, list_path};

pub mod ntfs;
pub mod partition;

pub use ntfs::{
    DirEntry, EntryKind, PartitionReader, copy_file_to_path, find_entry, list_directory,
    navigate_to_dir, read_file_data, read_file_data_bounded, with_file_data,
};
pub use partition::{find_ntfs_partitions, is_bitlocker_partition, select_partition};
