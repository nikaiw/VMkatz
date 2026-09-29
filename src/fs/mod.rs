//! Generic NTFS filesystem + partition access over a disk image, shared by the
//! `sam` (hive/NTDS extraction), `chrome` and `paging` consumers.

pub mod ntfs;
pub mod partition;

pub use ntfs::{PartitionReader, find_entry, list_directory, navigate_to_dir, read_file_data};
pub use partition::{find_ntfs_partitions, is_bitlocker_partition};
