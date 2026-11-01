//! CLI binary modules; re-exports what `main` dispatches to.
//!
//! `args`: argument parsing, colours, input classification. `output`: output
//! formats and export helpers. `lsass`: memory-snapshot pipeline. `dir`:
//! VM-directory pipelines. `disk` (`sam` only): disk-image, raw-file, Veeam
//! and VMFS pipelines.

pub mod args;
pub mod dir;
#[cfg(feature = "sam")]
pub mod disk;
pub mod lsass;
pub mod output;

#[cfg(feature = "sam")]
pub(crate) use args::is_block_dev;
pub(crate) use args::{Args, RawFileType, detect_file_type};
pub(crate) use dir::{run_directory, run_recursive};
#[cfg(all(
    feature = "sam",
    any(
        feature = "vmware",
        feature = "vbox",
        feature = "qemu",
        feature = "hyperv"
    )
))]
pub(crate) use disk::run_associated_lsass_for_disk;
#[cfg(feature = "ntds.dit")]
pub(crate) use disk::run_raw_ntds;
#[cfg(feature = "veeam")]
pub(crate) use disk::run_veeam;
#[cfg(feature = "sam")]
pub(crate) use disk::{run_raw_hives, run_sam};
#[cfg(feature = "vmfs")]
pub(crate) use disk::{run_vmfs, run_vmfs_list};
pub(crate) use lsass::{run_lsass, run_minidump};
