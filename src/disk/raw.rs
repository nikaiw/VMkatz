use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::error::{GovmemError, Result};

/// Raw flat disk image — no container format, just raw sectors.
/// Handles flat VMDKs (`-flat.vmdk`), raw dumps (`.raw`, `.img`, `.dd`),
/// and block devices (`/dev/...`).
pub struct RawDisk {
    file: File,
    size: u64,
}

impl RawDisk {
    pub fn open(path: &Path) -> Result<Self> {
        let mut file = File::open(path).map_err(GovmemError::Io)?;
        // metadata().len() returns 0 for block devices, so seek to end instead
        let size = file.seek(SeekFrom::End(0)).map_err(GovmemError::Io)?;
        file.seek(SeekFrom::Start(0)).map_err(GovmemError::Io)?;
        log::info!(
            "Raw disk: {} ({} MB)",
            path.display(),
            size / (1024 * 1024)
        );
        Ok(Self { file, size })
    }
}

impl Read for RawDisk {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buf)
    }
}

impl Seek for RawDisk {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.file.seek(pos)
    }
}

impl super::DiskImage for RawDisk {
    fn disk_size(&self) -> u64 {
        self.size
    }
}
