use thiserror::Error;

#[derive(Error, Debug)]
pub enum VmkatzError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid magic: 0x{0:08x}")]
    InvalidMagic(u32),

    #[error("Group '{0}' not found in VMSN")]
    GroupNotFound(&'static str),

    #[error("Physical address 0x{0:x} unmappable (outside all regions)")]
    UnmappablePhysical(u64),

    #[error("Page fault at 0x{0:x} (level: {1})")]
    PageFault(u64, &'static str),

    #[error("Pagefile fault at 0x{0:x} (PTE: 0x{1:x})")]
    PageFileFault(u64, u64),

    #[error("System process not found")]
    SystemProcessNotFound,

    #[error("Process '{0}' not found")]
    ProcessNotFound(String),

    #[error("PE parse error at 0x{0:x}: {1}")]
    PeError(u64, String),

    #[error("Pattern not found: {0}")]
    PatternNotFound(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),

    #[error("Disk format error: {0}")]
    DiskFormatError(String),

    #[error("ELF error: {0}")]
    ElfError(String),

    #[error("Parse error: {0}")]
    Parse(String),

}

pub type Result<T> = std::result::Result<T, VmkatzError>;
