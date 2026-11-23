mod layer;
mod savevm;

pub use layer::QemuElfLayer;
pub use savevm::{QemuSavevmLayer, is_qemu_savevm};

#[cfg(test)]
fn truncated_pread_fixture(tag: &str) -> (std::path::PathBuf, crate::utils::MappedFile) {
    // Simulate a file that became shorter after its size was recorded.
    pread_fixture(tag, &[0xA5; 4], 16)
}

#[cfg(test)]
fn pread_fixture(
    tag: &str,
    bytes: &[u8],
    size: u64,
) -> (std::path::PathBuf, crate::utils::MappedFile) {
    let path = std::env::temp_dir().join(format!("vmkatz-qemu-{tag}-{}", std::process::id()));
    std::fs::write(&path, bytes).unwrap();
    let backing = crate::utils::MappedFile::Pread {
        file: std::sync::Mutex::new(std::fs::File::open(&path).unwrap()),
        size,
    };
    (path, backing)
}
