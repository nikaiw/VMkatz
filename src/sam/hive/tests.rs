use super::*;
use std::io::{Cursor, ErrorKind, SeekFrom};

fn header() -> Vec<u8> {
    let mut bytes = vec![0; 2 * 65536];
    bytes[..4].copy_from_slice(b"regf");
    bytes[0x24..0x28].copy_from_slice(&0x20u32.to_le_bytes());
    bytes[0x1024..0x1026].copy_from_slice(b"nk");
    bytes[0x1038..0x103C].copy_from_slice(&1u32.to_le_bytes());
    bytes[0x1040..0x1044].copy_from_slice(&0xF000u32.to_le_bytes());
    bytes
}

#[test]
fn optional_cache_lookup_propagates_storage_errors() -> Result<()> {
    struct Fault(Cursor<Vec<u8>>);
    impl Read for Fault {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            if self.0.position() >= 65536 {
                return Err(ErrorKind::PermissionDenied.into());
            }
            self.0.read(output)
        }
    }
    impl Seek for Fault {
        fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
            self.0.seek(position)
        }
    }
    let hive = Hive::from_reader(Fault(Cursor::new(header())))?;
    let result = crate::sam::cache::extract_cached_credentials_from_hive(&hive, &[0; 32]);
    assert!(
        matches!(result, Err(VmkatzError::Io(error)) if error.kind() == ErrorKind::PermissionDenied)
    );
    Ok(())
}

#[test]
fn cyclic_subkey_indexes_do_not_recurse_or_repeat() -> Result<()> {
    let mut bytes = header();
    bytes[65536..65540].copy_from_slice(&(-16i32).to_le_bytes());
    bytes[65540..65542].copy_from_slice(b"ri");
    bytes[65542..65544].copy_from_slice(&1u16.to_le_bytes());
    bytes[65544..65548].copy_from_slice(&0xF000u32.to_le_bytes());
    let hive = Hive::from_reader(Cursor::new(bytes))?;
    let root = hive.root_key()?;
    assert!(root.subkeys(&hive)?.is_empty());
    assert!(root.subkey(&hive, "missing").is_err());
    Ok(())
}
