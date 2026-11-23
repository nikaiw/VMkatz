use super::*;
use std::io::{Cursor, SeekFrom};

fn image() -> Vec<u8> {
    let mut bytes = vec![0; 1024];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[0x3C..0x40].copy_from_slice(&64u32.to_le_bytes());
    bytes[64..68].copy_from_slice(b"PE\0\0");
    bytes[70..72].copy_from_slice(&2u16.to_le_bytes());
    for (index, flags) in [0, SCN_MEM_WRITE].into_iter().enumerate() {
        let offset = 88 + index * 40;
        for (field, value) in [
            (8, 4096),
            (12, 4096 + index as u32 * 4096),
            (16, 256),
            (20, 512 + index as u32 * 256),
            (36, flags),
        ] {
            bytes[offset + field..offset + field + 4].copy_from_slice(&value.to_le_bytes());
        }
    }
    bytes[512..768].fill(0x5A);
    bytes[768..].fill(0xDA);
    bytes
}

#[test]
fn a_huge_pe_overlay_is_never_loaded() -> Result<()> {
    struct SparsePe {
        inner: Cursor<Vec<u8>>,
        read: usize,
    }
    impl Read for SparsePe {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.read += buf.len();
            assert!(self.read < 1024, "unexpected full PE read");
            self.inner.read(buf)
        }
    }
    impl Seek for SparsePe {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            self.inner.seek(pos)
        }
    }
    let mut reader = SparsePe {
        inner: Cursor::new(image()),
        read: 0,
    };
    let sections = FileBackedResolver::read_sections(&mut reader, 8 << 40, 0x1000_0000, 4096)?;
    assert_eq!(sections.len(), 1);
    assert_eq!(sections[0].va_start, 0x1000_1000);
    assert_eq!(&sections[0].data[..256], &[0x5A; 256]);
    assert!(sections[0].data[256..].iter().all(|&byte| byte == 0));
    Ok(())
}

#[test]
fn section_budget_counts_padding_and_previously_retained_sections() {
    let mut bytes = image();
    bytes[128 + 36..128 + 40].fill(0); // Both sections are now retained.
    for budget in [4095, 8191] {
        assert!(matches!(
            FileBackedResolver::read_sections(&mut Cursor::new(&bytes), 1024, 0, budget),
            Err(VmkatzError::AllocTooLarge { .. })
        ));
    }
    let mut oversized = image();
    oversized[88 + 8..88 + 12].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(
        FileBackedResolver::read_sections(&mut Cursor::new(oversized), 1024, 0, MAX_SECTION_BYTES),
        Err(VmkatzError::AllocTooLarge { .. })
    ));
}
