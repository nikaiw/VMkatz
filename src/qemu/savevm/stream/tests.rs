use super::*;
use crate::memory::page_index::PageLocation;

#[test]
fn sixty_four_gib_index_fits_in_64_mib() -> Result<()> {
    #[cfg(target_os = "linux")]
    if crate::memory::test_limit::child(
        "qemu::savevm::stream::tests::sixty_four_gib_index_fits_in_64_mib",
    )? {
        return Ok(());
    }
    let mut index = RamPageIndex::default();
    let pages = (64u64 * 1024 * 1024 * 1024) / PAGE_SIZE as u64;
    for page in 0..pages {
        index.record(page * PAGE_SIZE as u64, Some(100 + page * 4104))?;
    }
    index.record(4096, None)?;
    index.record(8192, Some(123456))?;
    let index = index.finish()?;
    assert_eq!(index.page_count(), pages - 1);
    assert_eq!(index.get(4096), None);
    assert_eq!(index.get(8192), Some(PageLocation::File(123456)));
    assert_eq!(
        index.get((pages - 1) * 4096),
        Some(PageLocation::File(100 + (pages - 1) * 4104))
    );
    Ok(())
}

#[test]
fn repeated_pages_keep_only_the_latest_mapping() -> Result<()> {
    let mut pages = RamPageIndex::default();
    for offset in 0..100_000 {
        pages.record(0, Some(offset))?;
    }
    assert_eq!(pages.offsets.page_count(), 1);
    let pages = pages.finish()?;
    assert_eq!(pages.page_count(), 1);
    assert_eq!(pages.get(0), Some(PageLocation::File(99_999)));
    Ok(())
}

#[test]
fn zero_pages_need_no_index_entries() -> Result<()> {
    let mut pages = RamPageIndex::default();
    for page in 0..100_000 {
        pages.record(page * PAGE_SIZE as u64, None)?;
    }
    assert_eq!(pages.finish()?.page_count(), 0);
    assert!(RamPageIndex::default().finish().is_err());
    Ok(())
}

#[test]
fn migration_updates_preserve_page_and_zero_order() -> anyhow::Result<()> {
    let mut data = Vec::new();
    for (gpa, fill) in [
        (0u64, Some(0x11)),
        (4096, None),
        (4096, Some(0x22)),
        (0, None),
    ] {
        let kind = if fill.is_some() {
            RAM_SAVE_FLAG_PAGE
        } else {
            RAM_SAVE_FLAG_ZERO
        };
        data.extend_from_slice(&(gpa | kind | RAM_SAVE_FLAG_CONTINUE).to_be_bytes());
        if let Some(fill) = fill {
            data.extend_from_slice(&[fill; PAGE_SIZE]);
        } else {
            data.push(0);
        }
    }
    data.extend_from_slice(&RAM_SAVE_FLAG_EOS.to_be_bytes());
    let blocks = [RamBlock {
        name: "pc.ram".into(),
        size: 8192,
    }];
    let mut pages = RamPageIndex::default();
    let end = parse_ram_pages(&data, 0, &blocks, &mut pages, &mut Some(0), 0x8000_0000)?;
    assert_eq!(end, data.len());
    let pages = pages.finish()?;
    assert_eq!(pages.page_count(), 1);
    assert_eq!(pages.get(0), None);
    let offset = usize::try_from(
        pages
            .get(4096)
            .and_then(PageLocation::offset)
            .expect("latest raw page"),
    )?;
    assert_eq!(&data[offset..offset + PAGE_SIZE], &[0x22; PAGE_SIZE]);
    Ok(())
}

fn string(data: &mut Vec<u8>, name: &str) {
    data.push(u8::try_from(name.len()).expect("short fixture name"));
    data.extend_from_slice(name.as_bytes());
}

fn setup(blocks: &[&str]) -> Vec<u8> {
    let mut data = b"QEVM".to_vec();
    data.extend_from_slice(&3u32.to_be_bytes());
    section(&mut data, QEMU_VM_SECTION_START);
    string(&mut data, "ram");
    data.extend_from_slice(&0u32.to_be_bytes());
    data.extend_from_slice(&4u32.to_be_bytes());
    data.extend_from_slice(&((blocks.len() as u64 * 4096) | RAM_SAVE_FLAG_MEM_SIZE).to_be_bytes());
    for name in blocks {
        string(&mut data, name);
        data.extend_from_slice(&4096u64.to_be_bytes());
    }
    end_section(&mut data);
    data
}

fn section(data: &mut Vec<u8>, kind: u8) {
    data.push(kind);
    data.extend_from_slice(&1u32.to_be_bytes());
}

fn end_section(data: &mut Vec<u8>) {
    data.extend_from_slice(&RAM_SAVE_FLAG_EOS.to_be_bytes());
    section(data, QEMU_VM_SECTION_FOOTER);
}

fn page(data: &mut Vec<u8>, name: &str, fill: Option<u8>) {
    let kind = if fill.is_some() {
        RAM_SAVE_FLAG_PAGE
    } else {
        RAM_SAVE_FLAG_ZERO
    };
    data.extend_from_slice(&kind.to_be_bytes());
    string(data, name);
    if let Some(fill) = fill {
        data.extend_from_slice(&[fill; PAGE_SIZE]);
    } else {
        data.push(0);
    }
}

fn initial_page() -> Vec<u8> {
    let mut data = setup(&["pc.ram"]);
    section(&mut data, QEMU_VM_SECTION_PART);
    page(&mut data, "pc.ram", Some(0xA5));
    end_section(&mut data);
    data
}

fn assert_page(data: &[u8], fill: u8) -> anyhow::Result<()> {
    let (pages, phys_end) = parse(data, None)?;
    assert_eq!(phys_end, 4096);
    if fill == 0 {
        assert_eq!(pages.get(0), None);
    } else {
        let Some(PageLocation::File(offset)) = pages.get(0) else {
            panic!("missing guest RAM page");
        };
        let offset = usize::try_from(offset)?;
        assert_eq!(&data[offset..offset + PAGE_SIZE], &[fill; PAGE_SIZE]);
    }
    Ok(())
}

#[test]
fn end_sections_apply_final_raw_and_zero_updates() -> anyhow::Result<()> {
    for first in [false, true] {
        for fill in [None, Some(0xB6)] {
            let mut data = if first {
                initial_page()
            } else {
                setup(&["pc.ram"])
            };
            section(&mut data, QEMU_VM_SECTION_END);
            page(&mut data, "pc.ram", fill);
            end_section(&mut data);
            data.push(QEMU_VM_EOF);
            assert_page(&data, fill.unwrap_or(0))?;
        }
    }
    Ok(())
}

#[test]
fn device_ram_cannot_replace_main_ram_regardless_of_block_order() -> anyhow::Result<()> {
    for blocks in [["vga.vram", "pc.ram"], ["pc.ram", "vga.vram"]] {
        let mut data = setup(&blocks);
        section(&mut data, QEMU_VM_SECTION_PART);
        page(&mut data, "pc.ram", Some(0xA5));
        page(&mut data, "vga.vram", Some(0xB6));
        end_section(&mut data);
        data.push(QEMU_VM_EOF);
        assert_page(&data, 0xA5)?;
    }
    Ok(())
}

#[test]
fn truncated_updates_never_return_stale_pages() {
    for kind in [QEMU_VM_SECTION_PART, QEMU_VM_SECTION_END] {
        for fill in [None, Some(0xB6)] {
            let mut data = initial_page();
            let start = data.len();
            section(&mut data, kind);
            page(&mut data, "pc.ram", fill);
            end_section(&mut data);
            for end in start + 1..data.len() {
                // A complete EOS without a footer is legal when footers are disabled.
                if end == data.len() - 5 {
                    continue;
                }
                assert!(parse(&data[..end], None).is_err(), "accepted cut at {end}");
            }
        }
    }
}

#[test]
fn unsupported_or_invalid_page_records_are_rejected() {
    for (flags, name, payload) in [
        (RAM_SAVE_FLAG_ZERO, Some("pc.ram"), vec![0x7F]),
        (RAM_SAVE_FLAG_COMPRESS_PAGE, Some("pc.ram"), vec![0; 16]),
        (
            RAM_SAVE_FLAG_PAGE | RAM_SAVE_FLAG_ZERO,
            Some("pc.ram"),
            vec![0; PAGE_SIZE],
        ),
        (RAM_SAVE_FLAG_PAGE, Some("unknown"), vec![0; PAGE_SIZE]),
        (
            4096 | RAM_SAVE_FLAG_PAGE,
            Some("pc.ram"),
            vec![0; PAGE_SIZE],
        ),
    ] {
        let mut data = initial_page();
        section(&mut data, QEMU_VM_SECTION_END);
        data.extend_from_slice(&flags.to_be_bytes());
        if let Some(name) = name {
            string(&mut data, name);
        }
        data.extend_from_slice(&payload);
        end_section(&mut data);
        data.push(QEMU_VM_EOF);
        assert!(parse(&data, None).is_err());
    }
    let mut data = setup(&["pc.ram"]);
    section(&mut data, QEMU_VM_SECTION_END);
    data.extend_from_slice(&(RAM_SAVE_FLAG_PAGE | RAM_SAVE_FLAG_CONTINUE).to_be_bytes());
    data.extend_from_slice(&[0; PAGE_SIZE]);
    end_section(&mut data);
    assert!(parse(&data, None).is_err());
}

#[test]
fn scanning_past_a_device_finds_the_final_ram_section() -> anyhow::Result<()> {
    let mut data = initial_page();
    section(&mut data, QEMU_VM_SECTION_FULL);
    string(&mut data, "device");
    data.extend_from_slice(&[0; 8]);
    data.extend_from_slice(&[0xFF; 50]);
    section(&mut data, QEMU_VM_SECTION_END);
    page(&mut data, "pc.ram", Some(0xB6));
    end_section(&mut data);
    data.push(QEMU_VM_EOF);
    assert_page(&data, 0xB6)?;

    // A final section containing only EOS is also recognizable at EOF.
    let mut eos = vec![0xFF];
    section(&mut eos, QEMU_VM_SECTION_END);
    eos.extend_from_slice(&RAM_SAVE_FLAG_EOS.to_be_bytes());
    assert_eq!(scan_for_next_section(&eos, 0, Some(1)), Some(1));
    Ok(())
}
