#![cfg(feature = "disk")]

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use vmkatz::disk::{DiskImage, qcow2::QcowDisk, vdi::VdiDisk, vhd::VhdDisk, vhdx::VhdxDisk};

const MIB: u64 = 1 << 20;
const EIGHT_TIB: u64 = 8 << 40;

struct Fixture(PathBuf);

impl Fixture {
    fn new(tag: &str) -> anyhow::Result<Self> {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "vmkatz-tables-{tag}-{}-{stamp}",
            std::process::id()
        ));
        fs::create_dir(&dir)?;
        Ok(Self(dir))
    }

    fn file(&self, name: &str) -> anyhow::Result<(PathBuf, File)> {
        let path = self.0.join(name);
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)?;
        Ok((path, file))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0) {
            eprintln!("Cannot clean fixture {}: {error}", self.0.display());
        }
    }
}

fn put(file: &mut File, offset: u64, bytes: &[u8]) -> std::io::Result<()> {
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(bytes)
}

fn payload(file: &mut File, offset: u64, block: u64, value: u8) -> std::io::Result<()> {
    put(file, offset, &[value; 512])?;
    put(file, offset + block - 512, &[value; 512])
}

struct Layout {
    path: PathBuf,
    size: u64,
    block: u64,
    present: Vec<u64>,
    table_end: u64,
}

fn samples(blocks: u64) -> Vec<u64> {
    vec![0, 511, 512, 1023, 1024, 4095, 4096, blocks - 1]
}

fn vdi(fixture: &Fixture) -> anyhow::Result<Layout> {
    let (path, mut file) = fixture.file("disk.vdi")?;
    let block = MIB / 4;
    let entries = EIGHT_TIB / block;
    let table_end = 512 + entries * 4; // 128 MiB BAT
    let present = samples(entries);
    file.set_len(table_end + present.len() as u64 * block)?;
    for (offset, value) in [
        (0x40, 0xBEDA_107F),
        (0x4c, 1),
        (0x154, 512),
        (0x158, u32::try_from(table_end)?),
        (0x178, u32::try_from(block)?),
        (0x180, u32::try_from(entries)?),
    ] {
        put(&mut file, offset, &value.to_le_bytes())?;
    }
    put(&mut file, 0x170, &EIGHT_TIB.to_le_bytes())?;
    for (index, &logical) in present.iter().enumerate() {
        put(
            &mut file,
            512 + logical * 4,
            &u32::try_from(index)?.to_le_bytes(),
        )?;
        payload(
            &mut file,
            table_end + index as u64 * block,
            block,
            u8::try_from(index + 1)?,
        )?;
    }
    put(&mut file, 512 + 2 * 4, &u32::MAX.to_le_bytes())?;
    Ok(Layout {
        path,
        size: EIGHT_TIB,
        block,
        present,
        table_end,
    })
}

fn vhd(fixture: &Fixture) -> anyhow::Result<Layout> {
    let (path, mut file) = fixture.file("disk.vhd")?;
    let size = 1 << 40;
    let block = 32 * 1024;
    let entries = size / block;
    let table_end = 2048 + entries * 4; // 128 MiB BAT
    let present = samples(entries);
    let footer = table_end + present.len() as u64 * (block + 512);
    file.set_len(footer + 512)?;
    put(&mut file, footer, b"conectix")?;
    put(&mut file, footer + 16, &512u64.to_be_bytes())?;
    put(&mut file, footer + 48, &size.to_be_bytes())?;
    put(&mut file, footer + 60, &3u32.to_be_bytes())?;
    put(&mut file, 512, b"cxsparse")?;
    put(&mut file, 512 + 16, &2048u64.to_be_bytes())?;
    put(&mut file, 512 + 28, &u32::try_from(entries)?.to_be_bytes())?;
    put(&mut file, 512 + 32, &u32::try_from(block)?.to_be_bytes())?;
    for (index, &logical) in present.iter().enumerate() {
        let offset = table_end + index as u64 * (block + 512);
        put(
            &mut file,
            2048 + logical * 4,
            &u32::try_from(offset / 512)?.to_be_bytes(),
        )?;
        payload(&mut file, offset + 512, block, u8::try_from(index + 1)?)?;
    }
    put(&mut file, 2048 + 2 * 4, &u32::MAX.to_be_bytes())?;
    Ok(Layout {
        path,
        size,
        block,
        present,
        table_end,
    })
}

fn vhdx(fixture: &Fixture) -> anyhow::Result<Layout> {
    let (path, mut file) = fixture.file("disk.vhdx")?;
    let entries = EIGHT_TIB / MIB;
    let bat_entries = entries + (entries - 1) / 4096;
    let table_end = 2 * MIB + bat_entries * 8;
    let region_len = (bat_entries * 8).div_ceil(MIB) * MIB;
    let data_offset = 2 * MIB + region_len;
    let present = samples(entries);
    file.set_len(data_offset + present.len() as u64 * MIB)?;
    put(&mut file, 0, b"vhdxfile")?;
    put(&mut file, 0x10000, b"head")?;
    put(&mut file, 0x10008, &1u64.to_le_bytes())?;
    put(&mut file, 0x30000, b"regi")?;
    put(&mut file, 0x30008, &2u32.to_le_bytes())?;
    for (index, (guid, offset, len)) in [
        ("6677c22d23f600429d64115e9bfd4a08", 2 * MIB, region_len),
        ("06a27c8b90479a4bb8fe575f050f886e", MIB, MIB),
    ]
    .iter()
    .enumerate()
    {
        let entry = 0x30010 + index as u64 * 32;
        put(&mut file, entry, &hex::decode(guid)?)?;
        put(&mut file, entry + 16, &offset.to_le_bytes())?;
        put(&mut file, entry + 24, &u32::try_from(*len)?.to_le_bytes())?;
    }
    put(&mut file, MIB, b"metadata")?;
    put(&mut file, MIB + 10, &3u16.to_le_bytes())?;
    let parameters = [u32::try_from(MIB)?.to_le_bytes(), 0u32.to_le_bytes()].concat();
    for (index, (guid, data)) in [
        ("3767a1ca36fa434db3b633f0aa44e76b", parameters),
        (
            "2442a52f1bcd7648b2115dbed83bf4b8",
            EIGHT_TIB.to_le_bytes().to_vec(),
        ),
        (
            "1dbf41816fa90947ba47f233a8faab5f",
            512u32.to_le_bytes().to_vec(),
        ),
    ]
    .iter()
    .enumerate()
    {
        let entry = MIB + 32 + index as u64 * 32;
        let offset = 0x10000 + u32::try_from(index)? * 16;
        put(&mut file, entry, &hex::decode(guid)?)?;
        put(&mut file, entry + 16, &offset.to_le_bytes())?;
        put(
            &mut file,
            entry + 20,
            &u32::try_from(data.len())?.to_le_bytes(),
        )?;
        put(&mut file, MIB + u64::from(offset), data)?;
    }
    for (index, &logical) in present.iter().enumerate() {
        let offset = data_offset + index as u64 * MIB;
        put(
            &mut file,
            2 * MIB + (logical + logical / 4096) * 8,
            &(offset | 6).to_le_bytes(),
        )?;
        payload(&mut file, offset, MIB, u8::try_from(index + 1)?)?;
    }
    Ok(Layout {
        path,
        size: EIGHT_TIB,
        block: MIB,
        present,
        table_end,
    })
}

fn qcow(fixture: &Fixture, bits: u32, size: u64, present: Vec<u64>) -> anyhow::Result<Layout> {
    let (path, mut file) = fixture.file("disk.qcow2")?;
    let block = 1u64 << bits;
    let l2_entries = block / 8;
    let l1_entries = size.div_ceil(block * l2_entries);
    let table_end = block + l1_entries * 8;
    let l2_start = table_end.div_ceil(block) * block;
    let mut tables = BTreeMap::new();
    for logical in &present {
        let next = tables.len() as u64;
        tables
            .entry(logical / l2_entries)
            .or_insert(l2_start + next * block);
    }
    let data_offset = l2_start + tables.len() as u64 * block;
    file.set_len(data_offset + present.len() as u64 * block)?;
    for (offset, value) in [
        (0, 0x5146_49FB),
        (4, 2),
        (20, bits),
        (36, u32::try_from(l1_entries)?),
    ] {
        put(&mut file, offset, &value.to_be_bytes())?;
    }
    put(&mut file, 24, &size.to_be_bytes())?;
    put(&mut file, 40, &block.to_be_bytes())?;
    for (&index, &offset) in &tables {
        put(&mut file, block + index * 8, &offset.to_be_bytes())?;
    }
    for (index, &logical) in present.iter().enumerate() {
        let offset = data_offset + index as u64 * block;
        let l2 = tables[&(logical / l2_entries)];
        put(
            &mut file,
            l2 + (logical % l2_entries) * 8,
            &offset.to_be_bytes(),
        )?;
        payload(&mut file, offset, block, u8::try_from(index + 1)?)?;
    }
    Ok(Layout {
        path,
        size,
        block,
        present,
        table_end,
    })
}

fn open(path: &Path) -> anyhow::Result<Box<dyn DiskImage>> {
    Ok(match path.extension().and_then(|v| v.to_str()) {
        Some("vdi") => Box::new(VdiDisk::open(path)?),
        Some("vhd") => Box::new(VhdDisk::open(path)?),
        Some("vhdx") => Box::new(VhdxDisk::open(path)?),
        _ => Box::new(QcowDisk::open(path)?),
    })
}

fn check_reads(layout: &Layout) -> anyhow::Result<()> {
    let mut disk = open(&layout.path)?;
    assert_eq!(disk.disk_size(), layout.size);
    for _ in 0..3 {
        for (index, logical) in layout.present.iter().enumerate().rev() {
            let value = u8::try_from(index + 1)?;
            let mut data = [0; 128];
            disk.seek(SeekFrom::Start(logical * layout.block + 17))?;
            disk.read_exact(&mut data)?;
            assert_eq!(data, [value; 128]);
            if layout.present.get(index + 1) == Some(&(logical + 1)) {
                disk.seek(SeekFrom::Start((logical + 1) * layout.block - 2))?;
                let mut crossing = [0; 4];
                disk.read_exact(&mut crossing)?;
                assert_eq!(crossing, [value, value, value + 1, value + 1]);
            }
        }
    }
    disk.seek(SeekFrom::Start(2 * layout.block))?;
    let mut zeros = [0xFF; 128];
    disk.read_exact(&mut zeros)?;
    assert_eq!(zeros, [0; 128]);
    Ok(())
}

#[cfg(target_os = "linux")]
fn limit_memory() -> std::io::Result<()> {
    for (resource, bytes) in [(libc::RLIMIT_AS, 64 * 1024 * 1024), (libc::RLIMIT_CORE, 0)] {
        let limit = libc::rlimit {
            rlim_cur: bytes,
            rlim_max: bytes,
        };
        // SAFETY: limit is valid for this call, which retains no pointer.
        if unsafe { libc::setrlimit(resource, &raw const limit) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn child_test(name: &str) -> anyhow::Result<bool> {
    if std::env::var_os("VMKATZ_TABLE_MEMORY_CHILD").is_none() {
        use std::os::unix::process::CommandExt as _;
        let mut command = std::process::Command::new(std::env::current_exe()?);
        command
            .args(["--exact", name, "--nocapture"])
            .env("VMKATZ_TABLE_MEMORY_CHILD", "1");
        // SAFETY: the hook only calls setrlimit and reads errno.
        unsafe { command.pre_exec(limit_memory) };
        let output = command.output()?;
        anyhow::ensure!(
            output.status.success(),
            "{name}: {}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return Ok(true);
    }
    Ok(false)
}

#[test]
fn large_disk_tables_fit_in_a_bounded_process() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    if child_test("large_disk_tables_fit_in_a_bounded_process")? {
        return Ok(());
    }
    let fixture = Fixture::new("large")?;
    let layouts = [
        vdi(&fixture)?,
        vhd(&fixture)?,
        vhdx(&fixture)?,
        qcow(
            &fixture,
            9,
            EIGHT_TIB,
            vec![0, 63, 64, 32767, 32768, EIGHT_TIB / 512 - 1],
        )?,
    ];
    for layout in &layouts {
        check_reads(layout)?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&layout.path)?;
        let mut footer = [0; 512];
        let is_vhd = layout.path.extension().is_some_and(|ext| ext == "vhd");
        if is_vhd {
            file.seek(SeekFrom::End(-512))?;
            file.read_exact(&mut footer)?;
        }
        // Reopening a truncated table must fail before allocating or reading it.
        file.set_len(layout.table_end - 1)?;
        if is_vhd {
            put(&mut file, layout.table_end - 1 - 512, &footer)?;
        }
        let error = open(&layout.path).err().expect("truncated table must fail");
        assert!(matches!(error.downcast_ref::<vmkatz::error::VmkatzError>(),
            Some(vmkatz::error::VmkatzError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof));
    }
    Ok(())
}

#[test]
fn qcow_large_l2_tables_share_a_bounded_cache() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    if child_test("qcow_large_l2_tables_share_a_bounded_cache")? {
        return Ok(());
    }
    let fixture = Fixture::new("l2")?;
    let block = 16 * MIB;
    let per_table = block / 8;
    let present = (0..8).map(|i| i * per_table).collect();
    let layout = qcow(&fixture, 24, 8 * per_table * block, present)?;
    check_reads(&layout)?;
    Ok(())
}

#[test]
fn deep_qcow_backing_chain_keeps_table_buffers_off_the_stack() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    if child_test("deep_qcow_backing_chain_keeps_table_buffers_off_the_stack")? {
        return Ok(());
    }
    let fixture = Fixture::new("chain")?;
    let mut parent = "disk.qcow2".to_string();
    qcow(&fixture, 9, 512, vec![0])?;
    for depth in 1..=64 {
        let name = format!("child-{depth}.qcow2");
        let (_, mut file) = fixture.file(&name)?;
        file.set_len(1024)?;
        for (offset, value) in [(0, 0x5146_49FBu32), (4, 2), (20, 9), (36, 1)] {
            put(&mut file, offset, &value.to_be_bytes())?;
        }
        put(&mut file, 8, &72u64.to_be_bytes())?;
        put(&mut file, 16, &u32::try_from(parent.len())?.to_be_bytes())?;
        put(&mut file, 24, &512u64.to_be_bytes())?;
        put(&mut file, 40, &512u64.to_be_bytes())?;
        put(&mut file, 72, parent.as_bytes())?;
        parent = name;
    }
    let mut disk = QcowDisk::open(&fixture.0.join(parent))?;
    let mut bytes = [0; 128];
    disk.read_exact(&mut bytes)?;
    assert_eq!(bytes, [1; 128]);
    Ok(())
}

#[test]
fn vhdx_payload_and_sector_bitmap_lookups_preserve_parent_fallback() -> anyhow::Result<()> {
    let fixture = Fixture::new("vhdx-parent")?;
    let base = vhdx(&fixture)?;
    let mut source = File::open(&base.path)?;
    let (path, mut child) = fixture.file("child.vhdx")?;
    let payload_offset = base.table_end.div_ceil(MIB) * MIB;
    let bitmap_offset = payload_offset + MIB;
    child.set_len(bitmap_offset + MIB)?;
    for (offset, len) in [(0, 512), (0x10000, 512), (0x30000, 512), (MIB, 0x10100)] {
        source.seek(SeekFrom::Start(offset))?;
        child.seek(SeekFrom::Start(offset))?;
        std::io::copy(&mut Read::by_ref(&mut source).take(len), &mut child)?;
    }
    put(&mut child, MIB + 0x10004, &2u32.to_le_bytes())?; // HasParent
    put(&mut child, MIB + 10, &4u16.to_le_bytes())?;
    let entry = MIB + 32 + 3 * 32;
    put(
        &mut child,
        entry,
        &hex::decode("2d5fd3a80bb34d45abf7d3d84834ab0c")?,
    )?;
    put(&mut child, entry + 16, &0x20000u32.to_le_bytes())?;
    put(&mut child, entry + 20, &512u32.to_le_bytes())?;
    let locator = MIB + 0x20000;
    let key: Vec<u8> = "relative_path"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let value: Vec<u8> = "disk.vhdx"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    put(&mut child, locator + 18, &1u16.to_le_bytes())?;
    put(&mut child, locator + 20, &32u32.to_le_bytes())?;
    put(
        &mut child,
        locator + 24,
        &(32 + u32::try_from(key.len())?).to_le_bytes(),
    )?;
    put(
        &mut child,
        locator + 28,
        &u16::try_from(key.len())?.to_le_bytes(),
    )?;
    put(
        &mut child,
        locator + 30,
        &u16::try_from(value.len())?.to_le_bytes(),
    )?;
    put(&mut child, locator + 32, &key)?;
    put(&mut child, locator + 32 + key.len() as u64, &value)?;

    // Block 511 uses a distant sector bitmap entry. Only its first sector is in the child.
    put(
        &mut child,
        2 * MIB + 511 * 8,
        &(payload_offset | 7).to_le_bytes(),
    )?;
    put(
        &mut child,
        2 * MIB + 4096 * 8,
        &(bitmap_offset | 6).to_le_bytes(),
    )?;
    put(&mut child, bitmap_offset + 511 * (MIB / 512) / 8, &[1])?;
    put(&mut child, payload_offset, &[0xDA; 1024])?;
    drop(child);
    let mut disk = VhdxDisk::open(&path)?;
    for (offset, expected) in [
        (511 * MIB, 0xDA),
        (511 * MIB + 512, 0),
        (512 * MIB - 512, 2),
        (4096 * MIB, 7),
    ] {
        disk.seek(SeekFrom::Start(offset))?;
        let mut bytes = [0xFF; 128];
        disk.read_exact(&mut bytes)?;
        assert_eq!(bytes, [expected; 128]);
    }
    Ok(())
}
