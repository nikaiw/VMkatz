use super::*;
use std::io::Write as _;

fn fixture(name: &str, blocks: u64) -> anyhow::Result<(std::path::PathBuf, VmrsLayer)> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("vmkatz-vmrs-{name}-{}-{stamp}", std::process::id()));
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&path)?;
    file.set_len((blocks + 1) * RAM_BLOCK_SIZE as u64)?;
    let mut key_values = HashMap::new();
    for index in 0..blocks {
        let offset = (index + 1) * RAM_BLOCK_SIZE as u64;
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(&[u8::try_from(index + 1)?])?;
        key_values.insert(format!("RamBlock{index}"), (offset, RAM_BLOCK_SIZE as u32));
    }
    let layer = VmrsLayer {
        inner: RefCell::new(VmrsInner {
            file,
            cache: BlockCache::with_limit(24),
        }),
        header: HvsHeader {
            sequence: 0,
            version: 0,
            data_alignment: 0,
            data_offset: 0,
            data_size: 0,
        },
        object_entries: Vec::new(),
        key_bytes: key_values.keys().map(|key| key.len() + 128).sum(),
        key_values,
        ram_block_count: blocks,
        memory_chunks: Vec::new(),
        phys_size: blocks * RAM_BLOCK_SIZE as u64,
        mmio_gap_base: 0,
        mmio_gap_size: 0,
        read_masked: std::cell::Cell::new(false),
    };
    Ok((path, layer))
}

#[test]
fn parallel_scan_replaces_the_old_cache_without_raising_its_limit() -> anyhow::Result<()> {
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    let (path, layer) = fixture("scan", 24)?;
    layer.inner.borrow_mut().cache.insert(1000, vec![0xFF]);
    let count = AtomicUsize::new(0);
    let seen = AtomicU64::new(0);
    assert!(layer.par_scan(&|gpa, block| {
        let index = gpa / RAM_BLOCK_SIZE as u64;
        assert!(index < 24);
        assert_eq!(block.len(), RAM_BLOCK_SIZE);
        assert_eq!(u64::from(block[0]), index + 1);
        assert_eq!(block[RAM_BLOCK_SIZE - 1], 0);
        count.fetch_add(1, Ordering::Relaxed);
        seen.fetch_or(1 << index, Ordering::Relaxed);
        true
    }));
    assert_eq!(count.load(Ordering::Relaxed), 24);
    assert_eq!(seen.load(Ordering::Relaxed), (1 << 24) - 1);
    {
        let inner = layer.inner.borrow();
        assert!(!inner.cache.map.contains_key(&1000));
        assert!(inner.cache.limit <= 24);
        assert!(inner.cache.map.len() <= inner.cache.limit);
        let bytes: usize = inner
            .cache
            .map
            .values()
            .map(|node| node.data.capacity())
            .sum();
        assert!(bytes <= inner.cache.limit * RAM_BLOCK_SIZE);
    }
    for index in 0..24 {
        let mut byte = [0];
        layer.read_phys(index * RAM_BLOCK_SIZE as u64, &mut byte)?;
        assert_eq!(u64::from(byte[0]), index + 1);
    }
    drop(layer);
    fs::remove_file(path)?;
    Ok(())
}

#[test]
#[cfg(unix)]
fn parallel_scan_uses_the_opened_file_after_path_replacement() -> anyhow::Result<()> {
    let (path, layer) = fixture("unlinked-scan", 1)?;
    fs::remove_file(&path)?;
    for replaced in [false, true] {
        if replaced {
            fs::write(&path, b"a different file")?;
        }
        let count = std::sync::atomic::AtomicUsize::new(0);
        assert!(layer.par_scan(&|gpa, block| {
            assert_eq!(gpa, 0);
            assert_eq!(block[0], 1);
            count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            false
        }));
        assert_eq!(count.load(std::sync::atomic::Ordering::Relaxed), 1);
    }
    fs::remove_file(path)?;
    Ok(())
}

#[test]
fn parallel_scan_reports_incomplete_reads() -> anyhow::Result<()> {
    for readable in [0, 1] {
        let (path, layer) = fixture("short-scan", 2)?;
        layer
            .inner
            .borrow()
            .file
            .set_len((readable + 1) * RAM_BLOCK_SIZE as u64)?;
        let count = std::sync::atomic::AtomicU64::new(0);
        assert!(!layer.par_scan(&|_, block| {
            assert_eq!(block[0], 1);
            count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            false
        }));
        assert_eq!(count.load(std::sync::atomic::Ordering::Relaxed), readable);
        drop(layer);
        fs::remove_file(path)?;
    }
    Ok(())
}

#[test]
fn insufficient_scan_budget_keeps_sequential_reads_available() -> anyhow::Result<()> {
    let (path, layer) = fixture("serial", 1)?;
    layer.inner.borrow_mut().cache.set_limit(0);
    assert!(!layer.par_scan(&|_, _| panic!("parallel scan must be skipped")));
    let mut byte = [0];
    layer.read_phys(0, &mut byte)?;
    assert_eq!(byte, [1]);
    assert!(layer.inner.borrow().cache.map.is_empty());
    drop(layer);
    fs::remove_file(path)?;
    Ok(())
}

#[test]
fn cache_limit_changes_preserve_lru_and_allow_disabling_retention() {
    let mut cache = BlockCache::with_limit(2);
    cache.insert(1, vec![1]);
    cache.insert(2, vec![2]);
    assert_eq!(cache.get(1), Some([1].as_slice()));
    cache.insert(3, vec![3]);
    assert_eq!(cache.get(2), None);
    cache.set_limit(0);
    cache.insert(4, vec![4]);
    assert!(cache.map.is_empty());
    assert_eq!((cache.head, cache.tail), (None, None));
    cache.set_limit(1);
    cache.insert(5, vec![5]);
    assert_eq!(cache.get(5), Some([5].as_slice()));
}

#[test]
fn reads_reject_oversized_or_missing_data_before_allocating() -> anyhow::Result<()> {
    let (path, layer) = fixture("bounds", 1)?;
    let too_large = crate::memory::reader::MAX_READ_BYTES + 1;
    assert!(matches!(
        layer.read_file_bytes(0, too_large),
        Err(VmkatzError::AllocTooLarge { .. })
    ));
    for offset in [2 * RAM_BLOCK_SIZE as u64, u64::MAX] {
        assert!(layer.read_file_bytes(offset, 16).is_err());
    }
    assert_eq!(layer.read_file_bytes(RAM_BLOCK_SIZE as u64, 1)?, [1]);
    drop(layer);
    fs::remove_file(path)?;
    Ok(())
}

fn key_entry(name: &str, child: u32, reference: Option<(u64, u32)>) -> Vec<u8> {
    let size = 21 + name.len() + 1 + reference.map_or(0, |_| 12);
    let mut data = vec![0; size];
    data[0] = if reference.is_some() { 7 } else { 0 };
    data[1] = u8::from(reference.is_some());
    data[2..6].copy_from_slice(&(size as u32).to_le_bytes());
    data[8..12].copy_from_slice(&child.to_le_bytes());
    data[20] = (name.len() + 1) as u8;
    data[21..21 + name.len()].copy_from_slice(name.as_bytes());
    if let Some((offset, size)) = reference {
        let start = 22 + name.len();
        data[start..start + 4].copy_from_slice(&size.to_le_bytes());
        data[start + 4..].copy_from_slice(&offset.to_le_bytes());
    }
    data
}

fn table(offset: u64, size: u32) -> ObjectTableEntry {
    ObjectTableEntry {
        entry_type: 2,
        crc32: 0,
        file_offset: offset,
        size,
        flags: 0,
    }
}

#[test]
fn large_nested_key_tables_stream_under_64_mib_and_reject_cycles() -> anyhow::Result<()> {
    if crate::memory::test_limit::child(
        "hyperv::vmrs::memory_tests::large_nested_key_tables_stream_under_64_mib_and_reject_cycles",
    )? {
        return Ok(());
    }
    let (path, mut layer) = fixture("metadata", 0)?;
    let size = 256 * 1024 * 1024;
    let root = 4096u64;
    let child = root + u64::from(size);
    let payload = child + u64::from(size);
    {
        let mut inner = layer.inner.borrow_mut();
        inner.file.set_len(payload + 4096)?;
        inner.file.seek(SeekFrom::Start(root))?;
        inner.file.write_all(&2u16.to_le_bytes())?;
        inner.file.seek(SeekFrom::Start(root + 10))?;
        inner.file.write_all(&key_entry("savedstate", 1, None))?;
        inner.file.seek(SeekFrom::Start(child))?;
        inner.file.write_all(&2u16.to_le_bytes())?;
        inner.file.seek(SeekFrom::Start(child + 10))?;
        inner
            .file
            .write_all(&key_entry("RamBlock9", 0, Some((payload, 4096))))?;
    }
    layer.object_entries = vec![table(root, size), table(child, size)];
    layer.parse_key_tables()?;
    assert_eq!(
        layer.key_values.get("savedstate/RamBlock9"),
        Some(&(payload, 4096))
    );
    {
        let mut inner = layer.inner.borrow_mut();
        inner.file.seek(SeekFrom::Start(child + 10 + 8))?;
        inner.file.write_all(&(root as u32).to_le_bytes())?;
    }
    assert!(layer.parse_key_tables().unwrap_err().is_resource_limit());
    drop(layer);
    fs::remove_file(path)?;
    Ok(())
}

#[test]
fn metadata_budgets_fail_before_growing_collections() -> anyhow::Result<()> {
    let (path, mut layer) = fixture("metadata-budget", 0)?;
    layer.key_bytes = 32 * 1024 * 1024 - 140;
    layer.insert_key("RamBlock0".into(), (4096, 4096))?;
    let bytes = layer.key_bytes;
    layer.insert_key("RamBlock0".into(), (8192, 4096))?;
    assert_eq!(layer.key_bytes, bytes);
    assert!(
        layer
            .insert_key("RamBlock1".into(), (4096, 4096))
            .unwrap_err()
            .is_resource_limit()
    );
    assert_eq!(layer.key_values.len(), 1);
    layer
        .object_entries
        .resize(metadata::MAX_OBJECT_ENTRIES, table(1, 1));
    assert!(
        metadata::reserve_object(&mut layer.object_entries)
            .unwrap_err()
            .is_resource_limit()
    );
    drop(layer);
    fs::remove_file(path)?;
    Ok(())
}

#[test]
fn sparse_parallel_jobs_keep_high_indices_and_alias_priority() -> anyhow::Result<()> {
    let (path, mut layer) = fixture("sparse-scan", 1)?;
    layer.key_values.clear();
    let index = 8u64 * 1024 * 1024; // 8 TiB GPA, one block to scan.
    layer.key_values.insert(
        format!("RamBlock{index}"),
        (RAM_BLOCK_SIZE as u64, RAM_BLOCK_SIZE as u32),
    );
    layer.key_values.insert(
        format!("savedstate/RamBlock{index}"),
        (RAM_BLOCK_SIZE as u64, RAM_BLOCK_SIZE as u32),
    );
    let count = std::sync::atomic::AtomicUsize::new(0);
    assert!(layer.par_scan(&|gpa, data| {
        assert_eq!(gpa, index * RAM_BLOCK_SIZE as u64);
        assert_eq!(data[0], 1);
        count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        false
    }));
    assert_eq!(count.load(std::sync::atomic::Ordering::Relaxed), 1);
    drop(layer);
    fs::remove_file(path)?;
    Ok(())
}
