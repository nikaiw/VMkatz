use super::*;

#[test]
fn sequential_pages_and_overwrites_match_a_simple_map() -> io::Result<()> {
    let mut index = PageIndex::default();
    let mut reference = BTreeMap::new();
    for page in 0..100_000 {
        index.insert(page * PAGE_SIZE, Some(page * 4104))?;
        reference.insert(page, Some(page * 4104));
    }
    assert_eq!(index.runs.len(), 1);
    let mut seed = 42u64;
    for n in 0..20_000 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let page = (seed >> 32) % 100_100;
        let value = (n % 3 != 0).then_some(n * 4097);
        #[cfg(feature = "qemu")]
        if n % 5 == 0 {
            index.remove(page * PAGE_SIZE)?;
            reference.remove(&page);
            continue;
        }
        index.insert(page * PAGE_SIZE, value)?;
        reference.insert(page, value);
    }
    for page in 0..100_110 {
        assert_eq!(
            index.get(page * PAGE_SIZE),
            reference
                .get(&page)
                .map(|offset| offset.map_or(PageLocation::Zero, PageLocation::File))
        );
    }
    assert_eq!(index.page_count(), reference.len() as u64);
    Ok(())
}

#[test]
fn updates_at_the_run_limit_preserve_mappings_and_the_budget() -> io::Result<()> {
    let mut index = PageIndex::default();
    for page in 0..MAX_RUNS as u64 {
        index.insert(page * 8192, Some(4096))?;
    }
    let last = (MAX_RUNS as u64 - 1) * 8192;
    index.insert(0, Some(4096))?;
    index.insert(last + 4096, Some(8192))?;
    index.insert(last + 8192, Some(12288))?;
    assert_eq!(index.runs.len(), MAX_RUNS);
    assert_eq!(index.page_count(), MAX_RUNS as u64 + 2);

    // Splitting the final run would exceed the budget: leave it intact.
    assert_eq!(
        index.insert(last + 4096, None).unwrap_err().kind(),
        io::ErrorKind::OutOfMemory
    );
    #[cfg(feature = "qemu")]
    assert_eq!(
        index.remove(last + 4096).unwrap_err().kind(),
        io::ErrorKind::OutOfMemory
    );
    for (gpa, offset) in [
        (0, 4096),
        (last, 4096),
        (last + 4096, 8192),
        (last + 8192, 12288),
    ] {
        assert_eq!(index.get(gpa), Some(PageLocation::File(offset)));
    }
    assert_eq!(index.runs.len(), MAX_RUNS);
    assert_eq!(index.page_count(), MAX_RUNS as u64 + 2);

    // Bridging two runs frees a slot, even when the budget was exhausted.
    index.insert(4096, Some(4096))?;
    assert_eq!(index.runs.len(), MAX_RUNS - 1);
    index.insert(last + 16384, None)?;
    assert_eq!(index.runs.len(), MAX_RUNS);
    assert_eq!(index.get(last + 16384), Some(PageLocation::Zero));
    Ok(())
}

#[test]
fn fragmentation_and_address_overflow_fail_cleanly() -> io::Result<()> {
    let mut index = PageIndex::default();
    for n in 0..MAX_RUNS {
        index.insert(n as u64 * 8192, Some(0))?;
    }
    assert_eq!(
        index.insert(u64::MAX - 8191, None).unwrap_err().kind(),
        io::ErrorKind::OutOfMemory
    );
    assert!(PageIndex::default().insert(u64::MAX - 4095, None).is_err());
    assert!(PageIndex::default().insert(1, None).is_err());
    assert!(PageIndex::default().insert(0, Some(u64::MAX)).is_err());
    Ok(())
}
