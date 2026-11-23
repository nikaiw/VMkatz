#![cfg(feature = "chrome")]

use std::fs;
use vmkatz::chrome::sqlite::Pager;

#[cfg(test)]
fn load() -> Vec<u8> {
    fs::read("tests/fixtures/chrome/sqlite/mini.sqlite").expect("fixture present")
}

#[test]
fn header_parses() {
    let bytes = load();
    let pager = Pager::open(&bytes).unwrap();
    assert_eq!(pager.header.page_size, 4096);
    assert!(pager.header.page_count >= 2);
}

#[test]
fn page1_accessible() {
    let bytes = load();
    let pager = Pager::open(&bytes).unwrap();
    let p1 = pager.page(1).unwrap();
    assert_eq!(&p1[..16], b"SQLite format 3\x00");
}

#[test]
fn large_page_numbers_do_not_wrap_to_the_first_page() {
    let bytes = load();
    let pager = Pager::open(&bytes).unwrap();
    for page in [0, (1 << 20) + 1, u32::MAX] {
        assert!(pager.page(page).is_err(), "page {page}");
    }
}

#[test]
fn root_page_numbers_are_checked_before_narrowing_to_u32() {
    let mut bytes = vec![0u8; 512];
    bytes[..16].copy_from_slice(b"SQLite format 3\0");
    bytes[16..18].copy_from_slice(&512u16.to_be_bytes());
    bytes[28..32].copy_from_slice(&1u32.to_be_bytes());
    bytes[100] = 0x0D; // leaf table
    bytes[103..105].copy_from_slice(&1u16.to_be_bytes());
    bytes[108..110].copy_from_slice(&256u16.to_be_bytes());
    // One sqlite_master row: ("table", "x", "x", rootpage: i64, NULL).
    bytes[256..271].copy_from_slice(&[
        21, 1, 6, 23, 15, 15, 6, 0, b't', b'a', b'b', b'l', b'e', b'x', b'x',
    ]);
    for root in [-1, 1i64 << 32, (1i64 << 32) + 1] {
        bytes[271..279].copy_from_slice(&root.to_be_bytes());
        let pager = Pager::open(&bytes).unwrap();
        assert!(pager.root_of("x").is_err(), "root {root}");
    }
    bytes[271..279].copy_from_slice(&1i64.to_be_bytes());
    let pager = Pager::open(&bytes).unwrap();
    assert_eq!(pager.root_of("x").unwrap(), Some(1));
    assert_eq!(pager.root_of("missing").unwrap(), None);
}

#[test]
fn list_tables_finds_logins_and_cookies() {
    let bytes = load();
    let pager = Pager::open(&bytes).unwrap();
    let tables: Vec<String> = pager
        .list_tables()
        .unwrap()
        .into_iter()
        .map(|t| t.name)
        .collect();
    assert!(tables.contains(&"logins".to_string()), "got {tables:?}");
    assert!(tables.contains(&"cookies".to_string()), "got {tables:?}");
}

#[test]
fn walk_logins_table_finds_alice_and_bob() {
    use vmkatz::chrome::sqlite::walk_table;
    let bytes = load();
    let pager = Pager::open(&bytes).unwrap();
    let root = pager.root_of("logins").unwrap().unwrap();
    let mut users: Vec<String> = Vec::new();
    walk_table(&pager, root, |_rid, cols| {
        if let Some(u) = cols.get(1).and_then(|c| c.as_text()) {
            users.push(u.to_string());
        }
        Ok(())
    })
    .unwrap();
    assert!(users.contains(&"alice".to_string()), "got {users:?}");
    assert!(users.contains(&"bob".to_string()), "got {users:?}");
}

#[test]
fn wal_replay_surfaces_uncheckpointed_rows() {
    use vmkatz::chrome::sqlite::walk_table;
    let db = std::fs::read("tests/fixtures/chrome/sqlite/with_wal.sqlite").unwrap();
    let wal = std::fs::read("tests/fixtures/chrome/sqlite/with_wal.sqlite-wal").unwrap();
    let pager = Pager::open_with_wal(&db, &wal).unwrap();
    let root = pager.root_of("logins").unwrap().unwrap();
    let mut urls = Vec::new();
    walk_table(&pager, root, |_, cols| {
        if let Some(u) = cols.first().and_then(|c| c.as_text()) {
            urls.push(u.to_string());
        }
        Ok(())
    })
    .unwrap();
    assert!(urls.iter().any(|u| u.contains("baseline")), "got {urls:?}");
    assert!(
        urls.iter().any(|u| u.contains("wal_only")),
        "WAL replay failed; got {urls:?}"
    );
}
