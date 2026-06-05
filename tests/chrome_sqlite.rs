#![cfg(feature = "chrome")]

use std::fs;
use vmkatz::chrome::sqlite::Pager;

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
fn list_tables_finds_logins_and_cookies() {
    let bytes = load();
    let pager = Pager::open(&bytes).unwrap();
    let tables: Vec<String> = pager
        .list_tables()
        .unwrap()
        .into_iter()
        .map(|t| t.name)
        .collect();
    assert!(tables.contains(&"logins".to_string()), "got {:?}", tables);
    assert!(tables.contains(&"cookies".to_string()), "got {:?}", tables);
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
    assert!(users.contains(&"alice".to_string()), "got {:?}", users);
    assert!(users.contains(&"bob".to_string()), "got {:?}", users);
}
