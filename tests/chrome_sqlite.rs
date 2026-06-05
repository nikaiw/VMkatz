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
