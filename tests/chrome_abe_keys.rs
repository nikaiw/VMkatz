#![cfg(feature = "chrome")]

//! Smoke test: parse a real `elevation_service.exe` sample if available locally.
//! The test is skipped (passes with a printed note) when the sample file is
//! absent so CI stays green.

use vmkatz::chrome::abe_keys::{
    BrowserKeyMap, CHROME_135_V1, CHROME_135_V2, CHROME_135_V3,
};

#[test]
fn parse_local_chrome135_elevation_service() {
    let path = "/tmp/elev_chrome135.exe";
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("skipping: cannot read {} ({})", path, e);
            return;
        }
    };
    let map = BrowserKeyMap::from_pe_or_fallback(&bytes);
    assert!(
        !map.fallback,
        "expected to extract keys from real PE, got fallback"
    );
    assert_eq!(map.resolve(1), Some(CHROME_135_V1));
    assert_eq!(map.resolve(2), Some(CHROME_135_V2));
    assert_eq!(map.resolve(3), Some(CHROME_135_V3));
}
