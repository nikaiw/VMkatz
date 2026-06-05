#![cfg(feature = "chrome")]

use vmkatz::chrome::{run_placeholder, ChromeFindings};

#[test]
fn run_placeholder_returns_empty() {
    let f: ChromeFindings = run_placeholder();
    assert!(f.is_empty());
}
