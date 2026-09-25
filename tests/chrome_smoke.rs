#![cfg(feature = "chrome")]

use vmkatz::chrome::types::ChromeFindings;

/// A freshly constructed findings set holds nothing.
#[test]
fn default_findings_are_empty() {
    let f = ChromeFindings::default();
    assert!(f.is_empty());
    assert!(f.passwords.is_empty());
    assert!(f.cookies.is_empty());
    assert!(f.autofill.is_empty());
}
