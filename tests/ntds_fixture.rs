//! Real-NTDS regression test, gated on a local fixture.
//!
//! Drop a DC's `ntds.dit` and `SYSTEM` hive into `tests/fixtures/ntds/`
//! (git-ignored — these hold real credential material, never commit them).
//! When absent, the test skips so public CI stays green.
//!
//! It pins the class of bug where `objectSid` RIDs were decoded with the wrong
//! byte order (little-endian instead of NTDS's big-endian), which byte-swapped
//! every RID (e.g. 500 -> 0xF4010000) and silently corrupted all NT/LM hashes.
#![cfg(feature = "ntds.dit")]

use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/ntds")
        .join(name)
}

#[test]
fn ntds_fixture_rids_and_hashes_are_sane() {
    let (dit, system) = (fixture("ntds.dit"), fixture("SYSTEM"));
    if !dit.exists() || !system.exists() {
        eprintln!(
            "skipping: drop a DC ntds.dit + SYSTEM into {} to run this test",
            dit.parent().unwrap().display()
        );
        return;
    }

    let ntds_data = std::fs::read(&dit).expect("read ntds.dit fixture");
    let system_data = std::fs::read(&system).expect("read SYSTEM fixture");

    let hashes = vmkatz::ntds::extract_ad_hashes(&ntds_data, &system_data, false)
        .expect("extract_ad_hashes on the fixture");

    assert!(
        hashes.len() >= 30,
        "expected a populated DC datatable, got {} entries",
        hashes.len()
    );

    // Byte-swapped RIDs land in the billions; every real account RID is small.
    for h in &hashes {
        assert!(
            h.rid < 1_000_000,
            "implausible RID {} for {} — objectSid likely decoded with the wrong \
             byte order",
            h.rid,
            h.username
        );
    }

    // Built-in principals have fixed, well-known RIDs: a direct check that the
    // last sub-authority is read correctly.
    let rid_of = |name: &str| {
        hashes
            .iter()
            .find(|h| !h.is_history && h.username.eq_ignore_ascii_case(name))
            .map(|h| h.rid)
    };
    assert_eq!(rid_of("Administrator"), Some(500), "Administrator RID");
    assert_eq!(rid_of("krbtgt"), Some(502), "krbtgt RID");

    // A correctly-keyed decrypt yields varied hashes; a wholly broken PEK/RID
    // path tends to collapse them. Require more than one distinct NT hash.
    let distinct = hashes
        .iter()
        .filter(|h| !h.is_history)
        .map(|h| h.nt_hash)
        .collect::<std::collections::HashSet<_>>();
    assert!(
        distinct.len() > 1,
        "all accounts share one NT hash — decryption is broken"
    );
}
