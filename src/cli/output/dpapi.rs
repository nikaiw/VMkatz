//! Disk master key selection and output.

use vmkatz::dpapi::masterkey::DpapiMasterKeyHash;

use super::csv_escape;
use crate::cli::args::Colors;

/// Borrow the most recent DPAPI master key per (username, sid) for display.
/// `show_all` preserves every key in input order; the source stays intact for CredMan.
pub fn dedup_dpapi_hashes(
    hashes: &[DpapiMasterKeyHash],
    show_all: bool,
) -> Vec<&DpapiMasterKeyHash> {
    let mut hashes: Vec<_> = hashes.iter().collect();
    if show_all || hashes.len() <= 1 {
        return hashes;
    }
    // Sort by (username, sid, modified DESC) so the most recent key comes first
    hashes.sort_by(|a, b| {
        a.username
            .cmp(&b.username)
            .then(a.sid.cmp(&b.sid))
            .then(b.modified.cmp(&a.modified))
    });
    hashes.dedup_by(|a, b| a.username == b.username && a.sid == b.sid);
    hashes
}

pub fn print_dpapi_masterkey_csv(hashes: &[&DpapiMasterKeyHash]) {
    println!("provider,username,domain,secret_type,secret,target");
    for h in hashes {
        println!(
            "dpapi_disk,{},{},masterkey_hash,{},{}",
            csv_escape(&h.username),
            csv_escape(&h.sid),
            csv_escape(&h.hash),
            csv_escape(&h.guid),
        );
    }
}

pub fn print_dpapi_masterkey_text(hashes: &[&DpapiMasterKeyHash], c: &Colors) {
    use vmkatz::lsass::types::filetime_to_string;

    println!(
        "\n{}[+] DPAPI Master Key Files ({} found):{}",
        c.green,
        hashes.len(),
        c.reset
    );
    for h in hashes {
        println!("  User: {} ({})", h.username, h.sid);
        println!("    GUID    : {}", h.guid);
        if h.modified != 0 {
            println!("    Modified: {}", filetime_to_string(h.modified));
        }
        let mode_desc = match h.mode {
            15300 => "3DES/SHA1, local",
            15310 => "3DES/SHA1, domain",
            15900 => "AES256/SHA512, local",
            15910 => "AES256/SHA512, domain",
            _ => "unknown",
        };
        println!("    Hashcat : mode {} ({})", h.mode, mode_desc);
        println!("    Hash    : {}", h.hash);
    }
}

pub fn print_dpapi_masterkey_hashcat(hashes: &[&DpapiMasterKeyHash]) {
    for h in hashes {
        println!("{}", h.hash);
    }
}

#[cfg(test)]
mod tests {
    use super::{DpapiMasterKeyHash, dedup_dpapi_hashes};

    fn key(username: &str, sid: &str, guid: &str, modified: u64) -> DpapiMasterKeyHash {
        DpapiMasterKeyHash {
            username: username.into(),
            sid: sid.into(),
            guid: guid.into(),
            hash: format!("fixture-{guid}"),
            mode: 15900,
            modified,
        }
    }

    #[test]
    fn newest_key_is_selected_per_exact_username_and_sid() {
        let hashes = vec![
            key("bob", "S-B", "bob", 2),
            key("alice", "S-A", "old", 1),
            key("alice", "S-A", "new", 3),
            key("alice", "S-Z", "other-sid", 0),
            key("Alice", "S-A", "case-sensitive", 2),
        ];
        let selected = dedup_dpapi_hashes(&hashes, false);
        let guids: Vec<_> = selected.iter().map(|h| h.guid.as_str()).collect();
        assert_eq!(guids, ["case-sensitive", "new", "other-sid", "bob"]);
        assert!(std::ptr::eq(selected[1], std::ptr::from_ref(&hashes[2])));
        // Display selection must leave every candidate available to CredMan.
        let original: Vec<_> = hashes.iter().map(|h| h.guid.as_str()).collect();
        assert_eq!(
            original,
            ["bob", "old", "new", "other-sid", "case-sensitive"]
        );
    }

    #[test]
    fn equal_or_unknown_timestamps_keep_the_first_key() {
        let hashes = vec![
            key("alice", "S-A", "first", 5),
            key("alice", "S-A", "second", 5),
            key("alice", "S-A", "older", 0),
            key("bob", "S-B", "unknown-first", 0),
            key("bob", "S-B", "unknown-second", 0),
        ];
        let selected = dedup_dpapi_hashes(&hashes, false);
        let guids: Vec<_> = selected.iter().map(|h| h.guid.as_str()).collect();
        assert_eq!(guids, ["first", "unknown-first"]);
    }

    #[test]
    fn show_all_preserves_duplicates_and_input_order() {
        let hashes = vec![
            key("bob", "S-B", "bob", 0),
            key("alice", "S-A", "old", 1),
            key("alice", "S-A", "new", 2),
        ];
        let selected = dedup_dpapi_hashes(&hashes, true);
        assert_eq!(selected.len(), hashes.len());
        for (selected, original) in selected.into_iter().zip(&hashes) {
            assert!(std::ptr::eq(selected, original));
        }
    }

    #[test]
    fn empty_and_single_key_inputs_are_preserved() {
        let hashes = [key("alice", "S-A", "only", 0)];
        for show_all in [false, true] {
            assert!(dedup_dpapi_hashes(&[], show_all).is_empty());
            let selected = dedup_dpapi_hashes(&hashes, show_all);
            assert_eq!(selected.len(), 1);
            assert!(std::ptr::eq(selected[0], std::ptr::from_ref(&hashes[0])));
        }
    }
}
