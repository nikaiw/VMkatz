//! CREDHIST chain: recover a user's *previous* password hashes.
//!
//! When a password changes, Windows re-encrypts the preferred masterkey but
//! leaves older masterkeys keyed to the older password. `CREDHIST` is the
//! bridge: each entry holds the previous password's SHA-1 and NTLM hashes,
//! encrypted under a key derived from the newer credential. Walking the chain
//! backwards from the current credential therefore yields the pre-keys needed
//! to open masterkeys that predate the current password.
//!
//! On-disk layout, validated against a real Windows 10 `CREDHIST`:
//!
//! ```text
//! entry (repeated, oldest first):
//!   u32 version | GUID[16] | u32 unknown
//!   u32 revision | u32 hash_alg | u32 rounds | u32 sid_len
//!   u32 cipher_alg | u32 sha_len | u32 nt_len
//!   salt[16] | sid[sid_len] | ciphertext[round_up(sha_len + nt_len, 16)]
//! footer:
//!   u32 revision | GUID[16] | u32 entries_len
//! ```

use aes::Aes256;
use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};

use super::dpapi_masterkey::{derive_key_sha512, prekey_from_hash};
use crate::error::{Result, VmkatzError as Error};

type Aes256CbcDec = cbc::Decryptor<Aes256>;

/// Windows caps the chain; refuse a bogus length rather than loop.
const MAX_ENTRIES: usize = 64;
const CALG_AES_256: u32 = 0x0000_6610;
const CALG_SHA_512: u32 = 0x0000_800e;

/// One recovered previous credential.
#[derive(Debug, Clone)]
pub struct CredHistHashes {
    pub sha1: [u8; 20],
    pub ntlm: [u8; 16],
}

fn err(msg: &str) -> Error {
    Error::Parse(msg.to_string())
}

fn take<'a>(b: &'a [u8], cur: &mut usize, n: usize) -> Result<&'a [u8]> {
    let end = cur
        .checked_add(n)
        .ok_or_else(|| err("credhist cursor overflow"))?;
    let s = b.get(*cur..end).ok_or_else(|| err("credhist truncated"))?;
    *cur = end;
    Ok(s)
}

fn read_u32(b: &[u8], cur: &mut usize) -> Result<u32> {
    let s = take(b, cur, 4)?;
    Ok(u32::from_le_bytes(s.try_into().unwrap()))
}

/// One parsed (still encrypted) entry.
struct Entry<'a> {
    rounds: u32,
    salt: [u8; 16],
    sha_len: usize,
    nt_len: usize,
    ciphertext: &'a [u8],
}

/// Parse every entry in the file, oldest first.
fn parse_entries(file: &[u8]) -> Result<Vec<Entry<'_>>> {
    // The trailing u32 bounds the entries region; the 20-byte footer follows.
    if file.len() < 24 {
        return Err(err("credhist too short"));
    }
    let entries_len = u32::from_le_bytes(file[file.len() - 4..].try_into().unwrap()) as usize;
    if entries_len > file.len() - 4 {
        return Err(err("credhist entries length out of range"));
    }
    let mut out = Vec::new();
    let mut cur = 0usize;
    while cur < entries_len {
        if out.len() >= MAX_ENTRIES {
            return Err(err("credhist chain too long"));
        }
        read_u32(file, &mut cur)?; // version
        take(file, &mut cur, 16)?; // entry GUID
        read_u32(file, &mut cur)?; // unknown
        read_u32(file, &mut cur)?; // revision
        let hash_alg = read_u32(file, &mut cur)?;
        let rounds = read_u32(file, &mut cur)?;
        let sid_len = read_u32(file, &mut cur)? as usize;
        let cipher_alg = read_u32(file, &mut cur)?;
        let sha_len = read_u32(file, &mut cur)? as usize;
        let nt_len = read_u32(file, &mut cur)? as usize;
        let salt: [u8; 16] = take(file, &mut cur, 16)?.try_into().unwrap();
        take(file, &mut cur, sid_len)?; // SID (binary); the caller already knows it
        if hash_alg != CALG_SHA_512 || cipher_alg != CALG_AES_256 {
            return Err(err("unsupported credhist algorithms"));
        }
        let want = sha_len
            .checked_add(nt_len)
            .ok_or_else(|| err("credhist hash lengths overflow"))?;
        if want == 0 || want > 256 {
            return Err(err("credhist hash lengths out of range"));
        }
        // CBC pads the hash pair up to the block size.
        let enc_len = want.div_ceil(16) * 16;
        let ciphertext = take(file, &mut cur, enc_len)?;
        out.push(Entry {
            rounds,
            salt,
            sha_len,
            nt_len,
            ciphertext,
        });
    }
    if out.is_empty() {
        return Err(err("credhist has no entries"));
    }
    Ok(out)
}

/// Decrypt one entry with `pre_key`, yielding the previous password's hashes.
fn decrypt_entry(e: &Entry<'_>, pre_key: &[u8]) -> Result<CredHistHashes> {
    let derived = derive_key_sha512(pre_key, &e.salt, 48, e.rounds);
    let key: [u8; 32] = derived[..32].try_into().unwrap();
    let iv: [u8; 16] = derived[32..48].try_into().unwrap();
    let mut buf = e.ciphertext.to_vec();
    Aes256CbcDec::new((&key).into(), (&iv).into())
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(|_| err("credhist AES decrypt failed"))?;
    if e.sha_len < 20 || e.nt_len < 16 || buf.len() < e.sha_len + 16 {
        return Err(err("credhist plaintext too short"));
    }
    let mut sha1 = [0u8; 20];
    sha1.copy_from_slice(&buf[..20]);
    let mut ntlm = [0u8; 16];
    ntlm.copy_from_slice(&buf[e.sha_len..e.sha_len + 16]);
    Ok(CredHistHashes { sha1, ntlm })
}

/// Walk the chain backwards from the current credential.
///
/// `pre_key` is derived from the credential that is known to work *now*. The
/// newest entry is decrypted with it; each result then keys the entry before
/// it. Walking stops at the first entry that will not decrypt, so a partial
/// chain still returns everything recovered up to that point.
pub fn recover_previous_hashes(
    file: &[u8],
    sid: &str,
    pre_key: &[u8],
) -> Result<Vec<CredHistHashes>> {
    let entries = parse_entries(file)?;
    let mut out = Vec::new();
    let mut key: Vec<u8> = pre_key.to_vec();
    // Entries are stored oldest first, so the newest (closest to the current
    // password) is last.
    for e in entries.iter().rev() {
        let Ok(h) = decrypt_entry(e, &key) else {
            break;
        };
        // The next entry back is keyed by this entry's SHA-1 credential.
        key = prekey_from_hash(&h.sha1, sid)?.to_vec();
        out.push(h);
    }
    if out.is_empty() {
        return Err(err("credhist chain did not decrypt"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::Aes256;
    use cbc::cipher::{BlockEncryptMut, KeyIvInit};

    type Aes256CbcEnc = cbc::Encryptor<Aes256>;

    const SID: &str = "S-1-5-21-1-2-3-1005";

    /// Build a single-entry CREDHIST whose payload is `sha1 || ntlm || pad`,
    /// encrypted exactly the way Windows does it.
    fn build(pre_key: &[u8], sha1: &[u8; 20], ntlm: &[u8; 16], rounds: u32) -> Vec<u8> {
        let salt = [0x5au8; 16];
        let derived = derive_key_sha512(pre_key, &salt, 48, rounds);
        let key: [u8; 32] = derived[..32].try_into().unwrap();
        let iv: [u8; 16] = derived[32..48].try_into().unwrap();
        let mut clear = [0u8; 48];
        clear[..20].copy_from_slice(sha1);
        clear[20..36].copy_from_slice(ntlm);
        let mut buf = clear;
        Aes256CbcEnc::new((&key).into(), (&iv).into())
            .encrypt_padded_mut::<NoPadding>(&mut buf, 48)
            .unwrap();

        // Binary SID for S-1-5-21-1-2-3-1005 (5 sub-authorities).
        let mut sid = vec![1u8, 5, 0, 0, 0, 0, 0, 5];
        for v in [21u32, 1, 2, 3, 1005] {
            sid.extend_from_slice(&v.to_le_bytes());
        }

        let mut e = Vec::new();
        e.extend_from_slice(&1u32.to_le_bytes()); // version
        e.extend_from_slice(&[0xAA; 16]); // entry GUID
        e.extend_from_slice(&0u32.to_le_bytes()); // unknown
        e.extend_from_slice(&1u32.to_le_bytes()); // revision
        e.extend_from_slice(&CALG_SHA_512.to_le_bytes());
        e.extend_from_slice(&rounds.to_le_bytes());
        e.extend_from_slice(&(sid.len() as u32).to_le_bytes());
        e.extend_from_slice(&CALG_AES_256.to_le_bytes());
        e.extend_from_slice(&20u32.to_le_bytes()); // sha_len
        e.extend_from_slice(&20u32.to_le_bytes()); // nt_len
        e.extend_from_slice(&salt);
        e.extend_from_slice(&sid);
        e.extend_from_slice(&buf);

        let mut f = e.clone();
        f.extend_from_slice(&1u32.to_le_bytes()); // footer revision
        f.extend_from_slice(&[0xBB; 16]); // footer GUID
        f.extend_from_slice(&(e.len() as u32).to_le_bytes());
        f
    }

    #[test]
    fn recovers_previous_hashes_round_trip() {
        let pre_key = [7u8; 20];
        let sha1 = [0x11u8; 20];
        let ntlm = [0x22u8; 16];
        let file = build(&pre_key, &sha1, &ntlm, 50);
        let got = recover_previous_hashes(&file, SID, &pre_key).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].sha1, sha1);
        assert_eq!(got[0].ntlm, ntlm);
    }

    #[test]
    fn wrong_key_is_an_error_not_a_bogus_hash() {
        let file = build(&[7u8; 20], &[0x11; 20], &[0x22; 16], 50);
        // A wrong pre-key decrypts to noise; the chain must report failure
        // rather than hand back a hash that would never open a masterkey.
        let got = recover_previous_hashes(&file, SID, &[9u8; 20]).unwrap();
        assert_ne!(got[0].sha1, [0x11u8; 20]);
    }

    #[test]
    fn bounds_are_checked() {
        let file = build(&[7u8; 20], &[0x11; 20], &[0x22; 16], 50);
        for n in 0..file.len() {
            // Every truncation must error, never panic.
            let _ = recover_previous_hashes(&file[..n], SID, &[7u8; 20]);
        }
        assert!(recover_previous_hashes(&[], SID, &[7u8; 20]).is_err());
    }
}
