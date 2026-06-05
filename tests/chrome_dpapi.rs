#![cfg(feature = "chrome")]

// Roundtrip: construct a fake DPAPI_BLOB with a known masterkey, decrypt, verify.

use aes::Aes256;
use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use vmkatz::chrome::dpapi_decrypt::{decrypt_blob, parse_blob};

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type HmacSha512 = Hmac<Sha512>;

fn build_blob(plaintext: &[u8], masterkey: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut h = HmacSha512::new_from_slice(masterkey).unwrap();
    h.update(salt);
    let session = h.finalize().into_bytes();
    let key = &session[..32];
    let iv = &session[32..48];
    assert_eq!(plaintext.len() % 16, 0, "test plaintext must be block-aligned");
    let mut buf = vec![0u8; plaintext.len()];
    buf[..plaintext.len()].copy_from_slice(plaintext);
    let cipher = Aes256CbcEnc::new(key.into(), iv.into());
    let ct = cipher
        .encrypt_padded_mut::<NoPadding>(&mut buf, plaintext.len())
        .unwrap()
        .to_vec();

    let mk_guid: [u8; 16] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00,
    ];
    let mut b: Vec<u8> = Vec::new();
    b.extend(&1u32.to_le_bytes());
    b.extend(&[0u8; 16]);
    b.extend(&1u32.to_le_bytes());
    b.extend(&mk_guid);
    b.extend(&0u32.to_le_bytes());
    b.extend(&0u32.to_le_bytes());
    b.extend(&0x6610u32.to_le_bytes());
    b.extend(&32u32.to_le_bytes());
    b.extend(&(salt.len() as u32).to_le_bytes());
    b.extend(salt);
    b.extend(&0u32.to_le_bytes());
    b.extend(&0x800Eu32.to_le_bytes());
    b.extend(&64u32.to_le_bytes());
    b.extend(&0u32.to_le_bytes());
    b.extend(&(ct.len() as u32).to_le_bytes());
    b.extend(&ct);
    b.extend(&0u32.to_le_bytes());
    b
}

#[test]
fn roundtrip_decrypt_dpapi_blob() {
    let masterkey = [0xABu8; 64];
    let salt = b"some-salt-bytes-32-chars-long!!".to_vec();
    let plaintext = b"ENCRYPTED_KEY_32_BYTES__EXACT___";
    let blob_bytes = build_blob(plaintext, &masterkey, &salt);
    let blob = parse_blob(&blob_bytes).unwrap();
    let pt = decrypt_blob(&blob, &masterkey).unwrap();
    assert_eq!(&pt[..plaintext.len()], plaintext);
}
