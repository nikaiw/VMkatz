//! AES-XTS sector-level decryption for BitLocker volume decryption.
//!
//! Implements AES-XTS-128 and AES-XTS-256 as used by BitLocker (Win8+).
//! Uses raw AES ECB operations from the `aes` crate — not CBC wrappers.

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes256};

use crate::error::{Result, VmkatzError};

/// Sector size for BitLocker XTS decryption.
const SECTOR_SIZE: usize = 512;

/// AES block size.
const BLOCK_SIZE: usize = 16;

/// Multiply tweak by x in GF(2^128) (little-endian representation).
///
/// This is the standard XTS tweak update: shift left by 1 bit,
/// and if the carry bit was set, XOR with the reduction polynomial 0x87.
pub(crate) fn gf128_mul_x(tweak: &mut [u8; 16]) {
    let mut carry = 0u8;
    for byte in tweak.iter_mut() {
        let new_carry = *byte >> 7;
        *byte = (*byte << 1) | carry;
        carry = new_carry;
    }
    if carry != 0 {
        tweak[0] ^= 0x87;
    }
}

/// Decrypt a single 512-byte sector using AES-XTS.
///
/// `key` must be 32 bytes (AES-128-XTS: two 16-byte keys) or
/// 64 bytes (AES-256-XTS: two 32-byte keys).
///
/// `sector` must be exactly 512 bytes and is decrypted in place.
///
/// `sector_number` is the sector index used to derive the XTS tweak value.
pub fn aes_xts_decrypt_sector(key: &[u8], sector: &mut [u8], sector_number: u64) -> Result<()> {
    if sector.len() != SECTOR_SIZE {
        return Err(VmkatzError::DecryptionError(format!(
            "AES-XTS: sector size must be {} bytes, got {}",
            SECTOR_SIZE,
            sector.len()
        )));
    }

    match key.len() {
        32 => xts_decrypt_128(key, sector, sector_number),
        64 => xts_decrypt_256(key, sector, sector_number),
        n => Err(VmkatzError::DecryptionError(format!(
            "AES-XTS: key must be 32 or 64 bytes, got {}",
            n
        ))),
    }
}

/// AES-128-XTS decryption: key1 and key2 are each 16 bytes.
fn xts_decrypt_128(key: &[u8], sector: &mut [u8], sector_number: u64) -> Result<()> {
    let key1 = &key[..16];
    let key2 = &key[16..32];

    let cipher1 = Aes128::new(GenericArray::from_slice(key1));
    let cipher2 = Aes128::new(GenericArray::from_slice(key2));

    xts_decrypt_inner(&cipher1, &cipher2, sector, sector_number)
}

/// AES-256-XTS decryption: key1 and key2 are each 32 bytes.
fn xts_decrypt_256(key: &[u8], sector: &mut [u8], sector_number: u64) -> Result<()> {
    let key1 = &key[..32];
    let key2 = &key[32..64];

    let cipher1 = Aes256::new(GenericArray::from_slice(key1));
    let cipher2 = Aes256::new(GenericArray::from_slice(key2));

    xts_decrypt_inner(&cipher1, &cipher2, sector, sector_number)
}

/// Generic XTS decryption core that works with any AES key size.
fn xts_decrypt_inner<C1, C2>(
    cipher1: &C1,
    cipher2: &C2,
    sector: &mut [u8],
    sector_number: u64,
) -> Result<()>
where
    C1: BlockDecrypt,
    C2: BlockEncrypt,
{
    // Step 1: Encrypt the sector number as the initial tweak
    let mut tweak = [0u8; 16];
    tweak[..8].copy_from_slice(&sector_number.to_le_bytes());

    let mut tweak_block = GenericArray::clone_from_slice(&tweak);
    cipher2.encrypt_block(&mut tweak_block);
    tweak.copy_from_slice(&tweak_block);

    // Step 2: Decrypt each 16-byte block with XTS
    let num_blocks = SECTOR_SIZE / BLOCK_SIZE;
    for i in 0..num_blocks {
        let offset = i * BLOCK_SIZE;
        let block = &mut sector[offset..offset + BLOCK_SIZE];

        // XOR with tweak (pre-decrypt)
        for (b, t) in block.iter_mut().zip(tweak.iter()) {
            *b ^= *t;
        }

        // AES decrypt
        let mut aes_block = GenericArray::clone_from_slice(block);
        cipher1.decrypt_block(&mut aes_block);
        block.copy_from_slice(&aes_block);

        // XOR with tweak (post-decrypt)
        for (b, t) in block.iter_mut().zip(tweak.iter()) {
            *b ^= *t;
        }

        // Advance tweak for next block
        gf128_mul_x(&mut tweak);
    }

    Ok(())
}

/// Decrypt a buffer of contiguous sectors using AES-XTS.
///
/// `data` length must be a multiple of 512. Sectors are numbered sequentially
/// starting from `first_sector_number`.
pub fn aes_xts_decrypt_sectors(
    key: &[u8],
    data: &mut [u8],
    first_sector_number: u64,
) -> Result<()> {
    if !data.len().is_multiple_of(SECTOR_SIZE) {
        return Err(VmkatzError::DecryptionError(format!(
            "AES-XTS: data length {} is not a multiple of sector size {}",
            data.len(),
            SECTOR_SIZE
        )));
    }

    let num_sectors = data.len() / SECTOR_SIZE;
    for i in 0..num_sectors {
        let offset = i * SECTOR_SIZE;
        let sector = &mut data[offset..offset + SECTOR_SIZE];
        aes_xts_decrypt_sector(key, sector, first_sector_number + i as u64)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gf128_mul_x_no_carry() {
        let mut tweak = [0u8; 16];
        tweak[0] = 0x01; // x^0
        gf128_mul_x(&mut tweak);
        assert_eq!(tweak[0], 0x02); // x^1
    }

    #[test]
    fn test_gf128_mul_x_with_carry() {
        let mut tweak = [0u8; 16];
        tweak[15] = 0x80; // MSB set = carry
        gf128_mul_x(&mut tweak);
        // After shift: all zeros. Carry set, so XOR 0x87 into byte[0]
        assert_eq!(tweak[0], 0x87);
        assert_eq!(tweak[15], 0x00);
    }

    #[test]
    fn test_xts_decrypt_wrong_sector_size() {
        let key = [0u8; 32];
        let mut sector = [0u8; 256]; // wrong size
        let result = aes_xts_decrypt_sector(&key, &mut sector, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_xts_decrypt_wrong_key_size() {
        let key = [0u8; 48]; // invalid
        let mut sector = [0u8; 512];
        let result = aes_xts_decrypt_sector(&key, &mut sector, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_xts_roundtrip_128() {
        // Encrypt then decrypt should give back the original plaintext.
        // We'll encrypt manually and then verify decryption.
        let key = [0x42u8; 32];
        let plaintext = [0xABu8; 512];

        // Encrypt: same as decrypt but use BlockEncrypt for cipher1
        let key1 = &key[..16];
        let key2 = &key[16..32];
        let cipher1 = Aes128::new(GenericArray::from_slice(key1));
        let cipher2 = Aes128::new(GenericArray::from_slice(key2));

        let sector_number: u64 = 42;
        let mut tweak = [0u8; 16];
        tweak[..8].copy_from_slice(&sector_number.to_le_bytes());
        let mut tweak_block = GenericArray::clone_from_slice(&tweak);
        cipher2.encrypt_block(&mut tweak_block);
        tweak.copy_from_slice(&tweak_block);

        let mut ciphertext = plaintext;
        for i in 0..(512 / 16) {
            let offset = i * 16;
            let block = &mut ciphertext[offset..offset + 16];
            for (b, t) in block.iter_mut().zip(tweak.iter()) {
                *b ^= *t;
            }
            let mut aes_block = GenericArray::clone_from_slice(block);
            cipher1.encrypt_block(&mut aes_block);
            block.copy_from_slice(&aes_block);
            for (b, t) in block.iter_mut().zip(tweak.iter()) {
                *b ^= *t;
            }
            gf128_mul_x(&mut tweak);
        }

        // Now decrypt and verify
        let mut decrypted = ciphertext;
        aes_xts_decrypt_sector(&key, &mut decrypted, sector_number).unwrap();
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_xts_roundtrip_256() {
        let key = [0x55u8; 64];
        let plaintext = [0xCDu8; 512];

        let key1 = &key[..32];
        let key2 = &key[32..64];
        let cipher1 = Aes256::new(GenericArray::from_slice(key1));
        let cipher2 = Aes256::new(GenericArray::from_slice(key2));

        let sector_number: u64 = 100;
        let mut tweak = [0u8; 16];
        tweak[..8].copy_from_slice(&sector_number.to_le_bytes());
        let mut tweak_block = GenericArray::clone_from_slice(&tweak);
        cipher2.encrypt_block(&mut tweak_block);
        tweak.copy_from_slice(&tweak_block);

        let mut ciphertext = plaintext;
        for i in 0..(512 / 16) {
            let offset = i * 16;
            let block = &mut ciphertext[offset..offset + 16];
            for (b, t) in block.iter_mut().zip(tweak.iter()) {
                *b ^= *t;
            }
            let mut aes_block = GenericArray::clone_from_slice(block);
            cipher1.encrypt_block(&mut aes_block);
            block.copy_from_slice(&aes_block);
            for (b, t) in block.iter_mut().zip(tweak.iter()) {
                *b ^= *t;
            }
            gf128_mul_x(&mut tweak);
        }

        let mut decrypted = ciphertext;
        aes_xts_decrypt_sector(&key, &mut decrypted, sector_number).unwrap();
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_xts_multi_sector() {
        let key = [0x37u8; 32];
        let plaintext = [0x99u8; 1024]; // 2 sectors

        // Encrypt both sectors
        let mut ciphertext = plaintext;
        for s in 0..2u64 {
            let key1 = &key[..16];
            let key2 = &key[16..32];
            let cipher1 = Aes128::new(GenericArray::from_slice(key1));
            let cipher2 = Aes128::new(GenericArray::from_slice(key2));

            let mut tweak = [0u8; 16];
            tweak[..8].copy_from_slice(&s.to_le_bytes());
            let mut tweak_block = GenericArray::clone_from_slice(&tweak);
            cipher2.encrypt_block(&mut tweak_block);
            tweak.copy_from_slice(&tweak_block);

            let sector = &mut ciphertext[(s as usize * 512)..((s as usize + 1) * 512)];
            for i in 0..(512 / 16) {
                let offset = i * 16;
                let block = &mut sector[offset..offset + 16];
                for (b, t) in block.iter_mut().zip(tweak.iter()) {
                    *b ^= *t;
                }
                let mut aes_block = GenericArray::clone_from_slice(block);
                cipher1.encrypt_block(&mut aes_block);
                block.copy_from_slice(&aes_block);
                for (b, t) in block.iter_mut().zip(tweak.iter()) {
                    *b ^= *t;
                }
                gf128_mul_x(&mut tweak);
            }
        }

        let mut decrypted = ciphertext;
        aes_xts_decrypt_sectors(&key, &mut decrypted, 0).unwrap();
        assert_eq!(&decrypted[..], &plaintext[..]);
    }
}
