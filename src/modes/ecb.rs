use std::vec::Vec;

use super::pkcs7_padding;
use crate::aes_128;


pub fn encrypt(data: &[u8], key: &[u8; 16]) -> Vec<u8> {
    let padded = pkcs7_padding::pad(data, aes_128::BLOCK_SIZE);
    let mut encrypted = Vec::<u8>::with_capacity(padded.len());

    for block in padded.chunks_exact(aes_128::BLOCK_SIZE) {
        let ciphertext = aes_128::encrypt(block.try_into().unwrap(), key);
        encrypted.extend_from_slice(ciphertext.as_slice());
    }

    encrypted
}

pub fn decrypt(data: &[u8], key: &[u8; 16]) -> Vec<u8> {
    let mut decrypted = Vec::<u8>::with_capacity(data.len());

    for block in data.chunks_exact(aes_128::BLOCK_SIZE) {
        let plaintext = aes_128::decrypt(block.try_into().unwrap(), key);
        decrypted.extend_from_slice(plaintext.as_slice());
    }

    let unpadded = pkcs7_padding::unpad(decrypted.as_slice());
    decrypted.truncate(unpadded.len());
    decrypted
}
