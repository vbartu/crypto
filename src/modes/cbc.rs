use std::vec::Vec;

use super::pkcs7_padding;
use crate::aes_128;
use crate::utils;


pub fn encrypt(data: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Vec<u8> {
    let padded = pkcs7_padding::pad(data, aes_128::BLOCK_SIZE);
    let mut encrypted = Vec::<u8>::with_capacity(padded.len());

    let mut prev_ciphertext = iv.clone();
    for block in padded.chunks_exact(aes_128::BLOCK_SIZE) {
        utils::xor_slice(&mut prev_ciphertext, block);
        let ciphertext = aes_128::encrypt(&prev_ciphertext, key);
        encrypted.extend_from_slice(ciphertext.as_slice());
        prev_ciphertext.copy_from_slice(ciphertext.as_slice());
    }

    encrypted
}

pub fn decrypt(data: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Vec<u8> {
    let mut decrypted = Vec::<u8>::with_capacity(data.len());

    let mut prev_ciphertext = iv.clone();
    for block in data.chunks_exact(aes_128::BLOCK_SIZE) {
        let mut plaintext = aes_128::decrypt(block.try_into().unwrap(), key);
        utils::xor_slice(plaintext.as_mut_slice(), prev_ciphertext.as_slice());
        decrypted.extend_from_slice(plaintext.as_slice());
        prev_ciphertext.copy_from_slice(block);
    }

    let unpadded = pkcs7_padding::unpad(decrypted.as_slice());
    decrypted.truncate(unpadded.len());
    decrypted
}
