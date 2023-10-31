use super::pkcs7_padding;
use crate::cipher::{Cipher,CipherErr};
use crate::utils;


pub fn encrypt(data: &[u8], cipher: &impl Cipher, iv: &[u8])
        -> Result<Vec<u8>,CipherErr> {
    let padded = pkcs7_padding::pad(data, cipher.block_size());
    let mut encrypted = Vec::<u8>::with_capacity(padded.len());

    if iv.len() != cipher.block_size() {
        return Err(CipherErr::BlockSize);
    }
    let mut prev_ciphertext: Vec<u8> = iv.to_owned();
    for block in padded.chunks_exact(cipher.block_size()) {
        utils::xor_slice(&mut prev_ciphertext, block);
        let ciphertext = cipher.encrypt(&prev_ciphertext)
            .expect("Invalid block size");
        encrypted.extend_from_slice(ciphertext.as_slice());
        prev_ciphertext.copy_from_slice(ciphertext.as_slice());
    }

    Ok(encrypted)
}

pub fn decrypt(data: &[u8], cipher: &impl Cipher, iv: &[u8])
        -> Result<Vec<u8>,CipherErr> {
    let mut decrypted = Vec::<u8>::with_capacity(data.len());

    if iv.len() != cipher.block_size() {
        return Err(CipherErr::BlockSize);
    }
    let mut prev_ciphertext: Vec<u8> = iv.to_owned();
    for block in data.chunks_exact(cipher.block_size()) {
        let mut plaintext = cipher.decrypt(block)
            .expect("Invalid block size");
        utils::xor_slice(plaintext.as_mut_slice(), prev_ciphertext.as_slice());
        decrypted.extend_from_slice(plaintext.as_slice());
        prev_ciphertext.copy_from_slice(block);
    }

    let unpadded = pkcs7_padding::unpad(decrypted.as_slice());
    decrypted.truncate(unpadded.len());
    Ok(decrypted)
}
