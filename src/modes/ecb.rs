use super::pkcs7_padding;
use crate::cipher::{Cipher,CipherErr};


pub fn encrypt(data: &[u8], cipher: &impl Cipher)
        -> Result<Vec<u8>, CipherErr> {
    let padded = pkcs7_padding::pad(data, cipher.block_size());
    let mut encrypted = Vec::<u8>::with_capacity(padded.len());

    for block in padded.chunks_exact(cipher.block_size()) {
        let ciphertext = cipher.encrypt(block)
            .expect("Invalid block size");
        encrypted.extend_from_slice(ciphertext.as_slice());
    }

    Ok(encrypted)
}

pub fn decrypt(data: &[u8], cipher: &impl Cipher)
        -> Result<Vec<u8>, CipherErr> {
    let mut decrypted = Vec::<u8>::with_capacity(data.len());

    for block in data.chunks_exact(cipher.block_size()) {
        let plaintext = cipher.decrypt(block)
            .expect("Invalid block size");
        decrypted.extend_from_slice(plaintext.as_slice());
    }

    let unpadded = pkcs7_padding::unpad(decrypted.as_slice());
    decrypted.truncate(unpadded.len());
    Ok(decrypted)
}
