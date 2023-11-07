use crate::cipher::{Cipher,CipherErr};
use crate::utils;


pub fn encrypt(data: &[u8], cipher: &impl Cipher, nonce: &[u8])
        -> Result<Vec<u8>,CipherErr> {
    let nonce_size: usize = cipher.block_size() / 2;
    if nonce.len() != nonce_size {
        return Err(CipherErr::BlockSize);
    }
    let mut counter: u64 = 0;
    let mut encrypted: Vec<u8> = Vec::with_capacity(data.len());
    let mut nonce_counter: Vec<u8> = vec![0; cipher.block_size()];
    nonce_counter[..nonce_size].clone_from_slice(nonce);

    for block in data.chunks(cipher.block_size()) {
        let counter_bytes = &counter.to_be_bytes()[8-nonce_size..];
        nonce_counter[nonce_size..].clone_from_slice(counter_bytes);
        let mut stream = cipher.encrypt(nonce_counter.as_slice())
            .expect("Invalid nonce_counter size");
        utils::xor_slice(stream.as_mut_slice(), block);
        encrypted.extend_from_slice(&stream[..block.len()]);
        counter += 1;
    }

    Ok(encrypted)
}

pub fn decrypt(data: &[u8], cipher: &impl Cipher, nonce: &[u8])
        -> Result<Vec<u8>,CipherErr> {
    encrypt(data, cipher, nonce)
}
