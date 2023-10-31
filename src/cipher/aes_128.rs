mod aes_implementation;
mod aes_constants;

use super::{Cipher,CipherErr};


pub struct Aes128Cipher {
    key: [u8; Self::BLOCK_SIZE],
}

impl Cipher for Aes128Cipher {
    const BLOCK_SIZE: usize = aes_constants::BLOCK_SIZE;

    fn new(key: &[u8]) -> Result<Self, CipherErr> {
        match key.try_into() {
            Ok(key) => Ok(Self { key }),
            Err(_) => Err(CipherErr::KeySize)
        }
    }

    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CipherErr> {
        match data.try_into() {
            Ok(data) => {
                let ciphertext = aes_implementation::encrypt(&data, &self.key);
                Ok(Vec::from(ciphertext))
            },
            Err(_) => Err(CipherErr::BlockSize)
        }
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CipherErr> {
        match data.try_into() {
            Ok(data) => {
                let plaintext = aes_implementation::decrypt(&data, &self.key);
                Ok(Vec::from(plaintext))
            },
            Err(_) => Err(CipherErr::BlockSize)
        }
    }
}
