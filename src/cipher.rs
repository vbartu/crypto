mod aes_128;
mod aes_128_constants;
mod des;
mod des_constants;

use crate::error::{InvalidKeyLen,InvalidDataLen};
pub use aes_128::Aes128Cipher;
pub use des::DesCipher;


pub trait Cipher {
    const BLOCK_SIZE: usize;

    fn new(key: &[u8]) -> Result<Self, InvalidKeyLen> where Self: Sized;

    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, InvalidDataLen>;

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, InvalidDataLen>;

    fn block_size(&self) -> usize {
        Self::BLOCK_SIZE
    }
}
