mod aes_128;
mod aes_128_constants;
mod des;
mod des_constants;

use crate::error::CryptoErr;
pub use aes_128::Aes128Cipher;
pub use des::DesCipher;


pub trait Cipher {
    const BLOCK_SIZE: usize;

    fn new(key: &[u8]) -> Result<Self, CryptoErr> where Self: Sized;

    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoErr>;

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoErr>;

    fn block_size(&self) -> usize {
        Self::BLOCK_SIZE
    }
}
