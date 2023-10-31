mod aes_128;
mod aes_128_constants;

pub use aes_128::Aes128Cipher;


#[derive(Debug)]
pub enum CipherErr {
    KeySize,
    BlockSize,
}

impl std::fmt::Display for CipherErr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CipherErr::KeySize => write!(f, "{}", "Invalid key size"),
            CipherErr::BlockSize => write!(f, "{}", "Invalid block size"),
        }
    }
}

impl std::error::Error for CipherErr {}


pub trait Cipher {
    const BLOCK_SIZE: usize;

    fn new(key: &[u8]) -> Result<Self, CipherErr> where Self: Sized;

    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CipherErr>;

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CipherErr>;

    fn block_size(&self) -> usize {
        Self::BLOCK_SIZE
    }
}
