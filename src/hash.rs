mod sha2;
mod sha2_common;
mod sha2_constants;

pub use sha2::{Sha224,Sha256,Sha512};


pub trait Hash {
    const DIGEST_SIZE: usize;

    fn new() -> Self;

    // Digest MUST reset the hash
    fn digest(&mut self, data: &[u8]) -> Vec<u8>;

    fn update(&mut self, data: &[u8]);

    fn digest_size(&self) -> usize {
        Self::DIGEST_SIZE
    }
}
