mod sha2;
mod sha2_common;
mod sha2_constants;

pub use sha2::{Sha224,Sha256,Sha384,Sha512,Sha512_224,Sha512_256};


pub trait Hash {
    const DIGEST_SIZE: usize;

    fn new() -> Self;

    fn update(&mut self, data: &[u8]);

    fn digest(&mut self) -> Vec<u8>;

    fn reset(&mut self);

    fn digest_size(&self) -> usize {
        Self::DIGEST_SIZE
    }
}
