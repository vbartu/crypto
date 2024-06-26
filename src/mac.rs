mod hmac;
pub use hmac::Hmac;

use crate::error::IncorrectMac;
use crate::hash::Hash;


pub trait Mac<H> where H: Hash {
    fn new(key: &[u8]) -> Self where Self: Sized;

    fn update(&mut self, data: &[u8]);

    fn finalize(&mut self) -> Vec<u8>;

    fn reset(&mut self);

    fn verify(&mut self, data: &[u8], signature: &[u8])
            -> Result<(), IncorrectMac>;

    fn size(&self) -> usize {
        H::DIGEST_SIZE
    }
}
