mod hmac;
pub use hmac::Hmac;

use crate::error::{IncorrectMac, InvalidKeyLen};


pub trait Mac {
    fn new(key: &[u8]) -> Result<Self, InvalidKeyLen> where Self: Sized;

    fn update(&mut self, data: &[u8]);

    fn generate(&mut self) -> Vec<u8>;

    fn reset(&mut self);

    fn verify(&mut self, data: &[u8], signature: &[u8])
            -> Result<(), IncorrectMac> {
        self.reset();
        self.update(data);
        let expected_signature = self.generate();
        if expected_signature != signature {
            return Err(IncorrectMac);
        }
        Ok(())
    }

    fn size(&self) -> usize;
}
