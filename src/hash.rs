pub mod sha2;


pub trait Hash {
    const DIGEST_SIZE: usize;

    fn new() -> Self;

    fn digest(&mut self, data: &[u8]) -> Vec<u8>;

    fn update(&mut self, data: &[u8]);

    fn digest_size(&self) -> usize {
        Self::DIGEST_SIZE
    }
}
