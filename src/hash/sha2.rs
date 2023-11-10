
use super::sha2_constants as constants;
use super::sha2_common::ShaCommon;


pub struct Sha224 {
    hash: Box<[u32; 8]>,
    data: [u8; constants::SHA256_BLOCK_SIZE],
    pending_data: usize,
    total_data: usize,
}

impl ShaCommon for Sha224 {
    type T = u32;
    const DIGEST_SIZE: usize = constants::SHA224_DIGEST_SIZE;
    const BLOCK_SIZE: usize = constants::SHA256_BLOCK_SIZE;
    const W_LENGTH: usize = constants::SHA256_W_LENGTH;
    const K_CONST: &'static[Self::T] = &constants::SHA256_K;

    fn new() -> Self {
        Self {
            hash: Box::new(constants::SHA224_INIT_H),
            data: [0; Self::BLOCK_SIZE],
            pending_data: 0,
            total_data: 0,
        }
    }

    fn hash(&mut self) -> &mut [Self::T; 8] {
        &mut self.hash
    }
    fn data(&mut self) -> &mut [u8] {
        &mut self.data
    }

    fn get_pending(&mut self) -> usize {
        self.pending_data
    }

    fn set_pending(&mut self, value: usize) {
        self.pending_data = value;
    }

    fn inc_total(&mut self, value: usize) {
        self.total_data += value;
    }

    fn get_total(&self) -> usize {
        self.total_data
    }

    fn reset(&mut self) {
        self.hash = Box::new(constants::SHA224_INIT_H);
        self.pending_data = 0;
        self.total_data = 0;
    }
}


pub struct Sha256 {
    hash: Box<[u32; 8]>,
    data: [u8; constants::SHA256_BLOCK_SIZE],
    pending_data: usize,
    total_data: usize,
}

impl ShaCommon for Sha256 {
    type T = u32;
    const DIGEST_SIZE: usize = constants::SHA256_DIGEST_SIZE;
    const BLOCK_SIZE: usize = constants::SHA256_BLOCK_SIZE;
    const W_LENGTH: usize = constants::SHA256_W_LENGTH;
    const K_CONST: &'static[Self::T] = &constants::SHA256_K;

    fn new() -> Self {
        Self {
            hash: Box::new(constants::SHA256_INIT_H),
            data: [0; Self::BLOCK_SIZE],
            pending_data: 0,
            total_data: 0,
        }
    }

    fn hash(&mut self) -> &mut [Self::T; 8] {
        &mut self.hash
    }
    fn data(&mut self) -> &mut [u8] {
        &mut self.data
    }

    fn get_pending(&mut self) -> usize {
        self.pending_data
    }

    fn set_pending(&mut self, value: usize) {
        self.pending_data = value;
    }

    fn inc_total(&mut self, value: usize) {
        self.total_data += value;
    }

    fn get_total(&self) -> usize {
        self.total_data
    }

    fn reset(&mut self) {
        self.hash = Box::new(constants::SHA256_INIT_H);
        self.pending_data = 0;
        self.total_data = 0;
    }
}


pub struct Sha512 {
    hash: Box<[u64; 8]>,
    data: [u8; constants::SHA512_BLOCK_SIZE],
    pending_data: usize,
    total_data: usize,
}

impl ShaCommon for Sha512 {
    type T = u64;
    const DIGEST_SIZE: usize = constants::SHA512_DIGEST_SIZE;
    const BLOCK_SIZE: usize = constants::SHA512_BLOCK_SIZE;
    const W_LENGTH: usize = constants::SHA512_W_LENGTH;
    const K_CONST: &'static[Self::T] = &constants::SHA512_K;

    fn new() -> Self {
        Self {
            hash: Box::new(constants::SHA512_INIT_H),
            data: [0; Self::BLOCK_SIZE],
            pending_data: 0,
            total_data: 0,
        }
    }

    fn hash(&mut self) -> &mut [Self::T; 8] {
        &mut self.hash
    }
    fn data(&mut self) -> &mut [u8] {
        &mut self.data
    }

    fn get_pending(&mut self) -> usize {
        self.pending_data
    }

    fn set_pending(&mut self, value: usize) {
        self.pending_data = value;
    }

    fn inc_total(&mut self, value: usize) {
        self.total_data += value;
    }

    fn get_total(&self) -> usize {
        self.total_data
    }

    fn reset(&mut self) {
        self.hash = Box::new(constants::SHA512_INIT_H);
        self.pending_data = 0;
        self.total_data = 0;
    }
}
