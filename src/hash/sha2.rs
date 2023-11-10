use super::Hash;
use super::sha2_constants as constants;
use std::ops::{BitAnd, BitXor, Not};


pub struct Sha224 {
    hash: Box<[u32; 8]>,
    data: [u8; constants::SHA256_BLOCK_SIZE],
    pending_data: usize,
    total_data: usize,
}

impl ShaCommon<u32> for Sha224 {
    const DIGEST_SIZE: usize = constants::SHA224_DIGEST_SIZE;
    const BLOCK_SIZE: usize = constants::SHA256_BLOCK_SIZE;
    const W_LENGTH: usize = constants::SHA256_W_LENGTH;
    const K_CONST: &'static[u32] = &constants::SHA256_K;

    fn new() -> Self {
        Self {
            hash: Box::new(constants::SHA224_H),
            data: [0; Self::BLOCK_SIZE],
            pending_data: 0,
            total_data: 0,
        }
    }

    fn hash(&mut self) -> &mut [u32; 8] {
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
        self.hash = Box::new(constants::SHA224_H);
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

impl ShaCommon<u32> for Sha256 {
    const DIGEST_SIZE: usize = constants::SHA256_DIGEST_SIZE;
    const BLOCK_SIZE: usize = constants::SHA256_BLOCK_SIZE;
    const W_LENGTH: usize = constants::SHA256_W_LENGTH;
    const K_CONST: &'static[u32] = &constants::SHA256_K;

    fn new() -> Self {
        Self {
            hash: Box::new(constants::SHA256_H),
            data: [0; Self::BLOCK_SIZE],
            pending_data: 0,
            total_data: 0,
        }
    }

    fn hash(&mut self) -> &mut [u32; 8] {
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
        self.hash = Box::new(constants::SHA256_H);
        self.pending_data = 0;
        self.total_data = 0;
    }
}

trait ShaCommon<T: 'static> {
    const BLOCK_SIZE: usize;
    const DIGEST_SIZE: usize;
    const W_LENGTH: usize;
    const K_CONST: &'static[T];
    fn new() -> Self;
    fn hash(&mut self) -> &mut [T; 8];
    fn data(&mut self) -> &mut [u8]; // Size MUST BE BLOCK_SIZE
    fn get_pending(&mut self) -> usize;
    fn set_pending(&mut self, value: usize);
    fn inc_total(&mut self, value: usize);
    fn get_total(&self) -> usize;
    fn reset(&mut self);
}

impl <T: ShaCommon<u32>> Hash for T {
    const DIGEST_SIZE: usize = <T as ShaCommon<u32>>::DIGEST_SIZE;

    fn new() -> Self {
        <T as ShaCommon<u32>>::new()
    }

    fn update(&mut self, data: &[u8]) {
        let pending = self.get_pending();
        if pending + data.len() < Self::BLOCK_SIZE {
            self.data()[pending..pending+data.len()].copy_from_slice(data);
            self.set_pending(pending + data.len());
            return;
        }

        let missing_data = Self::BLOCK_SIZE - pending;
        //TODO: unsafe to dereference data?
        let mut old_data = self.data().to_vec();
        old_data[pending..].copy_from_slice(&data[..missing_data]);
        process_block(&mut self.hash(), &old_data, &Self::K_CONST, Self::W_LENGTH);
        self.inc_total(Self::BLOCK_SIZE);

        let block_iter = data[missing_data..].chunks_exact(Self::BLOCK_SIZE);
        let rem = block_iter.remainder();
        for block in block_iter {
            process_block(&mut self.hash(), block, &Self::K_CONST, Self::W_LENGTH);
            self.inc_total(Self::BLOCK_SIZE);
        }

        self.set_pending(rem.len());
        self.data()[..rem.len()].copy_from_slice(rem);
    }

    fn digest(&mut self, data: &[u8]) -> Vec<u8> {
        self.update(data);
        let pending = self.get_pending();
        let total = self.get_total();
        let padded = pad_last_block(&self.data()[..pending], total, Self::BLOCK_SIZE);
        for block in padded.chunks_exact(Self::BLOCK_SIZE) {
            process_block(&mut self.hash(), block, &Self::K_CONST, Self::W_LENGTH);
        }
        let mut digest: Vec<u8> = Vec::with_capacity(Self::DIGEST_SIZE);
        for i in 0..Self::DIGEST_SIZE/4 {
            digest.extend_from_slice(self.hash()[i].to_be_bytes().as_slice());
        }
        self.reset();
        digest
    }
}

trait ShaUnsg: Copy
             + BitAnd<Output = Self>
             + BitXor<Output = Self>
             + Not<Output = Self>
{
    fn s0(self) -> Self;
    fn s1(self) -> Self;
    fn v0(self) -> Self;
    fn v1(self) -> Self;
    fn wrapping_add(self, lhs: Self) -> Self;
    fn from_be_bytes(bytes: &[u8]) -> Self;

    fn ch(x: Self, y: Self, z: Self) -> Self
    {
        (x & y) ^ (!x & z)
    }

    fn maj(x: Self, y: Self, z: Self) -> Self
    {
        (x & y) ^ (x & z) ^ (y & z)
    }
}

impl ShaUnsg for u32 {
    fn s0(self) -> Self {
        self.rotate_right(2) ^ self.rotate_right(13) ^ self.rotate_right(22)
    }

    fn s1(self) -> Self {
        self.rotate_right(6) ^ self.rotate_right(11) ^ self.rotate_right(25)
    }

    fn v0(self) -> Self {
        self.rotate_right(7) ^ self.rotate_right(18) ^ (self >> 3)
    }

    fn v1(self) -> Self {
        self.rotate_right(17) ^ self.rotate_right(19) ^ (self >> 10)
    }

    fn wrapping_add(self, lhs: Self) -> Self {
        self.wrapping_add(lhs)
    }

    fn from_be_bytes(bytes: &[u8]) -> Self {
        u32::from_be_bytes(bytes.try_into().unwrap())
    }
}

impl ShaUnsg for u64 {
    fn s0(self) -> Self {
        self.rotate_right(28) ^ self.rotate_right(34) ^ self.rotate_right(39)
    }

    fn s1(self) -> Self {
        self.rotate_right(14) ^ self.rotate_right(18) ^ self.rotate_right(41)
    }

    fn v0(self) -> Self {
        self.rotate_right(1) ^ self.rotate_right(8) ^ (self >> 7)
    }

    fn v1(self) -> Self {
        self.rotate_right(19) ^ self.rotate_right(61) ^ (self >> 6)
    }

    fn wrapping_add(self, lhs: Self) -> Self {
        self.wrapping_add(lhs)
    }

    fn from_be_bytes(bytes: &[u8]) -> Self {
        u64::from_be_bytes(bytes.try_into().unwrap())
    }
}

fn pad_last_block(block: &[u8], total_data: usize,
                  block_size: usize) -> Vec<u8> {
    assert!(block.len() <= block_size);
    let mut padded = Vec::with_capacity(block_size);
    padded.extend_from_slice(block);
    padded.push(0x80);
    let k: usize;
    if block.len() < 56 {
        k = block_size - block.len() - 1 - block_size/8;
    } else {
        k = block_size*2 - block.len() - 1 - block_size/8;
    }
    for _ in 0..k {
        padded.push(0)
    }
    let length = (((total_data+block.len())*8) as u64).to_be_bytes();
    padded.extend_from_slice(&length);
    padded
}

fn process_block<T: ShaUnsg>(hash: &mut [T; 8], block: &[u8],
                             k_const: &[T], w_length: usize) {
    // Message schedule (W)
    let mut w: Vec<T> = Vec::with_capacity(w_length);
    
    // Always 16 rounds
    for int_bytes in block.chunks(std::mem::size_of::<T>()) {
        w.push(T::from_be_bytes(int_bytes));
    }
    for i in 16..w_length {
        w.push(T::v1(w[i-2])
            .wrapping_add(w[i-7])
            .wrapping_add(T::v0(w[i-15]))
            .wrapping_add(w[i-16]));
    }

    // Working variables: a(0), b(1), c(2), d(3), e(4), f(5), g(6), h(7)
    let mut v = hash.clone();

    for i in 0..w_length {
        // t1 = h + s1(e) + ch(e, f, g) + K[t] +  w[t]
        let t1: T = v[7]
            .wrapping_add(T::s1(v[4]))
            .wrapping_add(T::ch(v[4], v[5], v[6]))
            .wrapping_add(k_const[i])
            .wrapping_add(w[i]);
        // t2 = s0(a) + maj(a, b, c);
        let t2: T = T::s0(v[0]).wrapping_add(T::maj(v[0], v[1], v[2]));

        v[7] = v[6];                  // h = g;
        v[6] = v[5];                  // g = f;
        v[5] = v[4];                  // f = e;
        v[4] = v[3].wrapping_add(t1); // e = d + t1;
        v[3] = v[2];                  // d = c;
        v[2] = v[1];                  // c = b;
        v[1] = v[0];                  // b = a;
        v[0] = t1.wrapping_add(t2);   // a = t1 + t2;
    }

    for i in 0..v.len() {
        hash[i] = hash[i].wrapping_add(v[i]);
    }
}
