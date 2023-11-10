use std::ops::{BitAnd, BitXor, Not};

use super::Hash;
use super::sha2_constants::SHA256_BLOCK_SIZE;


pub trait ShaUint: Copy
             + BitAnd<Output = Self>
             + BitXor<Output = Self>
             + Not<Output = Self>
{
    fn ch(x: Self, y: Self, z: Self) -> Self
    {
        (x & y) ^ (!x & z)
    }

    fn maj(x: Self, y: Self, z: Self) -> Self
    {
        (x & y) ^ (x & z) ^ (y & z)
    }
    fn s0(self) -> Self;
    fn s1(self) -> Self;
    fn v0(self) -> Self;
    fn v1(self) -> Self;

    fn wrapping_add(self, lhs: Self) -> Self;
    fn to_be_bytes(self) -> Vec<u8>;
    fn from_be_bytes(bytes: &[u8]) -> Self;
}

impl ShaUint for u32 {
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

    fn to_be_bytes(self) -> Vec<u8> {
        u32::to_be_bytes(self).to_vec()
    }
}

impl ShaUint for u64 {
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

    fn to_be_bytes(self) -> Vec<u8> {
        u64::to_be_bytes(self).to_vec()
    }
}


pub trait ShaCommon {
    type T: ShaUint + 'static;

    const DIGEST_SIZE: usize;
    const BLOCK_SIZE: usize;
    const W_LENGTH: usize;
    const K_CONST: &'static[Self::T];

    fn new() -> Self;
    fn hash(&mut self) -> &mut [Self::T; 8];
    fn data(&mut self) -> &mut [u8]; // Size MUST BE BLOCK_SIZE
    fn get_pending(&mut self) -> usize;
    fn set_pending(&mut self, value: usize);
    fn inc_total(&mut self, value: usize);
    fn get_total(&self) -> usize;
    fn reset(&mut self);

    fn process_block(&mut self, block: &[u8]) {
        // Message schedule (W)
        let mut w: Vec<Self::T> = Vec::with_capacity(Self::W_LENGTH);

        // Always 16 rounds
        for int_bytes in block.chunks(std::mem::size_of::<Self::T>()) {
            w.push(Self::T::from_be_bytes(int_bytes));
        }
        for i in 16..Self::W_LENGTH {
            w.push(Self::T::v1(w[i-2])
                .wrapping_add(w[i-7])
                .wrapping_add(Self::T::v0(w[i-15]))
                .wrapping_add(w[i-16]));
        }

        // Working variables: a(0), b(1), c(2), d(3), e(4), f(5), g(6), h(7)
        let mut v = self.hash().clone();

        for i in 0..Self::W_LENGTH {
            // t1 = h + s1(e) + ch(e, f, g) + K[t] +  w[t]
            let t1: Self::T = v[7]
                .wrapping_add(Self::T::s1(v[4]))
                .wrapping_add(Self::T::ch(v[4], v[5], v[6]))
                .wrapping_add(Self::K_CONST[i])
                .wrapping_add(w[i]);
            // t2 = s0(a) + maj(a, b, c);
            let t2: Self::T = Self::T::s0(v[0])
                .wrapping_add(Self::T::maj(v[0], v[1], v[2]));

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
            self.hash()[i] = self.hash()[i].wrapping_add(v[i]);
        }
    }

    fn pad_last_block(&mut self) -> Vec<u8> {
        let pending = self.get_pending();
        let block = &self.data()[..pending];
        assert!(block.len() <= Self::BLOCK_SIZE);

        let mut padded = Vec::with_capacity(Self::BLOCK_SIZE);
        padded.extend_from_slice(block);
        padded.push(0x80);

        let k: usize;
        if block.len() < Self::BLOCK_SIZE - Self::BLOCK_SIZE/8 {
            k = Self::BLOCK_SIZE - block.len() - 1 - Self::BLOCK_SIZE/8;
        } else {
            k = Self::BLOCK_SIZE*2 - block.len() - 1 - Self::BLOCK_SIZE/8;
        }
        for _ in 0..k {
            padded.push(0)
        }

        let block_len = block.len();
        let total_data = self.get_total();
        if Self::BLOCK_SIZE == SHA256_BLOCK_SIZE {
            let length = (((total_data+block_len)*8) as u64).to_be_bytes();
            padded.extend_from_slice(&length);
        } else {
            let length = (((total_data+block_len)*8) as u128).to_be_bytes();
            padded.extend_from_slice(&length);
        }
        padded
    }
}

impl <T: ShaCommon> Hash for T {
    const DIGEST_SIZE: usize = <T as ShaCommon>::DIGEST_SIZE;

    fn new() -> Self {
        <T as ShaCommon>::new()
    }

    fn update(&mut self, data: &[u8]) {
        let pending = self.get_pending();
        if pending + data.len() < Self::BLOCK_SIZE {
            self.data()[pending..pending+data.len()].copy_from_slice(data);
            self.set_pending(pending + data.len());
            return;
        }

        let missing_data = Self::BLOCK_SIZE - pending;
        //TODO: Fix!! unsafe to dereference data?
        let mut old_data = self.data().to_vec();
        old_data[pending..].copy_from_slice(&data[..missing_data]);
        self.process_block(&old_data);
        self.inc_total(Self::BLOCK_SIZE);

        let block_iter = data[missing_data..].chunks_exact(Self::BLOCK_SIZE);
        let rem = block_iter.remainder();
        for block in block_iter {
            self.process_block(block);
            self.inc_total(Self::BLOCK_SIZE);
        }

        self.set_pending(rem.len());
        self.data()[..rem.len()].copy_from_slice(rem);
    }

    fn digest(&mut self, data: &[u8]) -> Vec<u8> {
        self.update(data);
        let padded = self.pad_last_block();
        for block in padded.chunks_exact(Self::BLOCK_SIZE) {
            self.process_block(block);
        }
        let mut digest: Vec<u8> = Vec::with_capacity(Self::DIGEST_SIZE);
        for i in 0..Self::DIGEST_SIZE*16/Self::BLOCK_SIZE {
            digest.extend_from_slice(self.hash()[i].to_be_bytes().as_slice());
        }
        self.reset();
        digest
    }
}
