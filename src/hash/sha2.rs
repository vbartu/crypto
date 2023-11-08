use std::num::Wrapping;

use super::Hash;
use crate::utils::print_hex;

pub struct Sha256 {
    hash: Box<[u32; 8]>,
    data: [u8; BLOCK_SIZE],
    pending_data: usize,
    total_data: usize,
}

impl Hash for Sha256 {
    const DIGEST_SIZE: usize = 32;

    fn new() -> Self {
        Self {
            hash: Box::new(SHA256_H),
            data: [0; BLOCK_SIZE],
            pending_data: 0,
            total_data: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        if self.pending_data + data.len() < BLOCK_SIZE {
            self.data[self.pending_data..self.pending_data+data.len()]
                .copy_from_slice(data);
            self.pending_data += data.len();
            return;
        }

        let missing_data = BLOCK_SIZE - self.pending_data;
        self.data[self.pending_data..].copy_from_slice(&data[..missing_data]);
        process_block(&mut self.hash, &self.data);
        self.total_data += BLOCK_SIZE;

        let block_iter = data[missing_data..].chunks_exact(BLOCK_SIZE);
        let rem = block_iter.remainder();
        for block in block_iter {
            process_block(&mut self.hash, &block);
            self.total_data += BLOCK_SIZE;
        }

        self.pending_data = rem.len();
        self.data[..self.pending_data].copy_from_slice(rem);
    }

    fn digest(&mut self, data: &[u8]) -> Vec<u8> {
        self.update(data);
        let padded = pad_last_block(&self.data[..self.pending_data],
                                    self.total_data);
        for block in padded.chunks_exact(BLOCK_SIZE) {
            process_block(&mut self.hash, block);
        }
        let mut digest: Vec<u8> = Vec::with_capacity(self::DIGEST_SIZE);
        for hash_word in self.hash.iter() {
            digest.extend_from_slice(hash_word.to_be_bytes().as_slice());
        }
        digest
    }
}


fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn s0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

fn s1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

fn v0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

fn v1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

fn pad_last_block(block: &[u8], total_data: usize) -> Vec<u8> {
    assert!(block.len() <= BLOCK_SIZE);
    let mut padded = Vec::with_capacity(BLOCK_SIZE);
    padded.extend_from_slice(block);
    padded.push(0x80);
    let k: usize;
    if block.len() < 56 {
        k = BLOCK_SIZE - block.len() - 1 - 8;
    } else {
        k = BLOCK_SIZE*2 - block.len() - 1 - 8;
    }
    for _ in 0..k {
        padded.push(0)
    }
    let length = (((total_data+block.len())*8) as u64).to_be_bytes();
    padded.extend_from_slice(&length);
    padded
}

fn process_block(hash: &mut [u32; 8], block: &[u8]) {
    let mut w: [u32; 64] = [0; 64]; // message schedule
    for i in 0..16 {
        let index = 4*i;
        w[i] = u32::from_be_bytes(block[index..index+4].try_into().unwrap());
    }
    for i in 16..64 {
        w[i] = v1(w[i-2]) + w[i-7] + v0(w[i-15]) + w[i-16];
    }
    
    let mut a: u32 = hash[0];
    let mut b: u32 = hash[1];
    let mut c: u32 = hash[2];
    let mut d: u32 = hash[3];
    let mut e: u32 = hash[4];
    let mut f: u32 = hash[5];
    let mut g: u32 = hash[6];
    let mut h: u32 = hash[7];

    for t in 0..w.len() {
        let t1: u32 = h + s1(e) + ch(e, f, g) + K[t] +  w[t];
        let t2: u32 = s0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    hash[0] += a;
    hash[1] += b;
    hash[2] += c;
    hash[3] += d;
    hash[4] += e;
    hash[5] += f;
    hash[6] += g;
    hash[7] += h;
}

const BLOCK_SIZE: usize = 64;
const DIGEST_SIZE: usize = 32;

const SHA256_H: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K: [u32; 64] = [
   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
