use super::Hash;
use super::sha2_constants::{SHA256_DIGEST_SIZE,
                            SHA256_H,
                            SHA256_BLOCK_SIZE,
                            SHA256_K};

pub struct Sha256 {
    hash: Box<[u32; 8]>,
    data: [u8; SHA256_BLOCK_SIZE],
    pending_data: usize,
    total_data: usize,
}

impl ShaCommon for Sha256 {
    const DIGEST_SIZE: usize = SHA256_DIGEST_SIZE;
    const BLOCK_SIZE: usize = SHA256_BLOCK_SIZE;

    fn new() -> Self {
        Self {
            hash: Box::new(SHA256_H),
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
}

trait ShaCommon{
    const BLOCK_SIZE: usize;
    const DIGEST_SIZE: usize;
    fn new() -> Self;
    fn hash(&mut self) -> &mut [u32; 8];
    fn data(&mut self) -> &mut [u8]; // Size MUST BE BLOCK_SIZE
    fn get_pending(&mut self) -> usize;
    fn set_pending(&mut self, value: usize);
    fn inc_total(&mut self, value: usize);
    fn get_total(&self) -> usize;
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
        //TODO: unsafe to dereference data?
        let mut old_data = self.data().to_vec();
        old_data[pending..].copy_from_slice(&data[..missing_data]);
        process_block(&mut self.hash(), &old_data);
        self.inc_total(Self::BLOCK_SIZE);

        let block_iter = data[missing_data..].chunks_exact(Self::BLOCK_SIZE);
        let rem = block_iter.remainder();
        for block in block_iter {
            process_block(&mut self.hash(), block);
            self.inc_total(Self::BLOCK_SIZE);
        }

        self.set_pending(rem.len());
        self.data()[..rem.len()].copy_from_slice(rem);
    }

    fn digest(&mut self, data: &[u8]) -> Vec<u8> {
        self.update(data);
        let pending = self.get_pending();
        let total = self.get_total();
        let padded = pad_last_block(&self.data()[..pending], total);
        for block in padded.chunks_exact(Self::BLOCK_SIZE) {
            process_block(&mut self.hash(), block);
        }
        let mut digest: Vec<u8> = Vec::with_capacity(Self::DIGEST_SIZE);
        for i in 0..Self::DIGEST_SIZE/4 {
            digest.extend_from_slice(self.hash()[i].to_be_bytes().as_slice());
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
    assert!(block.len() <= SHA256_BLOCK_SIZE);
    let mut padded = Vec::with_capacity(SHA256_BLOCK_SIZE);
    padded.extend_from_slice(block);
    padded.push(0x80);
    let k: usize;
    if block.len() < 56 {
        k = SHA256_BLOCK_SIZE - block.len() - 1 - 8;
    } else {
        k = SHA256_BLOCK_SIZE*2 - block.len() - 1 - 8;
    }
    for _ in 0..k {
        padded.push(0)
    }
    let length = (((total_data+block.len())*8) as u64).to_be_bytes();
    padded.extend_from_slice(&length);
    padded
}

fn process_block(hash: &mut [u32; 8], block: &[u8]) {
    // Message schedule (W)
    let mut w: [u32; 64] = [0; 64];
    for i in 0..16 {
        let index = 4*i;
        w[i] = u32::from_be_bytes(block[index..index+4].try_into().unwrap());
    }
    for i in 16..64 {
        w[i] = v1(w[i-2])
            .wrapping_add(w[i-7])
            .wrapping_add(v0(w[i-15]))
            .wrapping_add(w[i-16]);
    }

    // Working variables: a(0), b(1), c(2), d(3), e(4), f(5), g(6), h(7)
    let mut v = hash.clone();

    for i in 0..w.len() {
        // t1 = h + s1(e) + ch(e, f, g) + K[t] +  w[t]
        let t1: u32 = v[7]
            .wrapping_add(s1(v[4]))
            .wrapping_add(ch(v[4], v[5], v[6]))
            .wrapping_add(SHA256_K[i])
            .wrapping_add(w[i]);
        // t2 = s0(a) + maj(a, b, c);
        let t2: u32 = s0(v[0]).wrapping_add(maj(v[0], v[1], v[2]));
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
