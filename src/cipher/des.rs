use crate::error::{InvalidKeyLen,InvalidDataLen};
use super::des_constants as constants;
use super::Cipher;


pub struct DesCipher {
    keys: Box<[[u8; 6]; 16]>, // Internal keys are 48 bits long
}

impl Cipher for DesCipher {
    const BLOCK_SIZE: usize = constants::BLOCK_SIZE;

    fn new(key: &[u8]) -> Result<Self, InvalidKeyLen> {
        let key: [u8; Self::BLOCK_SIZE] = match key.try_into() {
            Ok(key) => key,
            Err(_) => return Err(InvalidKeyLen),
        };

        let keys = key_expansion(&key);
        Ok(Self { keys })
    }

    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, InvalidDataLen> {
        match data.try_into() {
            Ok(data) => {
                let ciphertext = des_algorithm(&data, &self.keys);
                Ok(Vec::from(ciphertext))
            },
            Err(_) => Err(InvalidDataLen)
        }
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, InvalidDataLen> {
        match data.try_into() {
            Ok(data) => {
                let mut keys = self.keys.clone();
                keys.reverse();
                let plaintext = des_algorithm(&data, &keys);
                Ok(Vec::from(plaintext))
            },
                Err(_) => Err(InvalidDataLen)
        }
    }
}


fn key_expansion(initial_key: &[u8; 8]) -> Box<[[u8; 6]; 16]> {
    let mut key: u64 = u64::from_be_bytes(initial_key.clone());
    let mut keys: Box<[[u8; 6]; 16]> = Box::default();

    permutation(&mut key, constants::PC_1.as_slice(), 64);

    let mut left: u64 = (key >> 28) & 0x0FFF_FFFF;
    let mut right: u64 = key & 0x0FFF_FFFF;
    for i in 0..16 {
        bit_rotation_28(&mut left, constants::BIT_ROTATION[i]);
        bit_rotation_28(&mut right, constants::BIT_ROTATION[i]);
        let mut k_n = left << 28 | right;

        permutation(&mut k_n, &constants::PC_2, 56);
        keys[i] = k_n.to_be_bytes()[2..].try_into().unwrap();
    }

    keys
}

fn bit_rotation_28(n: &mut u64, shift: u8) {
    *n = (*n << shift | *n >> (28 - shift)) & 0x0FFF_FFFF;
}

fn permutation(chunk: &mut u64, p: &[u8], chunk_size: u8) {
    let orig_chunk = *chunk;
    *chunk = 0;

    for i in 0..p.len() {
       *chunk |= ((orig_chunk >> chunk_size-p[i]) & 0x1) << (p.len()-i-1);
    }
}

fn feistel_function(word: u32, key: &[u8; 6]) -> u32 {
    let mut word: u64 = word.into();
    permutation(&mut word, constants::E.as_slice(), 32);



    let mut key_64: [u8; 8] = [0; 8];
    key_64[2..].copy_from_slice(key);
    let xor = word ^ u64::from_be_bytes(key_64);

    let mut result: u64 = 0;
    for i in 0..constants::S_BOXES.len() {
        let piece: usize = ((xor >> (42 - 6*i)) & 0x3F).try_into().unwrap();
        let outer_bits: usize = (piece & 0x20) >> 4 | (piece & 0x01);
        let inner_bits: usize = (piece >> 1) & 0x0F;
        result |= u64::from(
            constants::S_BOXES[i][outer_bits][inner_bits]) << (28 - (4*i)
        );
    }
    permutation(&mut result, constants::P.as_slice(), 32);
    result as u32
}

fn feistel_round(chunk: &mut u64, key: &[u8; 6]) {
    let mut left: u32 = (*chunk >> 32) as u32;
    let right: u32 = (*chunk & 0xFFFFFFFF) as u32;
    left = left ^ feistel_function(right, key);
    *chunk = (right as u64) << 32 | left as u64;
}

pub fn des_algorithm(plaintext: &[u8; 8], keys: &[[u8; 6]; 16]) -> [u8; 8] {
    let mut chunk: u64 = u64::from_be_bytes(plaintext.clone());

    // Initial permutation
    permutation(&mut chunk, constants::IP.as_slice(), 64);

    // 15 feistel rounds
    for i in 0..16 {
        feistel_round(&mut chunk, &keys[i]);
    }
    // Last round does swaps again
    chunk = (chunk << 32) | (chunk >> 32);

    // Final permutation
    permutation(&mut chunk, constants::FP.as_slice(), 64);

    chunk.to_be_bytes()
}


#[cfg(test)]
mod tests {
    use super::{DesCipher,Cipher};
    use crate::utils::decode_hex;

    const KEY: &[u8] = "computer".as_bytes();
    const MSG: &[u8] = "delivery".as_bytes();

    #[test]
    fn des() {
        let expected = decode_hex("0b006d5e6b241848").unwrap();
        let des = DesCipher::new(KEY).expect("Key size error");
        let encrypted = des.encrypt(MSG).unwrap();
        assert_eq!(encrypted, expected);
        let decrypted = des.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, MSG);
    }
}
