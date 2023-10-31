use super::aes_128_constants as constants;
use crate::utils;

use super::{Cipher,CipherErr};


pub struct Aes128Cipher {
    key: [u8; Self::BLOCK_SIZE],
}

impl Cipher for Aes128Cipher {
    const BLOCK_SIZE: usize = constants::BLOCK_SIZE;

    fn new(key: &[u8]) -> Result<Self, CipherErr> {
        match key.try_into() {
            Ok(key) => Ok(Self { key }),
            Err(_) => Err(CipherErr::KeySize)
        }
    }

    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CipherErr> {
        match data.try_into() {
            Ok(data) => {
                let ciphertext = encrypt(&data, &self.key);
                Ok(Vec::from(ciphertext))
            },
            Err(_) => Err(CipherErr::BlockSize)
        }
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CipherErr> {
        match data.try_into() {
            Ok(data) => {
                let plaintext = decrypt(&data, &self.key);
                Ok(Vec::from(plaintext))
            },
            Err(_) => Err(CipherErr::BlockSize)
        }
    }
}

fn sub_bytes(state: &mut [u8; 16], s_box: &[u8; 256]) {
    for x in state {
        *x = s_box[*x as usize];
    }
}


fn shift_rows(state: &mut [u8; 16], rot: constants::ShiftRows) {
    let orig: Box<[u8; 16]> = Box::new(state.clone());

    for i in 1..4 { // First word does not rotate
        for j in 0..4 {
            match rot {
                constants::ShiftRows::LEFT => {
                    state[i + 4*j] = orig[(i + 4*(j+i)) % 16];
                },
                constants::ShiftRows::RIGHT => {
                    state[(i + 4*(j+i)) % 16] = orig[i + 4*j]
                }
            }
        }
    }
}

fn galois_mult(mut a: u8, mut b: u8) -> u8 {
    let mut p: u8 = 0;
    while b != 0 {
        if b & 0x01 != 0 {
            p ^= a;
        }
        if a & 0x80 != 0 {
            a = (a << 1) ^ 0x1B;
        } else {
            a <<= 1;
        }
        b >>= 1;
    }
    p
}

fn mix_columns(state: &mut [u8; 16], matrix: &[[u8; 4]; 4]) {
    let orig = state.clone();

    for i in 0..4 {
        for j in 0..4 {
            state[i*4 + j] = galois_mult(matrix[j][0], orig[i*4])
                           ^ galois_mult(matrix[j][1], orig[i*4 + 1])
                           ^ galois_mult(matrix[j][2], orig[i*4 + 2])
                           ^ galois_mult(matrix[j][3], orig[i*4 + 3]);
        }
    }
}

fn add_round_key(state: &mut [u8; 16], key: &[u8; 16]) {
    utils::xor_slice(state.as_mut_slice(), key.as_slice());
}

fn key_expansion(prev_key: &[u8; 16], round: usize) -> [u8; 16] {
    let mut next_key: [u8; 16] = [0; 16];

    // Rotate, Sub, XOR
    for i in 0..4 {
        next_key[i] = prev_key[12 + (i+1)%4];
        next_key[i] = constants::S_BOX[next_key[i] as usize];
        next_key[i] ^= prev_key[i];
    }

    // Round constant
    next_key[0] ^= constants::R_CONST[round-1];


    for i in 4..prev_key.len() {
        next_key[i] = prev_key[i] ^ next_key[i-4];
    }
    next_key
}

fn encrypt(plaintext: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
    let mut state: [u8; 16] = plaintext.clone();
    let mut expanded_key: [u8; 16] = key.clone();

    add_round_key(&mut state, &expanded_key);

    for i in 0..constants::ROUNDS-1 {
        sub_bytes(&mut state, &constants::S_BOX);
        shift_rows(&mut state, constants::ShiftRows::LEFT);
        mix_columns(&mut state, &constants::MC_MATRIX);
        expanded_key = key_expansion(&expanded_key, i+1);
        add_round_key(&mut state, &expanded_key);
    }
    // Last round
    sub_bytes(&mut state, &constants::S_BOX);
    shift_rows(&mut state, constants::ShiftRows::LEFT);
    expanded_key = key_expansion(&expanded_key, constants::ROUNDS);
    add_round_key(&mut state, &expanded_key);

    state
}

fn decrypt(ciphertext: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
    let mut state: [u8; 16] = ciphertext.clone();

    // Generate keys
    let mut expanded_keys: Box<[[u8; 16]; 11]> = Default::default();
    expanded_keys[0] = key.clone();
    for i in 1..expanded_keys.len() {
        expanded_keys[i] = key_expansion(&expanded_keys[i-1], i);
    }

    add_round_key(&mut state, &expanded_keys[10]);

    for i in 0..constants::ROUNDS-1 {
        shift_rows(&mut state, constants::ShiftRows::RIGHT);
        sub_bytes(&mut state, &constants::INV_S_BOX);
        add_round_key(&mut state, &expanded_keys[9-i]);
        mix_columns(&mut state, &constants::INV_MC_MATRIX);
    }

    shift_rows(&mut state, constants::ShiftRows::RIGHT);
    sub_bytes(&mut state, &constants::INV_S_BOX);
    add_round_key(&mut state, &expanded_keys[0]);

    state
}
