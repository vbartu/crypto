use std::boxed::Box;

use super::aes_constants as constants;


fn sub_bytes(state: &mut [u8; 16], s_box: &[u8; 256]) {
    for x in state {
        *x = s_box[*x as usize];
    }
}

fn shift_rows(state: &mut [u8; 16]) {
    let orig: Box<[u8; 16]> = Box::new(state.clone());

    for i in 1..4 { // First word does not rotate
        for j in 0..4 {
            state[i + 4*j] = orig[(i + 4*(j+i)) % 16];
        }
    }
}

fn inv_shift_rows(state: &mut [u8; 16]) {
    let orig: Box<[u8; 16]> = Box::new(state.clone());

    for i in 1..4 {
        for j in 0..4 {
            state[(i + 4*(j+i)) % 16] = orig[i + 4*j]
        }
    }
}

fn galois_mult(mut a: u8, mut b: u8) -> u8 {
    let mut result: u8 = 0;
    while b != 0 {
        if b & 0x01 != 0 {
            result ^= a;
        }
        if a & 0x80 != 0 {
            a = (a << 1) ^ 0x1B;
        } else {
            a <<= 1;
        }
        b >>= 1;
    }
    result
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
    for i in 0..state.len() {
        state[i] ^= key[i];
    }
}

fn key_expansion(prev_key: &[u8; 16], round: usize) -> Box<[u8; 16]> {
    let mut new_key: Box<[u8; 16]> = Box::new([0; 16]);

    // Rotate, Sub, XOR
    for i in 0..4 {
        new_key[i] = prev_key[12 + (i+1)%4];
        new_key[i] = constants::S_BOX[new_key[i] as usize];
        new_key[i] ^= prev_key[i];
    }

    // Round constant
    new_key[0] ^= constants::R_CONST[round-1];


    for i in 4..prev_key.len() {
        new_key[i] = prev_key[i] ^ new_key[i-4];
    }
    new_key
}

pub fn encrypt(plaintext: &[u8; 16], key: &[u8; 16]) -> Box<[u8; 16]> {
    let mut state: Box<[u8; 16]> = Box::new(plaintext.clone());
    let mut expanded_key: Box<[u8; 16]> = Box::new(key.clone());

    add_round_key(&mut state, &expanded_key);

    for i in 0..constants::AES_128_ROUNDS-1 {
        sub_bytes(&mut state, &constants::S_BOX);
        shift_rows(&mut state);
        mix_columns(&mut state, &constants::MC_MATRIX);
        expanded_key = key_expansion(&expanded_key, i+1);
        add_round_key(&mut state, &expanded_key);
    }
    // Last round
    sub_bytes(&mut state, &constants::S_BOX);
    shift_rows(&mut state);
    expanded_key = key_expansion(&expanded_key, constants::AES_128_ROUNDS);
    add_round_key(&mut state, &expanded_key);

    state
}

pub fn decrypt(ciphertext: &[u8; 16], key: &[u8; 16]) -> Box<[u8; 16]> {
    let mut state: Box<[u8; 16]> = Box::new(ciphertext.clone());

    // Generate keys
    let mut expanded_keys: Box<[[u8; 16]; 11]> = Box::new(Default::default());
    expanded_keys[0] = key.clone();
    for i in 1..expanded_keys.len() {
        expanded_keys[i] = *key_expansion(&expanded_keys[i-1], i);
    }

    add_round_key(&mut state, &expanded_keys[10]);

    for i in 0..constants::AES_128_ROUNDS-1 {
        inv_shift_rows(&mut state);
        sub_bytes(&mut state, &constants::INV_S_BOX);
        add_round_key(&mut state, &expanded_keys[9-i]);
        mix_columns(&mut state, &constants::INV_MC_MATRIX);
    }

    inv_shift_rows(&mut state);
    sub_bytes(&mut state, &constants::INV_S_BOX);
    add_round_key(&mut state, &expanded_keys[0]);

    state
}
