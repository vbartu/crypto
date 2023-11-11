use std::num::ParseIntError;

pub fn print_hex(data: &[u8]) {
    for i in 0..data.len() {
        print!("{:02x}", data[i]);
        if (i+1) % 4 == 0 {
            print!(" ");
        }
    }
    println!();
}

pub fn xor_slice(a: &mut [u8], b: &[u8]) {
    for i in 0..std::cmp::min(a.len(), b.len()) {
        a[i] ^= b[i];
    }
}

#[allow(dead_code)] // Use for tests
pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    let mut bytes = Vec::with_capacity(s.len()/2);
    for i in (0..s.len()).step_by(2) {
        match u8::from_str_radix(&s[i..i+2], 16) {
            Ok(byte) => bytes.push(byte),
            Err(e) => return Err(e),
        }
    }
    Ok(bytes)
}
