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
