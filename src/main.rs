mod aes;


fn print_hex(data: &[u8]) {
    for i in 0..data.len() {
        print!("{:02x}", data[i]);
        if (i+1) % 4 == 0 {
            print!(" ");
        }
    }
    println!();
}

fn main() {
    let data: [u8; 16] = "Attack at dawn!!".as_bytes().try_into().unwrap();
    let key: [u8; 16] = "yellow submarine".as_bytes().try_into().unwrap();

    let ciphertext = aes::aes_128_encrypt(&data, &key);
    print_hex(ciphertext.as_slice());
}
