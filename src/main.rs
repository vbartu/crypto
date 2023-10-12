mod aes_128;

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

    print_hex(data.as_slice());

    let ciphertext = aes_128::encrypt(&data, &key);
    print_hex(ciphertext.as_slice());

    let plaintext = aes_128::decrypt(&ciphertext, &key);
    print_hex(plaintext.as_slice());
    assert_eq!(&data, plaintext.as_ref());
}
