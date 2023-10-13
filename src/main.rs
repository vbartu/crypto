mod aes_128;
mod modes;

use std::string::String;

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


    let msg = String::from("Hey friends, this is a longer message!!!");
    print_hex(msg.as_bytes());
    let ecb_encrypted = modes::ecb::encrypt(msg.as_bytes(), &key);
    print_hex(ecb_encrypted.as_slice());
    let ecb_decrypted = modes::ecb::decrypt(&ecb_encrypted, &key);
    print_hex(ecb_decrypted.as_slice());
    println!("{}", String::from_utf8(ecb_decrypted).unwrap());
}
