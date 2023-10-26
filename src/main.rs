mod aes_128;
mod modes;
mod utils;

use std::string::String;

use utils::print_hex;


fn main() {
    let data: [u8; 16] = "Attack at dawn!!".as_bytes().try_into().unwrap();
    let key: [u8; 16] = "yellow submarine".as_bytes().try_into().unwrap();

    let ciphertext = aes_128::encrypt(&data, &key);
    println!("AES encryption");

    let plaintext = aes_128::decrypt(&ciphertext, &key);
    assert_eq!(&data, plaintext.as_ref());
    println!("AES encryption");


    let msg = String::from("Hey friends, this is a longer message!!!");

    let ecb_encrypted = modes::ecb::encrypt(msg.as_bytes(), &key);
    let ecb_decrypted = modes::ecb::decrypt(&ecb_encrypted, &key);
    assert_eq!(msg, String::from_utf8(ecb_decrypted).unwrap());
    print_hex(ecb_encrypted.as_slice());
    println!("AES-ECB");

    // let iv: [u8; 16] = [0; 16];
    let iv = data.clone();
    let cbc_encrypted = modes::cbc::encrypt(msg.as_bytes(), &key, &iv);
    let cbc_decrypted = modes::cbc::decrypt(&cbc_encrypted, &key, &iv);
    assert_eq!(msg, String::from_utf8(cbc_decrypted).unwrap());
    print_hex(cbc_encrypted.as_slice());
    println!("AES-CBC");
}
