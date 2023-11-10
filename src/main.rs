mod cipher;
mod hash;
mod modes;
mod utils;

use cipher::Cipher;
use hash::Hash;
use modes::{ecb,cbc,ctr};


fn test_hash(hash: &mut impl Hash, name: &str) {
    println!("Testing {}", name);

    // Short test
    hash.update("ab".as_bytes());
    let digest = hash.digest("c".as_bytes());
    utils::print_hex(digest.as_slice());

    // Long test
    let msg: &mut [u8] = &mut [0; 1029];
    for i in 0..msg.len() {
        msg[i] = i as u8;
    }
    hash.update(msg);
    let digest = hash.digest(&[]);
    utils::print_hex(digest.as_slice());
}


fn main() {
    // AES cipher
    let data: &[u8] = "Attack at dawn!!".as_bytes();
    let key: &[u8] = "yellow submarine".as_bytes();
    let aes_cipher = cipher::Aes128Cipher::new(&key)
        .expect("Key size error");

    let ciphertext = aes_cipher.encrypt(&data).unwrap();
    let plaintext = aes_cipher.decrypt(&ciphertext).unwrap();
    let expected: [u8; cipher::Aes128Cipher::BLOCK_SIZE] = [
        0x90, 0x12, 0x93, 0x2c, 0xf5, 0xa9, 0x53, 0xb0,
        0xe9, 0x7f, 0xf4, 0xe2, 0x1a, 0x8e, 0xa9, 0xdf
    ];
    assert_eq!(expected.as_slice(), ciphertext.as_slice());
    assert_eq!(data, plaintext.as_slice());
    println!("AES cipher");

    // DES cipher
    let des_data: [u8; 8] = 0x0123456789ABCDEFu64.to_be_bytes();
    let des_key: [u8; 8] = 0x133457799BBCDFF1u64.to_be_bytes();
    let des_cipher = cipher::DesCipher::new(&des_key)
        .expect("DES key size error");

    let ciphertext = des_cipher.encrypt(&des_data).unwrap();
    let plaintext = des_cipher.decrypt(&ciphertext).unwrap();
    assert_eq!(ciphertext, 0x85e813540f0ab405u64.to_be_bytes());
    assert_eq!(plaintext, des_data);
    println!("DES cipher");

    // ECB/CBC + AES cipher
    let msg = String::from("Hey friends, this is a longer message!!!");

    let ecb_encrypted = ecb::encrypt(msg.as_bytes(), &aes_cipher).unwrap();
    let ecb_decrypted = ecb::decrypt(&ecb_encrypted, &aes_cipher).unwrap();
    assert_eq!(msg, String::from_utf8(ecb_decrypted).unwrap());
    utils::print_hex(ecb_encrypted.as_slice());
    println!("AES-ECB");

    let iv: &[u8] = [0; 16].as_slice();
    let cbc_encrypted = cbc::encrypt(msg.as_bytes(), &aes_cipher, &iv).unwrap();
    let cbc_decrypted = cbc::decrypt(&cbc_encrypted, &aes_cipher, &iv).unwrap();
    assert_eq!(msg, String::from_utf8(cbc_decrypted).unwrap());
    utils::print_hex(cbc_encrypted.as_slice());
    println!("AES-CBC");

    let nonce: &[u8] = [0; 8].as_slice();
    let ctr_encrypted = ctr::encrypt(msg.as_bytes(), &aes_cipher, &nonce).unwrap();
    let ctr_decrypted = ctr::decrypt(&ctr_encrypted, &aes_cipher, &nonce).unwrap();
    assert_eq!(msg, String::from_utf8(ctr_decrypted).unwrap());
    utils::print_hex(ctr_encrypted.as_slice());
    println!("AES-CTR");

    let mut hash = hash::Sha256::new();
    hash.update("ab".as_bytes());
    let d2 = hash.digest("c".as_bytes());
    utils::print_hex(d2.as_slice());

    let mut hash = hash::Sha224::new();
    test_hash(&mut hash, "sha224");
    let mut hash = hash::Sha256::new();
    test_hash(&mut hash, "sha256");
    let mut hash = hash::Sha512::new();
    test_hash(&mut hash, "sha512");
}
