mod pkcs7_padding;
pub mod ecb;
pub mod cbc;
pub mod ctr;


#[cfg(test)]
mod tests {
    use crate::cipher::{Cipher,Aes128Cipher};
    use crate::modes::{ecb, cbc, ctr};
    use crate::utils::decode_hex;

    const KEY: &[u8] = "yellow submarine".as_bytes();
    const MSG: &[u8] = "Hey friends, this is a longer message!!!".as_bytes();

    #[test]
    fn mode_ecb() {
        let expected = decode_hex("ec31b1198e2a31fff7fa490574e5a4d280c348ab464\
                                  240f2f1156eac25fd482b79fb8309dffe8edf3d48781\
                                  0776a8fe7").unwrap();
        let aes = Aes128Cipher::new(KEY).expect("Key size error");
        let encrypted = ecb::encrypt(MSG, &aes).unwrap();
        assert_eq!(encrypted, expected);
        let decrypted = ecb::decrypt(&encrypted, &aes).unwrap();
        assert_eq!(decrypted, MSG);
    }

    #[test]
    fn mode_cbc() {
        let expected = decode_hex("ec31b1198e2a31fff7fa490574e5a4d23eb974dd42c\
                                  2f64fd998522e81bce59ce55a7fe1ffc0c3473400ad1\
                                  7f259b780").unwrap();
        let aes = Aes128Cipher::new(KEY).expect("Key size error");
        let iv: &[u8] = [0; 16].as_slice();
        let encrypted = cbc::encrypt(MSG, &aes, iv).unwrap();
        assert_eq!(encrypted, expected);
        let decrypted = cbc::decrypt(&encrypted, &aes, iv).unwrap();
        assert_eq!(decrypted, MSG);
    }

    #[test]
    fn mode_ctr() {
        let expected = decode_hex("6c192f33797d95add6c89e26548e1c661bdd2941e5f\
                                  686b08191354fcd3732f58798c9cb6de45d6e")
                       .unwrap();
        let aes = Aes128Cipher::new(KEY).expect("Key size error");
        let nonce: &[u8] = [0; 8].as_slice();
        let encrypted = ctr::encrypt(MSG, &aes, nonce).unwrap();
        assert_eq!(encrypted, expected);
        let decrypted = ctr::decrypt(&encrypted, &aes, nonce).unwrap();
        assert_eq!(decrypted, MSG);
    }
}
