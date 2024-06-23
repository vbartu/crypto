mod cipher;
mod error;
mod hash;
mod mac;
mod modes;
mod utils;


fn main() {
    println!("Run the tests!!!");
    t::hmac()
}

mod t {
    use crate::mac::{Hmac,Mac};
    use crate::hash::Sha256;
    use crate::utils::decode_hex;

    const KEY: &[u8] = "key".as_bytes();
    const MSG: &[u8] = "The quick brown fox jumps over the lazy dog"
        .as_bytes();

    pub fn hmac() {
        let expected = decode_hex("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8").unwrap();
        let mut hmac_sha256 = Hmac::<Sha256>::new(KEY);
        hmac_sha256.update(MSG);
        let signature = hmac_sha256.finalize();
        crate::utils::print_hex(&signature);
        assert_eq!(signature, expected);
        let result = hmac_sha256.verify(MSG, signature.as_slice());
        assert!(result.is_ok());
    }
}
