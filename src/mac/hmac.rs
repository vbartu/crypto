use crate::hash::Hash;
use super::Mac;


const INNER_PAD_VAL: u8 = 0x36;
const OUTER_PAD_VAL: u8 = 0x5C;

pub struct Hmac<H> where H: Hash {
    hash: H,
    key: Vec<u8>,
    msg: Vec<u8>,
}

fn sanitize_key<H: Hash>(key: &[u8]) -> Vec<u8> {
    let mut hash = H::new();
    if key.len() > H::BLOCK_SIZE {
        hash.update(key);
        let sanitized_key = hash.digest();
        return sanitized_key;
    }

    let mut sanitized_key = Vec::<u8>::from(key);
    while sanitized_key.len() < H::BLOCK_SIZE {
        sanitized_key.push(0);
    }
    sanitized_key
}

impl<H> Mac<H> for Hmac<H> where H: Hash {
    fn new(key: &[u8]) -> Self {
        let hash = H::new();
        let key = sanitize_key::<H>(key);
        let msg = Vec::new();

        Self {hash, key, msg}
    }

    fn update(&mut self, data: &[u8]) {
        self.msg.extend_from_slice(data);
    }


    fn finalize(&mut self) -> Vec<u8> {
        let mut ipad_key = self.key.clone();
        let mut opad_key = self.key.clone();
        for i in 0..ipad_key.len() {
            ipad_key[i] ^= INNER_PAD_VAL;
            opad_key[i] ^= OUTER_PAD_VAL;
        }

        self.hash.update(ipad_key.as_slice());
        self.hash.update(self.msg.as_slice());
        let inner_hash = self.hash.digest();
        self.hash.reset();
        self.hash.update(opad_key.as_slice());
        self.hash.update(inner_hash.as_slice());
        let outer_hash = self.hash.digest();
        outer_hash
    }

    fn reset(&mut self) {
        self.msg.clear();
        self.hash.reset();
    }
}


#[cfg(test)]
mod tests {
    use super::{Hmac,Mac};
    use crate::hash::Sha256;
    use crate::utils::decode_hex;

    const KEY: &[u8] = "key".as_bytes();
    const MSG: &[u8] = "The quick brown fox jumps over the lazy dog"
        .as_bytes();

    #[test]
    fn hmac() {
        let expected = decode_hex("f7bc83f430538424b13298e6aa6fb143ef4d59a1494\
                                   6175997479dbc2d1a3cd8").unwrap();
        let mut hmac_sha256 = Hmac::<Sha256>::new(KEY);
        hmac_sha256.update(MSG);
        let signature = hmac_sha256.finalize();
        crate::utils::print_hex(&signature);
        assert_eq!(signature, expected);
        let result = hmac_sha256.verify(MSG, signature.as_slice());
        assert!(result.is_ok());
    }
}
