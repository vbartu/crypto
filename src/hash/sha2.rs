use super::sha2_constants as constants;
use super::sha2_common::ShaCommon;


macro_rules! sha_impl {
    ( $name:ident, $type:ty, $dig_s:expr, $init_h:expr, $block_s:expr,
      $w_len:expr, $k_const:expr ) =>
    {
        pub struct $name {
            hash: Box<[$type; 8]>,
            data: [u8; $block_s],
            pending_data: usize,
            total_data: usize,
        }

        impl ShaCommon for $name {
            type T = $type;
            const DIGEST_SIZE: usize = $dig_s;
            const BLOCK_SIZE: usize = $block_s;
            const W_LENGTH: usize = $w_len;
            const K_CONST: &'static[Self::T] = &$k_const;

            fn new() -> Self {
                Self {
                    hash: Box::new($init_h),
                    data: [0; Self::BLOCK_SIZE],
                    pending_data: 0,
                    total_data: 0,
                }
            }

            fn hash(&mut self) -> &mut [Self::T; 8] {
                &mut self.hash
            }
            fn data(&mut self) -> &mut [u8] {
                &mut self.data
            }

            fn get_pending(&mut self) -> usize {
                self.pending_data
            }

            fn set_pending(&mut self, value: usize) {
                self.pending_data = value;
            }

            fn inc_total(&mut self, value: usize) {
                self.total_data += value;
            }

            fn get_total(&self) -> usize {
                self.total_data
            }

            fn reset(&mut self) {
                self.hash = Box::new($init_h);
                self.pending_data = 0;
                self.total_data = 0;
            }
        }
    }
}


sha_impl!(Sha224, u32, constants::SHA224_DIGEST_SIZE, constants::SHA224_INIT_H,
          constants::SHA256_BLOCK_SIZE, constants::SHA256_W_LENGTH,
          constants::SHA256_K);

sha_impl!(Sha256, u32, constants::SHA256_DIGEST_SIZE, constants::SHA256_INIT_H,
          constants::SHA256_BLOCK_SIZE, constants::SHA256_W_LENGTH,
          constants::SHA256_K);

sha_impl!(Sha384, u64, constants::SHA384_DIGEST_SIZE, constants::SHA384_INIT_H,
          constants::SHA512_BLOCK_SIZE, constants::SHA512_W_LENGTH,
          constants::SHA512_K);

sha_impl!(Sha512, u64, constants::SHA512_DIGEST_SIZE, constants::SHA512_INIT_H,
          constants::SHA512_BLOCK_SIZE, constants::SHA512_W_LENGTH,
          constants::SHA512_K);

sha_impl!(Sha512_224, u64, constants::SHA512_224_DIGEST_SIZE,
          constants::SHA512_224_INIT_H, constants::SHA512_BLOCK_SIZE,
          constants::SHA512_W_LENGTH, constants::SHA512_K);

sha_impl!(Sha512_256, u64, constants::SHA512_256_DIGEST_SIZE,
          constants::SHA512_256_INIT_H, constants::SHA512_BLOCK_SIZE,
          constants::SHA512_W_LENGTH, constants::SHA512_K);


#[cfg(test)]
mod tests {
    use crate::hash as hash;
    use crate::hash::Hash;
    use crate::utils::decode_hex;

    const SHORT_MSG: &[u8] = "abc".as_bytes();
    const LONG_MSG_SIZE: usize = 4500;

    fn long_msg() -> Vec<u8> {
        let mut msg = Vec::with_capacity(LONG_MSG_SIZE);
        for i in 0..LONG_MSG_SIZE {
            msg.push(i as u8);
        }
        msg
    }
    fn test_sha(h: &mut impl Hash, expected_s: &[u8], expected_l: &[u8]) {
        let digest = h.digest(SHORT_MSG);
        assert_eq!(digest, expected_s);
        let long_msg = long_msg();
        let iter = long_msg.chunks_exact(700);
        let rem = iter.remainder();
        for chunk in iter {
            h.update(chunk);
        }
        let digest = h.digest(rem);
        assert_eq!(digest, expected_l);
    }

    #[test]
    fn sha224() {
        let mut h = hash::Sha224::new();
        let expected_s = decode_hex("23097d223405d8228642a477bda255b32aadbce4b\
                                    da0b3f7e36c9da7").unwrap();
        let expected_l = decode_hex("ff3c9df48705fc482b9740169320b1442f64e496c\
                                    8d9081b6ed06013").unwrap();
        test_sha(&mut h, &expected_s, &expected_l);
    }

    #[test]
    fn sha256() {
        let mut h = hash::Sha256::new();
        let expected_s = decode_hex("ba7816bf8f01cfea414140de5dae2223b00361a39\
                                    6177a9cb410ff61f20015ad").unwrap();
        let expected_l = decode_hex("e4c274a735996fe7c2d552936358e2e9b7c60c6fa\
                                    6201bdf54bcb026772a4f33").unwrap();
        test_sha(&mut h, &expected_s, &expected_l);
    }

    #[test]
    fn sha384() {
        let mut h = hash::Sha384::new();
        let expected_s = decode_hex("cb00753f45a35e8bb5a03d699ac65007272c32ab0\
                                    eded1631a8b605a43ff5bed8086072ba1e7cc2358b\
                                    aeca134c825a7").unwrap();
        let expected_l = decode_hex("3dc59a1d95bd0f49f9d4f8d8bda9f45d6630fc928\
                                    6441662759b7ba83dbb8934cc6dd373eabdc911904\
                                    eb9100dcdcf5a").unwrap();
        test_sha(&mut h, &expected_s, &expected_l);
    }

    #[test]
    fn sha512() {
        let mut h = hash::Sha512::new();
        let expected_s = decode_hex("ddaf35a193617abacc417349ae20413112e6fa4e8\
                                    9a97ea20a9eeee64b55d39a2192992a274fc1a836b\
                                    a3c23a3feebbd454d4423643ce80e2a9ac94fa54ca\
                                    49f").unwrap();
        let expected_l = decode_hex("cb4879ea297dfe0f9073dc5824ad4681d28cbc9c2\
                                    a996c0ccabfaa9dc07ba3288eae8acde3e6779d7fa\
                                    50701c3af7401df4b74dd88f42879101006c854385\
                                    692").unwrap();
        test_sha(&mut h, &expected_s, &expected_l);
    }

    #[test]
    fn sha512_224() {
        let mut h = hash::Sha512_224::new();
        let expected_s = decode_hex("4634270f707b6a54daae7530460842e20e37ed265\
                                    ceee9a43e8924aa").unwrap();
        let expected_l = decode_hex("07838e07c274670f46827aa3542de114c75a81424\
                                    a14d1ef4def5f6c").unwrap();
        test_sha(&mut h, &expected_s, &expected_l);
    }

    #[test]
    fn sha512_256() {
        let mut h = hash::Sha512_256::new();
        let expected_s = decode_hex("53048e2681941ef99b2e29b76b4c7dabe4c2d0c63\
                                    4fc6d46e0e2f13107e7af23").unwrap();
        let expected_l = decode_hex("e147f7b5e3760b03b4a454cc6f828383078ccbe1a\
                                    936aa29ac2fb68b5c49fbfc").unwrap();
        test_sha(&mut h, &expected_s, &expected_l);
    }
}
