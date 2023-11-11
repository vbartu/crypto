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
