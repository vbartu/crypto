macro_rules! error_decl {
    ( $name:ident, $err_msg:expr ) =>
    {
        #[derive(Debug)]
        pub struct $name;

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "Error: {}", $err_msg)
            }
        }

        impl std::error::Error for $name {}
    }
}


error_decl!(InvalidKeyLen, "Invalid key length");
error_decl!(InvalidDataLen, "Invalid data length");
error_decl!(InvalidIvLen, "Invalid iv/nonce length");
error_decl!(IncorrectMac, "MAC signature was incorrect");
