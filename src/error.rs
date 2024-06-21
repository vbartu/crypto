#[derive(Debug)]
pub enum CryptoErr {
    KeySize,
    BlockSize,
}

impl std::fmt::Display for CryptoErr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CryptoErr::KeySize => write!(f, "{}", "Invalid key size"),
            CryptoErr::BlockSize => write!(f, "{}", "Invalid block size"),
        }
    }
}

impl std::error::Error for CryptoErr {}
