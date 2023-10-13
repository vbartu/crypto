use std::vec::Vec;


pub fn pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let size: usize = (data.len()/block_size + 1) * block_size;
    let padding: u8 = (size - data.len()) as u8;

    let mut result: Vec<u8> = Vec::with_capacity(size);
    result.extend_from_slice(data);
    for _ in 0..padding {
        result.push(padding);
    }

    assert!(result.len() % block_size == 0);
    result
}

pub fn unpad(data: &[u8]) -> &[u8] {
    let padding: usize = data[data.len()-1] as usize;
    assert!(1 <= padding && padding <= 8);
    &data[..data.len()-padding]
}
