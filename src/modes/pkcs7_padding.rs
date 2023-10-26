use std::vec::Vec;


pub fn pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let mut padded: Vec<u8> = data.to_vec();
    let total_size: usize = (data.len()/block_size + 1) * block_size;
    let padding_size: usize = total_size - data.len();

    for _ in 0..padding_size {
        padded.push(padding_size as u8);
    }
    padded
}

pub fn unpad(data: &[u8]) -> &[u8] {
    let padding_size: usize = data[data.len()-1] as usize;
    &data[..data.len()-padding_size]
}
