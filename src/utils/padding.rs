pub fn pkcs1_pad(bytes: &[u8], n_size: usize) -> Vec<u8> {
  let padding_len = n_size - 3 - bytes.len();
  [
    vec![0x00, 0x01],
    vec![0xff; padding_len],
    vec![0x00],
    bytes.to_vec(),
  ]
  .concat()
}

pub fn pkcs1_unpad(padded_bytes: &[u8]) -> Vec<u8> {
  if padded_bytes.len() < 3 || padded_bytes[0] != 0x00 || padded_bytes[1] != 0x01 {
    return padded_bytes.to_vec();
  }
  let mut padding_end = 1;
  while padding_end < padded_bytes.len() && padded_bytes[padding_end] != 0x00 {
    padding_end += 1;
  }
  padded_bytes[padding_end + 1..].to_vec()
}
