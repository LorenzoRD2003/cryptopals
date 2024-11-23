use rand::{thread_rng, Rng};

pub fn pkcs1_v15_pad(bytes: &[u8], n_size: usize) -> Vec<u8> {
  let padding_len = n_size - 3 - bytes.len();
  let mut rng = thread_rng();
  let mut padded = vec![0x00, 0x02];
  for _ in 0..padding_len {
    padded.push(rng.gen_range(1..=255));
  }
  padded.push(0x00);
  padded.extend_from_slice(bytes);
  padded
}

pub fn pkcs1_v15_unpad(padded_bytes: &[u8]) -> Vec<u8> {
  if padded_bytes.len() < 3 || padded_bytes[0] != 0x00 || padded_bytes[1] != 0x02 {
    return padded_bytes.to_vec();
  }
  let mut padding_end = 1;
  while padding_end < padded_bytes.len() && padded_bytes[padding_end] != 0x00 {
    padding_end += 1;
  }
  padded_bytes[padding_end + 1..].to_vec()
}
