use super::{
  aes_error::AESError,
  constants::tables::{ROUND_CONSTANTS, S_BOX},
};

#[derive(Debug, Clone, PartialEq)]
pub enum AESMode {
  ECB,
  CBC([u8; 16]),
  CTR(u64),
  GCM,
}

pub fn word_modifier(word: (u8, u8, u8, u8), round: u8) -> (u8, u8, u8, u8) {
  // Left-shift
  let mut temp = (0, 0, 0, 0);
  temp.0 = word.1;
  temp.1 = word.2;
  temp.2 = word.3;
  temp.3 = word.0;

  // SubBytes
  temp.0 = S_BOX[temp.0 as usize];
  temp.1 = S_BOX[temp.1 as usize];
  temp.2 = S_BOX[temp.2 as usize];
  temp.3 = S_BOX[temp.3 as usize];

  // Adding round constant (XOR)
  temp.0 = temp.0 ^ ROUND_CONSTANTS[(round - 1) as usize];
  temp
}

pub fn pkcs_padding<S: AsRef<[u8]>>(bytes: &S, final_length: u8) -> Vec<u8> {
  let text_length = bytes.as_ref().len() as u8;
  let mut vec = bytes.as_ref().to_vec();
  let remainder = text_length % final_length;
  if remainder != 0 {
    let diff: u8 = final_length - remainder;
    for _ in 0..diff {
      vec.push(diff);
    }
  }
  vec
}

pub fn has_valid_pkcs_padding<S: AsRef<[u8]>>(bytes: &S, block_size: u8) -> Result<(), AESError> {
  let byte_slice = bytes.as_ref();
  if byte_slice.is_empty() {
    return Err(AESError::PaddingError);
  }
  let padding_len = *bytes.as_ref().last().ok_or(AESError::PaddingError)?;

  if padding_len == 0 || padding_len > block_size {
    return Err(AESError::PaddingError);
  }

  let padding_start = bytes
    .as_ref()
    .len()
    .checked_sub(padding_len as usize)
    .ok_or(AESError::PaddingError)?;

  for &byte in &byte_slice[padding_start..] {
    if byte != padding_len {
      return Err(AESError::PaddingError);
    }
  }

  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::utils::aes::constants::sizes::AES_BLOCK_SIZE;

  #[test]
  fn test_aes_word_modifier() {
    let word = (0x67, 0x20, 0x46, 0x75);
    let round = 1;
    assert_eq!(word_modifier(word, round), (0xb6, 0x5a, 0x9d, 0x85))
  }

  #[test]
  fn test_pkcs_padding() {
    let block = b"YELLOW SUBMARINE";
    let padding = 20;
    assert_eq!(
      pkcs_padding(block, padding),
      b"YELLOW SUBMARINE\x04\x04\x04\x04"
    );
  }

  #[test]
  fn test_valid_pkcs_padding() {
    let string = "ICE ICE BABY\x04\x04\x04\x04";
    has_valid_pkcs_padding(&string, AES_BLOCK_SIZE as u8).unwrap();
  }

  #[test]
  fn test_invalid_pkcs_padding() {
    let str1 = "ICE ICE BABY\x05\x05\x05\x05";
    assert_eq!(
      has_valid_pkcs_padding(&str1, AES_BLOCK_SIZE as u8),
      Err(AESError::PaddingError)
    );
    let str2 = "ICE ICE BABY\x01\x02\x03\x04";
    assert_eq!(
      has_valid_pkcs_padding(&str2, AES_BLOCK_SIZE as u8),
      Err(AESError::PaddingError)
    );
  }
}
