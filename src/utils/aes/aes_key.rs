use core::fmt;
use rand::Rng;

use crate::utils::conversion::hex_string::HexString;
use super::{aes_block::AESBlock, aes_error::AESError, constants::*};

#[derive(Debug, Clone, Copy)]
pub enum AESKey {
  AES128Key([u8; AES128_KEY_SIZE]),
  AES192Key([u8; AES192_KEY_SIZE]),
  AES256Key([u8; AES256_KEY_SIZE]),
}

impl AESKey {
  pub fn default_value() -> Self {
    Self::AES128Key([0; 16])
  }

  pub fn from_bytes<S: AsRef<[u8]>>(key_bytes: &S) -> Result<Self, AESError> {
    let length = key_bytes.as_ref().len();
    match key_bytes.as_ref().len() {
      AES128_KEY_SIZE => Ok(Self::AES128Key(key_bytes.as_ref().try_into().unwrap())),
      AES192_KEY_SIZE => Ok(Self::AES192Key(key_bytes.as_ref().try_into().unwrap())),
      AES256_KEY_SIZE => Ok(Self::AES256Key(key_bytes.as_ref().try_into().unwrap())),
      _ => Err(AESError::InvalidKeySize(length))
    }
  }

  pub fn from_words(words: [(u8, u8, u8, u8); 4]) -> Self {
    let arr: Vec<u8> = words
      .map(|w| [w.0, w.1, w.2, w.3])
      .iter()
      .flat_map(|&arr| arr)
      .collect();
    Self::AES128Key(arr.try_into().unwrap())
  }

  pub fn as_hex_string(&self) -> HexString {
    HexString::try_from(self.get_array().to_vec()).unwrap()
  }

  pub fn size(&self) -> usize {
    match self {
      Self::AES128Key(_) => AES128_KEY_SIZE,
      Self::AES192Key(_) => AES192_KEY_SIZE,
      Self::AES256Key(_) => AES256_KEY_SIZE,
    }
  }

  pub fn get_array(&self) -> &[u8] {
    match self {
      Self::AES128Key(arr) => arr,
      Self::AES192Key(arr) => arr,
      Self::AES256Key(arr) => arr,
    }
  }

  pub fn as_block(&self) -> AESBlock {
    match self {
      Self::AES128Key(arr) => AESBlock::from_flat_array(arr),
      Self::AES192Key(_) => unimplemented!(),
      Self::AES256Key(_) => unimplemented!(),
    }
  }

  pub fn divide_in_words(&self) -> [(u8, u8, u8, u8); 4] {
    match self {
      Self::AES128Key(arr) => [
        (arr[0], arr[1], arr[2], arr[3]),
        (arr[4], arr[5], arr[6], arr[7]),
        (arr[8], arr[9], arr[10], arr[11]),
        (arr[12], arr[13], arr[14], arr[15]),
      ],
      Self::AES192Key(_) => unimplemented!(),
      Self::AES256Key(_) => unimplemented!(),
    }
  }

  pub fn random_key() -> Self {
    Self::AES128Key(rand::thread_rng().gen())
  }
}

impl fmt::Display for AESKey {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "{}", self.as_hex_string())
  }
}