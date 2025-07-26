use core::fmt;
use rand::Rng;

use super::{aes_error::AESError, constants::sizes::*};
use crate::utils::conversion::hex_string::HexString;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AESKey {
  AES128Key([u8; AES128_KEY_SIZE]),
  AES192Key([u8; AES192_KEY_SIZE]),
  AES256Key([u8; AES256_KEY_SIZE]),
}

impl AsRef<[u8]> for AESKey {
  fn as_ref(&self) -> &[u8] {
    self.get_array()
  }
}

impl TryFrom<&[u8]> for AESKey {
  type Error = AESError;
  fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
    let bytes = value.as_ref();
    let length = bytes.len();
    match length {
      AES128_KEY_SIZE => Ok(Self::AES128Key(bytes.try_into().unwrap())),
      AES192_KEY_SIZE => Ok(Self::AES192Key(bytes.try_into().unwrap())),
      AES256_KEY_SIZE => Ok(Self::AES256Key(bytes.try_into().unwrap())),
      _ => Err(AESError::InvalidKeySize(length)),
    }
  }
}

impl AESKey {
  pub fn default_value(size: usize) -> Result<Self, AESError> {
    match size {
      AES128_KEY_SIZE => Ok(Self::AES128Key([0; AES128_KEY_SIZE])),
      AES192_KEY_SIZE => Ok(Self::AES192Key([0; AES192_KEY_SIZE])),
      AES256_KEY_SIZE => Ok(Self::AES256Key([0; AES256_KEY_SIZE])),
      _ => Err(AESError::InvalidKeySize(size)),
    }
  }

  pub fn from_bytes<S: AsRef<[u8]>>(key_bytes: &S) -> Result<Self, AESError> {
    Self::try_from(key_bytes.as_ref())
  }

  pub fn from_words(words: Vec<(u8, u8, u8, u8)>) -> Self {
    let mut bytes = Vec::with_capacity(words.len() * 4);
    for (a, b, c, d) in words {
      bytes.extend_from_slice(&[a, b, c, d]);
    }
    Self::from_bytes(&bytes).unwrap()
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

  pub fn to_owned_array(&self) -> Vec<u8> {
    self.get_array().to_vec()
  }

  pub fn key_type(&self) -> &'static str {
    match self {
      Self::AES128Key(_) => "AES-128",
      Self::AES192Key(_) => "AES-192",
      Self::AES256Key(_) => "AES-256",
    }
  }

  pub fn divide_in_words(&self) -> Vec<(u8, u8, u8, u8)> {
    self
      .get_array()
      .chunks(4)
      .map(|chunk| (chunk[0], chunk[1], chunk[2], chunk[3]))
      .collect()
  }

  pub fn random_key(size: usize) -> Result<AESKey, AESError> {
    match size {
      AES128_KEY_SIZE => Ok(Self::AES128Key(rand::thread_rng().gen())),
      AES192_KEY_SIZE => Ok(Self::AES192Key(rand::thread_rng().gen())),
      AES256_KEY_SIZE => Ok(Self::AES256Key(rand::thread_rng().gen())),
      _ => Err(AESError::InvalidKeySize(size)),
    }
  }
}

impl fmt::Display for AESKey {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "{}", self.as_hex_string())
  }
}
