use core::fmt;
use crate::utils::{aes::constants::*, conversion::conversion::ConversionError};

#[derive(Debug, Clone, PartialEq)]
pub enum AESError {
  InvalidIndex(usize, usize),
  InvalidKeySize(usize),
  InvalidBlockSize(usize),
  PaddingError,
  ConversionError(ConversionError),
  UnexpectedError,
}

impl From<std::io::Error> for AESError {
  fn from(_: std::io::Error) -> AESError {
    Self::UnexpectedError
  }
}

impl From<ConversionError> for AESError {
  fn from(err: ConversionError) -> AESError {
    Self::ConversionError(err)
  }
}

impl fmt::Display for AESError {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match self {
      Self::InvalidIndex(index, max_index) => {
        write!(
          f,
          "Entered an invalid index {index}, the maximum possible was {max_index}."
        )
      }
      Self::InvalidKeySize(key_size) => {
        write!(
          f,
          "Keys in AES must be of 128, 192 or 256 bits. Tried to enter a key of {key_size} bits."
        )
      }
      Self::InvalidBlockSize(plaintext_size) => {
        write!(f, "Each block in AES must be {AES_BLOCK_SIZE} bits. Tried to enter a plaintext of {plaintext_size} bits, not multiple of {AES_BLOCK_SIZE}")
      }
      Self::PaddingError => {
        write!(f, "An error occurred with the padding.")
      }
      Self::UnexpectedError => {
        write!(f, "An unexpected error occurred during AES execution.")
      }
      Self::ConversionError(_) => {
        write!(f, "A conversion error occurred in the program.")
      }
    }
  }
}
