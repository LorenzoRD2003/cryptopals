use crate::utils::{
  aes::constants::sizes::*,
  conversion::{conversion::ConversionError, hex_string::HexString},
};
use core::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum AESError {
  InvalidIndex(usize, usize),
  InvalidKeySize(usize),
  InvalidBlockSize(usize),
  PaddingError,
  ConversionError(ConversionError),
  AsciiError(Vec<u8>),
  UnexpectedError(String),
}

impl From<std::io::Error> for AESError {
  fn from(err: std::io::Error) -> Self {
    Self::UnexpectedError(err.to_string())
  }
}

impl From<ConversionError> for AESError {
  fn from(err: ConversionError) -> Self {
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
          "Keys in AES must be 16, 24, or 32 bytes (128, 192, or 256 bits). Received key of {key_size} bytes."
        )
      }
      Self::InvalidBlockSize(plaintext_size) => {
        write!(f, "Each block in AES must be {AES_BLOCK_SIZE} bits. Tried to enter a plaintext of {plaintext_size} bits, not multiple of {AES_BLOCK_SIZE}")
      }
      Self::PaddingError => {
        write!(f, "An error occurred with the padding.")
      }
      Self::AsciiError(plaintext) => {
        let hex = HexString::from(plaintext.clone());
        write!(f, "ASCII error for obtained plaintext {hex}")
      }
      Self::UnexpectedError(msg) => {
        write!(f, "Unexpected error during AES execution: {msg}")
      }
      Self::ConversionError(_) => {
        write!(f, "A conversion error occurred in the program.")
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::utils::conversion::hex_string::HexString;

  #[test]
  fn test_invalid_index_display() {
    let err = AESError::InvalidIndex(5, 3);
    let msg = format!("{}", err);
    assert!(msg.contains("invalid index 5"));
    assert!(msg.contains("maximum possible was 3"));
  }

  #[test]
  fn test_invalid_key_size_display() {
    let err = AESError::InvalidKeySize(20);
    let msg = format!("{}", err);
    assert!(msg.contains("key"));
    assert!(msg.contains("20"));
  }

  #[test]
  fn test_invalid_block_size_display() {
    let err = AESError::InvalidBlockSize(31);
    let msg = format!("{}", err);
    assert!(msg.contains("block in AES must be"));
    assert!(msg.contains("31"));
  }

  #[test]
  fn test_padding_error_display() {
    let err = AESError::PaddingError;
    let msg = format!("{}", err);
    assert!(msg.contains("padding"));
  }

  #[test]
  fn test_ascii_error_display() {
    let input = b"\xff\xff".to_vec();
    let err = AESError::AsciiError(input.clone());
    let msg = format!("{}", err);
    let hex = HexString::try_from(input).unwrap().to_string();
    assert!(msg.contains(&hex));
  }

  #[test]
  fn test_conversion_error_display() {
    let conv_err = ConversionError::InvalidBase64InputLength;
    let err = AESError::ConversionError(conv_err);
    let msg = format!("{}", err);
    assert!(msg.contains("conversion error"));
  }

  #[test]
  fn test_unexpected_error_display() {
    let err = AESError::UnexpectedError("An error happened".into());
    let msg = format!("{}", err);
    assert!(msg.contains("Unexpected error"));
  }

  #[test]
  fn test_from_conversion_error() {
    let conv_err = ConversionError::InvalidBase64InputLength;
    let err: AESError = conv_err.into();
    assert_eq!(
      err,
      AESError::ConversionError(ConversionError::InvalidBase64InputLength)
    );
  }

  #[test]
  fn test_from_io_error() {
    let io_err = std::io::Error::new(std::io::ErrorKind::Other, "fail");
    let msg = format!("{}", AESError::from(io_err));
    assert!(msg.contains("Unexpected error"));
  }
}
