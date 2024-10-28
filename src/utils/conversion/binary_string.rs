use std::fmt;

use super::{conversion::{bytes_vector_to_base64, xor_bytes_vectors, ConversionError}, hex_string::HexString};

#[derive(Debug)]
pub struct BinaryString {
  string: String,
}

impl fmt::Display for BinaryString {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "{}", self.string)
  }
}

impl TryFrom<String> for BinaryString {
  type Error = ConversionError;
  fn try_from(str: String) -> Result<Self, ConversionError> {
    let binary_str = Self { string: str };
    binary_str.validate()?;
    Ok(binary_str)
  }
}

impl TryFrom<&str> for BinaryString {
  type Error = ConversionError;
  fn try_from(str: &str) -> Result<Self, ConversionError> {
    Self::try_from(String::from(str))
  }
}

impl TryFrom<Vec<u8>> for BinaryString {
  type Error = ConversionError;
  fn try_from(vec: Vec<u8>) -> Result<Self, ConversionError> {
    let formatted: String = vec
      .iter()
      .map(|byte| format!("{:08b}", byte))
      .collect();
    Self::try_from(formatted)
  }
}

impl PartialEq for BinaryString {
  fn eq(&self, other: &Self) -> bool {
    self.string == other.string
  }
}

impl AsRef<str> for BinaryString {
  fn as_ref(&self) -> &str {
    self.string.as_ref()
  }
}

impl BinaryString {
  pub fn validate(&self) -> Result<(), ConversionError> {
    if self.as_ref().len() % 8 != 0 {
      return Err(ConversionError::InvalidSizeOfString(8));
    }
    if let Some(invalid_char) = self.as_ref().chars().find(|&c| c != '0' && c != '1') {
      return Err(ConversionError::InvalidBinaryCharError(invalid_char));
    }
    Ok(())
  }

  pub fn as_vector_of_bytes(&self) -> Result<Vec<u8>, ConversionError> {
    let mut bytes: Vec<u8> = Vec::new();
    let mut byte: u8 = 0;
    for (i, c) in self.as_ref().chars().enumerate() {
      byte = (byte << 1) | (c.to_digit(2).unwrap() as u8);
      if (i + 1) % 8 == 0 {
        bytes.push(byte);
        byte = 0;
      }
    }
    Ok(bytes)
  }

  pub fn as_hex_string(&self) -> Result<HexString, ConversionError> {
    let bytes_vector = self.as_vector_of_bytes()?;
    HexString::try_from(hex::encode(bytes_vector)) // Use this since it this function is not part of the exercise
  }

  pub fn as_base64(&self) -> Result<String, ConversionError> {
    bytes_vector_to_base64(self.as_vector_of_bytes()?)
  }

  pub fn xor_with(&self, binary: Self) -> Result<Self, ConversionError> {
    let (bytes1, bytes2) = (self.as_vector_of_bytes()?, binary.as_vector_of_bytes()?);
    Self::try_from(xor_bytes_vectors(bytes1, bytes2)?)
  }

  pub fn xor_with_byte(&self, byte: u8) -> Result<Self, ConversionError> {
    let result: Vec<u8> = self.as_vector_of_bytes()?.iter().map(|&a| a ^ byte).collect();
    Self::try_from(result)
  }

  pub fn as_text(&self) -> Result<String, ConversionError> {
    let bytes = self.as_vector_of_bytes()?;
    Ok(String::from_utf8(bytes)?)
  }
}
