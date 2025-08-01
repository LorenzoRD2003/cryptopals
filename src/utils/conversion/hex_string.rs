use std::collections::HashSet;
use std::fmt;

use super::binary_string::BinaryString;
use super::conversion::{hex_char_to_binary, xor_bytes_vectors, ConversionError};

#[derive(Debug)]
pub struct HexString {
  string: String,
}

impl fmt::Display for HexString {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "{}", self.string)
  }
}

impl TryFrom<String> for HexString {
  type Error = ConversionError;
  fn try_from(str: String) -> Result<Self, Self::Error> {
    let final_str = if str.starts_with("0x") {
      String::from(&str[2..])
    } else {
      str
    };
    let hex_str = Self { string: final_str.to_ascii_lowercase().chars().filter(|&c| !c.is_whitespace()).collect() };
    hex_str.validate()?;
    Ok(hex_str)
  }
}

impl TryFrom<&str> for HexString {
  type Error = ConversionError;
  fn try_from(str: &str) -> Result<Self, Self::Error> {
    Self::try_from(String::from(str))
  }
}

impl From<Vec<u8>> for HexString {
  fn from(vec: Vec<u8>) -> Self {
    BinaryString::from(vec).as_hex_string()
  }
}

impl PartialEq for HexString {
  fn eq(&self, other: &Self) -> bool {
    self.string == other.string
  }
}

impl AsRef<str> for HexString {
  fn as_ref(&self) -> &str {
    self.string.as_ref()
  }
}

impl HexString {
  pub fn validate(&self) -> Result<(), ConversionError> {
    let valid_chars: HashSet<char> = "0123456789abcdefABCDEF".chars().collect();
    if let Some(c) = self.as_ref().chars().find(|c| !valid_chars.contains(&c)) {
      return Err(ConversionError::InvalidHexCharError(c));
    }
    Ok(())
  }

  pub fn as_binary_string(&self) -> BinaryString {
    let partial_result: Result<Vec<String>, ConversionError> =
      self.as_ref().chars().map(hex_char_to_binary).collect();
    let result: String = partial_result.unwrap().join("");
    if (self.as_ref().len() & 1) == 0 {
      BinaryString::try_from(result).unwrap()
    } else {
      BinaryString::try_from(String::from("0000") + &result).unwrap()
    }
  }

  pub fn as_vector_of_bytes(&self) -> Vec<u8> {
    self.as_binary_string().as_vector_of_bytes()
  }

  pub fn as_base64(&self) -> String {
    self.as_binary_string().as_base64()
  }

  pub fn xor_with(&self, hex: Self) -> Result<Self, ConversionError> {
    let (bytes1, bytes2) = (self.as_vector_of_bytes(), hex.as_vector_of_bytes());
    Ok(Self::from(xor_bytes_vectors(bytes1, bytes2)?))
  }

  pub fn xor_against_byte(&self, byte: u8) -> Self {
    let result: Vec<u8> = self.as_vector_of_bytes().iter().map(|&a| a ^ byte).collect();
    Self::from(result)
  }

  pub fn as_text(&self) -> Result<String, ConversionError> {
    self.as_binary_string().as_text()
  }
}
