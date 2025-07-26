use std::{fmt, string::FromUtf8Error};

#[derive(Debug, Clone, PartialEq)]
pub enum ConversionError {
  InvalidBinaryCharError(char),
  InvalidHexCharError(char),
  InvalidSizeOfString(usize),
  InvalidBase64Character(u8),
  InvalidBase64InputLength,
  SizesDoNotMatch(usize, usize),
  Utf8Error(FromUtf8Error)
}

impl fmt::Display for ConversionError {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match self {
      Self::InvalidBinaryCharError(c) => {
        write!(f, "Invalid char {c} processed when reading a binary string")
      }
      Self::InvalidHexCharError(c) => {
        write!(f, "Invalid char {c} processed when reading a hex string")
      }
      Self::InvalidSizeOfString(n) => {
        write!(f, "Size of binary string must be a multiple of {n}")
      }
      Self::SizesDoNotMatch(a, b) => {
        write!(f, "Sizes of strings must be equal, they are {a} and {b}")
      }
      Self::Utf8Error(error) => {
        write!(f, "UTF8 conversion error {error}.")
      }
      Self::InvalidBase64Character(c) => {
        write!(f, "Character {c} is invalid in Base64.")
      }
      Self::InvalidBase64InputLength => {
        write!(f, "A string in Base64 cannot have this length.")
      }
    }
  }
}

impl From<FromUtf8Error> for ConversionError {
  fn from(error: FromUtf8Error) -> Self {
    Self::Utf8Error(error)
  }
}

pub fn hex_char_to_binary(c: char) -> Result<String, ConversionError> {
  match c {
    '0' => Ok(String::from("0000")),
    '1' => Ok(String::from("0001")),
    '2' => Ok(String::from("0010")),
    '3' => Ok(String::from("0011")),
    '4' => Ok(String::from("0100")),
    '5' => Ok(String::from("0101")),
    '6' => Ok(String::from("0110")),
    '7' => Ok(String::from("0111")),
    '8' => Ok(String::from("1000")),
    '9' => Ok(String::from("1001")),
    'A' | 'a' => Ok(String::from("1010")),
    'B' | 'b' => Ok(String::from("1011")),
    'C' | 'c' => Ok(String::from("1100")),
    'D' | 'd' => Ok(String::from("1101")),
    'E' | 'e' => Ok(String::from("1110")),
    'F' | 'f' => Ok(String::from("1111")),
    ' ' | '\n' | '\t' => Ok(String::from("")),
    c => Err(ConversionError::InvalidHexCharError(c)),
  }
}

pub fn bytes_vector_to_base64(bytes: Vec<u8>) -> String {
  const BASE64_TABLE: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let mut result = String::from("");
  for chunk in bytes.chunks(3) {
    let (b0, b1, b2) = (
      *chunk.get(0).unwrap_or(&0) as u32,
      *chunk.get(1).unwrap_or(&0) as u32,
      *chunk.get(2).unwrap_or(&0) as u32,
    );
    let combined: u32 = ((b0 << 16) | (b1 << 8) | b2) as u32;

    result.push(BASE64_TABLE[((combined >> 18) & 0x3f) as usize] as char); // bits 0..5
    result.push(BASE64_TABLE[((combined >> 12) & 0x3f) as usize] as char); // bits 6..11
    result.push(BASE64_TABLE[((combined >> 6) & 0x3f) as usize] as char); // bits 12..17
    result.push(BASE64_TABLE[(combined & 0x3f) as usize] as char); // bits 18..23
  }
  let length: usize = bytes.len();
  if length % 3 == 1 { // Replace last two characters by ==
    result.pop();
    result.pop();
    result.push('=');
    result.push('=');
  } else if length % 3 == 2 { // Replace last character by =
    result.pop();
    result.push('=');
  }
  result
}

pub fn base64_to_bytes_vector<S: AsRef<str>>(base64_str: S) -> Result<Vec<u8>, ConversionError> {
  const BASE64_TABLE: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let mut bytes = Vec::new();
  let mut buffer = 0u32;
  let mut bits_collected = 0;

  for byte in base64_str.as_ref().bytes() {
    if byte == b'=' {
      break;
    } else if byte.is_ascii_whitespace() {
      continue;
    }

    let value = match BASE64_TABLE.iter().position(|&c| c == byte) {
      Some(v) => v as u32,
      None => return Err(ConversionError::InvalidBase64Character(byte)),
    };

    buffer = (buffer << 6) | value;
    bits_collected += 6;

    while bits_collected >= 8 {
      bits_collected -= 8;
      bytes.push((buffer >> bits_collected) as u8);
    }
  }
  Ok(bytes)
}

pub fn xor_bytes_vectors<S: AsRef<[u8]>, T: AsRef<[u8]>>(bytes1: S, bytes2: T) -> Result<Vec<u8>, ConversionError> {
  let (len1, len2) = (bytes1.as_ref().len(), bytes2.as_ref().len());
  if len1 != len2 {
    return Err(ConversionError::SizesDoNotMatch(len1, len2));
  }
  Ok(
    bytes1
      .as_ref()
      .into_iter()
      .zip(bytes2.as_ref().into_iter())
      .map(|(a, b)| a ^ b)
      .collect(),
  )
}

pub fn repeating_key_xor<S: AsRef<[u8]>, T: AsRef<[u8]>>(text: S, key: T) -> Vec<u8> {
  let (key_bytes, key_length) = (key.as_ref(), key.as_ref().len());
  text
    .as_ref()
    .iter()
    .enumerate()
    .map(|(i, &b)| {
      let kb = key_bytes[i % key_length];
      b ^ kb
    })
    .collect()
}


#[cfg(test)]
mod tests {
  use assert_matches::assert_matches;

use crate::utils::conversion::{binary_string::BinaryString, conversion::{bytes_vector_to_base64, hex_char_to_binary, ConversionError}, hex_string::HexString};

  #[test]
  fn hex_to_binary_valid_char() {
    assert_eq!("0000", hex_char_to_binary('0').unwrap());
    assert_eq!("1010", hex_char_to_binary('A').unwrap());
    assert_eq!("1100", hex_char_to_binary('c').unwrap());
  }

  #[test]
  fn hex_to_binary_invalid_char() {
    assert_matches!(
      hex_char_to_binary('x').unwrap_err(),
      ConversionError::InvalidHexCharError('x')
    );
  }

  #[test]
  fn valid_hex_string_to_binary_string() {
    assert_eq!(
      BinaryString::try_from("0000010100110100").unwrap(),
      HexString::try_from("534")
        .unwrap()
        .as_binary_string()
    );
  }

  #[test]
  #[should_panic]
  fn invalid_hex_string_to_binary_string() {
    HexString::try_from("51ab7x9")
      .unwrap()
      .as_binary_string();
  }

  #[test]
  fn valid_hex_string_starting_with_0x() {
    assert_eq!(
      BinaryString::try_from("0000010100110100").unwrap(),
      HexString::try_from("0x534")
        .unwrap()
        .as_binary_string()
    );
  }

  #[test]
  fn valid_binary_string_to_vector_u8() {
    assert_eq!(
      Vec::from([5, 52]),
      BinaryString::try_from("0000010100110100")
        .unwrap()
        .as_vector_of_bytes()
    );
  }

  #[test]
  fn invalid_size_binary_string() {
    assert_matches!(
      BinaryString::try_from("010100110100").unwrap_err(),
      ConversionError::InvalidSizeOfString(8)
    );
  }

  #[test]
  fn invalid_char_binary_string() {
    assert_matches!(
      BinaryString::try_from("0000010200110100").unwrap_err(),
      ConversionError::InvalidBinaryCharError('2')
    );
  }

  #[test]
  fn test_bytes_vector_to_base64() {
    assert_eq!(
      "SE9MQVFVRVRBTA==",
      bytes_vector_to_base64(Vec::from([72, 79, 76, 65, 81, 85, 69, 84, 65, 76])) // "HOLAQUETAL"
    );
  }

  #[test]
  fn from_hex_to_base64_test() {
    assert_eq!(
      HexString::try_from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
        .unwrap()
        .as_base64(),
      "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    )
  }

  #[test]
  fn xor_two_hex() {
    let (hex1, hex2, hex_result) = (
      HexString::try_from("1c0111001f010100061a024b53535009181c").unwrap(),
      HexString::try_from("686974207468652062756c6c277320657965").unwrap(),
      HexString::try_from("746865206b696420646f6e277420706c6179").unwrap(),
    );
    assert_eq!(hex1.xor_with(hex2).unwrap(), hex_result)
  }

  #[test]
  fn as_text() {
    assert_eq!(
      String::from("Hola que tal, aguante Boca"),
      HexString::try_from("486F6C61207175652074616C2C20616775616E746520426F6361")
        .unwrap()
        .as_text()
        .unwrap()
    )
  }
}
