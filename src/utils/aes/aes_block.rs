use crate::utils::conversion::hex_string::HexString;
use core::fmt;

use super::{
  aes_error::AESError,
  constants::sizes::*,
  constants::tables::{INVERSE_S_BOX, S_BOX},
};
use crate::utils::algebra::galois::galois_multiplication;

#[derive(Clone, Copy, Hash)]
pub struct AESBlock {
  pub mat: [[u8; AES_BLOCK_ROW_SIZE]; AES_BLOCK_COL_SIZE],
}

impl TryFrom<&[u8]> for AESBlock {
  type Error = AESError;
  fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
    if value.len() != 16 {
      return Err(AESError::InvalidBlockSize(value.len()));
    }
    let arr: [u8; 16] = value
      .try_into()
      .map_err(|_| AESError::UnexpectedError("This should never happen".into()))?;
    Ok(Self::from_flat_array(&arr))
  }
}

impl Default for AESBlock {
  fn default() -> Self {
    Self::from_flat_array(&[0u8; 16])
  }
}

impl PartialEq for AESBlock {
  fn eq(&self, other: &Self) -> bool {
    self.to_flat_array() == other.to_flat_array()
  }
}
impl Eq for AESBlock {}

impl fmt::Display for AESBlock {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "{}", self.as_hex_string())
  }
}

impl fmt::Debug for AESBlock {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    writeln!(f, "AESBlock {{")?;
    for row in 0..4 {
      writeln!(
        f,
        "  [{:02x}, {:02x}, {:02x}, {:02x}],",
        self.mat[row][0], self.mat[row][1], self.mat[row][2], self.mat[row][3]
      )?;
    }
    writeln!(f, "}}")
  }
}

impl AESBlock {
  const MIX_COLUMN_CT: Self = Self {
    mat: [
      [0x02, 0x03, 0x01, 0x01],
      [0x01, 0x02, 0x03, 0x01],
      [0x01, 0x01, 0x02, 0x03],
      [0x03, 0x01, 0x01, 0x02],
    ],
  };
  const INV_MIX_COLUMN_CT: Self = Self {
    mat: [
      [0x0e, 0x0b, 0x0d, 0x09],
      [0x09, 0x0e, 0x0b, 0x0d],
      [0x0d, 0x09, 0x0e, 0x0b],
      [0x0b, 0x0d, 0x09, 0x0e],
    ],
  };

  pub fn from_flat_array(arr: &[u8; 16]) -> Self {
    Self {
      mat: [
        [arr[0], arr[4], arr[8], arr[12]],
        [arr[1], arr[5], arr[9], arr[13]],
        [arr[2], arr[6], arr[10], arr[14]],
        [arr[3], arr[7], arr[11], arr[15]],
      ],
    }
  }

  pub fn from_bytes<S: AsRef<[u8]>>(bytes: &S) -> Result<Vec<Self>, AESError> {
    if bytes.as_ref().len() % 16 != 0 {
      return Err(AESError::InvalidBlockSize(bytes.as_ref().len()));
    }
    bytes
      .as_ref()
      .chunks(16)
      .map(|chunk| Self::try_from(chunk))
      .collect()
  }

  pub fn to_flat_array(&self) -> [u8; 16] {
    let mut out = [0u8; 16];
    for col in 0..4 {
      for row in 0..4 {
        out[col * 4 + row] = self.mat[row][col];
      }
    }
    out
  }

  pub fn as_hex_string(&self) -> HexString {
    HexString::try_from(self.to_flat_array().to_vec()).unwrap()
  }

  pub fn xor_with_block(&mut self, other_block: &Self) -> &mut Self {
    for i in 0..4 {
      for j in 0..4 {
        self.mat[i][j] = self.mat[i][j] ^ other_block.mat[i][j];
      }
    }
    self
  }

  pub fn add_round_key<S: AsRef<[u8]>>(&mut self, round_keys: &S, round: usize) -> &mut Self {
    let round_block = {
      let offset = round * 16;
      let round_bytes = &round_keys.as_ref()[offset..(offset + 16)];
      Self::from_flat_array(round_bytes.try_into().unwrap())
    };
    self.xor_with_block(&round_block)
  }

  pub fn sub_bytes(&mut self) -> &mut Self {
    for i in 0..4 {
      for j in 0..4 {
        self.mat[i][j] = S_BOX[self.mat[i][j] as usize];
      }
    }
    self
  }

  pub fn inv_sub_bytes(&mut self) -> &mut Self {
    for i in 0..4 {
      for j in 0..4 {
        self.mat[i][j] = INVERSE_S_BOX[self.mat[i][j] as usize];
      }
    }
    self
  }

  pub fn shift_rows(&mut self) -> &mut Self {
    for i in 0..4 {
      self.mat[i].rotate_left(i);
    }
    self
  }

  pub fn inv_shift_rows(&mut self) -> &mut Self {
    for i in 0..4 {
      self.mat[i].rotate_right(i);
    }
    self
  }

  fn matrix_gmult(first: &Self, second: &Self) -> [[u8; 4]; 4] {
    let mut result = [[0; 4]; 4];
    for i in 0..4 {
      for j in 0..4 {
        for k in 0..4 {
          result[i][j] ^= galois_multiplication(first.mat[i][k], second.mat[k][j]);
        }
      }
    }
    result
  }

  pub fn mix_columns(&mut self, ignore: bool) -> &mut Self {
    if ignore {
      return self;
    }
    self.mat = Self::matrix_gmult(&Self::MIX_COLUMN_CT, self);
    self
  }

  pub fn inv_mix_columns(&mut self, ignore: bool) -> &mut Self {
    if ignore {
      return self;
    }
    self.mat = Self::matrix_gmult(&Self::INV_MIX_COLUMN_CT, self);
    self
  }

  pub fn apply_round<S: AsRef<[u8]>>(
    &mut self,
    round_keys: &S,
    round: usize,
    ignore: bool,
  ) -> &mut Self {
    self
      .sub_bytes()
      .shift_rows()
      .mix_columns(ignore)
      .add_round_key(round_keys, round)
  }

  pub fn apply_inverse_round<S: AsRef<[u8]>>(
    &mut self,
    round_keys: &S,
    round: usize,
    ignore: bool,
  ) -> &mut Self {
    self
      .add_round_key(round_keys, round)
      .inv_mix_columns(ignore)
      .inv_shift_rows()
      .inv_sub_bytes()
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::convert::TryFrom;

  #[test]
  fn test_from_flat_array_and_as_flatten_array_roundtrip() {
    let bytes_array = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let block = AESBlock::from_flat_array(&bytes_array);
    assert_eq!(block.to_flat_array(), bytes_array);
  }

  #[test]
  fn test_xor_with_block() {
    let mut a = AESBlock::from_flat_array(&[0xFF; 16]);
    let b = AESBlock::from_flat_array(&[0x0F; 16]);
    a.xor_with_block(&b);
    assert_eq!(a.to_flat_array(), [0xF0; 16]);
  }

  #[test]
  fn test_shift_rows_and_inverse() {
    let original_block = AESBlock::from_flat_array(&(0..16).collect::<Vec<_>>().try_into().unwrap());
    let mut shifted_block = original_block.clone();
    shifted_block.shift_rows().inv_shift_rows();
    assert_eq!(shifted_block, original_block);
  }

  #[test]
  fn test_sub_bytes_and_inverse() {
    let original_block = AESBlock::from_flat_array(&(0..16).collect::<Vec<_>>().try_into().unwrap());
    let mut substituted_block = original_block.clone();
    substituted_block.sub_bytes().inv_sub_bytes();
    assert_eq!(substituted_block, original_block);
  }

  #[test]
  fn test_mix_columns_and_inverse() {
    let original_block = AESBlock::from_flat_array(&(0..16).collect::<Vec<_>>().try_into().unwrap());
    let mut mixed_block = original_block.clone();
    mixed_block.mix_columns(false).inv_mix_columns(false);
    assert_eq!(mixed_block, original_block);
  }

  #[test]
  fn test_try_from_slice_valid() {
    let bytes_array: [u8; 16] = [0xAB; 16];
    let block = AESBlock::try_from(&bytes_array[..]).unwrap();
    assert_eq!(block.to_flat_array(), bytes_array);
  }

  #[test]
  fn test_try_from_slice_invalid() {
    let bytes_array: [u8; 15] = [0x01; 15];
    let result = AESBlock::try_from(&bytes_array[..]);
    assert!(matches!(result, Err(AESError::InvalidBlockSize(15))));
  }

  #[test]
  fn test_default_block() {
    let default_block = AESBlock::default();
    assert_eq!(default_block.to_flat_array(), [0u8; 16]);
  }

  #[test]
  fn test_debug_format() {
    let block = AESBlock::from_flat_array(&(0..16).collect::<Vec<_>>().try_into().unwrap());
    let output = format!("{:?}", block);
    assert!(output.contains("AESBlock"));
    assert!(output.contains("0a")); // Check hex presence
  }

  #[test]
  fn test_from_bytes_valid() {
    let vec: [u8; 32] = [0x11; 32];
    let blocks = AESBlock::from_bytes(&vec).unwrap();
    assert_eq!(blocks.len(), 2);
    assert!(blocks.iter().all(|b| b.to_flat_array() == [0x11; 16]));
  }

  #[test]
  fn test_from_bytes_invalid_size() {
    let vec: [u8; 30] = [0xAA; 30]; // not a multiple of 16
    let err = AESBlock::from_bytes(&vec).unwrap_err();
    assert!(matches!(err, AESError::InvalidBlockSize(30)));
  }
}
