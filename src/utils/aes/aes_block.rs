use crate::utils::conversion::hex_string::HexString;
use core::fmt;

use super::{aes_error::AESError, aes_key::AESKey, constants::*};
use crate::utils::algebra::galois_multiplication;

#[derive(Debug, Clone, Copy, Hash)]
pub struct AESBlock {
  pub mat: [[u8; AES_BLOCK_ROW_SIZE]; AES_BLOCK_COL_SIZE],
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

  pub fn from_bytes_vector(vec: Vec<u8>) -> Result<Vec<Self>, AESError> {
    if vec.len() % 16 != 0 {
      return Err(AESError::InvalidBlockSize(vec.len()));
    }
    let matrices = vec
      .chunks(16)
      .map(|mat| Self::from_flat_array(mat.try_into().unwrap()))
      .collect();
    Ok(matrices)
  }

  pub fn as_flatten_array(&self) -> [u8; 16] {
    let matrix = self.mat;
    let arr = [
      matrix[0][0],
      matrix[1][0],
      matrix[2][0],
      matrix[3][0],
      matrix[0][1],
      matrix[1][1],
      matrix[2][1],
      matrix[3][1],
      matrix[0][2],
      matrix[1][2],
      matrix[2][2],
      matrix[3][2],
      matrix[0][3],
      matrix[1][3],
      matrix[2][3],
      matrix[3][3],
    ];
    arr.to_owned()
  }

  pub fn as_hex_string(&self) -> HexString {
    HexString::try_from(self.as_flatten_array().to_vec()).unwrap()
  }

  pub fn xor_with_block(&mut self, other_block: &Self) -> &mut Self {
    for i in 0..4 {
      for j in 0..4 {
        self.mat[i][j] = self.mat[i][j] ^ other_block.mat[i][j];
      }
    }
    self
  }

  pub fn add_round_key(&mut self, key: &AESKey) -> &mut Self {
    self.xor_with_block(&key.as_block())
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

  pub fn apply_round(&mut self, round_key: &AESKey, last_round: bool) -> &mut Self {
    self
      .sub_bytes()
      .shift_rows()
      .mix_columns(last_round)
      .add_round_key(round_key)
  }

  pub fn apply_inverse_round(&mut self, round_key: &AESKey, first_round: bool) -> &mut Self {
    self
      .add_round_key(round_key)
      .inv_mix_columns(first_round)
      .inv_shift_rows()
      .inv_sub_bytes()
  }
}

impl fmt::Display for AESBlock {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "{}", self.as_hex_string())
  }
}

impl PartialEq for AESBlock {
  fn eq(&self, other: &Self) -> bool {
    self.as_hex_string() == other.as_hex_string()
  }
}
impl Eq for AESBlock {}
