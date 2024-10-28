// This is an implementation of AES-128 in ECB mode
use super::{
  aes_block::AESBlock,
  aes_error::AESError,
  aes_key::AESKey,
  constants::*,
  utils::{pkcs_padding, word_modifier, AESMode},
};

pub struct AES {
  pub key: AESKey,
  pub mode: AESMode,
}

impl AES {
  pub fn create_from<S: AsRef<[u8]>>(key_bytes: &S, mode: AESMode) -> Result<Self, AESError> {
    Ok(Self {
      key: AESKey::from_bytes(key_bytes)?,
      mode,
    })
  }

  fn validate_text_size<S: AsRef<[u8]>>(text: &S) -> Result<(), AESError> {
    let plaintext_size = text.as_ref().len();
    if plaintext_size == 0 {
      return Err(AESError::InvalidBlockSize(plaintext_size));
    }
    Ok(())
  }

  pub fn key_size(&self) -> usize {
    self.key.size()
  }

  pub fn divide_in_blocks<S: AsRef<[u8]>>(text: &S) -> Result<Vec<AESBlock>, AESError> {
    Self::validate_text_size(text)?;
    let text_len = text.as_ref().len();
    let blocks_amount = text_len / AES_BLOCK_SIZE;
    let mut blocks: Vec<AESBlock> = vec![];
    for i in 0..blocks_amount {
      let flattened_block: [u8; 16] = text.as_ref()[i * AES_BLOCK_SIZE..(i + 1) * AES_BLOCK_SIZE]
        .try_into()
        .unwrap();
      let block: AESBlock = AESBlock::from_flat_array(&flattened_block);
      blocks.push(block);
    }
    Ok(blocks)
  }

  pub fn compute_all_round_keys(&self) -> [AESKey; AES128_ROUNDS] {
    match self.key {
      AESKey::AES128Key(_) => self.aes_128_compute_all_round_keys(),
      AESKey::AES192Key(_) => unimplemented!(),
      AESKey::AES256Key(_) => unimplemented!(),
    }
  }

  fn reverse_keys_for_decryption(&self, keys: &mut Vec<AESKey>) -> AESKey {
    keys.reverse();
    keys.push(self.key);
    keys.pop().unwrap()
  }

  fn aes_128_compute_all_round_keys(&self) -> [AESKey; AES128_ROUNDS] {
    const WK: usize = 4; // words-per-key
    let mut words: [(u8, u8, u8, u8); WK * (AES128_ROUNDS + 1)] =
      [(0, 0, 0, 0); WK * (AES128_ROUNDS + 1)];
    words[0..4].copy_from_slice(self.key.divide_in_words().as_slice());

    for i in WK..WK * (AES128_ROUNDS + 1) {
      let mut temp = words[i - 1]; // previous word
      if i % WK == 0 {
        temp = word_modifier(temp, (i / WK) as u8);
      }
      words[i].0 = words[i - WK].0 ^ temp.0;
      words[i].1 = words[i - WK].1 ^ temp.1;
      words[i].2 = words[i - WK].2 ^ temp.2;
      words[i].3 = words[i - WK].3 ^ temp.3;
    }

    let mut round_keys: [AESKey; AES128_ROUNDS] = [AESKey::default_value(); AES128_ROUNDS];
    for i in 0..AES128_ROUNDS {
      let word_group: [(u8, u8, u8, u8); 4] = words[4 * (i + 1)..4 * (i + 2)].try_into().unwrap();
      round_keys[i] = AESKey::from_words(word_group);
    }

    round_keys.try_into().unwrap()
  }

  fn return_blocks_as_bytes(blocks: &Vec<AESBlock>) -> Vec<u8> {
    blocks
      .iter()
      .map(|arr| arr.as_flatten_array())
      .flatten()
      .collect()
  }

  pub fn encode<S: AsRef<[u8]>, T: AsRef<[u8]>>(
    plaintext: &S,
    key_bytes: &T,
    mode: AESMode,
  ) -> Result<Vec<u8>, AESError> {
    let aes = Self::create_from(key_bytes, mode)?;
    match aes.mode {
      AESMode::ECB => match aes.key {
        AESKey::AES128Key(_) => aes.aes_128_ecb_encode(plaintext),
        AESKey::AES192Key(_) => unimplemented!(),
        AESKey::AES256Key(_) => unimplemented!(),
      },
      AESMode::CBC(iv) => match aes.key {
        AESKey::AES128Key(_) => aes.aes_128_cbc_encode(plaintext, &iv),
        AESKey::AES192Key(_) => unimplemented!(),
        AESKey::AES256Key(_) => unimplemented!(),
      },
      AESMode::CTR(nonce) => match aes.key {
        AESKey::AES128Key(_) => aes.aes_128_ctr(plaintext, nonce),
        AESKey::AES192Key(_) => unimplemented!(),
        AESKey::AES256Key(_) => unimplemented!(),
      },
      AESMode::GCM => unimplemented!(),
    }
  }

  pub fn decode<S: AsRef<[u8]>, T: AsRef<[u8]>>(
    ciphertext: &S,
    key_bytes: &T,
    mode: AESMode,
  ) -> Result<Vec<u8>, AESError> {
    let aes = Self::create_from(key_bytes, mode)?;

    match aes.mode {
      AESMode::ECB => match aes.key {
        AESKey::AES128Key(_) => aes.aes_128_ecb_decode(ciphertext),
        AESKey::AES192Key(_) => unimplemented!(),
        AESKey::AES256Key(_) => unimplemented!(),
      },
      AESMode::CBC(iv) => match aes.key {
        AESKey::AES128Key(_) => aes.aes_128_cbc_decode(ciphertext, &iv),
        AESKey::AES192Key(_) => unimplemented!(),
        AESKey::AES256Key(_) => unimplemented!(),
      },
      AESMode::CTR(nonce) => match aes.key {
        AESKey::AES128Key(_) => aes.aes_128_ctr(ciphertext, nonce),
        AESKey::AES192Key(_) => unimplemented!(),
        AESKey::AES256Key(_) => unimplemented!(),
      },
      AESMode::GCM => unimplemented!(),
    }
  }

  fn aes_128_ecb_encode<S: AsRef<[u8]>>(&self, plaintext: &S) -> Result<Vec<u8>, AESError> {
    let padded_text = pkcs_padding(plaintext, AES_BLOCK_SIZE as u8);
    let mut blocks = Self::divide_in_blocks(&padded_text)?;
    let keys = self.aes_128_compute_all_round_keys();

    for block in blocks.iter_mut() {
      block.add_round_key(&self.key);
      for round in 0..AES128_ROUNDS {
        block.apply_round(&keys[round], round == AES128_ROUNDS - 1);
      }
    }

    let ciphertext: Vec<u8> = blocks
      .iter()
      .map(|arr| arr.as_flatten_array())
      .flatten()
      .collect();
    Ok(ciphertext)
  }

  fn aes_128_ecb_decode<S: AsRef<[u8]>>(&self, ciphertext: &S) -> Result<Vec<u8>, AESError> {
    let mut keys = self.aes_128_compute_all_round_keys().to_vec();
    let last_key = self.reverse_keys_for_decryption(&mut keys);
    let padded_text = pkcs_padding(ciphertext, AES_BLOCK_SIZE as u8);
    let mut blocks = Self::divide_in_blocks(&padded_text)?;
    for block in blocks.iter_mut() {
      for round in 0..AES128_ROUNDS {
        block.apply_inverse_round(&keys[round], round == 0);
      }
      block.add_round_key(&last_key);
    }
    Ok(Self::return_blocks_as_bytes(&blocks))
  }

  fn aes_128_cbc_encode<S: AsRef<[u8]>>(
    &self,
    plaintext: &S,
    iv: &[u8; 16],
  ) -> Result<Vec<u8>, AESError> {
    let keys = self.aes_128_compute_all_round_keys();
    let padded_text = pkcs_padding(plaintext, AES_BLOCK_SIZE as u8);
    let mut blocks = Self::divide_in_blocks(&padded_text)?;

    blocks[0].xor_with_block(&AESBlock::from_flat_array(iv));
    blocks[0].add_round_key(&self.key);
    for round in 0..AES128_ROUNDS {
      blocks[0].apply_round(&keys[round], round == AES128_ROUNDS - 1);
    }

    for i in 1..blocks.len() {
      let previous_block = blocks[i - 1];
      blocks[i].xor_with_block(&previous_block);
      blocks[i].add_round_key(&self.key);
      for round in 0..AES128_ROUNDS {
        blocks[i].apply_round(&keys[round], round == AES128_ROUNDS - 1);
      }
    }
    Ok(Self::return_blocks_as_bytes(&blocks))
  }

  fn aes_128_cbc_decode<S: AsRef<[u8]>>(
    &self,
    ciphertext: &S,
    iv: &[u8; 16],
  ) -> Result<Vec<u8>, AESError> {
    let mut keys = self.aes_128_compute_all_round_keys().to_vec();
    let last_key = self.reverse_keys_for_decryption(&mut keys);

    let padded_text = pkcs_padding(ciphertext, AES_BLOCK_SIZE as u8);
    let mut blocks = Self::divide_in_blocks(&padded_text)?;
    let ciphered_blocks = blocks.clone();
    for round in 0..AES128_ROUNDS {
      blocks[0].apply_inverse_round(&keys[round], round == 0);
    }
    blocks[0].add_round_key(&last_key);
    blocks[0].xor_with_block(&AESBlock::from_flat_array(iv));

    for i in 1..blocks.len() {
      for round in 0..AES128_ROUNDS {
        blocks[i].apply_inverse_round(&keys[round], round == 0);
      }
      blocks[i].add_round_key(&last_key);
      blocks[i].xor_with_block(&ciphered_blocks[i - 1]);
    }
    Ok(Self::return_blocks_as_bytes(&blocks))
  }

  fn aes_128_ctr<S: AsRef<[u8]>>(
    &self,
    text: &S,
    nonce: u64,
  ) -> Result<Vec<u8>, AESError> {
    let mut result: Vec<u8> = Vec::new();
    let mut ctr: u64 = 0;

    for chunk in text.as_ref().chunks(16) {
      let b = [nonce.to_le_bytes(), ctr.to_le_bytes()].concat();
      let s = self.aes_128_ecb_encode(&b)?;
      let mut block = chunk.to_vec();
      for (i, byte) in block.iter_mut().enumerate() {
        *byte ^= s[i];
      }
      result.extend_from_slice(&block);
      ctr += 1;
    }
    Ok(result)
  }
}
