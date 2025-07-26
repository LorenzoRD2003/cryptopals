// This is an implementation of AES-128 in ECB mode
use super::{
  aes_block::AESBlock,
  aes_error::AESError,
  aes_key::AESKey,
  constants::sizes::*,
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
      let flattened_block: &[u8] = &text.as_ref()[i * AES_BLOCK_SIZE..(i + 1) * AES_BLOCK_SIZE];
      let block = AESBlock::try_from(flattened_block)?;
      blocks.push(block);
    }
    Ok(blocks)
  }

  fn aes_128_get_round_keys(&self) -> Vec<u8> {
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

    words
      .iter()
      .flat_map(|&(a, b, c, d)| vec![a, b, c, d])
      .collect()
  }

  fn return_blocks_as_bytes(blocks: &Vec<AESBlock>) -> Vec<u8> {
    blocks.iter().flat_map(|b| b.to_flat_array()).collect()
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
    let round_keys = self.aes_128_get_round_keys();

    for block in blocks.iter_mut() {
      block.add_round_key(&round_keys, 0);
      for round in 1..=AES128_ROUNDS {
        block.apply_round(&round_keys, round, round == AES128_ROUNDS);
      }
    }

    let ciphertext: Vec<u8> = blocks
      .iter()
      .map(|arr| arr.to_flat_array())
      .flatten()
      .collect();
    Ok(ciphertext)
  }

  fn aes_128_ecb_decode<S: AsRef<[u8]>>(&self, ciphertext: &S) -> Result<Vec<u8>, AESError> {
    let round_keys = self.aes_128_get_round_keys().to_vec();
    let padded_text = pkcs_padding(ciphertext, AES_BLOCK_SIZE as u8);
    let mut blocks = Self::divide_in_blocks(&padded_text)?;
    for block in blocks.iter_mut() {
      for round in (1..=AES128_ROUNDS).rev() {
        block.apply_inverse_round(&round_keys, round, round == AES128_ROUNDS);
      }
      block.add_round_key(&round_keys, 0);
    }
    Ok(Self::return_blocks_as_bytes(&blocks))
  }

  fn aes_128_cbc_encode<S: AsRef<[u8]>>(
    &self,
    plaintext: &S,
    iv: &[u8; 16],
  ) -> Result<Vec<u8>, AESError> {
    let round_keys = self.aes_128_get_round_keys();
    let padded_text = pkcs_padding(plaintext, AES_BLOCK_SIZE as u8);
    let mut blocks = Self::divide_in_blocks(&padded_text)?;

    blocks[0].xor_with_block(&AESBlock::from_flat_array(iv));
    blocks[0].add_round_key(&round_keys, 0);
    for round in 1..=AES128_ROUNDS {
      blocks[0].apply_round(&round_keys, round, round == AES128_ROUNDS);
    }

    for i in 1..blocks.len() {
      let previous_block = blocks[i - 1];
      blocks[i].xor_with_block(&previous_block);
      blocks[i].add_round_key(&round_keys, 0);
      for round in 1..=AES128_ROUNDS {
        blocks[i].apply_round(&round_keys, round, round == AES128_ROUNDS);
      }
    }
    Ok(Self::return_blocks_as_bytes(&blocks))
  }

  fn aes_128_cbc_decode<S: AsRef<[u8]>>(
    &self,
    ciphertext: &S,
    iv: &[u8; 16],
  ) -> Result<Vec<u8>, AESError> {
    let round_keys = self.aes_128_get_round_keys().to_vec();
    let padded_text = pkcs_padding(ciphertext, AES_BLOCK_SIZE as u8);
    let mut blocks = Self::divide_in_blocks(&padded_text)?;
    let ciphered_blocks = blocks.clone();

    for round in (1..=AES128_ROUNDS).rev() {
      blocks[0].apply_inverse_round(&round_keys, round, round == AES128_ROUNDS);
    }
    blocks[0].add_round_key(&round_keys, 0);
    blocks[0].xor_with_block(&AESBlock::from_flat_array(iv));

    for i in 1..blocks.len() {
      for round in (1..=AES128_ROUNDS).rev() {
        blocks[i].apply_inverse_round(&round_keys, round, round == AES128_ROUNDS);
      }
      blocks[i].add_round_key(&round_keys, 0);
      blocks[i].xor_with_block(&ciphered_blocks[i - 1]);
    }
    Ok(Self::return_blocks_as_bytes(&blocks))
  }

  fn aes_128_ctr<S: AsRef<[u8]>>(&self, text: &S, nonce: u64) -> Result<Vec<u8>, AESError> {
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

#[cfg(test)]
mod tests {
  use super::*;
  use crate::utils::conversion::hex_string::HexString;

  #[test]
  fn test_divide_plaintext_in_blocks() {
    let plaintext = b"Two One Nine TwoTwo One Nine Two";
    assert_eq!(
      HexString::try_from(plaintext.to_vec()).unwrap(),
      HexString::try_from("54776f204f6e65204e696e652054776f54776f204f6e65204e696e652054776f")
        .unwrap()
    );

    let plaintext_blocks = AES::divide_in_blocks(plaintext).unwrap();
    assert_eq!(
      plaintext_blocks[0].to_flat_array(),
      b"Two One Nine Two".clone(),
    );
    assert_eq!(
      plaintext_blocks[1].to_flat_array(),
      b"Two One Nine Two".clone(),
    )
  }

  #[test]
  fn test_aes_128_compute_all_round_keys() {
    let initial_key = b"Thats my Kung Fu";
    let aes = AES::create_from(initial_key, AESMode::ECB).unwrap();
    assert_eq!(
      aes.key.as_hex_string(),
      HexString::try_from("5468617473206d79204b756e67204675").unwrap()
    );

    let key_rounds = aes.aes_128_get_round_keys();
    let hexs: Vec<HexString> = key_rounds
      .chunks(16)
      .map(|x| HexString::try_from(x.to_vec()).unwrap())
      .collect();
    assert_eq!(
      hexs,
      vec![
        aes.key.as_hex_string(),
        HexString::try_from("e232fcf191129188b159e4e6d679a293").unwrap(),
        HexString::try_from("56082007c71ab18f76435569a03af7fa").unwrap(),
        HexString::try_from("d2600de7157abc686339e901c3031efb").unwrap(),
        HexString::try_from("a11202c9b468bea1d75157a01452495b").unwrap(),
        HexString::try_from("b1293b3305418592d210d232c6429b69").unwrap(),
        HexString::try_from("bd3dc287b87c47156a6c9527ac2e0e4e").unwrap(),
        HexString::try_from("cc96ed1674eaaa031e863f24b2a8316a").unwrap(),
        HexString::try_from("8e51ef21fabb4522e43d7a0656954b6c").unwrap(),
        HexString::try_from("bfe2bf904559fab2a16480b4f7f1cbd8").unwrap(),
        HexString::try_from("28fddef86da4244accc0a4fe3b316f26").unwrap()
      ]
    );
  }

  #[test]
  fn test_aes_add_round_key() {
    let plaintext = b"Two One Nine Two";
    let key = b"Thats my Kung Fu";
    let mut block = AESBlock::from_flat_array(plaintext);
    block.add_round_key(key, 0);
    dbg!(block);
    assert_eq!(
      block.as_hex_string(),
      HexString::try_from("001f0e543c4e08596e221b0b4774311a").unwrap()
    )
  }

  #[test]
  fn test_aes_128_one_round() {
    let plaintext = b"Two One Nine Two";
    let initial_key = b"Thats my Kung Fu";
    let aes = AES::create_from(initial_key, AESMode::ECB).unwrap();
    let round_keys = aes.aes_128_get_round_keys();
    let mut first_block = AES::divide_in_blocks(&plaintext).unwrap()[0];
    first_block.add_round_key(&round_keys, 0);

    let subbed_bytes = first_block.sub_bytes();
    assert_eq!(
      subbed_bytes.as_hex_string(),
      HexString::try_from("63c0ab20eb2f30cb9f93af2ba092c7a2").unwrap()
    );

    let shifted_rows = subbed_bytes.shift_rows();
    assert_eq!(
      shifted_rows.as_hex_string(),
      HexString::try_from("632fafa2eb93c7209f92abcba0c0302b").unwrap()
    );

    let mixed_columns = shifted_rows.mix_columns(false);
    assert_eq!(
      mixed_columns.as_hex_string(),
      HexString::try_from("ba75f47a84a48d32e88d060e1b407d5d").unwrap()
    );

    let result = mixed_columns.add_round_key(&round_keys, 1);
    assert_eq!(
      result.as_hex_string(),
      HexString::try_from("5847088b15b61cba59d4e2e8cd39dfce").unwrap()
    );
  }

  #[test]
  fn test_aes_128_ecb_encode() {
    let plaintext = b"Two One Nine TwoTwo One Nine Two";
    let initial_key = b"Thats my Kung Fu";
    let ciphertext = AES::encode(plaintext, initial_key, AESMode::ECB)
      .expect("An error occured during AES execution.");
    assert_eq!(
      HexString::try_from(ciphertext).unwrap(),
      HexString::try_from("29c3505f571420f6402299b31a02d73a29c3505f571420f6402299b31a02d73a")
        .unwrap()
    )
  }

  #[test]
  fn test_one_inverse_round() {
    let initial_key = b"Thats my Kung Fu".clone();
    let aes = AES::create_from(&initial_key, AESMode::ECB).unwrap();
    let round_keys = aes.aes_128_get_round_keys().to_vec();

    let mut cipherblock = AESBlock::from_bytes(
      &HexString::try_from("5847088b15b61cba59d4e2e8cd39dfce")
        .unwrap()
        .as_vector_of_bytes(),
    )
    .unwrap()[0];

    cipherblock.add_round_key(&round_keys, 1);
    assert_eq!(
      cipherblock.as_hex_string(),
      HexString::try_from("ba75f47a84a48d32e88d060e1b407d5d").unwrap()
    );

    cipherblock.inv_mix_columns(false);
    assert_eq!(
      cipherblock.as_hex_string(),
      HexString::try_from("632fafa2eb93c7209f92abcba0c0302b").unwrap()
    );

    cipherblock.inv_shift_rows();
    assert_eq!(
      cipherblock.as_hex_string(),
      HexString::try_from("63c0ab20eb2f30cb9f93af2ba092c7a2").unwrap()
    );

    let plaintext = cipherblock.inv_sub_bytes();
    assert_eq!(
      plaintext.as_hex_string(),
      HexString::try_from("001f0e543c4e08596e221b0b4774311a").unwrap()
    )
  }

  #[test]
  fn test_aes_128_ecb_decode() {
    let ciphertext =
      HexString::try_from("29c3505f571420f6402299b31a02d73a29c3505f571420f6402299b31a02d73a")
        .unwrap()
        .as_vector_of_bytes();
    let initial_key = b"Thats my Kung Fu";
    let plaintext = AES::decode(&ciphertext, initial_key, AESMode::ECB)
      .expect("An error occured during AES execution.");
    assert_eq!(
      HexString::try_from(plaintext).unwrap(),
      HexString::try_from("54776f204f6e65204e696e652054776f54776f204f6e65204e696e652054776f")
        .unwrap()
    )
  }

  #[test]
  fn test_aes_128_cbc_encode() {
    let plaintext = b"Aguante BocaaaaaAguante Bocaaaaa";
    let secret_key = b"YELLOW SUBMARINE";
    let iv = [0u8; 16];
    let ciphertext = AES::encode(plaintext, secret_key, AESMode::CBC(iv)).unwrap();
    assert_eq!(
      HexString::try_from(ciphertext).unwrap(),
      HexString::try_from("B4AA1A676828A22B6D8326EC96C526194885CB8A2625DE254C4089C2961257F4")
        .unwrap()
    )
  }

  #[test]
  fn test_aes_128_cbc_decode() {
    let ciphertext =
      HexString::try_from("B4AA1A676828A22B6D8326EC96C526194885CB8A2625DE254C4089C2961257F4")
        .unwrap()
        .as_vector_of_bytes();
    let secret_key = b"YELLOW SUBMARINE";
    let iv = [0u8; 16];
    let plaintext = AES::decode(&ciphertext, secret_key, AESMode::CBC(iv)).unwrap();
    assert_eq!(
      HexString::try_from(plaintext).unwrap(),
      HexString::try_from("416775616E746520426F636161616161416775616E746520426F636161616161")
        .unwrap()
    )
  }

  #[test]
  fn test_aes_128_ctr_encode() {
    let plaintext = b"BOCA YO TE AMO YO TE SIGO A TODOS LADOS DE CORAZON";
    let key = b"YELLOW SUBMARINE";
    let ciphertext = AES::encode(plaintext, key, AESMode::CTR(0)).unwrap();
    assert_eq!(
      HexString::try_from(ciphertext).unwrap(),
      HexString::try_from("349e880a8ffb09c2b7ea231c215ce32b9dcc3899b83e5b9980fa5eb3fba137577e80c28a5534646b879f9765fdaec5978ece").unwrap()
    );
  }

  #[test]
  fn test_aes_128_ctr_decode() {
    let ciphertext = HexString::try_from("349e880a8ffb09c2b7ea231c215ce32b9dcc3899b83e5b9980fa5eb3fba137577e80c28a5534646b879f9765fdaec5978ece").unwrap().as_vector_of_bytes();
    let key = b"YELLOW SUBMARINE";
    let plaintext = AES::decode(&ciphertext, key, AESMode::CTR(0)).unwrap();
    assert_eq!(
      plaintext.as_slice(),
      b"BOCA YO TE AMO YO TE SIGO A TODOS LADOS DE CORAZON"
    );
  }
}
