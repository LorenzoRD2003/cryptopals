#[cfg(test)]
mod tests {
  use cryptopals::utils::{
    aes::{aes::AES, aes_block::AESBlock, constants::*, utils::AESMode},
    conversion::hex_string::HexString,
  };

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
      plaintext_blocks[0].as_flatten_array(),
      b"Two One Nine Two".clone(),
    );
    assert_eq!(
      plaintext_blocks[1].as_flatten_array(),
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

    let keys = aes.compute_all_round_keys();
    let hexs = keys.map(|k| k.as_hex_string());
    assert_eq!(
      hexs,
      [
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
    let aes = AES::create_from(key, AESMode::ECB).unwrap();
    let mut first_block = AES::divide_in_blocks(&plaintext).unwrap()[0];
    let ciphertext = first_block.add_round_key(&aes.key);
    assert_eq!(
      ciphertext.as_hex_string(),
      HexString::try_from("001f0e543c4e08596e221b0b4774311a").unwrap()
    )
  }

  #[test]
  fn test_aes_128_one_round() {
    let plaintext = b"Two One Nine Two";
    let initial_key = b"Thats my Kung Fu";
    let aes = AES::create_from(initial_key, AESMode::ECB).unwrap();
    let keys = aes.compute_all_round_keys();
    let mut first_block = AES::divide_in_blocks(&plaintext).unwrap()[0];
    first_block.add_round_key(&aes.key);

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

    let result = mixed_columns.add_round_key(&keys[0]);
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
    let mut keys = aes.compute_all_round_keys().to_vec();
    keys.reverse();
    keys.push(aes.key);
    keys.pop();

    let mut cipherblock = AESBlock::from_flat_array(
      &HexString::try_from("5847088b15b61cba59d4e2e8cd39dfce")
        .unwrap()
        .as_vector_of_bytes()
        .unwrap()
        .try_into()
        .unwrap(),
    );

    cipherblock.add_round_key(&keys[AES128_ROUNDS - 1]);
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
        .as_vector_of_bytes()
        .unwrap();
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
        .as_vector_of_bytes()
        .unwrap();
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
    let ciphertext = HexString::try_from("349e880a8ffb09c2b7ea231c215ce32b9dcc3899b83e5b9980fa5eb3fba137577e80c28a5534646b879f9765fdaec5978ece").unwrap().as_vector_of_bytes().unwrap();
    let key = b"YELLOW SUBMARINE";
    let plaintext = AES::decode(&ciphertext, key, AESMode::CTR(0)).unwrap();
    assert_eq!(
      plaintext.as_slice(),
      b"BOCA YO TE AMO YO TE SIGO A TODOS LADOS DE CORAZON"
    );
  }
}
