use cryptopals::utils::aes::aes::AES;
use cryptopals::utils::aes::aes_block::AESBlock;
use cryptopals::utils::aes::aes_error::AESError;
use cryptopals::utils::aes::constants::sizes::AES_BLOCK_SIZE;
use cryptopals::utils::aes::utils::AESMode;
use cryptopals::utils::conversion::conversion::base64_to_bytes_vector;
use cryptopals::utils::conversion::hex_string::HexString;
use rand::thread_rng;
use rand::Rng;

const UNKNOWN_STRING: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

fn ecb_encryption(plaintext: &Vec<u8>, key: &[u8; 16], pre_bytes: &Vec<u8>) -> Vec<u8> {
  let mut text = pre_bytes.clone();
  text.extend(plaintext);
  text.extend(base64_to_bytes_vector(UNKNOWN_STRING).unwrap());
  //dbg!(HexString::try_from(text.clone()).unwrap());
  AES::encode(&text, key, AESMode::ECB).unwrap()
}

fn get_pre_len(
  true_pre_bytes: &Vec<u8>,
  random_key: &[u8; 16],
) -> Result<(usize, usize, usize), AESError> {
  let controlled_input = ['a' as u8; 64];
  let ciphertext_blocks = AESBlock::from_bytes(ecb_encryption(
    &controlled_input.to_vec(),
    &random_key,
    &true_pre_bytes,
  ))?;
  let last_block_index_without_all_a = (0..ciphertext_blocks.len() - 2)
    .find(|&i| ciphertext_blocks[i + 1] == ciphertext_blocks[i + 2])
    .expect("No valid index found");
  let encrypted_with_all_a = ciphertext_blocks[last_block_index_without_all_a + 1];

  let mut ciphertexts: Vec<Vec<AESBlock>> = vec![];
  for i in 0..32 {
    ciphertexts.push(AESBlock::from_bytes(ecb_encryption(
      &controlled_input[0..i].to_vec(),
      &random_key,
      &true_pre_bytes,
    ))?);
  }
  let j = (16..32)
    .find(|&i| ciphertexts[i].contains(&encrypted_with_all_a))
    .expect("No valid index found");
  let remainder = if j == 16 { 16 } else { 32 - j };
  Ok((last_block_index_without_all_a, remainder, j))
}

fn main() -> Result<(), AESError> {
  let random_key: [u8; 16] = thread_rng().gen();
  let pre_len: usize = thread_rng().gen_range(1..=20);
  let pre_bytes: Vec<u8> = (0..pre_len).map(|_| thread_rng().gen()).collect();

  // First obtain the length of the random prefix
  let (quotient, remainder, j) = get_pre_len(&pre_bytes, &random_key)?;
  assert_eq!(pre_len, 16 * quotient + remainder);

  let mut without_last_bytes: Vec<u8> = vec![];
  let mut possibilities: Vec<u8> = vec![];
  let mut last_result: u8 = 0;
  let mut block_number = quotient + 1;
  let mut final_string: Vec<u8> = vec![];

  for i in j - 1..17 {
    if i == j - 1 {
      without_last_bytes = vec!['a' as u8; j - 1];
      possibilities = vec!['a' as u8; j - 1];
    } else {
      possibilities.remove(0);
      possibilities.push(last_result);
      if i % 16 == (j - 1) % 16 {
        block_number += 1;
        without_last_bytes = vec!['a' as u8; j - 1];
      } else {
        without_last_bytes.remove(0);
      }
    };
    let true_ciphered_block: [u8; 16] =
      ecb_encryption(&without_last_bytes, &random_key, &pre_bytes)
        [AES_BLOCK_SIZE * block_number..AES_BLOCK_SIZE * (block_number + 1)]
        .try_into()
        .unwrap();
    for k in 0..=255 {
      let plaintext_key = [possibilities.clone(), vec![k]].concat();
      let ciphered_block: [u8; 16] = ecb_encryption(&plaintext_key, &random_key, &pre_bytes)
        [AES_BLOCK_SIZE..2 * AES_BLOCK_SIZE]
        .try_into()
        .unwrap();
      if ciphered_block == true_ciphered_block {
        last_result = plaintext_key[plaintext_key.len() - 1];
        final_string.push(last_result);
        println!(
          "The {}th byte of the unknown string is {}",
          i, last_result as char
        );
        break;
      }
    }
    /*dbg!(
      HexString::try_from(possible_keys.clone()).unwrap(),
      HexString::try_from(true_ciphered_block.to_vec()).unwrap()
    );*/
  }
  println!(
    "{}",
    HexString::try_from(final_string)
      .unwrap()
      .as_text()
      .unwrap()
  );

  Ok(())
}
