use cryptopals::utils::aes::constants::sizes::AES_BLOCK_SIZE;
use cryptopals::utils::aes::utils::AESMode;
use cryptopals::utils::conversion::conversion::base64_to_bytes_vector;
use cryptopals::utils::conversion::hex_string::HexString;
use rand::thread_rng;
use rand::Rng;

use cryptopals::utils::aes::aes::AES;

const UNKNOWN_STRING: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

fn ecb_encryption(plaintext: &Vec<u8>, key: &[u8; 16]) -> Vec<u8> {
  let mut text = plaintext.clone();
  text.extend(base64_to_bytes_vector(UNKNOWN_STRING).unwrap());
  AES::encode(&text, key, AESMode::ECB).unwrap()
}

fn main() {
  let random_key: [u8; 16] = thread_rng().gen();

  // Discover block-size of the cipher (it is 16 bytes)
  // Detect that the function is doing ECB
  /*let text = ['a' as u8; 48];
  for i in 0..48 {
    let ciphertext = ecb_encryption(&text[0..=i].to_vec(), &random_key);
    println!(
      "Ciphertext length for {i} bytes plus the unknown string: {}, it is {}",
      ciphertext.len(),
      HexString::try_from(ciphertext).unwrap()
    );
  }*/
  // The ciphertext length changes at 6 bytes and at 22 bytes. So 22 - 6 = 16 is the block length
  // It is using ECB because the first two blocks are equal when the known string is bigger than or equal to two blocks

  let mut without_last_bytes: Vec<u8> = vec![];
  let mut possibilities: Vec<u8> = vec![];
  let mut last_result: u8 = 0;
  let mut block_number = 0;
  let mut final_string: Vec<u8> = vec![];
  for i in 0..144 {
    if i == 0 {
      without_last_bytes = ['a' as u8; 15].to_vec();
      possibilities = ['a' as u8; 15].to_vec();
    } else {
      if i % 16 == 0 {
        block_number += 1;
        without_last_bytes = ['a' as u8; 15].to_vec();
      } else {
        without_last_bytes.remove(0);
      }
      possibilities.remove(0);
      possibilities.push(last_result);
    };
    // In the last byte position, the oracle function is going to put the first byte of the unknown string.
    let true_ciphered_block: [u8; 16] = ecb_encryption(&without_last_bytes, &random_key)
      [AES_BLOCK_SIZE * block_number..AES_BLOCK_SIZE * (block_number + 1)]
      .try_into()
      .unwrap();
    for j in 0..=255 {
      let plaintext_key = [possibilities.clone(), vec![j]].concat();
      let ciphered_block: [u8; 16] = ecb_encryption(&plaintext_key, &random_key)[0..AES_BLOCK_SIZE]
        .try_into()
        .unwrap();
      if ciphered_block == true_ciphered_block {
        last_result = plaintext_key[15];
        final_string.push(last_result);
        println!(
          "The {}th byte of the unknown string is {}",
          i, last_result as char
        );
        break;
      }
    }
  }
  println!(
    "{}",
    HexString::try_from(final_string)
      .unwrap()
      .as_text()
      .unwrap()
  )
}
