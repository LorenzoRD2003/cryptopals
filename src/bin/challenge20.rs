use std::{
  fs::File,
  io::{BufRead, BufReader},
};

use cryptopals::utils::{
  aes::{aes::AES, aes_error::AESError, constants::AES128_KEY_SIZE, utils::AESMode},
  conversion::{conversion::{base64_to_bytes_vector, repeating_key_xor}, hex_string::HexString}, metrics::{group_bytes_by_position, xor_against_all_bytes_and_find_best},
};
use rand::{thread_rng, Rng};

fn main() -> Result<(), AESError> {
  let random_key: [u8; AES128_KEY_SIZE] = thread_rng().gen();
  const PATH: &str = "./src/data/3-20.txt";
  let file = File::open(PATH).unwrap();
  let reader = BufReader::new(file);

  let mut ciphertexts: Vec<Vec<u8>> = reader
    .lines()
    .map(|l| {
      let plaintext = base64_to_bytes_vector(l.unwrap()).unwrap();
      AES::encode(&plaintext, &random_key, AESMode::CTR(0u64)).unwrap()
    })
    .collect();

  // Truncate all ciphertexts to the minimum length between them, then concatenate in a single ciphertext
  let min_len = ciphertexts.iter().map(|c| c.len()).min().unwrap_or(0);
  ciphertexts.iter_mut().for_each(|c| c.truncate(min_len));
  let conc_ciphertext = ciphertexts.concat();

  // Use repeating-key-xor from previous challenges
  let grouped = group_bytes_by_position(&conc_ciphertext, min_len);
  let mut final_key: Vec<u8> = vec![];

  for vec in grouped {
    let (best_byte, _) = xor_against_all_bytes_and_find_best(vec);
    final_key.push(best_byte);
  }
  let bytes_result = repeating_key_xor(&conc_ciphertext, &final_key);
  println!(
    "Final key: {}, \n Result: {} ",
    HexString::try_from(final_key).unwrap(),
    String::from_utf8_lossy(&bytes_result)
  );

  Ok(())
}
