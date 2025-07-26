use cryptopals::utils::aes::aes::AES;
use cryptopals::utils::aes::aes_error::AESError;
use cryptopals::utils::conversion::hex_string::HexString;
use std::collections::HashMap;
use std::{
  fs::File,
  io::{BufRead, BufReader},
};

fn main() -> Result<(), AESError> {
  const PATH: &str = "./src/data/1-8.txt";
  let file = File::open(PATH).unwrap();
  let reader = BufReader::new(file);

  let mut least_different_blocks: usize = 1e7 as usize;
  let mut best_ciphertext: Vec<u8> = vec![];
  let mut line_number: usize = 0;

  for (i, line) in reader.lines().enumerate() {
    let ciphertext = HexString::try_from(line.unwrap())
      .unwrap()
      .as_vector_of_bytes();

    let blocks = AES::divide_in_blocks(&ciphertext)?;
    let mut frequency_map = HashMap::new();

    for item in blocks {
      *frequency_map.entry(item).or_insert(0) += 1;
    }

    if frequency_map.len() < least_different_blocks {
      best_ciphertext = ciphertext;
      least_different_blocks = frequency_map.len();
      line_number = i + 1;
    }
  }
  println!(
    "Ciphertext encoded with AES:\n{} \nLine number: {}\nDifferent blocks: {}",
    HexString::try_from(best_ciphertext).unwrap(),
    line_number,
    least_different_blocks
  );
  Ok(())
}
