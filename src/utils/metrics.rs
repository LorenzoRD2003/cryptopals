use std::collections::{HashMap, HashSet};

use super::conversion::conversion::ConversionError;

pub fn character_frequency<S: AsRef<str>>(str: S) -> HashMap<char, u32> {
  let mut frequency_map = HashMap::new();
  for c in str.as_ref().chars() {
    frequency_map
      .entry(c)
      .and_modify(|counter| *counter += 1)
      .or_insert(1 as u32);
  }
  frequency_map
}

pub fn common_chars_fraction(map: HashMap<char, u32>, common_chars: &str) -> f64 {
  let common_chars_set: HashSet<char> = common_chars.chars().collect();

  let total_chars: u32 = map.values().sum();
  let common_chars_map: HashMap<char, u32> = map
    .into_iter()
    .filter(|(key, _value)| common_chars_set.contains(key))
    .collect();
  let total_common_chars: u32 = common_chars_map.values().sum();

  total_common_chars as f64 / total_chars as f64
}

pub fn hamming_distance<S: AsRef<[u8]>>(bytes1: S, bytes2: S) -> Result<usize, ConversionError> {
  let (len1, len2) = (bytes1.as_ref().len(), bytes2.as_ref().len());
  if len1 != len2 {
    return Err(ConversionError::SizesDoNotMatch(len1, len2));
  }
  Ok(
    bytes1
      .as_ref()
      .into_iter()
      .zip(bytes2.as_ref().into_iter())
      .map(|(b1, b2)| (b1 ^ b2).count_ones() as usize)
      .sum(),
  )
}

pub fn smallest_feasible_keysizes<S: AsRef<[u8]>>(
  encrypted: S,
  min_threshold: u8,
  max_threshold: u8,
  amount: usize,
) -> Vec<(u8, f64)> {
  let mut result: Vec<(u8, f64)> = vec![];
  for keysize in min_threshold as usize..=max_threshold as usize {
    let repetitions = 10;
    let mut total_normalized_distance: f64 = 0 as f64;
    for i in 0..repetitions {
      let first_block = &encrypted.as_ref()[i * keysize..(i + 1) * keysize];
      let second_block = &encrypted.as_ref()[(i + 1) * keysize..(i + 2) * keysize as usize];
      let normalized_distance =
        (hamming_distance(first_block, second_block).unwrap() as f64) / (keysize as f64);
      total_normalized_distance += normalized_distance;
    }
    result.push((keysize as u8, total_normalized_distance));
  }
  result.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
  result.into_iter().take(amount).collect()
}

pub fn group_bytes_by_position<S: AsRef<[u8]>>(input: S, keysize: usize) -> Vec<Vec<u8>> {
  let bytes = input.as_ref();
  let num_blocks = bytes.len() / keysize;
  let mut grouped: Vec<Vec<u8>> = vec![Vec::new(); keysize];

  for i in 0..=num_blocks {
    let start = i * keysize;
    let end = std::cmp::min(start + keysize, bytes.len());
    let block = &bytes[start..end];

    // Group each byte by its position in the block
    for (position, &byte) in block.iter().enumerate() {
      grouped[position].push(byte);
    }
  }
  grouped
}

pub fn xor_against_all_bytes_and_find_best<S: AsRef<[u8]>>(bytes: S) -> (u8, f64) {
  let mut best_byte: u8 = 0;
  let mut best_fraction: f64 = 0 as f64;
  for byte in 0u8..255 {
    let xored_bytes: Vec<u8> = bytes.as_ref().iter().map(|&a| a ^ byte).collect();
    //dbg!("{}", &xored_bytes);
    let text = String::from_utf8_lossy(&xored_bytes);

    let map = character_frequency(&text);
    let common_chars: &str = "etaoinsrhl";

    let fraction = common_chars_fraction(map, common_chars);
    if fraction >= best_fraction {
      best_byte = byte;
      best_fraction = fraction;
    }
  }
  (best_byte, best_fraction)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::utils::conversion::{
    binary_string::BinaryString,
    hex_string::HexString,
    conversion::{base64_to_bytes_vector, repeating_key_xor},
  };
  use std::fs;

  #[test]
  fn xor_against_byte() {
    assert_eq!(
      HexString::try_from("fc96a45df69f").unwrap(),
      HexString::try_from("12784ab31871")
        .unwrap()
        .xor_against_byte(238) // ee
        .unwrap()
    )
  }

  #[test]
  fn hex_character_frequency() {
    let hex = HexString::try_from("68656C6C6F").unwrap();
    let mut result: HashMap<char, u32> = HashMap::new();
    result.insert('h', 1);
    result.insert('e', 1);
    result.insert('l', 2);
    result.insert('o', 1);
    assert_eq!(result, character_frequency(hex.as_text().unwrap()))
  }

  #[test]
  fn test_common_chars_fraction() {
    let map = character_frequency("BOCA yo te amo");
    let common_chars: &str = "Oo";
    let expected = 3 as f64 / 14 as f64;
    assert_eq!(expected, common_chars_fraction(map, common_chars))
  }

  #[test]
  fn test_repeating_key_xor() {
    let hex = HexString::try_from(
      "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    ).unwrap().as_vector_of_bytes().unwrap();
    assert_eq!(
      hex,
      repeating_key_xor(
        "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",
        "ICE"
      )
    )
  }

  #[test]
  fn test_hamming_distance() {
    assert_eq!(
      37 as usize,
      hamming_distance("this is a test", "wokka wokka!!!").unwrap()
    )
  }

  #[test]
  fn obtain_smallest_normalized_keysizes() {
    let base64_contents = fs::read_to_string("src/data/1-6.txt").expect("Failed to read the file");
    let contents = base64_to_bytes_vector(&base64_contents).expect("Failed to convert from base64");
    let result = smallest_feasible_keysizes(contents, 2, 40, 3);
    assert_eq!(result[0].0, 29);
    assert!(result[0].1 - (800 as f64) / (29 as f64) <= 1e-6);
  }

  #[test]
  fn group_bytes_by_position_test() {
    let str = "Aguante el Club Atletico y Recreativo General San Martin de las Escobas";
    let grouped = group_bytes_by_position(str, 5);
    let correct_answer =
      BinaryString::try_from("010000010111010000100000001000000111010001111001011100100111011001101110001000000100110101101110011011000111001101110011")
      .unwrap()
      .as_vector_of_bytes()
      .unwrap();
    assert_eq!(grouped[0], correct_answer);
  }
}
