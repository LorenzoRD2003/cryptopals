use cryptopals::utils::{
  conversion::conversion::{base64_to_bytes_vector, repeating_key_xor, ConversionError},
  metrics::{
    group_bytes_by_position, smallest_feasible_keysizes, xor_against_all_bytes_and_find_best,
  },
};
use std::fs;

fn main() -> Result<(), ConversionError> {
  let base64_contents: String = fs::read_to_string("src/data/1-6.txt")
    .expect("Failed to read the file")
    .chars()
    .filter(|&c| !c.is_whitespace())
    .collect();
  let contents = base64_to_bytes_vector(&base64_contents).expect("Failed to convert from base64");

  let (min_keysize, max_keysize, keysizes_amount) = (2, 40, 1);
  let feasible_keysizes =
    smallest_feasible_keysizes(&contents, min_keysize, max_keysize, keysizes_amount);

  for (keysize, distance) in feasible_keysizes {
    println!("Keysize: {}, Distance: {}", keysize, distance);
    let grouped = group_bytes_by_position(&contents, keysize as usize);
    let mut final_key: Vec<u8> = vec![];

    for vec in grouped {
      let (best_byte, _) = xor_against_all_bytes_and_find_best(vec);
      final_key.push(best_byte);
    }
    //dbg!(&final_key, &final_key.len());
    let bytes_result = repeating_key_xor(&contents, &final_key);
    let result = String::from_utf8_lossy(&bytes_result);
    println!(
      "Final key: {}, \n {} ",
      String::from_utf8(final_key).unwrap(),
      result
    );
  }
  Ok(())
}
