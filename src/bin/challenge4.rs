use std::fs::File;
use std::io::{BufRead, BufReader};

use cryptopals::utils::conversion::conversion::ConversionError;
use cryptopals::utils::conversion::hex_string::HexString;
use cryptopals::utils::conversion::print::xor_against_all_bytes;

fn main() -> Result<(), ConversionError> {
  const PATH: &str = "./src/data/1-4.txt";
  let file = File::open(PATH).unwrap();

  // BufReader allows to handle the file efficiently
  let reader = BufReader::new(file);

  for line in reader.lines() {
    let line = HexString::try_from(line.unwrap())?;
    //println!("{}", line);
    xor_against_all_bytes(line, 0.4)?;
  }

  Ok(())
}
// FOUND
// 7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f
// 35 Now that the party is jumping
