use crate::utils::metrics::{character_frequency, common_chars_fraction};

use super::{conversion::ConversionError, hex_string::HexString};

pub fn xor_against_all_bytes(hex: HexString, fraction_threshold: f64) -> Result<(), ConversionError> {
  for byte in 0u8..255 {
    let text = hex
      .xor_against_byte(byte)
      .as_text()
      .unwrap_or_else(|_| String::from("\n"));

    let map = character_frequency(text);
    let common_chars: &str = "ETAOINSRHLetaoinsrhl";

    if common_chars_fraction(map, common_chars) >= fraction_threshold {
      println!(
        "{:} {:}",
        HexString::from(vec![byte]),
        hex.xor_against_byte(byte).as_text()?
      )
    }
  }
  Ok(())
}
