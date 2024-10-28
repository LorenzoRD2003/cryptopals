use cryptopals::utils::conversion::conversion::ConversionError;
use cryptopals::utils::conversion::hex_string::HexString;
use cryptopals::utils::conversion::print::xor_against_all_bytes;

fn main() -> Result<(), ConversionError> {
  let hex =
    HexString::try_from("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")?;
  xor_against_all_bytes(hex, 0.4)?;
  Ok(())
}
// SOLUTION: 58 in hex, 88 in decimal, original text is Cooking MC's like a pound of bacon
