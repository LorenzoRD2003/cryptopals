use cryptopals::utils::{
  aes::{aes::AES, aes_error::AESError, utils::AESMode},
  conversion::conversion::base64_to_bytes_vector,
};

fn main() -> Result<(), AESError> {
  let key = b"YELLOW SUBMARINE";
  let base64_str = std::fs::read_to_string("src/data/1-7.txt").expect("Could not find file");
  let ciphertext = base64_to_bytes_vector(&base64_str).expect("Failed to convert from base64");
  let plaintext = AES::decode(&ciphertext, key, AESMode::ECB)?;
  match String::from_utf8(plaintext) {
    Ok(ascii_str) => {
      println!("Plaintext:\n{}", ascii_str);
    }
    Err(e) => {
      println!("Error converting to ASCII. {}", e);
    }
  }
  Ok(())
}
