use cryptopals::utils::{
  aes::{aes::AES, aes_error::AESError, utils::AESMode},
  conversion::{conversion::base64_to_bytes_vector, hex_string::HexString},
};

fn main() -> Result<(), AESError> {
  let base64_ciphertext =
    "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
  let key = b"YELLOW SUBMARINE";
  let nonce: u64 = 0;
  // convert to bytes vector
  let ciphertext = base64_to_bytes_vector(base64_ciphertext).unwrap();
  println!("{}", HexString::try_from(ciphertext.clone()).unwrap());
  let plaintext = AES::decode(&ciphertext, key, AESMode::CTR(nonce))?;
  println!("{}", String::from_utf8_lossy(&plaintext));
  Ok(())
}
