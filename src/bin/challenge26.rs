use cryptopals::utils::{aes::{
  aes::AES,
  aes_error::AESError,
  constants::sizes::AES_BLOCK_SIZE,
  utils::{pkcs_padding, AESMode},
}, conversion::hex_string::HexString};
use rand::{thread_rng, Rng};

struct Oracle {
  key: [u8; AES_BLOCK_SIZE],
  nonce: u64,
}

impl Default for Oracle {
  fn default() -> Self {
    let mut rng: rand::prelude::ThreadRng = thread_rng();
    Self {
      key: rng.gen(),
      nonce: rng.gen()
    }
  }
}

impl Oracle {
  pub fn sanitize_and_encrypt<S: AsRef<[u8]>>(&self, input: &S) -> Result<Vec<u8>, AESError> {
    let sanitized_input = Self::sanitize_input(input);
    let plaintext = Self::prepare_plaintext(&sanitized_input);
    AES::encode(&plaintext, &self.key, AESMode::CTR(self.nonce))
  }

  fn sanitize_input<S: AsRef<[u8]>>(input: &S) -> Vec<u8> {
    input
      .as_ref()
      .iter()
      .filter(|&&c| c != b';' && c != b'=')
      .copied()
      .collect()
  }

  fn prepare_plaintext<S: AsRef<[u8]>>(input: &S) -> Vec<u8> {
    let plaintext = [
      b"comment1=cooking%20MCs;userdata=".to_vec(),
      input.as_ref().to_vec(),
      b";comment2=%20like%20a%20pound%20of%20bacon".to_vec(),
    ]
    .concat();
    pkcs_padding(&plaintext, AES_BLOCK_SIZE as u8)
  }

  pub fn decrypt_and_look_for_admin_true<S: AsRef<[u8]>>(
    &self,
    ciphertext: &S,
  ) -> Result<bool, AESError> {
    let plaintext_bytes = AES::decode(ciphertext, &self.key, AESMode::CTR(self.nonce))?;
    let target: &[u8; 12] = b";admin=true;";
    let result = plaintext_bytes
      .windows(target.len())
      .any(|window| window == target);
    Ok(result)
  }
}

fn main() -> Result<(), AESError> {
  let oracle = Oracle::default();

  // We have to inject a bit-flipping Chosen-Ciphertext-Attack (CCA) like in Challenge 16
  let malicious_input: &[u8; AES_BLOCK_SIZE] = b"abcde9admin9true";
  let mut malicious_ciphertext = oracle.sanitize_and_encrypt(malicious_input)?;
  let offset = "comment1=cooking%20MCs;userdata=".len();
  malicious_ciphertext[offset + 5] ^= b'9' ^ b';'; // Now we have to modify the third block
  malicious_ciphertext[offset + 11] ^= b'9' ^ b'=';
  let is_admin = oracle.decrypt_and_look_for_admin_true(&malicious_ciphertext)?;
  println!("Ciphertext: {}", HexString::from(malicious_ciphertext));
  println!("Is admin: {}", is_admin);

  Ok(())
}
