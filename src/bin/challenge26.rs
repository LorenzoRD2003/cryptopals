use cryptopals::utils::aes::{
  aes::AES,
  aes_error::AESError,
  constants::AES_BLOCK_SIZE,
  utils::{pkcs_padding, AESMode},
};
use rand::{thread_rng, Rng};

struct AttackerAPI {
  key: [u8; 16],
  nonce: u64,
}

impl AttackerAPI {
  fn create(key: &[u8; 16], nonce: u64) -> Self {
    Self {
      key: key.clone(),
      nonce,
    }
  }

  fn modify_and_encrypt_string<S: AsRef<[u8]>>(&self, input: &S) -> Result<Vec<u8>, AESError> {
    let without_special_chars: Vec<u8> = input
      .as_ref()
      .iter()
      .filter(|&&c| c != b';' && c != b'=')
      .copied()
      .collect();
    let plaintext_bytes = [
      b"comment1=cooking%20MCs;userdata=".to_vec(),
      without_special_chars,
      b";comment2=%20like%20a%20pound%20of%20bacon".to_vec(),
    ]
    .concat();
    let padded_plaintext = pkcs_padding(&plaintext_bytes, AES_BLOCK_SIZE as u8);
    AES::encode(&padded_plaintext, &self.key, AESMode::CTR(self.nonce))
  }

  fn decrypt_and_look_for_admin_true<S: AsRef<[u8]>>(
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
  let random_key: [u8; 16] = thread_rng().gen();
  let random_nonce: u64 = thread_rng().gen();
  let api = AttackerAPI::create(&random_key, random_nonce);
  // We have to inject a bit-flipping CCA like in Challenge 16
  let block: &[u8; 16] = b"abcde9admin9true";
  let mut ciphertext = api.modify_and_encrypt_string(block)?;
  ciphertext[2*AES_BLOCK_SIZE + 5] ^= 0x02; // Now we have to modify the third block
  ciphertext[2*AES_BLOCK_SIZE + 11] ^= 0x04;
  let is_admin = api.decrypt_and_look_for_admin_true(&ciphertext)?;
  assert!(is_admin);

  Ok(())
}
