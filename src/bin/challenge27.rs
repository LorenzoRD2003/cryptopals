use cryptopals::utils::aes::{
  aes::AES,
  aes_error::AESError,
  constants::AES_BLOCK_SIZE,
  utils::{pkcs_padding, AESMode},
};
use rand::{thread_rng, Rng};

struct AttackerAPI {
  key: [u8; 16], // in this exercise, the IV will be equal to the key
}

impl AttackerAPI {
  fn create(key: &[u8; 16]) -> Self {
    Self { key: key.clone() }
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
    AES::encode(&padded_plaintext, &self.key, AESMode::CBC(self.key))
  }

  fn decrypt_and_check_ascii<S: AsRef<[u8]>>(&self, ciphertext: &S) -> Result<Vec<u8>, AESError> {
    let plaintext = AES::decode(ciphertext, &self.key, AESMode::CBC(self.key))?;
    if plaintext.iter().any(|&byte| byte > b'z') {
      //return Err(AESError::AsciiError(plaintext));
      // We assume we get the error and we as humans read it
      return Ok(plaintext);
    }
    Ok(vec![])
  }
}

fn recover_key(api: &AttackerAPI) -> Result<[u8; 16], AESError> {
  let plaintext = b"abcdefghijk";
  let ciphertext = api.modify_and_encrypt_string(plaintext)?;
  let c1 = ciphertext[..16].to_vec();
  let modified_ciphertext = [c1.clone(), vec![0; 16], c1.clone()].concat();
  let new_plaintext = api.decrypt_and_check_ascii(&modified_ciphertext)?;
  /*
    Assuming IV = k:
    D(k, c1 0 c1) =
      D(k, c1) xor k = p1
      D(k, 0) xor c1
      D(k, c1) xor 0 = D(k, c1) = p3
    In particular, p1 xor p3 = k
  */
  let (p1, p3) = (new_plaintext[..16].to_vec(), new_plaintext[32..48].to_vec());
  let k: Vec<u8> = (0..16).map(|i| p1[i] ^ p3[i]).collect();
  Ok(k.try_into().unwrap())
}

fn main() -> Result<(), AESError> {
  let random_key: [u8; 16] = thread_rng().gen();
  let api = AttackerAPI::create(&random_key);
  let obtained_key = recover_key(&api)?;
  assert_eq!(random_key, obtained_key);
  Ok(())
}
