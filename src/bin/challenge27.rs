use cryptopals::utils::{
  aes::{
    aes::AES,
    aes_error::AESError,
    constants::sizes::AES_BLOCK_SIZE,
    utils::{pkcs_padding, AESMode},
  },
  conversion::hex_string::HexString,
};
use rand::{thread_rng, Rng};

struct Oracle {
  key: [u8; AES_BLOCK_SIZE], // in this exercise, the IV will be equal to the key
}

impl Default for Oracle {
  fn default() -> Self {
    Self {
      key: thread_rng().gen(),
    }
  }
}

impl Oracle {
  pub fn sanitize_and_encrypt<S: AsRef<[u8]>>(&self, input: &S) -> Result<Vec<u8>, AESError> {
    let sanitized_input = Self::sanitize_input(input);
    let plaintext = Self::prepare_plaintext(&sanitized_input);
    AES::encode(&plaintext, &self.key, AESMode::CBC(self.key))
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

  fn decrypt_and_check_ascii<S: AsRef<[u8]>>(&self, ciphertext: &S) -> Result<Vec<u8>, AESError> {
    let plaintext = AES::decode(ciphertext, &self.key, AESMode::CBC(self.key))?;
    if plaintext.iter().any(|&byte| byte < 0x20 || byte > 0x7E) { // if ASCII is not printable
      //return Err(AESError::AsciiError(plaintext));
      return Ok(plaintext); // We assume we get the error and we as humans read it
    }
    Ok(vec![])
  }
}

fn recover_key(oracle: &Oracle) -> Result<[u8; AES_BLOCK_SIZE], AESError> {
  let plaintext = b"abcdefghijk";
  let ciphertext = oracle.sanitize_and_encrypt(plaintext)?;
  let c1 = &ciphertext[..AES_BLOCK_SIZE];
  let mut modified_ciphertext = Vec::with_capacity(3 * AES_BLOCK_SIZE);
  modified_ciphertext.extend_from_slice(c1);
  modified_ciphertext.extend_from_slice(&[0u8; AES_BLOCK_SIZE]);
  modified_ciphertext.extend_from_slice(c1);
  let new_plaintext = oracle.decrypt_and_check_ascii(&modified_ciphertext)?;
  /*
    Assuming IV = k:
    D(k, c1 0 c1) =
      D(k, c1) xor k = p1
      D(k, 0) xor c1 = p2
      D(k, c1) xor 0 = D(k, c1) = p3
    In particular, p1 xor p3 = k
  */
  let (p1, p3) = (new_plaintext[..AES_BLOCK_SIZE].to_vec(), new_plaintext[32..48].to_vec());
  let mut key: [u8; AES_BLOCK_SIZE] = [0u8; AES_BLOCK_SIZE];
  for i in 0..AES_BLOCK_SIZE {
    key[i] = p1[i] ^ p3[i];
  }
  Ok(key)
}

fn main() -> Result<(), AESError> {
  let oracle = Oracle::default();
  let obtained_key = recover_key(&oracle)?;
  assert_eq!(oracle.key, obtained_key);
  println!(
    "Successfully recovered the key: {}",
    HexString::from(obtained_key.to_vec())
  );
  Ok(())
}
