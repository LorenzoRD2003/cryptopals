use cryptopals::utils::{
  aes::{aes::AES, aes_error::AESError, utils::AESMode},
  conversion::conversion::base64_to_bytes_vector,
};
use rand::{thread_rng, Rng};

struct ExposedAPI {
  key: [u8; 16],
  nonce: u64,
  never_encoded: bool
}

impl ExposedAPI {
  fn create() -> Self {
    let mut rng = thread_rng();
    Self {
      key: rng.gen(),
      nonce: rng.gen(),
      never_encoded: true
    }
  }

  fn encode_first_time<S: AsRef<[u8]>>(&mut self, plaintext: &S) -> Result<Vec<u8>, AESError> {
    if self.never_encoded {
      self.never_encoded = false;
      AES::encode(plaintext, &self.key, AESMode::CTR(self.nonce))
    } else {
      Err(AESError::UnexpectedError("You can only use this API to encode a plaintext once.".into()))
    }
  }

  fn edit_ciphertext_byte<S: AsRef<[u8]>>(
    &self,
    ciphertext: &S,
    offset: usize,
    newtext: u8,
  ) -> Result<Vec<u8>, AESError> {
    if offset >= ciphertext.as_ref().len() {
      return Err(AESError::UnexpectedError("Offset out of bounds".into()));
    }
    let mut plaintext = AES::decode(ciphertext, &self.key, AESMode::CTR(self.nonce))?;
    plaintext[offset] = newtext;
    let new_ciphertext = AES::encode(&plaintext, &self.key, AESMode::CTR(self.nonce))?;
    Ok(new_ciphertext)
  }
}

/*
  Remember how CTR mode works: XORing byte p_i with a_i = E(N, k_i) 
  Suppose we have the ciphertext C = c1..cn = (p1 ^ a1)..(pn ^ an)

  We do the following for each byte 1 <= i <= n to obtain pi (example for i = 1). We DO NOT KNOW pi
  C'1 := c'1..cn = (b ^ a1)(p2 ^ a2)..(pn ^ an) for any chosen byte b passed in the edit function
  In particular: b ^ c'1 = a1
  And we can obtain p1 as p1 = c1 ^ a1 = c1 ^ (b ^ c'1)
*/
fn recover_original_plaintext<S: AsRef<[u8]>>(
  ciphertext: &S,
  api: &ExposedAPI,
) -> Result<Vec<u8>, AESError> {
  let len = ciphertext.as_ref().len();
  let b: u8 = 0x01;
  let mut plaintext = Vec::with_capacity(len);
  for i in 0..len {
    let c_ = api.edit_ciphertext_byte(ciphertext, i, b)?[i];
    let a = b ^ c_; // ai = b ^ c'i
    plaintext.push(ciphertext.as_ref()[i] ^ a); // pi = ci ^ ai
  }
  Ok(plaintext)
}
fn main() -> Result<(), AESError> {
  let base64_str = std::fs::read_to_string("src/data/1-7.txt").expect("Could not find file");
  let ciphertext = base64_to_bytes_vector(&base64_str).expect("Failed to convert from base64");
  let plaintext = AES::decode(&ciphertext, b"YELLOW SUBMARINE", AESMode::ECB)?;

  let mut api = ExposedAPI::create();
  let ctr_ciphertext = api.encode_first_time(&plaintext)?;
  let recovered = recover_original_plaintext(&ctr_ciphertext, &api)?;
  println!("{}", String::from_utf8(recovered).unwrap());
  Ok(())
}
