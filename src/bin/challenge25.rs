use cryptopals::utils::{
  aes::{aes::AES, aes_error::AESError, utils::AESMode},
  conversion::conversion::base64_to_bytes_vector,
};
use rand::{thread_rng, Rng};

fn edit<S: AsRef<[u8]>>(
  ciphertext: &S,
  key: &[u8; 16],
  offset: usize,
  newtext: u8,
  nonce: u64,
) -> Result<Vec<u8>, AESError> {
  assert!(ciphertext.as_ref().len() > offset);
  let mut plaintext = AES::decode(ciphertext, key, AESMode::CTR(nonce))?;
  plaintext[offset] = newtext;
  let new_ciphertext = AES::encode(&plaintext, key, AESMode::CTR(nonce))?;
  Ok(new_ciphertext)
}

struct ExposedAPI {
  key: [u8; 16],
  nonce: u64,
}

impl ExposedAPI {
  fn create(key: &[u8; 16], nonce: u64) -> Self {
    Self {
      key: key.clone(),
      nonce,
    }
  }

  fn api_edit<S: AsRef<[u8]>>(
    &self,
    ciphertext: &S,
    offset: usize,
    newtext: u8,
  ) -> Result<Vec<u8>, AESError> {
    edit(ciphertext, &self.key, offset, newtext, self.nonce)
  }
}

/*
  C'1 = c'1..cn = (p'1 xor a1)(p2 xor a2)..(pn xor an)
  We choose p'1
  p'1 xor a1 = c'1
  p'1 xor c'1 = a1
  Then p1 = c1 xor a1
*/
fn recover_original_plaintext<S: AsRef<[u8]>>(ciphertext: &S, api: &ExposedAPI) -> Result<Vec<u8>, AESError> {
  let len = ciphertext.as_ref().len();
  let b: u8 = 0x01;
  let mut plaintext = vec![];
  for i in 0..len {
    let new_byte = api.api_edit(ciphertext, i, b)?[i];
    let a = 0x01 ^ new_byte;
    plaintext.push(ciphertext.as_ref()[i] ^ a);
  }
  Ok(plaintext)
}
fn main() -> Result<(), AESError> {
  let base64_str = std::fs::read_to_string("src/data/1-7.txt").expect("Could not find file");
  let ciphertext = base64_to_bytes_vector(&base64_str).expect("Failed to convert from base64");
  let plaintext = AES::decode(&ciphertext, b"YELLOW SUBMARINE", AESMode::ECB)?;
  let random_key: [u8; 16] = thread_rng().gen();
  let random_nonce: u64 = thread_rng().gen();
  let ctr_ciphertext = AES::encode(&plaintext, &random_key, AESMode::CTR(random_nonce))?;
  let api = ExposedAPI::create(&random_key, random_nonce);
  let recovered = recover_original_plaintext(&ctr_ciphertext, &api)?;
  println!("{}", String::from_utf8(recovered).unwrap());
  Ok(())
}
