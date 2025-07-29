use cryptopals::utils::{
  algebra::modulo::{inv_mod, mod_exp},
  mac::sha1::{Sha1, Sha1Digest},
  padding::pkcs1_unpad,
  rsa::{RSAKeys, RSA},
};
use num_bigint::{BigUint, RandBigInt};
use rand::{rngs::ThreadRng, thread_rng, Rng};
use std::collections::HashSet;

struct Server {
  rng: ThreadRng,
  pub keys: RSAKeys,
  hashed_messages: HashSet<Sha1Digest>,
}

impl Server {
  const E: u64 = 65537;
  pub fn start() -> Self {
    Self {
      rng: thread_rng(),
      keys: RSA::generate_keys_with_given_params(&BigUint::from(Self::E), 128),
      hashed_messages: HashSet::new(),
    }
  }

  pub fn encrypt_with_timestamp<S: AsRef<[u8]>>(&mut self, message: &S) -> Vec<u8> {
    let time: u32 = self.rng.gen();
    let string_time = time.to_string();
    let mut message_with_timestamp = message.as_ref().to_vec();
    message_with_timestamp.extend_from_slice(b"\n{\n  time: ");
    message_with_timestamp.extend_from_slice(string_time.as_ref());
    message_with_timestamp.extend_from_slice(b",\n  social: '555-55-5555',\n}");
    RSA::encrypt_with_key(&self.keys.pk, &message_with_timestamp)
  }

  pub fn decrypt_ciphertext<S: AsRef<[u8]>>(&mut self, ciphertext: &S) -> Result<Vec<u8>, String> {
    let hash = Sha1::hash(ciphertext);
    if self.hashed_messages.contains(&hash) {
      return Err("Message already decrypted.".to_string());
    }
    self.hashed_messages.insert(hash);
    Ok(RSA::decrypt_with_key(&self.keys.sk, ciphertext))
  }

  pub fn retrieve_pk(&self) -> (BigUint, BigUint) {
    self.keys.pk.clone()
  }
}

/// This function applies a transformation for each chunk of a byte array when thought as a BigUint
fn process_as_chunks<S: AsRef<[u8]>, F: Fn(&BigUint) -> BigUint>(
  input: &S,
  chunk_size: usize,
  transform: F,
  unpad: bool,
) -> Vec<u8> {
  let mut output = vec![];
  for chunk in input.as_ref().chunks(chunk_size) {
    let n = BigUint::from_bytes_be(chunk);
    let transformed = transform(&n).to_bytes_be();

    let mut extended = vec![0u8; chunk_size]; // Pad with zeros to match chunk size
    extended[chunk_size - transformed.len()..].copy_from_slice(&transformed);

    if unpad { // we should use unpad = true for decryption of rsa
      let unpadded = pkcs1_unpad(&extended); // safe unpadding
      output.extend(unpadded);
    } else {
      output.extend(extended);
    }
  }
  output
}

fn main() {
  let mut server = Server::start();
  let message = b"SENIORES SOY DE BOCA Y LO SIGO A TODOS LADOS".to_vec();
  let ciphertext = server.encrypt_with_timestamp(&message);
  let (e, n) = server.retrieve_pk();

  let expected_message = server.decrypt_ciphertext(&ciphertext).unwrap();
  println!("{}", String::from_utf8_lossy(&expected_message));
  let expected_error = server.decrypt_ciphertext(&ciphertext).unwrap_err();
  println!("{}", expected_error);

  /*
    S > 1 random number
    C' = (S^E * C) mod N
    Decrypt C' → P' = C'^D mod N (we dont know D but server decrypts)
    P' = (S^E * C)^D = S^(ED) * C^D = S * P (mod N)
    → P = P' * S^-1 (mod N)
  */
  // Generate random blinding factor `s` such that 1 < s < n
  let s = thread_rng().gen_biguint_range(&BigUint::from(2u8), &n);
  let m = mod_exp(&s, &e, &n);
  let inv_s = inv_mod(&s, &n).unwrap();
  let chunk_size = ((n.bits() + 7) / 8) as usize; // we require n.bits() >= 1024

  // First of all, we have to do this in chunks of size n
  let dif_ciphertext = process_as_chunks(&ciphertext, chunk_size, |c| (&m * c) % &n, false);
  let dif_plaintext = server.decrypt_ciphertext(&dif_ciphertext).unwrap();
  let plaintext = process_as_chunks(&dif_plaintext, chunk_size, |px| (px * &inv_s) % &n, true);
  println!("{}", String::from_utf8_lossy(&plaintext));
}
