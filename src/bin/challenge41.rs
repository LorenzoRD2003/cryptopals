use cryptopals::utils::{algebra::{inv_mod, mod_exp}, mac::sha1::{Sha1, Sha1Digest}, rsa::{RSAKeys, RSA}};
use num_bigint::{BigUint, RandBigInt};
use rand::{rngs::ThreadRng, thread_rng, Rng};

struct Server {
  rng: ThreadRng,
  keys: RSAKeys,
  hashed_messages: Vec<Sha1Digest>
}

impl Server {
  pub fn start() -> Self {
    Self {
      rng: thread_rng(),
      keys: RSA::generate_keys_with_given_size(128),
      hashed_messages: vec![]
    }
  }

  pub fn encrypt_with_timestamp<S: AsRef<[u8]>>(&mut self, message: &S) -> Vec<u8> {
    let time: [u8; 16] = self.rng.gen();
    let mut message_with_timestamp = message.as_ref().to_vec();
    message_with_timestamp.extend_from_slice(b"{\n time:");
    message_with_timestamp.extend_from_slice(&time);
    message_with_timestamp.extend_from_slice(b",\n  social: '555-55-5555',\n}");
    RSA::encrypt(&self.keys.pk, &message_with_timestamp)
  }

  pub fn decrypt_ciphertext<S: AsRef<[u8]>>(&mut self, ciphertext: &S) -> Result<Vec<u8>, String> {
    let hash = Sha1::hash(ciphertext);
    if self.hashed_messages.contains(&hash) {
      return Err("Message already decrypted.".to_string())
    }
    self.hashed_messages.push(hash);
    Ok(RSA::decrypt(&self.keys.sk, ciphertext))
  }

  pub fn retrieve_pk(&self) -> (BigUint, BigUint) {
    self.keys.pk.clone()
  }
}

fn main() {
  let mut server = Server::start();
  let message = b"SENIORES SOY DE BOCA Y LO SIGO A TODOS LADOS".to_vec();
  let c_bytes = server.encrypt_with_timestamp(&message);
  let c = BigUint::from_bytes_be(&c_bytes);
  let (e, n) = server.retrieve_pk();

  let expected_message = server.decrypt_ciphertext(&c_bytes).unwrap();
  println!("{}", String::from_utf8_lossy(&expected_message));
  let expected_error = server.decrypt_ciphertext(&c_bytes).unwrap_err();
  println!("{}", expected_error);

  /*
    S > 1 random number
    C' = (S^E * C) mod N
    Decrypt C' → P' = C'^D mod N (we dont know D but server decrypts)
    P' = (S^E * C)^D = S^(ED) * C^D = S * P (mod N)
    → P = P' * S^-1 (mod N)
  */
  let s = thread_rng().gen_biguint_range(&BigUint::from(2u8), &n);
  let px = {
    let cx = (mod_exp(&s, &e, &n) * c) % &n;
    let px_bytes = server.decrypt_ciphertext(&cx.to_bytes_be()).unwrap();
    BigUint::from_bytes_be(&px_bytes)
  };
  let p = px * inv_mod(&s, &n).unwrap();
  println!("{}", String::from_utf8_lossy(&p.to_bytes_be()));
}
