use cryptopals::utils::{
  algebra::{inv_mod, mod_exp},
  mac::sha1::{Sha1, Sha1Digest},
  padding::pkcs1_unpad,
  rsa::{RSAKeys, RSA},
};
use num_bigint::{BigUint, RandBigInt};
use rand::{rngs::ThreadRng, thread_rng, Rng};

struct Server {
  rng: ThreadRng,
  pub keys: RSAKeys,
  hashed_messages: Vec<Sha1Digest>,
}

impl Server {
  pub fn start() -> Self {
    Self {
      rng: thread_rng(),
      keys: RSA::generate_keys_with_given_size(128),
      hashed_messages: vec![],
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
    self.hashed_messages.push(hash);
    Ok(RSA::decrypt_with_key(&self.keys.sk, ciphertext))
  }

  pub fn retrieve_pk(&self) -> (BigUint, BigUint) {
    self.keys.pk.clone()
  }
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
  let s = thread_rng().gen_biguint_range(&BigUint::from(2u8), &n);
  let m = mod_exp(&s, &e, &n);
  let inv_s = inv_mod(&s, &n).unwrap();
  let chunk_size = ((n.bits() + 7) / 8) as usize;

  // First of all, we have to do this in chunks of size n
  let mut dif_ciphertext: Vec<u8> = vec![];
  for ciphertext_chunk in ciphertext.chunks(chunk_size) {
    let c = BigUint::from_bytes_be(ciphertext_chunk);
    let cx = (&m * &c) % &n;
    dif_ciphertext.extend(cx.to_bytes_be());
  }
  let dif_plaintext = server.decrypt_ciphertext(&dif_ciphertext).unwrap();
  let mut plaintext: Vec<u8> = vec![];
  for px_chunk in dif_plaintext.chunks(chunk_size) {
    let px = BigUint::from_bytes_be(px_chunk);
    let p = (&px * &inv_s) % &n;
    let p_bytes = p.to_bytes_be();
    let zeros = chunk_size - p_bytes.len();
    let extended_p = [vec![0; zeros], p_bytes].concat();
    let unpadded_p = pkcs1_unpad(&extended_p);
    plaintext.extend(unpadded_p);
  }
  println!("{}", String::from_utf8_lossy(&plaintext));
}
