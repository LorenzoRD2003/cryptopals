use cryptopals::utils::{
  algebra::bigint_utils::cbrt,
  mac::sha1::{Sha1, Sha1Digest},
  rsa::{RSAKeys, RSA},
};
use num_bigint::BigUint;
use num_traits::One;

struct SignerVerifierAPI {
  keys: RSAKeys,
}

impl SignerVerifierAPI {
  fn start() -> Self {
    Self {
      keys: RSA::generate_keys(),
    }
  }

  fn sign(&mut self, digest: &Sha1Digest) -> Vec<u8> {
    RSA::encrypt_with_key(&self.keys.sk, digest)
  }

  fn verify<S: AsRef<[u8]>>(&mut self, message: &S, signature: &Vec<u8>) -> bool {
    let expected_digest = Sha1::hash(&message);
    let data = RSA::decrypt_with_key(&self.keys.pk, signature);
    let obtained_digest: Sha1Digest = data[0..20].try_into().unwrap();
    expected_digest == obtained_digest
  }

  fn retrieve_pk(&self) -> (BigUint, BigUint) {
    self.keys.pk.clone()
  }
}

fn main() {
  let mut api = SignerVerifierAPI::start();
  let message = b"hi mom";
  let digest = Sha1::hash(message);

  // Check sign-verify process works as expected
  let signature = api.sign(&digest);
  assert!(api.verify(message, &signature));

  // We can forge signatures for e = 3 using the bad implementation of hash checking
  let (_e, n) = api.retrieve_pk();
  let n_size = ((n.bits() + 7) / 8) as usize;
  let zeros = n_size - 7 - digest.len();
  let vector: Vec<u8> = [
    vec![0x00, 0x01, 0xff, 0xff, 0xff, 0xff, 0x00],
    digest.to_vec(),
    vec![0x00; zeros],
  ]
  .concat();
  //dbg!(&vector);
  let a = BigUint::from_bytes_be(&vector);
  // a is a number of the form a1a2a3..ak0000000000000000000000000000 (in bytes)
  // and we want to add something that only affects the ending zeros to convert it into a perfect cube
  let root = cbrt(&a) + BigUint::one(); // This is the number representing the valid forged signature
  // when it is cubed by the server (e = 3), the padding and the hash will be correctly parsed
  let forged_signature = [vec![0x00], root.to_bytes_be()].concat();
  assert!(api.verify(message, &forged_signature));
}
