use num_bigint::BigUint;
use num_traits::One;
use crate::utils::algebra::{generate_prime, inv_mod, mod_exp};

pub struct RSA {
  pub sk: (BigUint, BigUint), // (d,n)
  pub pk: (BigUint, BigUint), // (e,n)
}

impl RSA {
  const E: u8 = 3;
  const BITS: u64 = 2048;
  const ITERATIONS: u64 = 7;

  pub fn generate_keys() -> Self {
    loop {
      let p: BigUint = generate_prime(Self::BITS, Self::ITERATIONS);
      let q: BigUint = generate_prime(Self::BITS, Self::ITERATIONS);
      let n = &p * &q;
      let et = (&p - BigUint::one()) * (&q - BigUint::one());
      let option_d = inv_mod(&BigUint::from(Self::E), &et);
      match option_d {
        Some(d) => {
          return Self {
            sk: (d, n.clone()),
            pk: (BigUint::from(Self::E), n),
          };
        }
        None => continue,
      }
    }
  }

  pub fn encrypt<S: AsRef<[u8]>>(pk: &(BigUint, BigUint), plaintext: &S) -> Vec<u8> {
    let m = BigUint::from_bytes_be(plaintext.as_ref());
    let res = mod_exp(&m, &pk.0, &pk.1);
    res.to_bytes_be()
  }

  pub fn decrypt<S: AsRef<[u8]>>(sk: &(BigUint, BigUint), ciphertext: &S) -> Vec<u8> {
    let c = BigUint::from_bytes_be(ciphertext.as_ref());
    let res = mod_exp(&c, &sk.0, &sk.1);
    res.to_bytes_be()
  }
}

#[cfg(test)]
mod tests {
  use num_bigint::RandBigInt;
  use rand::thread_rng;
  use super::*;

  #[test]
  fn test_rsa_small_numbers() {
    let rsa_keys = RSA::generate_keys();
    let plaintext = 42u8.to_be_bytes().to_vec();
    let ciphertext = RSA::encrypt(&rsa_keys.pk, &plaintext);
    assert_eq!(plaintext, RSA::decrypt(&rsa_keys.sk, &ciphertext));
  }

  #[test]
  fn test_rsa_big_numbers() {
    let rsa_keys = RSA::generate_keys();
    let mut rng = thread_rng();
    // Remember it should be sized <= 2048 bits, if not, separate in chunks
    let plaintext = rng.gen_biguint(1024).to_bytes_be();
    let ciphertext = RSA::encrypt(&rsa_keys.pk, &plaintext);
    assert_eq!(plaintext, RSA::decrypt(&rsa_keys.sk, &ciphertext));
  }

  #[test]
  fn test_rsa_text() {
    let rsa_keys: RSA = RSA::generate_keys();
    let plaintext = b"SOY BOSTERO DE LA CUNA A LA TUMBA Y NUNCA DESCENDERE".to_vec();
    let ciphertext = RSA::encrypt(&rsa_keys.pk, &plaintext);
    assert_eq!(plaintext, RSA::decrypt(&rsa_keys.sk, &ciphertext));
  }
}
