use crate::utils::algebra::{generate_prime, inv_mod, mod_exp};
use num_bigint::BigUint;
use num_traits::One;

pub struct RSAKeys {
  pub sk: (BigUint, BigUint), // (d,n)
  pub pk: (BigUint, BigUint), // (e,n)
}

pub struct RSA {}

impl RSA {
  const E: u8 = 3;
  const BITS: u64 = 128;
  const ITERATIONS: u64 = 7;

  pub fn generate_keys() -> RSAKeys {
    loop {
      let p: BigUint = generate_prime(Self::BITS, Self::ITERATIONS);
      let q: BigUint = generate_prime(Self::BITS, Self::ITERATIONS);
      let n = &p * &q;
      let et = (&p - BigUint::one()) * (&q - BigUint::one());
      let option_d = inv_mod(&BigUint::from(Self::E), &et);
      match option_d {
        Some(d) => {
          return RSAKeys {
            sk: (d, n.clone()),
            pk: (BigUint::from(Self::E), n),
          };
        }
        None => continue,
      }
    }
  }

  pub fn encrypt<S: AsRef<[u8]>>(pk: &(BigUint, BigUint), plaintext: &S) -> Vec<u8> {
    let (e, n) = pk;
    let n_size = ((n.bits() + 7) / 8) as usize;
    let mut ciphertext = Vec::new();
    for chunk in plaintext.as_ref().chunks(n_size - 11) {  // reserve 11 bytes for padding
        let m = BigUint::from_bytes_be(chunk);
        let ciphertext_chunk = mod_exp(&m, &e, &n);
        ciphertext.extend_from_slice(&ciphertext_chunk.to_bytes_be());
    }
    ciphertext
  }

  pub fn decrypt<S: AsRef<[u8]>>(sk: &(BigUint, BigUint), ciphertext: &S) -> Vec<u8> {
    let (d, n) = sk;
    let n_size = ((n.bits() + 7) / 8) as usize;
    let mut plaintext = Vec::new();
    for chunk in ciphertext.as_ref().chunks(n_size) {
        let m = BigUint::from_bytes_be(chunk);
        let plaintext_chunk = mod_exp(&m, &d, &n);
        plaintext.extend_from_slice(&plaintext_chunk.to_bytes_be());
    }
    plaintext
  }

  // Pre: p, q are primes
  pub fn generate_keys_with_given_size(bits: u64) -> RSAKeys {
    loop {
      let p: BigUint = generate_prime(bits, Self::ITERATIONS);
      let q: BigUint = generate_prime(bits, Self::ITERATIONS);
      let n = &p * &q;
      let et = (&p - BigUint::one()) * (&q - BigUint::one());
      let option_d = inv_mod(&BigUint::from(Self::E), &et);
      match option_d {
        Some(d) => {
          return RSAKeys {
            sk: (d, n.clone()),
            pk: (BigUint::from(Self::E), n),
          };
        }
        None => continue,
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use num_bigint::RandBigInt;
  use rand::thread_rng;

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
    let rsa_keys: RSAKeys = RSA::generate_keys();
    let plaintext = b"SOY BOSTERO DE LA CUNA A LA TUMBA Y NUNCA DESCENDERE".to_vec();
    let ciphertext = RSA::encrypt(&rsa_keys.pk, &plaintext);
    assert_eq!(plaintext, RSA::decrypt(&rsa_keys.sk, &ciphertext));
  }
}
