use num_bigint::BigUint;
use num_traits::One;

use super::{algebra::{modulo::{inv_mod, mod_exp}, primes::generate_prime}, padding::{pkcs1_pad, pkcs1_unpad}};

pub struct RSAKeys {
  pub sk: (BigUint, BigUint), // (d,n)
  pub pk: (BigUint, BigUint), // (e,n)
}

pub struct RSA {}

impl RSA {
  const E: u8 = 3;
  const BITS: u64 = 512;
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

  pub fn encrypt_with_key<S: AsRef<[u8]>>(pk: &(BigUint, BigUint), plaintext: &S) -> Vec<u8> {
    let (e, n) = pk;
    let n_size = ((n.bits() + 7) / 8) as usize;
    let mut ciphertext = Vec::new();
    for chunk in plaintext.as_ref().chunks(n_size - 3) {
      let padded_chunk = if chunk.len() < n_size {
        pkcs1_pad(chunk, n_size)
      } else {
        chunk.to_vec()
      };
      let m = BigUint::from_bytes_be(&padded_chunk);
      let ciphertext_chunk = mod_exp(&m, &e, &n).to_bytes_be();
      let zeros = n_size - ciphertext_chunk.len();
      let with_trailing_zeros: Vec<u8> = [vec![0x00; zeros], ciphertext_chunk].concat();
      ciphertext.extend_from_slice(&with_trailing_zeros);
    }
    ciphertext
  }

  pub fn decrypt_with_key<S: AsRef<[u8]>>(sk: &(BigUint, BigUint), ciphertext: &S) -> Vec<u8> {
    let (d, n) = sk;
    let n_size = ((n.bits() + 7) / 8) as usize;
    let mut plaintext = Vec::new();
    for chunk in ciphertext.as_ref().chunks(n_size) {
      let m = BigUint::from_bytes_be(chunk);
      let plaintext_chunk = mod_exp(&m, &d, &n).to_bytes_be();
      let unpadded_chunk = {
        let zeros = n_size - plaintext_chunk.len();
        let with_trailing_zeros = [vec![0x00; zeros], plaintext_chunk].concat();
        pkcs1_unpad(&with_trailing_zeros)
      };
      plaintext.extend_from_slice(&unpadded_chunk);
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
    let ciphertext = RSA::encrypt_with_key(&rsa_keys.pk, &plaintext);
    assert_eq!(plaintext, RSA::decrypt_with_key(&rsa_keys.sk, &ciphertext));
  }

  #[test]
  fn test_rsa_big_numbers() {
    let rsa_keys = RSA::generate_keys();
    let mut rng = thread_rng();
    // Remember it should be sized <= 2048 bits, if not, separate in chunks
    let plaintext = rng.gen_biguint(1024).to_bytes_be();
    let ciphertext = RSA::encrypt_with_key(&rsa_keys.pk, &plaintext);
    assert_eq!(plaintext, RSA::decrypt_with_key(&rsa_keys.sk, &ciphertext));
  }

  #[test]
  fn test_rsa_text() {
    let rsa_keys: RSAKeys = RSA::generate_keys();
    let plaintext = b"SOY BOSTERO DE LA CUNA A LA TUMBA Y NUNCA DESCENDERE".to_vec();
    let ciphertext = RSA::encrypt_with_key(&rsa_keys.pk, &plaintext);
    assert_eq!(plaintext, RSA::decrypt_with_key(&rsa_keys.sk, &ciphertext));
  }
}
