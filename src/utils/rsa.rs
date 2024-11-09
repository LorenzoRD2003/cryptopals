use num_bigint::BigUint;
use num_traits::One;
use rand::thread_rng;

use crate::utils::algebra::{inv_mod, mod_exp};

pub struct RSA2048Keys {
  pub sk: (BigUint, BigUint), // (d,n)
  pub pk: (BigUint, BigUint), // (e,n)
}

pub struct RSA2048 {}

impl RSA2048 {
  const E: u8 = 3;
  const BITS: usize = 2048;

  pub fn generate_keys() -> RSA2048Keys {
    let mut rng = thread_rng();
    loop {
      //let p: BigUint = rng.gen_safe_prime(Self::BITS);
      //let q: BigUint = rng.gen_safe_prime(Self::BITS);
      let (p, q) = (BigUint::from(17u32), BigUint::from(23u32));
      let n = &p * &q;
      let et = (&p - BigUint::one()) * (&q - BigUint::one());
      let option_d = inv_mod(&BigUint::from(Self::E), &et);
      option_d.clone().unwrap();
      println!("{}", option_d.is_none());
      match option_d {
        Some(d) => {
          return RSA2048Keys {
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
  use super::*;
  use crate::utils::algebra::get_nist_prime;

  #[test]
  fn test_rsa_small_numbers() {
    dbg!(1);
    let rsa_keys: RSA2048Keys = RSA2048::generate_keys();
    let plaintext = 42u32.to_be_bytes().to_vec();
    let ciphertext = RSA2048::encrypt(&rsa_keys.pk, &plaintext);
    assert_eq!(plaintext, RSA2048::decrypt(&rsa_keys.sk, &ciphertext));
  }

  #[test]
  fn test_rsa_big_numbers() {
    let rsa_keys: RSA2048Keys = RSA2048::generate_keys();
    let plaintext = get_nist_prime().to_bytes_be();
    let ciphertext = RSA2048::encrypt(&rsa_keys.pk, &plaintext);
    assert_eq!(plaintext, RSA2048::decrypt(&rsa_keys.sk, &ciphertext));
  }

  #[test]
  fn test_rsa_text() {
    let rsa_keys: RSA2048Keys = RSA2048::generate_keys();
    let plaintext = b"SOY BOSTERO DE LA CUNA A LA TUMBA Y NUNCA DESCENDERE".to_vec();
    let ciphertext = RSA2048::encrypt(&rsa_keys.pk, &plaintext);
    assert_eq!(plaintext, RSA2048::decrypt(&rsa_keys.sk, &ciphertext));
  }
}
