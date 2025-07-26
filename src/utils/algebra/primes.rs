use num_bigint::{BigUint, RandBigInt};
use num_traits::{FromBytes, One, Zero};
use crate::utils::conversion::hex_string::HexString;

use super::modulo::mod_exp;

pub fn get_nist_prime() -> BigUint {
  let hex = HexString::try_from(
    "
    ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
    e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
    3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
    6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
    24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
    c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
    bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
    fffffffffffff
  ",
  )
  .unwrap();
  BigUint::from_be_bytes(hex.as_vector_of_bytes().as_ref())
}

pub fn miller_rabin_test(n: &BigUint, k: u64) -> bool {
  if *n == BigUint::from(2u8) || *n == BigUint::from(3u8) {
    return true;
  }
  let mut d = n - BigUint::one();
  let mut r = 0u64;
  while &d % 2u64 == BigUint::zero() {
    d >>= 1;
    r += 1;
  }
  let mut rng = rand::thread_rng();
  for _ in 0..k {
    let a = rng.gen_biguint_range(&BigUint::from(2u8), n);
    let mut x = mod_exp(&a, &d, &n);
    if x == BigUint::one() || x == n - BigUint::one() {
      continue;
    }
    let mut i = 1u64;
    while i < r {
      x = x.modpow(&BigUint::from(2u8), n);
      if x == BigUint::one() {
        return false;
      } else if x == n - BigUint::one() {
        break;
      }
      i += 1;
    }
    if i == r {
      return false;
    }
  }
  true
}

pub fn generate_prime(bits: u64, iterations: u64) -> BigUint {
  let one = BigUint::one();
  let two = BigUint::from(2u8);
  loop {
    let mut rng = rand::thread_rng();
    let prime_candidate = rng.gen_biguint(bits);
    let candidate = if &prime_candidate % &two == BigUint::zero() {
      prime_candidate + &one
    } else {
      prime_candidate
    };
    if miller_rabin_test(&candidate, iterations) {
      return candidate;
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_miller_rabin_prime() {
    let prime = BigUint::from(7u8);
    assert!(miller_rabin_test(&prime, 3));
  }

  #[test]
  fn test_miller_rabin_composite() {
    let composite = BigUint::from(15u8);
    assert!(!miller_rabin_test(&composite, 3));
  }

  #[test]
  fn test_generate_prime() {
    let bits = 256;
    let iterations = 15;
    let prime = generate_prime(bits, iterations);
    assert!(miller_rabin_test(&prime, iterations));
  }
}
