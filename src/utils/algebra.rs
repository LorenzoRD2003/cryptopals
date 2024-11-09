use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::{FromBytes, One, Zero};

use super::conversion::hex_string::HexString;

pub fn galois_multiplication(x: u8, y: u8) -> u8 {
  let mut p = 0u8;
  let (mut a, mut b) = (x, y); // mutable copies of x,y
  for _ in 0..8 {
    if b & 1 != 0 {
      p ^= a;
    }
    let hi_bit_set = a & 0x80;
    a <<= 1;
    if hi_bit_set != 0 {
      a ^= 0x1b; // Reduce modulo the irreducible polynomial x^8 + x^4 + x^3 + x^2 + 1
    }
    b >>= 1;
  }
  p
}

pub fn mod_exp(g: &BigUint, exponent: &BigUint, p: &BigUint) -> BigUint {
  let mut res = BigUint::one();
  let mut b = g.clone();
  let mut e = exponent.clone();
  while e > BigUint::zero() {
    if &e % 2u32 == BigUint::one() {
      res = (res * &b) % p;
    }
    b = (&b * &b) % p;
    e >>= 1;
  }
  res
}

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
  BigUint::from_be_bytes(hex.as_vector_of_bytes().unwrap().as_ref())
}

pub fn concat_biguints(a: &BigUint, b: &BigUint) -> BigUint {
  let mut concatenated_bytes = a.to_bytes_be().clone();
  concatenated_bytes.extend_from_slice(&b.to_bytes_be());
  BigUint::from_bytes_le(&concatenated_bytes)
}

pub fn extended_gcd(x: &BigInt, y: &BigInt) -> (BigInt, BigInt, BigInt) {
  let (mut old_r, mut r) = (x.clone(), y.clone());
  let (mut old_s, mut s) = (BigInt::one(), BigInt::zero());
  let (mut old_t, mut t) = (BigInt::zero(), BigInt::one());

  while r != BigInt::zero() {
    let q = &old_r / &r;
    (old_r, r) = (r.clone(), old_r - &q * &r);
    (old_s, s) = (s.clone(), old_s - &q * &s);
    (old_t, t) = (t.clone(), old_t - &q * &t);
  }
  (old_s, old_t, old_r) // a, b, gcd(a,b)
}

pub fn inv_mod(a: &BigUint, m: &BigUint) -> Option<BigUint> {
  let m_ = m.to_bigint().unwrap();
  let (x, _, gcd) = extended_gcd(&a.to_bigint().unwrap(), &m_);
  if gcd.is_one() {
    let inverse = (x + &m_) % m_;
    Some(inverse.to_biguint().unwrap())
  } else {
    None
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_inv_mod_simple() {
    let a = BigUint::from(3u32);
    let m = BigUint::from(7u32);
    assert_eq!(inv_mod(&a, &m), Some(BigUint::from(5u32)));
  }

  #[test]
  fn test_inv_mod_no_inverse() {
    let a = BigUint::from(2u32);
    let m = BigUint::from(4u32);
    assert_eq!(inv_mod(&a, &m), None);
  }

  #[test]
  fn test_inv_mod_large_prime() {
    let a = BigUint::from(123456789u32);
    let m = BigUint::from(1000000007u32);
    let result = inv_mod(&a, &m);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), BigUint::from(18633540u32));
  }
}
