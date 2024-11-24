use num_bigint::{BigUint, ToBigInt};
use num_traits::{One, Zero};
use super::bigint_utils::extended_gcd;

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