use num_bigint::{BigInt, BigUint};
use num_traits::{One, Zero};

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

// Pre: n must be a perfect cube
pub fn cbrt(n: &BigUint) -> BigUint {
  if *n == BigUint::zero() {
    return BigUint::zero();
  }
  let mut low = BigUint::one();
  let mut high = n.clone();
  while low < high {
    let mid = (&low + &high) >> 1;
    let m3 = &mid * &mid * &mid;
    if &m3 == n {
      return mid;
    } else if &m3 < n {
      low = mid + BigUint::one();
    } else {
      high = mid;
    }
  }
  low - BigUint::one()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_cube_root() {
    let n = BigUint::parse_bytes(b"1000000000000000000000000000000000", 10).unwrap();
    let result = cbrt(&n);
    assert_eq!(result, BigUint::parse_bytes(b"100000000000", 10).unwrap())
  }
}
