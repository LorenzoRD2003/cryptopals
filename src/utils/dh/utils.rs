use num_bigint::BigUint;
use num_traits::{One, Zero};

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
