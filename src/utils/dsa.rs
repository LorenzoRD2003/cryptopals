use num_bigint::{BigUint, RandBigInt};
use num_traits::{One, Zero};
use rand::thread_rng;

use super::{
  algebra::modulo::{inv_mod, mod_exp},
  mac::sha1::Sha1,
};

// p,q,g are public parameters. (x,y) is the key pair in DSA
#[derive(Clone)]
pub struct DSA {
  pub p: BigUint,
  pub q: BigUint,
  pub g: BigUint,
}

impl DSA {
  pub fn with_default_params() -> Self {
    let p = BigUint::parse_bytes("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1".as_bytes(),
      16,
    )
    .unwrap();
    let q =
      BigUint::parse_bytes("f4f47f05794b256174bba6e9b396a7707e563c5b".as_bytes(), 16).unwrap();
    let g = BigUint::parse_bytes("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291".as_bytes(),
      16,
    )
    .unwrap();
    Self { p, q, g }
  }

  // Returns (x, y) = (secret_key, public_key)
  pub fn generate_keys(&self) -> (BigUint, BigUint) {
    let x = thread_rng().gen_biguint_range(&BigUint::from(2u8), &(&self.q - BigUint::one()));
    let y = mod_exp(&self.g, &x, &self.p);
    (x, y)
  }

  pub fn sign<S: AsRef<[u8]>>(&self, x: &BigUint, message: &S) -> (BigUint, BigUint) {
    let (mut r, mut s) = (BigUint::zero(), BigUint::zero());
    let h = BigUint::from_bytes_be(&Sha1::hash(message));
    while r.is_zero() || s.is_zero() {
      let k = thread_rng().gen_biguint_range(&BigUint::from(2u8), &self.q);
      r = mod_exp(&self.g, x, &self.p) % &self.q;
      if r.is_zero() {
        continue;
      }
      s = (inv_mod(&k, &self.q).unwrap() * (&h + x * &r)) % &self.q;
    }
    (r, s)
  }

  pub fn verify<S: AsRef<[u8]>>(
    &self,
    y: &BigUint,
    message: &S,
    signature: &(BigUint, BigUint),
  ) -> bool {
    let (r, s) = signature;
    if r.is_zero() || s.is_zero() || r > &self.q || s > &self.q {
      return false;
    }
    let w = inv_mod(s, &self.q).unwrap();
    let h = BigUint::from_bytes_be(&Sha1::hash(message));
    let u1 = (&h * &w) % &self.q;
    let u2 = (r * &w) % &self.q;
    let v = mod_exp(&self.g, &u1, &self.p) * mod_exp(y, &u2, &self.p) % &self.q;
    r.clone() == v
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_dsa_verifies_correct_signature() {
    let dsa = DSA::with_default_params();
    let (x, y) = dsa.generate_keys();
    let message = b"AGUANTE BOQUITA PAPA";
    let (r, s) = dsa.sign(&x, message);
    assert!(dsa.verify(&y, message, &(r, s)))
  }

  #[test]
  #[should_panic]
  fn test_dsa_does_not_verify_invalid_signature() {
    let dsa = DSA::with_default_params();
    let (x, y) = dsa.generate_keys();
    let message = b"AGUANTE BOQUITA PAPA";
    let (r, s) = dsa.sign(&x, message);
    assert!(dsa.verify(&y, message, &(r, s + BigUint::one())))
  }
}
