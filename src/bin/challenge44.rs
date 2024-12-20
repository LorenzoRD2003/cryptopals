use cryptopals::utils::{algebra::modulo::{inv_mod, mod_exp}, dsa::{SignatureAlgorithm, DSA}, mac::sha1::Sha1};
use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;

#[derive(Clone)]
struct BadDSA {
  dsa: DSA,
  k: BigUint
}

impl SignatureAlgorithm for BadDSA {
  type FieldElement = BigUint;
  fn with_default_params() -> Self {
    let dsa = DSA::with_default_params();
    let k = thread_rng().gen_biguint_range(&BigUint::from(2u8), &dsa.q);
    Self {dsa, k}
  }

  fn get_params(&self) -> (Self::FieldElement, Self::FieldElement, Self::FieldElement) {
    self.dsa.get_params()
  }

  fn generate_keys(&self) -> (Self::FieldElement, Self::FieldElement) {
    self.dsa.generate_keys()
  }

  fn sign<S: AsRef<[u8]>>(&self, x: &BigUint, message: &S) -> (BigUint, BigUint) {
    let h = BigUint::from_bytes_be(&Sha1::hash(message)) % &self.dsa.q;
    let inv_k = inv_mod(&self.k, &self.dsa.q).unwrap();
    let r = mod_exp(&self.dsa.g, &self.k, &self.dsa.p) % &self.dsa.q;
    let s = (&inv_k * (&h + x * &r)) % &self.dsa.q;
    (r, s)
  }

  fn verify<S: AsRef<[u8]>>(
      &self,
      _y: &Self::FieldElement,
      _message: &S,
      _signature: &(Self::FieldElement, Self::FieldElement),
    ) -> bool {
      unimplemented!()
  }
}

impl BadDSA {
  fn retrieve_k(&self) -> BigUint {
    self.k.clone()
  }
}

/*
  Suppose k is fixed:
    ks1 = H(m1) + xr (mod q)
    ks2 = H(m2) + xr (mod q)
    k(s1 - s2) = H(m1) - H(m2) (mod q)
    k = (H(m1) - H(m2))(s1 - s2)^(-1) (mod q)
*/

fn main() {
  let dsa = BadDSA::with_default_params();
  let (_, q, _) = dsa.get_params();
  let (x, _) = dsa.generate_keys();
  let m1 = b"AGUANTE BOCA";
  let h1 = BigUint::from_bytes_be(&Sha1::hash(m1)) % &q;
  let (_, s1) = dsa.sign(&x, m1);
  let m2 = b"BOCA YO TE AMO";
  let h2 = BigUint::from_bytes_be(&Sha1::hash(m2)) % &q;
  let (_, s2) = dsa.sign(&x, m2);

  let obtained_k = {
    let a = (&q + h1 - h2) % &q;
    let b = (&q + s1 - s2) % &q;
    (a * inv_mod(&b, &q).unwrap()) % &q
  };
  assert_eq!(obtained_k, dsa.retrieve_k())
}
