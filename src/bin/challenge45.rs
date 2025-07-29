use cryptopals::utils::{algebra::modulo::{inv_mod, mod_exp}, dsa::{SignatureAlgorithm, DSA}};
use num_bigint::BigUint;
use num_traits::{One, Zero};
fn main() {
  let mut dsa = DSA::with_default_params();
  let (_, y) = dsa.generate_keys();

  // We will forge signatures that work for every message in both cases, for example this one
  let message = b"BOCA YO TE AMO";

  /*
    g = 0 -> r = 0. Suppose we do not verify 0 < r.
    Then v = 0 and the signature will always validate, whatever the value of s.
    NOTE: We only modified the DSA code for this challenge. If you want the attack to work, remove the r > 0 assertion
  */
  dsa.g = BigUint::zero();
  let forged_signature_1 = (BigUint::zero(), BigUint::from(123456789u32));
  assert!(dsa.verify(&y, message, &forged_signature_1));

  /*
    g = p + 1 -> g = 1 (mod p).
    Choose z, suppose r = y^z (mod p) (mod q), s = r/z (mod q). Then:
    w = s^-1 = z/r (mod q)
    v = g^u1 y^u2 (mod p) (mod q)
      = y^(rw) (mod p) (mod q)   (since g = 1)
      = y^z (mod p) (mod q)
      = r
  */
  let (p, q, _) = dsa.get_params();
  dsa.g = &p + BigUint::one(); // g = p + 1
  let z = BigUint::from(234567u32); // choose z
  let r = mod_exp(&y, &z, &p) % &q; // r = y^z % p % q
  let s = (&r * inv_mod(&z, &q).unwrap()) % q; // s = r/z % q
  let forged_signature_2 = (r, s);
  assert!(dsa.verify(&y, message, &forged_signature_2));
}
