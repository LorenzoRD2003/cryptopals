use num_bigint::BigUint;
use num_traits::{FromBytes, One, Zero};

use crate::utils::conversion::hex_string::HexString;

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

pub fn get_dh_p() -> BigUint {
  let hex = HexString::try_from("
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
