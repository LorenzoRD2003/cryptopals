use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;
use sha2::{Digest, Sha256};

use super::utils::mod_exp;

#[derive(Debug, Clone, PartialEq)]
pub struct DiffieHellmanSession {
  encryption_key: [u8; 16],
  mac_key: [u8; 16],
}

#[derive(Debug, Clone)]
pub struct DiffieHellmanParty {
  pub p: BigUint,
  sk: BigUint,
  pub pk: BigUint,
}

impl DiffieHellmanParty {
  pub fn new(p: &BigUint, g: &BigUint) -> Self {
    let sk = thread_rng().gen_biguint_below(&p);
    let pk = mod_exp(&g, &sk, &p);
    Self {
      p: p.clone(),
      sk,
      pk,
    }
  }

  pub fn create_session_with(&self, other: &DiffieHellmanParty) -> DiffieHellmanSession {
    let s = mod_exp(&other.pk, &self.sk, &self.p);
    let mut hasher = Sha256::new();
    hasher.update(s.to_bytes_be());
    let digest = hasher.finalize();
    DiffieHellmanSession {
      encryption_key: digest[..16].try_into().unwrap(),
      mac_key: digest[16..32].try_into().unwrap(),
    }
  }
}

#[cfg(test)]
mod tests {
  use crate::utils::conversion::hex_string::HexString;

  use super::*;

  #[test]
  fn test_mod_exp() {
    let (p, g, a) = (
      BigUint::from(37u32),
      BigUint::from(5u32),
      BigUint::from(1000u32),
    );
    assert_eq!(mod_exp(&g, &a, &p), BigUint::from(7u32));
  }

  #[test]
  fn test_diffie_hellman() {
    let (p, g) = (BigUint::from(37u32), BigUint::from(5u32));
    let alice = DiffieHellmanParty::new(&p, &g);
    let bob = DiffieHellmanParty::new(&p, &g);
    let session_a = alice.create_session_with(&bob);
    let session_b = bob.create_session_with(&alice);
    assert_eq!(session_a, session_b);
  }

  #[test]
  fn test_diffie_hellman_with_bigger_nums() {
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
    dbg!(&hex);
    let p = BigUint::from_bytes_be(hex.as_vector_of_bytes().unwrap().as_ref());
    let g = BigUint::from(2u32);
    let alice = DiffieHellmanParty::new(&p, &g);
    let bob = DiffieHellmanParty::new(&p, &g);
    let session_a = alice.create_session_with(&bob);
    let session_b = bob.create_session_with(&alice);
    assert_eq!(session_a, session_b);
  }
}
