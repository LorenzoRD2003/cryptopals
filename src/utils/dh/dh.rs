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
  p: BigUint,
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
}
