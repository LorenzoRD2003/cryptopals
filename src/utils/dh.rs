use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;
use sha2::{Digest, Sha256};

use super::algebra::modulo::mod_exp;

// The session is "local" for each party, their params are never sent so they are set to public to be able to access them
#[derive(Debug, Clone, PartialEq)]
pub struct DiffieHellmanSession {
  pub encryption_key: [u8; 16],
  pub mac_key: [u8; 16],
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

  pub fn create_session_with(&self, other_pk: &BigUint) -> DiffieHellmanSession {
    let s = mod_exp(&other_pk, &self.sk, &self.p);
    let mut hasher = Sha256::new();
    hasher.update(s.to_bytes_be());
    let digest = hasher.finalize();
    DiffieHellmanSession {
      encryption_key: digest[..16].try_into().unwrap(),
      mac_key: digest[16..32].try_into().unwrap(),
    }
  }

  pub fn from_other_party_params(
    p: &BigUint,
    g: &BigUint,
    other_pk: &BigUint,
  ) -> (DiffieHellmanParty, DiffieHellmanSession) {
    let party = Self::new(&p, &g);
    let session = party.create_session_with(&other_pk);
    (party, session)
  }
}

#[cfg(test)]
mod tests {
  use crate::utils::algebra::primes::get_nist_prime;
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
    let session_a = alice.create_session_with(&bob.pk);
    let session_b = bob.create_session_with(&alice.pk);
    assert_eq!(session_a, session_b);
  }

  #[test]
  fn test_diffie_hellman_with_bigger_nums() {
    let p = get_nist_prime();
    let g = BigUint::from(2u32);
    let alice = DiffieHellmanParty::new(&p, &g);
    let bob = DiffieHellmanParty::new(&p, &g);
    let session_a = alice.create_session_with(&bob.pk);
    let session_b = bob.create_session_with(&alice.pk);
    assert_eq!(session_a, session_b);
  }
}
