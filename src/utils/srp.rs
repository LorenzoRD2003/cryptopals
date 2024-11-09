use num_bigint::{BigUint, RandBigInt};
use num_traits::{One, Zero};
use rand::thread_rng;
use sha2::{Digest, Sha256};
use crate::utils::mac::{hmac::Sha1HMac, sha1::Sha1Digest};

use super::algebra::{concat_biguints, get_nist_prime, mod_exp};

pub fn salt_then_hash_biguint(salt: &BigUint, password: &String) -> BigUint {
  let mut hasher = Sha256::new();
  hasher.update(salt.to_bytes_be());
  hasher.update(password);
  let xh = hasher.finalize();
  BigUint::from_bytes_be(&xh)
}

/*
  Correctness proof (both things are equal to S)
  (B - k * g^x)^(a + ux)
    =  (B - kv)^(a + ux)
    = (g^b)^(a + ux)
    = (g^a * g^(ux))^b
    = (A * v^u)^b
*/

struct ServerAbstraction {
  salt: BigUint,
  v: BigUint,
  sk: BigUint,
  pub pk: BigUint,
}

impl ServerAbstraction {
  fn define_server(password: &String, n: &BigUint, g: &BigUint, k: &BigUint) -> Self {
    let salt = thread_rng().gen_biguint_below(&(BigUint::one() << 256));
    let x = salt_then_hash_biguint(&salt, password);
    let v = mod_exp(&g, &x, &n);
    let sk = thread_rng().gen_biguint_below(&n);
    let pk = k * &v + mod_exp(&g, &sk, &n);
    Self { salt, v, sk, pk }
  }

  fn compute_u(&self, client_pk: &BigUint) -> BigUint {
    let mut hasher = Sha256::new();
    let concat_pk = concat_biguints(&client_pk, &self.pk);
    hasher.update(concat_pk.to_bytes_be());
    let uh = hasher.finalize();
    BigUint::from_bytes_be(&uh)
  }

  fn compute_key(&self, n: &BigUint, client_pk: &BigUint, u: &BigUint) -> Vec<u8> {
    let w = (client_pk * mod_exp(&self.v, u, n)) % n;
    let s = mod_exp(&w, &self.sk, n);
    let mut hasher = Sha256::new();
    hasher.update(s.to_bytes_be());
    hasher.finalize().to_vec()
  }
}

struct ClientAbstraction {
  sk: BigUint,
  pub pk: BigUint,
}

impl ClientAbstraction {
  fn define_client(n: &BigUint, g: &BigUint) -> Self {
    let sk = thread_rng().gen_biguint_below(&n);
    let pk = mod_exp(&g, &sk, &n);
    Self { sk, pk }
  }

  fn compute_u(&self, server_pk: &BigUint) -> BigUint {
    let mut hasher = Sha256::new();
    let concat_pk = concat_biguints(&self.pk, server_pk);
    hasher.update(concat_pk.to_bytes_be());
    let uh = hasher.finalize();
    BigUint::from_bytes_be(&uh)
  }

  fn compute_key(
    &self,
    password: &String,
    n: &BigUint,
    g: &BigUint,
    k: &BigUint,
    server_pk: &BigUint,
    salt: &BigUint,
    u: &BigUint,
  ) -> Vec<u8> {
    let x = salt_then_hash_biguint(salt, password);
    // Generate S = (B - k * g**x)**(a + u * x) % N
    let base: BigUint = (server_pk - k * mod_exp(g, &x, &n)) % n;
    let exp: BigUint = (&self.sk + u * x) % (n - BigUint::one());
    let s = mod_exp(&base, &exp, n);
    let mut hasher = Sha256::new();
    hasher.update(s.to_bytes_be());
    hasher.finalize().to_vec()
  }
}

pub struct SrpSimulator {
  server: ServerAbstraction,
  client: ClientAbstraction,
  pub n: BigUint,
  pub g: BigUint,
  pub k: BigUint,
  _email: String,
  password: String,
}

impl SrpSimulator {
  pub fn for_email_password(email: &String, password: &String) -> Self {
    let (n, g, k) = (get_nist_prime(), BigUint::from(2u32), BigUint::from(3u32));
    Self {
      server: ServerAbstraction::define_server(&password, &n, &g, &k),
      client: ClientAbstraction::define_client(&n, &g),
      n,
      g,
      k,
      _email: email.clone(),
      password: password.clone(),
    }
  }

  pub fn validate(&self) -> bool {
    // C sends (email, c_pk) to S. S sends (salt, s_pk) to C
    let server_u = self.server.compute_u(&self.client.pk);
    let client_u = self.client.compute_u(&self.server.pk);
    assert_eq!(server_u, client_u);

    // Both generate the key K
    let server_key = self.server.compute_key(&self.n, &self.client.pk, &server_u);
    let client_key = self.client.compute_key(
      &self.password,
      &self.n,
      &self.g,
      &self.k,
      &self.server.pk,
      &self.server.salt,
      &client_u,
    );
    assert_eq!(server_key, client_key);

    // C sends the digest HMAC(K, salt) to S. I use Sha1HMac because I implemented it, instead of HMAC-SHA256
    let hmac = Sha1HMac::new(&client_key);
    let client_digest: Sha1Digest = hmac.authenticate(&self.server.salt.to_bytes_be());

    // S validates HMAC(K, salt)
    let hmac = Sha1HMac::new(&server_key);
    hmac.verify(&self.server.salt.to_bytes_be(), client_digest)
  }

  pub fn bypass_with_zero_pk(&self) -> bool {
    // Note that in this whole function, C does not use the password! So it does not need to know it
    // C sends (email, 0) to S
    let u = self.server.compute_u(&BigUint::zero()); // I can put whichever multiple of N

    // S = (A * v**u) ** b % N = 0 → K = SHA256(0)
    let key = self.server.compute_key(&self.n, &BigUint::zero(), &u);
    let attacker_key = {
      let mut hasher = Sha256::new();
      hasher.update([0]);
      hasher.finalize().to_vec()
    };
    assert_eq!(key, attacker_key);

    let attacker_hmac = Sha1HMac::new(&attacker_key);
    let attacker_digest: Sha1Digest = attacker_hmac.authenticate(&self.server.salt.to_bytes_be());
    let hmac = Sha1HMac::new(&key);
    hmac.verify(&self.server.salt.to_bytes_be(), attacker_digest)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_srp() {
    let email = String::from("lorenzo@gmail.com");
    let password = String::from("abcdefghijklm");
    let srp = SrpSimulator::for_email_password(&email, &password);
    assert!(srp.validate());
  }

  #[test]
  fn test_bypass() {
    let email = String::from("lorenzo@gmail.com");
    let password = String::from("abcdefghijklm");
    let srp = SrpSimulator::for_email_password(&email, &password);
    assert!(srp.bypass_with_zero_pk());
  }
}
