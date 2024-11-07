use num_bigint::{BigUint, RandBigInt};
use num_traits::{One, Zero};
use rand::thread_rng;
use sha2::{Digest, Sha256};

use crate::utils::mac::{hmac::Sha1HMac, sha1::Sha1Digest};

use super::utils::{concat_biguints, get_dh_p, mod_exp, salt_then_hash_biguint};

// ODA == Offline-Dictionary-Attack
struct ServerAbstractionODA {
  salt: BigUint,
  v: BigUint,
  u: BigUint,
  sk: BigUint,
  pub pk: BigUint,
}

impl ServerAbstractionODA {
  fn define_server(password: &String, n: &BigUint, g: &BigUint) -> Self {
    let salt = thread_rng().gen_biguint_below(&(BigUint::one() << 256));
    let x = salt_then_hash_biguint(&salt, password);
    let v = mod_exp(&g, &x, &n);
    let sk = thread_rng().gen_biguint_below(&n);
    let pk = mod_exp(&g, &sk, &n);
    let u = thread_rng().gen_biguint_below(&(BigUint::one() << 128));
    Self { salt, v, u, sk, pk }
  }

  fn compute_key(&self, n: &BigUint, client_pk: &BigUint, u: &BigUint) -> Vec<u8> {
    let w = (client_pk * mod_exp(&self.v, u, n)) % n;
    let s = mod_exp(&w, &self.sk, n);
    let mut hasher = Sha256::new();
    hasher.update(s.to_bytes_be());
    hasher.finalize().to_vec()
  }
}

struct ClientAbstractionODA {
  sk: BigUint,
  pub pk: BigUint,
}

impl ClientAbstractionODA {
  fn define_client(n: &BigUint, g: &BigUint) -> Self {
    let sk = thread_rng().gen_biguint_below(&n);
    let pk = mod_exp(&g, &sk, &n);
    Self { sk, pk }
  }

  fn compute_key(
    &self,
    password: &String,
    n: &BigUint,
    server_pk: &BigUint,
    salt: &BigUint,
    u: &BigUint,
  ) -> Vec<u8> {
    let x = salt_then_hash_biguint(salt, password);
    // Generate S = B ** (a + u*x) % n
    let s: BigUint = mod_exp(&server_pk, &(&self.sk + u * x), &n);
    let mut hasher = Sha256::new();
    hasher.update(s.to_bytes_be());
    hasher.finalize().to_vec()
  }
}

pub struct SrpSimulatorODA {
  server: ServerAbstractionODA,
  client: ClientAbstractionODA,
  pub n: BigUint,
  pub g: BigUint,
  pub k: BigUint,
  _email: String,
  password: String,
}

impl SrpSimulatorODA {
  pub fn for_email_password(email: &String, password: &String) -> Self {
    let (n, g, k) = (get_dh_p(), BigUint::from(2u32), BigUint::from(3u32));
    Self {
      server: ServerAbstractionODA::define_server(&password, &n, &g),
      client: ClientAbstractionODA::define_client(&n, &g),
      n,
      g,
      k,
      _email: email.clone(),
      password: password.clone(),
    }
  }

  pub fn validate(&self) -> bool {
    // C sends (email, c_pk) to S. S sends (salt, s_pk, u) to C
    // Both generate the key K
    let server_key = self
      .server
      .compute_key(&self.n, &self.client.pk, &self.server.u);
    let client_key = self.client.compute_key(
      &self.password,
      &self.n,
      &self.server.pk,
      &self.server.salt,
      &self.server.u,
    );
    assert_eq!(server_key, client_key);

    // C sends the digest HMAC(K, salt) to S. I use Sha1HMac because I implemented it, instead of HMAC-SHA256
    let hmac = Sha1HMac::new(&client_key);
    let client_digest: Sha1Digest = hmac.authenticate(&self.server.salt.to_bytes_be());

    // S validates HMAC(K, salt)
    let hmac = Sha1HMac::new(&server_key);
    hmac.verify(&self.server.salt.to_bytes_be(), client_digest)
  }

  pub fn mitm_crack_password(&self) -> String {
    

    String::from("")
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_srp_oda() {
    let email = String::from("lorenzo@gmail.com");
    let password = String::from("abcdefghijklm");
    let srp = SrpSimulatorODA::for_email_password(&email, &password);
    assert!(srp.validate());
  }
}
