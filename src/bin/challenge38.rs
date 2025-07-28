use cryptopals::utils::{
  algebra::{modulo::mod_exp, primes::get_nist_prime},
  mac::{hmac::Sha1HMac, sha1::Sha1Digest},
  srp::salt_then_hash_biguint,
};
use num_bigint::{BigUint, RandBigInt};
use num_traits::{One, Zero};
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha256};

struct ServerAbstraction {
  salt: BigUint,
  v: BigUint,
  u: BigUint,
  sk: BigUint,
  pub pk: BigUint,
}

impl ServerAbstraction {
  fn define_server(password: &str, n: &BigUint, g: &BigUint) -> Self {
    let salt = thread_rng().gen_biguint_below(&(BigUint::one() << 256));
    let x = salt_then_hash_biguint(&salt, password); // x = SHA256(salt | password)
    let v = mod_exp(&g, &x, &n); // v = g^x % n
    let sk = thread_rng().gen_biguint_below(&n); // b random
    let pk = mod_exp(&g, &sk, &n); // B = g^b % n
    let u = thread_rng().gen_biguint_below(&(BigUint::one() << 128)); // u random
    Self { salt, v, u, sk, pk }
  }

  fn compute_key(&self, n: &BigUint, client_pk: &BigUint, u: &BigUint) -> Vec<u8> {
    let w = (client_pk * mod_exp(&self.v, u, n)) % n; // w = A * v^u % n
    let s = mod_exp(&w, &self.sk, n); // s = w^b % n = (A * v^u)^b % n
    let mut hasher = Sha256::new();
    hasher.update(s.to_bytes_be());
    hasher.finalize().to_vec() // K = SHA256(s)
  }
}

struct ClientAbstraction {
  sk: BigUint,
  pub pk: BigUint,
}

impl ClientAbstraction {
  fn define_client(n: &BigUint, g: &BigUint) -> Self {
    let sk = thread_rng().gen_biguint_below(&n); // a random
    let pk = mod_exp(&g, &sk, &n); // A = g^a % n
    Self { sk, pk }
  }

  fn compute_key(
    &self,
    password: &str,
    n: &BigUint,
    server_pk: &BigUint,
    salt: &BigUint,
    u: &BigUint,
  ) -> Vec<u8> {
    let x = salt_then_hash_biguint(salt, password); // x = SHA256(salt | password)
    let s: BigUint = mod_exp(&server_pk, &(&self.sk + u * x), &n); // s = B^(a + ux) % n
    let mut hasher = Sha256::new();
    hasher.update(s.to_bytes_be());
    hasher.finalize().to_vec() // K = SHA256(s)
  }
}

pub struct SrpSimulator {
  server: ServerAbstraction,
  client: ClientAbstraction,
  pub n: BigUint,
  pub g: BigUint,
  _email: String,
  password: String,
}

impl SrpSimulator {
  pub fn for_email_password(email: &str, password: &str) -> Self {
    let (n, g) = (get_nist_prime(), BigUint::from(2u32));
    Self {
      server: ServerAbstraction::define_server(&password, &n, &g),
      client: ClientAbstraction::define_client(&n, &g),
      n,
      g,
      _email: email.into(),
      password: password.into(),
    }
  }

  pub fn validate(&self) -> bool {
    // C sends (email, c_pk = a) to S. S sends (salt, s_pk = b, u) to C
    // Both can generate the key K
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
    // B^(a + ux) = (g^b)^(a + ux) = (g^a * g^ux)^b = (A * v^u)^b (all modulo n) justify this equality of obtained keys

    // C sends the digest HMAC(K, salt) to S. I use Sha1HMac because I implemented it, instead of HMAC-SHA256
    let hmac = Sha1HMac::new(&client_key);
    let client_digest: Sha1Digest = hmac.authenticate(&self.server.salt.to_bytes_be());

    // S validates HMAC(K, salt)
    let hmac = Sha1HMac::new(&server_key);
    hmac.verify(&self.server.salt.to_bytes_be(), client_digest)
  }

  // ODA == Offline-Dictionary-Attack
  pub fn mitm_crack_password(&self, dictionary: &Vec<String>) -> Option<String> {
    // The thing is, M does NOT know the password. He wants the password
    // M sends arbitrary (salt, s_pk, u) to C
    // M chooses salt = 0, u = 1 to simplify the computations
    let (salt, u) = (BigUint::zero(), BigUint::one());
    let client_key = self
      .client
      .compute_key(&self.password, &self.n, &self.server.pk, &salt, &u);
    let hmac = Sha1HMac::new(&client_key);
    let client_digest: Sha1Digest = hmac.authenticate(&salt.to_bytes_be());

    // The dictionary means that M is able to find the word if it is common
    for possible_password in dictionary {
      let possible_key = {
        let x = salt_then_hash_biguint(&salt, possible_password);
        // u = 1 → s = B^a * B^x % n
        let s = mod_exp(&self.server.pk, &(&self.client.sk + &x), &self.n);
        let mut hasher = Sha256::new();
        hasher.update(s.to_bytes_be());
        hasher.finalize().to_vec()
      };
      let hmac = Sha1HMac::new(&possible_key);
      if hmac.verify(&salt.to_bytes_be(), client_digest) {
        return Some(possible_password.clone());
      }
    }
    None
  }
}

fn main() {
  let email = String::from("lorenzo@gmail.com");
  let password = String::from("abcdefghijklm");
  let srp = SrpSimulator::for_email_password(&email, &password);
  assert!(srp.validate());
  println!("The SRP simulation runs correctly.");

  // Dictionary attack
  let possible_passwords = vec![
    String::from("HOLAQUETAL"),
    String::from("BOCAJUNIORS"),
    String::from("AguanteLionelMessi"),
    String::from("MiltonGimenezElHuracan"),
    String::from("ParalelePIPEDO"),
    String::from("MCLPLODLK"),
    String::from("Hubieras ganado las elecciones"),
    String::from("EsExactamenteLoQueVote"),
    String::from("JumanjiTop1PelisDeLaInfancia"),
    String::from("BUUUUUUUUEEEEEEEEEEEEEE"),
  ];
  let index = thread_rng().gen_range(0..possible_passwords.len());
  let crackable_srp = SrpSimulator::for_email_password(&email, &possible_passwords[index]);
  let result = crackable_srp.mitm_crack_password(&possible_passwords);
  assert!(result.is_some());
  println!("{}", result.unwrap());
}
