use cryptopals::utils::{
  algebra::modulo::mod_exp,
  conversion::conversion::base64_to_bytes_vector,
  rsa::{RSAKeys, RSA},
};
use num_bigint::BigUint;
use num_traits::{One, Zero};

/*
  Let c be a RSA ciphertext (d, e, n). c = m^e (mod n) we do not know d.
  Given c, the oracle returns true iff m = c^d (mod n) is odd.
  We can double the ciphertext → c1 = 2^e c (mod n)
  c1^d = 2^(ed) c^d = 2m (mod n)

  Observe as 0 <= m < n then 0 <= 2m < 2n and since 2m is even and n = pq is odd,
  there are two cases:
    - m <= n/2: 2m <= n and 2m (mod n) is even
    - m > n/2: 2m > n and 2m (mod n) is odd (2m - n is odd)
  So the oracle will return true iff m > n/2 (in half the cases)

  The thing is, we can do this many times, each one reducing by half the search space.
  So the first time it will tell us the first bit of m.
  We can double it again to get the second bit! c2 = 2^e c1 (mod n) → c2^d = 4m (mod n)
    - If it was m <= n/2, then now we are checking if m <= n/4.
    - If it was m > n/2, then now we are checking if m <= 3/4 n
      (If 4m > 3n: 4m - 3n is odd. If not, 4m - 2n is even.)
  And so on to get m bit-by-bit.
*/

struct RSAParityOracle {
  keys: RSAKeys,
}

impl RSAParityOracle {
  fn start(bits: u64) -> Self {
    Self {
      keys: RSA::generate_keys_with_given_size(bits),
    }
  }

  fn get_pk(&self) -> (BigUint, BigUint) {
    self.keys.pk.clone()
  }

  fn encrypt<S: AsRef<[u8]>>(&self, plaintext: &S) -> Vec<u8> {
    RSA::encrypt_with_key(&self.keys.pk, plaintext)
  }

  fn is_plaintext_odd<S: AsRef<[u8]>>(&self, ciphertext: &S) -> bool {
    let plaintext = RSA::decrypt_with_key(&self.keys.sk, ciphertext);
    let num = BigUint::from_bytes_be(plaintext.as_ref());
    num % BigUint::from(2u8) == BigUint::one()
  }
}

fn main() {
  let base64_str = "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==";
  let plaintext = base64_to_bytes_vector(base64_str).unwrap_or(vec![]);
  dbg!(plaintext.len());

  //let plaintext = b"AGUANTE BOCA";
  let oracle = RSAParityOracle::start(1024);
  let ciphertext = oracle.encrypt(&plaintext);
  let (e, n) = oracle.get_pk();
  let two = BigUint::from(2u8);
  let (mut lower_bound, mut upper_bound) = (BigUint::zero(), n.clone());

  let mut k = n.clone();
  let mut ct0 = ciphertext.clone();
  let factor = mod_exp(&two, &e, &n);

  for i in 0..n.bits() {
    k /= &two;
    let ct1 = {
      let c = BigUint::from_bytes_be(&ct0);
      let c_ = (&factor * &c) % &n;
      c_.to_bytes_be()
    };
    ct0 = ct1.clone();
    if oracle.is_plaintext_odd(&ct1) {
      lower_bound += &k;
    } else {
      upper_bound -= &k;
    }
    println!("{} {}", i, String::from_utf8_lossy(upper_bound.to_bytes_be().as_ref()));
  }
  // another thing that is possible is to remove padding
}
