use std::collections::HashSet;

use cryptopals::utils::{
  algebra::modulo::{inv_mod, mod_exp}, padding::pkcs1_unpad, rsa::{RSAKeys, RSA}
};
use num::Integer;
use num_bigint::{BigUint, RandBigInt};
use num_traits::{One, Zero};
use rand::thread_rng;

#[derive(Clone)]
struct RSAPaddingOracle {
  keys: RSAKeys,
  calls: u64,
}

impl RSAPaddingOracle {
  const E: u64 = 65537;

  fn start(bits: usize) -> Self {
    Self {
      keys: RSA::generate_keys_with_given_params(&BigUint::from(Self::E), bits),
      calls: 0
    }
  }

  fn get_pk(&self) -> (BigUint, BigUint) {
    self.keys.pk.clone()
  }

  fn encrypt<S: AsRef<[u8]>>(&self, plaintext: &S) -> Vec<u8> {
    RSA::encrypt_with_key(&self.keys.pk, plaintext)
  }

  /*
    This should be the full check but the probability of working is high with the previous one, and much faster.
    if plaintext.len() < 11 || plaintext[0] != 0x00 && plaintext[1] != 0x02 {
      return false;
    }
    for i in 2..=9 {
      if plaintext[i] == 0x00 {
        return false;
      }
    }
    for i in 10..plaintext.len() {
      if plaintext[i] == 0x00 {
        return true;
      }
    }
    false
  */
  fn has_pkcs_padding(&mut self, c: &BigUint) -> bool {
    self.calls += 1;
    let (d, n) = &self.keys.sk;
    let n_size = ((n.bits() + 7) / 8) as usize;
    let plaintext = mod_exp(&c, &d, &n).to_bytes_be();
    let zeros = n_size - plaintext.len();
    let with_trailing_zeros = [vec![0x00; zeros], plaintext].concat();
    with_trailing_zeros.len() > 11
      && with_trailing_zeros[0] == 0x00
      && with_trailing_zeros[1] == 0x02
  }
}

struct BleichenbacherAttack<'a> {
  oracle: &'a mut RSAPaddingOracle,
  e: BigUint,
  n: BigUint,
  b: BigUint,
  c0: BigUint,
  s: Vec<BigUint>,
  intervals: HashSet<(BigUint, BigUint)>,
  i: usize,
}

impl<'a> BleichenbacherAttack<'a> {
  pub fn start_step1<S: AsRef<[u8]>>(oracle: &'a mut RSAPaddingOracle, ciphertext: &S) -> Self {
    let (e, n) = oracle.get_pk();
    let b = {
      let k = (n.bits() + 7) / 8;
      let exponent = 8 * (k - 2);
      mod_exp(&BigUint::from(2u8), &BigUint::from(exponent), &n)
    };
    let c = BigUint::from_bytes_be(ciphertext.as_ref());
    let mut s0: BigUint;
    let mut c0: BigUint;
    let mut rng = thread_rng();
    loop {
      // this step is because the expected m may not be pkcs padded
      s0 = rng.gen_biguint_range(&BigUint::zero(), &n);
      c0 = (&c * mod_exp(&s0, &e, &n)) % &n;
      if oracle.calls % 100 == 0 {
        println!("{}", oracle.calls);
      }
      if oracle.has_pkcs_padding(&c0) {
        break;
      }
    }
    let mut intervals: HashSet<(BigUint, BigUint)> = HashSet::new();
    intervals.insert((BigUint::from(2u8) * &b, BigUint::from(3u8) * &b));
    Self {
      oracle,
      e,
      n,
      b: b.clone(),
      c0,
      s: vec![s0],
      intervals,
      i: 1,
    }
  }

  pub fn get_solution(&mut self) -> BigUint {
    dbg!(2);
    let (mut a, mut b) = self.get_interval();
    while self.intervals.len() > 1 || a < b {
      dbg!(self.intervals.len(), &a, &b, self.oracle.calls);
      let si = self.step2();
      self.s.push(si);
      self.step3();
      self.i = self.i + 1;
      (a, b) = self.get_interval();
    }
    (a * inv_mod(&self.s[0], &self.n).unwrap()) % &self.n
  }

  fn get_interval(&self) -> (BigUint, BigUint) {
    let intervals = self.intervals.clone();
    intervals.iter().next().unwrap().clone()
  }

  fn step2(&mut self) -> BigUint {
    if self.i == 1 {
      self.step2a() // This step works as a heuristic for more efficiency
    } else if self.intervals.len() > 1 {
      self.step2b() // It is expected to execute this one only once
    } else {
      self.step2c() // This step works as a heuristic for more efficiency
    }
  }

  fn step2a(&mut self) -> BigUint {
    let mut s1 = self.n.div_ceil(&(BigUint::from(3u8) * &self.b));
    loop {
      let c1 = (&self.c0 * mod_exp(&s1, &self.e, &self.n)) % &self.n;
      if self.oracle.has_pkcs_padding(&c1) {
        break;
      }
      s1 += BigUint::one();
    }
    s1
  }

  fn step2b(&mut self) -> BigUint {
    let mut si = &self.s[self.i - 1] + BigUint::one();
    loop {
      let ci = (&self.c0 * mod_exp(&si, &self.e, &self.n)) % &self.n;
      if self.oracle.has_pkcs_padding(&ci) {
        break;
      }
      si += BigUint::one();
    }
    si
  }

  fn step2c(&mut self) -> BigUint {
    let (a, b) = &self.intervals.iter().next().unwrap();
    let (two, three) = (BigUint::from(2u8), BigUint::from(3u8));
    let mut ri: BigUint = &two * (b * &self.s[self.i - 1] - &two * &self.b).div_ceil(&self.n);
    let mut si: BigUint;
    let mut found = false;
    loop {
      si = (&two * &self.b + &ri * &self.n).div_ceil(b);
      let s_ub = (&three * &self.b + &ri * &self.n).div_floor(a);
      while si <= s_ub {
        let ci = (&self.c0 * mod_exp(&si, &self.e, &self.n)) % &self.n;
        if self.oracle.has_pkcs_padding(&ci) {
          found = true;
          break;
        }
        si += BigUint::one();
      }
      if found {
        break;
      }
      ri += BigUint::one();
    }
    si
  }

  /*
    Construction of intervals M_i.
    We have s_i such that (c0 (s_i)^e)^d = m0 s_i mod n is PKCS padded
    This means 2B <= m0 s_i mod n <= 3B - 1, and so there exists r such that 2B <= m0 s_i - rn <= 3B - 1
    implying (2B + rn)/s_i <= m0 <= (3B - 1 + rn)/s_i.

    So we test for every possible value of r. Doing the math...  (m0 s_i - 3B + 1)/n <= r <= (m0 s_i - 2B)/n
    The thing is, we do not know m0 either. But it is in at least one interval [a,b] in M_i-1: a <= m0 <= b
    Then, we test for all valid triples (a,b,r) with [a,b] in M_i-1 such that (a s_i - 3B + 1)/n <= r <= (b s_i - 2B)/n
  */
  fn step3(&mut self) {
    let si = &self.s[self.i];
    let intervals = self.intervals.clone();
    let mut new_intervals = HashSet::new();
    let (one, two, three) = (BigUint::one(), BigUint::from(2u8), BigUint::from(3u8));

    for (a, b) in intervals {
      let mut r = (&a * si - &three * &self.b + &one).div_ceil(&self.n);
      let r_ub = (&b * si - &two * &self.b).div_floor(&self.n);
      while r <= r_ub {
        let new_a = {
          let a_ = (&two * &self.b + &r * &self.n).div_ceil(&si);
          a.clone().max(a_)
        };
        let new_b = {
          let b_ = (&three * &self.b - &one + &r * &self.n).div_floor(&si);
          b.clone().min(b_)
        };
        new_intervals.insert((new_a, new_b));
        r += BigUint::one();
      }
    }
    self.intervals = new_intervals;
  }
}

fn main() {
  let secret_message = b"Aguante Boca";
  //let mut oracle = RSAPaddingOracle::start(128); // CHALLENGE 47
  let mut oracle = RSAPaddingOracle::start(512); // CHALLENGE 48
  let ciphertext = oracle.encrypt(&secret_message);

  dbg!(1);
  let mut algorithm = BleichenbacherAttack::start_step1(&mut oracle, &ciphertext);
  let m = algorithm.get_solution();
  let solution = [vec![0x00], m.to_bytes_be()].concat();
  let unpadded_solution = pkcs1_unpad(&solution);
  dbg!(&m);
  println!("{}", String::from_utf8_lossy(&unpadded_solution));
}
