use cryptopals::utils::{
  algebra::modulo::{inv_mod, mod_exp},
  conversion::hex_string::HexString,
  dsa::{SignatureAlgorithm, DSA},
  mac::sha1::Sha1,
};
use num_bigint::BigUint;

fn main() {
  let message = b"For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n";
  let digest = Sha1::hash(message);
  let expected_digest = HexString::try_from("d2d0714f014a9784047eaeccf956520045c45265")
    .unwrap()
    .as_vector_of_bytes();
  assert_eq!(digest.to_vec(), expected_digest);
  let h = BigUint::from_bytes_be(&digest);

  let (p, q, g) = DSA::with_default_params().get_params();
  let y = BigUint::parse_bytes("84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17".as_bytes(), 16).unwrap();

  // Expected signature
  let r = BigUint::parse_bytes(b"548099063082341131477253921760299949438196259240", 10).unwrap();
  let s = BigUint::parse_bytes(b"857042759984254168557880549501802188789837994940", 10).unwrap();

  // We know that k is between 0 and 2^16 - 1. So we try all those values
  let inv_r = inv_mod(&r, &q).unwrap();
  for k in 0u16..=65535 {
    let x = { // x = (sk - H(m))/r % q
      let mut acc = (&s * &k) % &q;
      acc = (&q + acc - &h) % &q;
      acc = (acc * &inv_r) % &q;
      acc
    };
    println!("{} {}", k, x);
    if mod_exp(&g, &x, &p) == y {
      // solution: k = 16575, x = 125489817134406768603130881762531825565433175625
      let fingerprint = Sha1::hash(&x.to_bytes_be());
      println!(
        "Found key: {}, SHA1: {}",
        &x,
        HexString::from(fingerprint.to_vec())
      );
      break;
    }
  }
}
