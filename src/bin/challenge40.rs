use cryptopals::utils::{algebra::{cbrt, inv_mod}, rsa::RSA};
use num_bigint::BigUint;

fn main() {
  let plaintext = String::from("BOCA");
  let keys_1 = RSA::generate_keys_with_given_size(64);
  let keys_2 = RSA::generate_keys_with_given_size(64);
  let keys_3 = RSA::generate_keys_with_given_size(64);

  let result = {
    let (c1, c2, c3) = (
      BigUint::from_bytes_be(RSA::encrypt_with_key(&keys_1.pk, &plaintext).as_ref()),
      BigUint::from_bytes_be(RSA::encrypt_with_key(&keys_2.pk, &plaintext).as_ref()),
      BigUint::from_bytes_be(RSA::encrypt_with_key(&keys_3.pk, &plaintext).as_ref()),
    );
    let (n1, n2, n3) = (keys_1.pk.1, keys_2.pk.1, keys_3.pk.1);
    let (m1, m2, m3) = (&n2 * &n3, &n1 * &n3, &n1 * &n2);
    let n = &n1 * &n2 * &n3;
    let (r1, r2, r3) = (
      &c1 * &m1 * inv_mod(&m1, &n1).unwrap(),
      &c2 * &m2 * inv_mod(&m2, &n2).unwrap(),
      &c3 * &m3 * inv_mod(&m3, &n3).unwrap(),
    );
    let r = (r1 + r2 + r3) % n;
    cbrt(&r)
  };
  dbg!(String::from_utf8_lossy(result.to_bytes_be().as_ref()));
  assert_eq!(plaintext.as_bytes().to_vec(), result.to_bytes_be())
}
