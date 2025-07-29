use cryptopals::utils::{
  algebra::bigint_utils::cbrt,
  conversion::hex_string::HexString,
  mac::sha1::{Sha1, Sha1Digest},
  rsa::{RSAKeys, RSA},
};
use num_bigint::BigUint;
use num_traits::One;

struct SignerVerifierAPI {
  keys: RSAKeys,
}

impl SignerVerifierAPI {
  const E: u64 = 3;
  fn start(bits: usize) -> Self {
    Self {
      keys: RSA::generate_keys_with_given_params(&BigUint::from(Self::E), bits),
    }
  }

  fn sign(&mut self, digest: &Sha1Digest) -> Vec<u8> {
    let asn = HexString::try_from("3021300906052b0e03021a05000414")
      .unwrap()
      .as_vector_of_bytes();
    let data = [asn, digest.to_vec()].concat();
    RSA::encrypt_with_key(&self.keys.sk, &data) // RSA::encrypt_with_key already does PKCS padding
  }

  fn verify<S: AsRef<[u8]>>(&mut self, message: &S, signature: &Vec<u8>) -> bool {
    let expected_digest = Sha1::hash(&message);
    let data = RSA::decrypt_with_key(&self.keys.pk, signature);

    // The first part (up to the last 0x00) is already taken by the PKCS unpadding in RSA::decrypt_by_key
    // 1) Check for ASN
    let asn = HexString::try_from("3021300906052b0e03021a05000414")
      .unwrap()
      .as_vector_of_bytes();
    if !data.starts_with(&asn) {
      return false;
    }

    // 2) Simulate a bad verifier that looks for the digest anywhere
    data
      .windows(expected_digest.len())
      .any(|w| w == expected_digest)
  }

  fn retrieve_pk(&self) -> (BigUint, BigUint) {
    self.keys.pk.clone()
  }
}

/*
  vector de tamaño n_size (tamaño de la pk en bytes)
  00 01 ff ff ff ff 00 DIGEST 00 00 ... 00
  Asi es como se ve un bloque formateado PKCS1.5 antes de ser encriptado. luego, M = vector

  La idea es que un verificador incorrecto solamente va a testear la primera parte (y llegar hasta el digest)
  y no la longitud de lo que viene despues (que sea efectivamente un digest y no algo mas largo)

  El mensaje se encripta haciendo C = M^d (mod n) y se decripta haciendo M = C^e (mod n)
  donde en particular e = 3 y d = 3^-1 (mod phi(n))

  Ahora bien, si podemos tener mensajes que el parser considera como validos dejando ceros al final,
  podemos poner lo que queramos al final. Y que pasa si tenemos suficiente espacio como para hacer un cubo perfecto?
  Podemos hacerle raiz cubica en enteros y daria lo mismo que hacer M^d.
  Entonces, para ese mensaje podriamos construir una firma valida (forge signature) sin conocer d
*/

fn main() {
  let mut api = SignerVerifierAPI::start(1024);
  let message = b"hi mom";
  let digest = Sha1::hash(message);

  // Check sign-verify process works as expected
  let signature = api.sign(&digest);
  assert!(api.verify(message, &signature));
  println!("Signature API works correctly.");

  // We can forge signatures for e = 3 using the bad implementation of hash checking
  let (_e, n) = api.retrieve_pk();
  let n_size = ((n.bits() + 7) / 8) as usize;
  let initial_vec = vec![0x00, 0x01, 0xff, 0xff, 0xff, 0xff, 0x00];
  let asn = HexString::try_from("3021300906052b0e03021a05000414")
    .unwrap()
    .as_vector_of_bytes();
  let number_of_zeros = n_size - initial_vec.len() - asn.len() - digest.len();
  let vector: Vec<u8> = [
    initial_vec,
    asn,
    digest.to_vec(),
    vec![0x00; number_of_zeros],
  ]
  .concat();

  // a is a number of the form a1a2a3..ak0000000000000000000000000000 (in bytes)
  let a = BigUint::from_bytes_be(&vector);
  // and we want to add something that only affects the ending zeros to convert it into a perfect cube
  let root = cbrt(&a) + BigUint::one(); // This is the number representing the valid forged signature

  // when it is cubed by the server (e = 3), the padding and the hash will be correctly parsed
  let forged_signature = root.to_bytes_be();
  assert!(api.verify(message, &forged_signature));
  println!(
    "Forged signature successfully!
    Message: {}
    Signature: {}",
    HexString::from(message.to_vec()).as_text().unwrap(),
    HexString::from(forged_signature)
  );
}
