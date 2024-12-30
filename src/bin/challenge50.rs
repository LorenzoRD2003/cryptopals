use cryptopals::utils::{
  aes::{aes::AES, utils::AESMode},
  conversion::{conversion::xor_bytes_vectors, hex_string::HexString},
};

/*
  MAC gives us unforgeatibility (cannot generate a valid tag T for a message M without knowing the key K)
  Hash functions have different properties (public functions, no key, collision-resistant, preimage-resistant)
  Do not use MAC as hash functions.
*/

fn cbc_mac<S: AsRef<[u8]>, T: AsRef<[u8]>>(msg: &S, key: &T, iv: [u8; 16]) -> [u8; 16] {
  let cip = AES::encode(msg, &key, AESMode::CBC(iv)).unwrap();
  cip[cip.len() - 16..].try_into().unwrap()
}

fn main() {
  // msg1 = P1 || P2 has padding when using the cbc_mac
  let msg1 = b"alert('MZA who was that?');\n";
  let key = b"YELLOW SUBMARINE";
  let mac1 = cbc_mac(msg1, key, [0; 16]);
  println!("{}", HexString::try_from(mac1.to_vec()).unwrap());

  // msg2 = Q1 || Q2 has exactly two blocks without padding
  // Whatever we put right after msg2 will be ignored because it is behind a JS comment
  let msg2 = b"alert('Ayo, the Wu is back!');//";
  let mac2 = cbc_mac(msg2, key, [0; 16]);
  // msg3 = msg2 || B1 || B2 has the same effect as msg2, but its mac3 will be the same as mac1
  let msg3 = {
    let b1 = xor_bytes_vectors(mac2, msg1[..16].as_ref()).unwrap(); // B2 = MAC2 ^ P1
    let b2 = msg1[16..].as_ref(); // B3 = P2
    [msg2.as_ref(), b1.as_ref(), b2].concat()
  };
  // The important step is E(K, B1 ^ MAC2) = E(K, P1) as in the msg1 encryption 
  let mac3 = cbc_mac(&msg3, key, [0; 16]);
  assert_eq!(mac1, mac3);
  println!(
    "{} has a CBC-MAC of {}",
    String::from_utf8_lossy(msg3.as_ref()),
    HexString::try_from(mac1.to_vec()).unwrap()
  );
  // It works in the DOM!
}
