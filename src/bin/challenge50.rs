use cryptopals::utils::{
  aes::{aes::AES, constants::sizes::AES_BLOCK_SIZE, utils::AESMode},
  conversion::{
    conversion::{xor_bytes_vectors, ConversionError},
    hex_string::HexString,
  },
};

/*
  MAC gives us unforgeatibility (cannot generate a valid tag T for a message M without knowing the key K)
  Hash functions have different properties (public functions, no key, collision-resistant, preimage-resistant)
  Do not use MAC as hash functions.
*/

fn cbc_mac<S: AsRef<[u8]>, T: AsRef<[u8]>>(
  msg: &S,
  key: &T,
  iv: [u8; AES_BLOCK_SIZE],
) -> [u8; AES_BLOCK_SIZE] {
  let cip = AES::encode(msg, &key, AESMode::CBC(iv)).unwrap();
  cip[cip.len() - AES_BLOCK_SIZE..].try_into().unwrap()
}

fn main() -> Result<(), ConversionError> {
  // msg1 = P1 || P2 has padding when using the cbc_mac
  let msg1 = b"alert('MZA who was that?');\n";
  let key = b"YELLOW SUBMARINE";
  let mac1 = cbc_mac(msg1, key, [0; 16]);
  println!(
    "{} has a CBC-MAC of {}",
    String::from_utf8_lossy(msg1.as_ref()),
    HexString::from(mac1.to_vec())
  );

  // msg2 = Q1 || Q2 has exactly two blocks without padding
  // Whatever we put right after msg2 will be ignored because it is behind a JS comment
  let msg2 = b"alert('Ayo, the Wu is back!');//";
  let mac2 = cbc_mac(msg2, key, [0; AES_BLOCK_SIZE]);
  // msg3 = msg2 || B1 || B2 has the same effect as msg2, but its mac3 will be the same as mac1
  let msg3 = {
    let b1 = xor_bytes_vectors(mac2, msg1[..AES_BLOCK_SIZE].as_ref())?; // B1 = MAC2 ^ P1
    let b2 = msg1[AES_BLOCK_SIZE..].as_ref(); // B2 = P2
    [msg2.as_ref(), b1.as_ref(), b2].concat()
  };
  // The important step is CBC-MAC(K, B1 ^ MAC2) = CBC-MAC(K, P1) as in the msg1 encryption
  let mac3 = cbc_mac(&msg3, key, [0; AES_BLOCK_SIZE]);
  /*
    MAC3 = CBC-MAC(K, msg3) = CBC-MAC(K, msg2 || B1 || B2)
         = CBC-MAC(K, (MAC2 ^ B1) || B2)
         = CBC-MAC(K, P1 || P2) (since B1 = MAC2 ^ P1 and B2 = P2)
         = CBC-MAC(K, msg1) = MAC1
  */
  assert_eq!(mac1, mac3);
  println!(
    "{} has a CBC-MAC of {}",
    String::from_utf8_lossy(msg3.as_ref()),
    HexString::from(mac3.to_vec())
  );
  Ok(()) // It works in the DOM!
}
