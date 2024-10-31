use super::sha1::{Sha1, Sha1Block, Sha1Digest, SHA1_BLOCK_SIZE};

pub struct Sha1HMac {
  key: Vec<u8>,
}

impl Sha1HMac {
  pub fn new<S: AsRef<[u8]>>(key: &S) -> Self {
    Self {
      key: key.as_ref().to_vec(),
    }
  }

  pub fn authenticate<S: AsRef<[u8]>>(&self, message: &S) -> Sha1Digest {
    let k_: Sha1Block = self.get_blocksize_key();
    let opad: Sha1Block = [0x5c; SHA1_BLOCK_SIZE];
    let ipad: Sha1Block = [0x36; SHA1_BLOCK_SIZE];
    let inner_message = [Self::xor_blocks(&k_, &ipad), message.as_ref().to_vec()].concat();
    let outer_message = [Self::xor_blocks(&k_, &opad), Sha1::hash(&inner_message).to_vec()].concat();
    Sha1::hash(&outer_message)
  }

  pub fn verify<S: AsRef<[u8]>>(&self, message: &S, expected: Sha1Digest) -> bool {
    self.authenticate(message) == expected
  }

  fn get_blocksize_key(&self) -> Sha1Block {
    let mut blocksize_key = if self.key.len() > SHA1_BLOCK_SIZE {
      Sha1::hash(&self.key).to_vec()
    } else {
      self.key.clone()
    };
    blocksize_key.resize(64, 0);
    blocksize_key.try_into().unwrap()
  }

  fn xor_blocks(bytes1: &Sha1Block, bytes2: &Sha1Block) -> Vec<u8> {
    assert_eq!(bytes1.len(), bytes2.len());
    bytes1
      .as_ref()
      .into_iter()
      .zip(bytes2.as_ref().into_iter())
      .map(|(a, b)| a ^ b)
      .collect()
  }
}

#[cfg(test)]
mod tests {
  use crate::utils::conversion::hex_string::HexString;

use super::*;

  #[test]
  fn test_sha1_hmac_base() {
    let key = b"HOLA COMO VA";
    let message = b"AGUANTE EL CLUB ATLETICO Y RECREATIVO GENERAL SAN MARTIN DE LAS ESCOBAS";
    let hmac = Sha1HMac::new(&key);
    let digest = hmac.authenticate(message);
    assert_eq!(
      HexString::try_from(digest.to_vec()).unwrap(),
      HexString::try_from("ec4a5c188f50d378c66730b435052aedbb1bb6f4").unwrap()
    );
    assert!(hmac.verify(&message, digest));
  }

  #[test]
  fn test_sha1_hmac_authenticate_longkey() {
    let key = b"AGUANTE EL CLUB ATLETICO Y RECREATIVO GENERAL SAN MARTIN DE LAS ESCOBAS";
    let message = b"AGUANTE EL CLUB ATLETICO Y RECREATIVO GENERAL SAN MARTIN DE LAS ESCOBAS";
    let hmac = Sha1HMac::new(&key);
    let digest = hmac.authenticate(message);
    assert_eq!(
      HexString::try_from(digest.to_vec()).unwrap(),
      HexString::try_from("4f831c69ba2b801202973dd79b133b39bf6bcd44").unwrap()
    );
  }
}
