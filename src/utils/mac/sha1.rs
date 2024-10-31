type SHA1Digest = [u8; 20];
pub const SHA1_BLOCK_SIZE: usize = 64;

pub struct SHA1 {
  h: [u32; 5],
  buf: Vec<u8>,
  data_len: u64
}

impl SHA1 {
  pub fn new() -> Self {
    Self {
      h: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
      buf: Vec::new(),
      data_len: 0
    }
  }

  pub fn update<S: AsRef<[u8]>>(&mut self, data: &S) {
    self.buf.extend_from_slice(data.as_ref());
    self.data_len += data.as_ref().len() as u64;
    while self.buf.len() >= SHA1_BLOCK_SIZE {
      let block: [u8; SHA1_BLOCK_SIZE] = self.buf[..SHA1_BLOCK_SIZE].try_into().unwrap();
      self.buf.drain(..SHA1_BLOCK_SIZE);
      self.process_block(&block);
    }
  }

  pub fn finalize(&mut self) -> SHA1Digest {
    let mut padded_buf = self.buf.clone();
    let len = self.data_len * 8;
    padded_buf.push(0x80);
    while padded_buf.len() % SHA1_BLOCK_SIZE != 56 {
      padded_buf.push(0);
    }
    padded_buf.extend_from_slice(&len.to_be_bytes());

    for block in padded_buf.chunks(SHA1_BLOCK_SIZE) {
      self.process_block(block.try_into().unwrap());
    }

    let mut result: SHA1Digest = [0u8; 20];
    for (i, &h) in self.h.iter().enumerate() {
      result[4 * i..4 * (i + 1)].copy_from_slice(&h.to_be_bytes());
    }
    result
  }

  fn process_block(&mut self, block: &[u8; SHA1_BLOCK_SIZE]) {
    let mut words = [0u32; 80];

    for i in 0..16 {
      words[i] = u32::from_be_bytes(block[i * 4..(i + 1) * 4].try_into().unwrap());
    }

    for i in 16..80 {
      words[i] = Self::rotate_left(
        words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16],
        1,
      );
    }

    let (mut a, mut b, mut c, mut d, mut e) =
      (self.h[0], self.h[1], self.h[2], self.h[3], self.h[4]);

    for i in 0..80 {
      let f;
      let k;

      if i < 20 {
        f = (b & c) | ((!b) & d);
        k = 0x5A827999;
      } else if i < 40 {
        f = b ^ c ^ d;
        k = 0x6ED9EBA1;
      } else if i < 60 {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8F1BBCDC;
      } else {
        f = b ^ c ^ d;
        k = 0xCA62C1D6;
      }

      let temp = Self::rotate_left(a, 5)
        .wrapping_add(f)
        .wrapping_add(e)
        .wrapping_add(k)
        .wrapping_add(words[i]);
      e = d;
      d = c;
      c = Self::rotate_left(b, 30);
      b = a;
      a = temp;
    }

    self.h[0] = self.h[0].wrapping_add(a);
    self.h[1] = self.h[1].wrapping_add(b);
    self.h[2] = self.h[2].wrapping_add(c);
    self.h[3] = self.h[3].wrapping_add(d);
    self.h[4] = self.h[4].wrapping_add(e);
  }

  fn rotate_left(value: u32, amount: u32) -> u32 {
    (value << amount) | (value >> (32 - amount))
  }

  pub fn new_with_fixed_state(h: [u32; 5], data_len: u64) -> Self { // allow this for Challenge 29
    Self {
      h,
      buf: Vec::new(),
      data_len
    }
  }
}

pub struct SHA1MAC {
  key: Vec<u8>,
}

impl SHA1MAC {
  pub fn new<S: AsRef<[u8]>>(key: &S) -> Self {
    Self {
      key: key.as_ref().to_vec(),
    }
  }

  pub fn authenticate<S: AsRef<[u8]>>(&self, message: &S) -> SHA1Digest {
    let mut hash_fn = SHA1::new();
    hash_fn.update(&self.key);
    hash_fn.update(message);
    hash_fn.finalize()
  }

  pub fn verify<S: AsRef<[u8]>>(&self, message: &S, expected: SHA1Digest) -> bool {
    self.authenticate(message) == expected
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::utils::conversion::hex_string::HexString;

  fn hash<S: AsRef<[u8]>>(data: &S) -> SHA1Digest {
    let mut hash_fn = SHA1::new();
    hash_fn.update(data);
    hash_fn.finalize()
  }

  #[test]
  fn test_sha1_only_one_block() {
    let digest1 = hash(b"abc");
    assert_eq!(
      HexString::try_from(digest1.to_vec()).unwrap(),
      HexString::try_from("A9993E364706816ABA3E25717850C26C9CD0D89D").unwrap()
    );
    let digest2 = hash(b"The quick brown fox jumps over the lazy cog");
    assert_eq!(
      HexString::try_from(digest2.to_vec()).unwrap(),
      HexString::try_from("DE9F2C7FD25E1B3AFAD3E85A0BD17D9B100DB4B3").unwrap()
    );
    let digest3 = hash(b"The quick brown fox jumps over the lazy dog");
    assert_eq!(
      HexString::try_from(digest3.to_vec()).unwrap(),
      HexString::try_from("2FD4E1C67A2D28FCED849EE1BB76E7391B93EB12").unwrap()
    );
    let digest4 = hash(b"");
    assert_eq!(
      HexString::try_from(digest4.to_vec()).unwrap(),
      HexString::try_from("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709").unwrap()
    );
  }

  #[test]
  fn test_multiple_data() {
    let mut hash_fn = SHA1::new();
    hash_fn.update(b"ab");
    hash_fn.update(b"c");
    let digest = hash_fn.finalize();
    assert_eq!(
      HexString::try_from(digest.to_vec()).unwrap(),
      HexString::try_from("A9993E364706816ABA3E25717850C26C9CD0D89D").unwrap()
    )
  }

  #[test]
  fn test_sha1_multiple_blocks() {
    let digest1 = hash(b"AGUANTE EL CLUB ATLETICO Y RECREATIVO GENERAL SAN MARTIN DE LAS ESCOBAS");
    assert_eq!(
      HexString::try_from(digest1.to_vec()).unwrap(),
      HexString::try_from("FB5C2CD7783BE22D7EBBC63E69BDBF2018E72078").unwrap()
    );
    let digest2 = hash(b"AGUANTE EL CLUB ATLETICO Y RECREATIVO GENERAL SAN MARTIN DE LAS ");
    assert_eq!(
      HexString::try_from(digest2.to_vec()).unwrap(),
      HexString::try_from("3D696BBE476F4AE7CCA8955C3E1C6F578584FCD9").unwrap()
    );
  }

  #[test]
  fn test_sha1_mac() {
    let secret_key = b"YELLOW SUBMARINE";
    let mac = SHA1MAC::new(secret_key);
    let digest = mac.authenticate(b"HOLA");
    assert_eq!(
      HexString::try_from(digest.to_vec()).unwrap(),
      HexString::try_from("29BEBA5E4112AF916AA62B73505AB76AE61A94F0").unwrap()
    )
  }

  #[test]
  fn test_sha1_mac_verify() {
    let secret_key = b"YELLOW SUBMARINE";
    let mac = SHA1MAC::new(secret_key);
    let digest = mac.authenticate(b"HOLA");
    assert!(mac.verify(b"HOLA", digest));
    assert!(!mac.verify(b"", digest));
  }
}
