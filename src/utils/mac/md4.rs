// Implementation adapted from https://rosettacode.org/wiki/MD4
type MD4Digest = [u8; 16];
const MD4_BLOCK_SIZE: usize = 64;

fn f(w: u32, y: u32, z: u32) -> u32 {
  (w & y) | (!w & z)
}
fn g(w: u32, y: u32, z: u32) -> u32 {
  (w & y) | (w & z) | (y & z)
}
fn h(w: u32, y: u32, z: u32) -> u32 {
  w ^ y ^ z
}

macro_rules! md4round1 {
  ( $a:expr, $b:expr, $c:expr, $d:expr, $i:expr, $s:expr, $x:expr) => {{
    $a = ($a.wrapping_add(f($b, $c, $d)).wrapping_add($x[$i])).rotate_left($s);
  }};
}

macro_rules! md4round2 {
  ( $a:expr, $b:expr, $c:expr, $d:expr, $i:expr, $s:expr, $x:expr) => {{
    $a = ($a
      .wrapping_add(g($b, $c, $d))
      .wrapping_add($x[$i])
      .wrapping_add(0x5a827999_u32))
    .rotate_left($s);
  }};
}

macro_rules! md4round3 {
  ( $a:expr, $b:expr, $c:expr, $d:expr, $i:expr, $s:expr, $x:expr) => {{
    $a = ($a
      .wrapping_add(h($b, $c, $d))
      .wrapping_add($x[$i])
      .wrapping_add(0x6ed9eba1_u32))
    .rotate_left($s);
  }};
}

pub struct MD4 {
  states: [u32; 4],
  buf: Vec<u8>,
  data_len: u64,
}

impl MD4 {
  pub fn new() -> Self {
    Self {
      states: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
      buf: Vec::new(),
      data_len: 0,
    }
  }

  pub fn update<S: AsRef<[u8]>>(&mut self, data: &S) {
    self.buf.extend_from_slice(data.as_ref());
    self.data_len += data.as_ref().len() as u64;
    while self.buf.len() >= MD4_BLOCK_SIZE {
      let block: [u8; MD4_BLOCK_SIZE] = self.buf[..MD4_BLOCK_SIZE].try_into().unwrap();
      self.buf.drain(..MD4_BLOCK_SIZE);
      self.process_block(&block);
    }
  }

  pub fn finalize(&mut self) -> MD4Digest {
    let mut padded_buf = self.buf.clone();
    let len = self.data_len * 8;
    padded_buf.push(0x80);
    while padded_buf.len() % MD4_BLOCK_SIZE != 56 {
      padded_buf.push(0);
    }
    padded_buf.extend_from_slice(&len.to_be_bytes());

    for block in padded_buf.chunks(MD4_BLOCK_SIZE) {
      self.process_block(block.try_into().unwrap());
    }

    let result: MD4Digest = [
      self.states[0].to_le_bytes(),
      self.states[1].to_le_bytes(),
      self.states[2].to_le_bytes(),
      self.states[3].to_le_bytes(),
    ]
    .concat()
    .try_into()
    .unwrap();
    result
  }

  fn process_block(&mut self, block: &[u8; MD4_BLOCK_SIZE]) {
    // Everything after this operates on 32-bit words, so reinterpret the block.
    let w = Self::convert_bytes(block);

    let mut a = self.states[0];
    let mut b = self.states[1];
    let mut c = self.states[2];
    let mut d = self.states[3];

    let aa = a;
    let bb = b;
    let cc = c;
    let dd = d;

    md4round1!(a, b, c, d, 0, 3, w);
    md4round1!(d, a, b, c, 1, 7, w);
    md4round1!(c, d, a, b, 2, 11, w);
    md4round1!(b, c, d, a, 3, 19, w);
    md4round1!(a, b, c, d, 4, 3, w);
    md4round1!(d, a, b, c, 5, 7, w);
    md4round1!(c, d, a, b, 6, 11, w);
    md4round1!(b, c, d, a, 7, 19, w);
    md4round1!(a, b, c, d, 8, 3, w);
    md4round1!(d, a, b, c, 9, 7, w);
    md4round1!(c, d, a, b, 10, 11, w);
    md4round1!(b, c, d, a, 11, 19, w);
    md4round1!(a, b, c, d, 12, 3, w);
    md4round1!(d, a, b, c, 13, 7, w);
    md4round1!(c, d, a, b, 14, 11, w);
    md4round1!(b, c, d, a, 15, 19, w);

    md4round2!(a, b, c, d, 0, 3, w);
    md4round2!(d, a, b, c, 4, 5, w);
    md4round2!(c, d, a, b, 8, 9, w);
    md4round2!(b, c, d, a, 12, 13, w);
    md4round2!(a, b, c, d, 1, 3, w);
    md4round2!(d, a, b, c, 5, 5, w);
    md4round2!(c, d, a, b, 9, 9, w);
    md4round2!(b, c, d, a, 13, 13, w);
    md4round2!(a, b, c, d, 2, 3, w);
    md4round2!(d, a, b, c, 6, 5, w);
    md4round2!(c, d, a, b, 10, 9, w);
    md4round2!(b, c, d, a, 14, 13, w);
    md4round2!(a, b, c, d, 3, 3, w);
    md4round2!(d, a, b, c, 7, 5, w);
    md4round2!(c, d, a, b, 11, 9, w);
    md4round2!(b, c, d, a, 15, 13, w);

    md4round3!(a, b, c, d, 0, 3, w);
    md4round3!(d, a, b, c, 8, 9, w);
    md4round3!(c, d, a, b, 4, 11, w);
    md4round3!(b, c, d, a, 12, 15, w);
    md4round3!(a, b, c, d, 2, 3, w);
    md4round3!(d, a, b, c, 10, 9, w);
    md4round3!(c, d, a, b, 6, 11, w);
    md4round3!(b, c, d, a, 14, 15, w);
    md4round3!(a, b, c, d, 1, 3, w);
    md4round3!(d, a, b, c, 9, 9, w);
    md4round3!(c, d, a, b, 5, 11, w);
    md4round3!(b, c, d, a, 13, 15, w);
    md4round3!(a, b, c, d, 3, 3, w);
    md4round3!(d, a, b, c, 11, 9, w);
    md4round3!(c, d, a, b, 7, 11, w);
    md4round3!(b, c, d, a, 15, 15, w);

    self.states = [
      a.wrapping_add(aa),
      b.wrapping_add(bb),
      c.wrapping_add(cc),
      d.wrapping_add(dd),
    ];
  }

  fn convert_bytes(bytes: &[u8; MD4_BLOCK_SIZE]) -> Vec<u32> {
    bytes
      .chunks(4)
      .map(|chunk| {
        let bytes = [chunk[0], chunk[1], chunk[2], chunk[3]];
        u32::from_le_bytes(bytes)
      })
      .collect()
  }
}

pub struct MD4MAC {
  key: Vec<u8>,
}

impl MD4MAC {
  pub fn new<S: AsRef<[u8]>>(key: &S) -> Self {
    Self {
      key: key.as_ref().to_vec(),
    }
  }

  pub fn authenticate<S: AsRef<[u8]>>(&self, message: &S) -> MD4Digest {
    let mut hash_fn = MD4::new();
    hash_fn.update(&self.key);
    hash_fn.update(message);
    hash_fn.finalize()
  }

  pub fn verify<S: AsRef<[u8]>>(&self, message: &S, wpected: MD4Digest) -> bool {
    self.authenticate(message) == wpected
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::utils::conversion::hex_string::HexString;

  #[test]
  fn test_md4() {
    let mut hash_fn = MD4::new();
    hash_fn.update(b"Rosetta Code");
    let digest = hash_fn.finalize();
    assert_eq!(
      HexString::try_from(digest.to_vec()).unwrap(),
      HexString::try_from("a52bcfc6a0d0d300cdc5ddbfbefe478b").unwrap()
    );
  }

  #[test]
  fn test_md4_sha1() {
    let mac = MD4MAC::new(b"Rosetta");
    let digest = mac.authenticate(b" Code");
    assert_eq!(
      HexString::try_from(digest.to_vec()).unwrap(),
      HexString::try_from("a52bcfc6a0d0d300cdc5ddbfbefe478b").unwrap()
    );
  }
}
