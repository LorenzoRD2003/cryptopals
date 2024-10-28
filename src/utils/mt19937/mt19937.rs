use super::constants::*;

pub struct MT19937TwisterRNG {
  states: [u32; N],
  index: usize,
}

impl MT19937TwisterRNG {
  pub fn initialize(seed: u32) -> Self {
    let mut states = [0u32; N];
    states[0] = seed;
    for i in 1..N {
      states[i] = F * states[i - 1] ^ (states[i - 1] >> (W - 2)) + (i as u32);
    }
    Self { states, index: 0 }
  }

  pub fn extract_number(&mut self) -> u32 {
    // Need to generate N new numbers
    if self.index == N {
      self.twist();
    }
    let mut y = self.states[self.index];
    y ^= (y >> U) ^ (y << (W - U)); // Shift right and left
    y ^= (y << S) & Self::mask(S);
    y ^= (y << T) & Self::mask(T);
    y ^= y >> L;
    self.index += 1;
    return y;
  }

  fn twist(&mut self) {
    for i in 0..N {
      let x = (self.states[i] & 0x80000000) + (self.states[(i + 1) % N] & 0x7FFFFFFF);
      let mut x_a = x >> 1;
      if x & 1 != 0 {
        x_a ^= A;
      }
      self.states[i] = self.states[(i + M) % N] ^ x_a;
    }
    self.index = 0;
  }

  fn mask(k: u32) -> u32 {
    assert!(k < 64);
    (1 << k) - 1
  }
}
