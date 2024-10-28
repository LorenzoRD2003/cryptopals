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
      states[i] = (states[i - 1] ^ (states[i - 1] >> (W - 2)))
        .wrapping_mul(F)
        .wrapping_add(i as u32);
    }
    dbg!(states[..3].to_vec());
    Self { states, index: 624 }
  }

  pub fn extract_number(&mut self) -> u32 {
    // Need to generate N new numbers
    if self.index == N {
      self.twist();
    }
    dbg!(self.index);
    let mut y = self.states[self.index];
    self.index += 1;
    dbg!(y);
    y ^= y >> U;
    dbg!(y);
    y ^= (y << S) & B;
    dbg!(y);
    y ^= (y << T) & C;
    dbg!(y);
    y ^= y >> L;
    y
  }

  fn twist(&mut self) {
    for i in 0..N {
      let x = (self.states[i] & UMASK) | (self.states[(i + 1) % N] & LMASK);
      let mut x_a = x >> 1;
      if x & 1 != 0 {
        x_a ^= A;
      }
      self.states[i] = self.states[(i + M) % N] ^ x_a;
    }
    self.index = 0;
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_extract_numbers() {
    let seed: u32 = 5489;
    let mut rng = MT19937TwisterRNG::initialize(seed);
    assert_eq!(rng.extract_number(), 3499211612);
    assert_eq!(rng.extract_number(), 581869302);
    assert_eq!(rng.extract_number(), 3890346734);
    assert_eq!(rng.extract_number(), 3586334585);
    assert_eq!(rng.extract_number(), 545404204);
  }
}
