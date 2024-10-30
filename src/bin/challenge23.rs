use cryptopals::utils::rng::{constants::*, mt19937::MT19937TwisterRNG};
use rand::{thread_rng, Rng};

fn untemper(y: u32) -> u32 {
  let mut y0 = y;
  y0 ^= y0 >> L;
  y0 ^= (y0 << T) & C;
  let m: u32 = 0x0000007f;
  for i in 0..4 {
    let b = B & (m << 7*(i + 1));
    y0 ^= (y0 << S) & b;
  }
  for _ in 0..3 {
    y0 ^= y0 >> U;
  }
  y0
}

fn main() {
  let seed: u32 = thread_rng().gen();
  let mut rng = MT19937TwisterRNG::initialize(seed);
  //let number = rng.extract_number();
  //assert_eq!(seed, untemper(number)); // it works

  let mut nums = [0u32; N];
  for i in 0..N {
    nums[i] = rng.extract_number();
  }
  let states = nums.map(|y| untemper(y));
  let mut new_rng = MT19937TwisterRNG::from_states(states);
  for i in 0..N {
    assert_eq!(nums[i], new_rng.extract_number());
  }
  for _ in 0..N {
    assert_eq!(rng.extract_number(), new_rng.extract_number());
  }
}