use std::time::{Duration, SystemTimeError};
use std::thread::sleep;
use std::time::{SystemTime, UNIX_EPOCH};
use rand::{thread_rng, Rng};
use cryptopals::utils::rng::mt19937::MT19937TwisterRNG;

fn get_pseudorandom_number() -> Result<u32, SystemTimeError> {
  sleep(Duration::from_secs(thread_rng().gen_range(10..=40)));
  let time = SystemTime::now()
    .duration_since(UNIX_EPOCH)?
    .as_secs();
  let mut rng = MT19937TwisterRNG::initialize(time as u32);
  sleep(Duration::from_secs(thread_rng().gen_range(10..=40)));
  Ok(rng.extract_number())
}

fn main() -> Result<(), SystemTimeError> {
  let n = get_pseudorandom_number()?;
  // Test it with the different possible times
  let time = SystemTime::now()
    .duration_since(UNIX_EPOCH)?
    .as_secs();
  for i in 10..=82 {
    let possible_seed = (time - i) as u32;
    let mut possible_rng = MT19937TwisterRNG::initialize(possible_seed);
    if possible_rng.extract_number() == n {
      println!("The seed is {}", possible_seed);
      break;
    }
  }
  Ok(())
}