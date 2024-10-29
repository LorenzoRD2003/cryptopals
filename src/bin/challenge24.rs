use cryptopals::utils::mt19937::mt19937::MT19937TwisterRNG;
use rand::{thread_rng, Rng};
use std::{thread::sleep, time::{Duration, SystemTime, SystemTimeError, UNIX_EPOCH}};

#[derive(Debug, Clone)]
struct StreamCipher24 {
  seed: u16,
}

impl StreamCipher24 {
  fn from_seed(seed: u16) -> Self {
    Self { seed }
  }

  fn apply_to<S: AsRef<[u8]>>(&self, text: &S) -> Vec<u8> {
    let mut twister = MT19937TwisterRNG::initialize(self.seed as u32);
    let len = text.as_ref().len();
    let stream: Vec<u8> = (0..len).map(|_| twister.extract_number() as u8).collect();
    let mut result: Vec<u8> = vec![];
    for i in 0..len {
      result.push(text.as_ref()[i] ^ stream[i]);
    }
    result
  }
}

fn recover_seed(sc: &StreamCipher24, ciphertext: &Vec<u8>) -> Option<u16> {
  assert!(ciphertext.len() > 0);
  let plaintext = sc.apply_to(ciphertext);
  for possible_seed in 0u16..=65535 {
    let possible_sc = StreamCipher24::from_seed(possible_seed);
    if possible_sc.apply_to(&plaintext) == ciphertext.clone() {
      dbg!(possible_seed);
      return Some(possible_seed);
    }
  }
  None
}

fn password_reset_token<S: AsRef<[u8]>>(password: &S) -> Result<Vec<u8>, SystemTimeError> {
  let current_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
  let sc = StreamCipher24::from_seed(current_time as u16);
  let token = sc.apply_to(password);
  Ok(token)
}

fn check_token_is_prng<S: AsRef<[u8]>, T:AsRef<[u8]>>(password: &S, token: &T) -> Result<bool, SystemTimeError> {
  let max_time: u64 = 600; // token valid for 10 minutes
  let time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
  for i in 0u64..=max_time {
    let sc = StreamCipher24::from_seed((time - i) as u16);
    if sc.apply_to(password) == token.as_ref().to_vec() {
      dbg!(i);
      return Ok(true);
    }
  }
  Ok(false)
}

fn main() -> Result<(), SystemTimeError> {
  let r: usize = thread_rng().gen_range(1..=30);
  let random_part: Vec<u8> = (0..r).map(|_| thread_rng().gen()).collect();
  let known_part = b"aaaaaaaaaaaaaa";
  let plaintext = [random_part, known_part.to_vec()].concat();
  let random_seed: u16 = thread_rng().gen();
  let stream_cipher = StreamCipher24::from_seed(random_seed);
  let ciphertext = stream_cipher.apply_to(&plaintext);
  assert_eq!(plaintext, stream_cipher.apply_to(&ciphertext));
  assert_eq!(
    recover_seed(&stream_cipher, &ciphertext).unwrap_or(0),
    random_seed
  );
  let my_password = "CLUB ATLETICO BOCA JRS";
  let my_token = password_reset_token(&my_password)?;
  dbg!(&my_token);
  sleep(Duration::from_secs(thread_rng().gen_range(10..=30)));
  assert!(check_token_is_prng(&my_password, &my_token)?);
  Ok(())
}
