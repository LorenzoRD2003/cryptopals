use cryptopals::utils::{
  aes::{
    aes::AES,
    aes_key::AESKey,
    constants::sizes::AES128_KEY_SIZE,
    utils::{pkcs_padding, AESMode},
  },
  conversion::hex_string::HexString,
};
use num::pow;
use rand::{thread_rng, Rng};
use std::collections::{HashMap, HashSet};

type HasherState = u16;
const HASHER_STATE_BYTES: usize = 2;
type Collision = (Vec<u8>, Vec<u8>);

struct Challenge52 {
  key: AESKey,
}

impl Challenge52 {
  fn new() -> Self {
    Self {
      key: AESKey::random_key(AES128_KEY_SIZE).unwrap(),
    }
  }

  fn md<S: AsRef<[u8]>>(&self, msg: &S, h: HasherState) -> HasherState {
    let padded_msg = pkcs_padding(msg, 16);
    let mut h_ = h;
    for (_, &m) in padded_msg.iter().enumerate() { // for M[i] in pad(M)
      let pt = [h_.to_be_bytes().as_ref(), [m].as_ref()].concat();
      let ct = AES::encode(&pt, &self.key, AESMode::ECB).unwrap(); // I choose this compression fn
      h_ = HasherState::from_be_bytes(ct[..HASHER_STATE_BYTES].try_into().unwrap()); // h := C(M[i], h)
    }
    h_
  }
}

fn find_collision(hasher: &Challenge52, h: HasherState) -> Collision {
  let mut digests_set: HashSet<HasherState> = HashSet::new();
  let mut digests_map: HashMap<Vec<u8>, HasherState> = HashMap::new();
  let mut collision: bool = false;
  let mut collision_key1: Vec<u8> = vec![];
  let mut collision_key2: Vec<u8> = vec![];
  let mut rng = thread_rng();

  while !collision {
    let msg: [u8; 8] = rng.gen();
    let padded_msg = pkcs_padding(&msg, 16);
    let digest = hasher.md(&padded_msg, h);

    collision = !digests_set.insert(digest);
    if !collision {
      digests_map.insert(padded_msg, digest);
    } else {
      collision_key1 = digests_map
        .iter()
        .find(|(_, &v)| v == digest)
        .map(|(k, _)| k.clone())
        .unwrap();
      collision_key2 = padded_msg;
    }
  }
  (collision_key1, collision_key2)
}

// Find 2^n collisions. Since we have one collision, we can append whatever we want at the end
fn find_exponential_collisions(hasher: &Challenge52, h: HasherState, n: u8) -> Vec<Collision> {
  assert!(n <= 32);
  let power = pow(2, n as usize);
  let mut result: Vec<Collision> = vec![];
  let (collision_key1, collision_key2) = find_collision(hasher, h);
  for i in 0u32..power {
    let i_bytes = i.to_be_bytes();
    result.push((
      [collision_key1.as_ref(), i_bytes.as_ref()].concat(),
      [collision_key2.as_ref(), i_bytes.as_ref()].concat(),
    ));
  }
  result
}

fn main() {
  let hasher_f = Challenge52::new();
  let hasher_g = Challenge52::new();
  let h: HasherState = 0;
  let n = 16;

  let collisions: Vec<Collision> = find_exponential_collisions(&hasher_f, h, n);
  assert_eq!(collisions.len(), pow(2, n as usize));
  println!("Found exponential collisions!");

  for (ck1, ck2) in collisions {
    // This shows that a hash function f(x) || g(x) created by cascading two hash functions is not stronger.
    // Since we have generated 2^n collisions in f(x), there PROBABLY is a collision in g(x) between them
    if hasher_g.md(&ck1, h) == hasher_g.md(&ck2, h) {
      println!(
        "Found a super collision!!!\nCollision key 1: {}\nCollision key 2: {}",
        HexString::from(ck1),
        HexString::from(ck2)
      );
      break;
    }
  }
}
