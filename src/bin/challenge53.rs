use cryptopals::utils::aes::{
  aes::AES,
  aes_key::AESKey,
  utils::{pkcs_padding, AESMode},
};
use num::pow;
use rand::{rngs::ThreadRng, thread_rng, Rng};
use std::collections::{HashMap, HashSet};

type HasherState = u16;
type Collision = (Vec<u8>, Vec<u8>);

const K: usize = 8; // x will be a message of size 2^k
const TWO_POW_K: usize = 256;
const BLOCK_SIZE: usize = 16;

struct Challenge53 {
  key: AESKey,
}

impl Challenge53 {
  fn new() -> Self {
    Self {
      key: AESKey::random_key(),
    }
  }

  fn md<S: AsRef<[u8]>>(&self, msg: &S, h: HasherState) -> HasherState {
    let padded_msg = pkcs_padding(msg, BLOCK_SIZE as u8);
    let mut h_ = h;
    for &m in padded_msg.iter() {
      let pt = [h_.to_be_bytes().as_ref(), [m].as_ref()].concat();
      let ct = AES::encode(&pt, &self.key, AESMode::ECB).unwrap();
      h_ = u16::from_be_bytes([ct[0], ct[1]]);
    }
    h_
  }
}

fn random_message_of_blocks(
  hasher: &Challenge53,
  rng: &mut ThreadRng,
  blocks: usize,
  initial_state: HasherState,
) -> (Vec<u8>, HasherState) {
  let mut x: Vec<u8> = vec![];
  for _ in 0..blocks {
    let new_block: [u8; 16] = rng.gen();
    x.extend_from_slice(&new_block);
  }
  let hx = hasher.md(&x, initial_state);
  (x, hx)
}

fn find_collision(
  hasher: &Challenge53,
  rng: &mut ThreadRng,
  initial_state: HasherState,
  block_amount: usize,
) -> (HasherState, Collision) {
  let mut one_block_set: HashSet<HasherState> = HashSet::new();
  let mut one_block_map: HashMap<Vec<u8>, HasherState> = HashMap::new();

  for _ in 0..1024 {
    let (mi, hmi) = random_message_of_blocks(&hasher, rng, 1, initial_state);
    if !one_block_set.contains(&hmi) {
      one_block_set.insert(hmi);
      one_block_map.insert(mi, hmi);
    }
  }

  let mut found_collision: bool = false;
  let mut collision: Collision = (vec![], vec![]);
  let mut collision_state: HasherState = 0;
  let (start_point, start_state) =
    random_message_of_blocks(&hasher, rng, block_amount - 1, initial_state);

  while !found_collision {
    let (mi_, hmi_) = random_message_of_blocks(&hasher, rng, 1, start_state);
    found_collision = one_block_set.contains(&hmi_);
    if found_collision {
      collision.0 = one_block_map
        .iter()
        .find(|(_, &v)| v == hmi_)
        .map(|(k, _)| k.clone())
        .unwrap();
      collision.1 = [start_point.clone(), mi_].concat();
      collision_state = hmi_;
    }
  }
  (collision_state, collision)
}

fn main() {
  let hasher = Challenge53::new();
  let initial_state: HasherState = 0;
  let mut state: HasherState = initial_state;
  let mut rng = thread_rng();
  let (x, h_x) = random_message_of_blocks(&hasher, &mut rng, TWO_POW_K, state);

  // We want to find x' such that H(x') = H(x).
  // 1) Find k collisions.
  let mut msgs_1 = vec![];
  let mut msgs_2 = vec![];
  for i in 0..K {
    dbg!(i);
    let (obtained_state, (a, b)) = find_collision(&hasher, &mut rng, state, pow(2, K - 1 - i) + 1);
    msgs_1.push(a);
    msgs_2.push(b);
    state = obtained_state;
  }
  dbg!(msgs_2[0].len());
  let z = state;

  // It is expected that every message conformed by elements of vectors hashes to z
  state = initial_state;
  for i in 0..K {
    let r: bool = thread_rng().gen();
    let chosen: &Vec<u8> = if r { &msgs_1[i] } else { &msgs_2[i] };
    state = hasher.md(chosen, state);
  }
  assert_eq!(z, state);

  // 2) Save all intermediate states
  let mut intermediate_states_set: HashSet<HasherState> = HashSet::new();
  let mut intermediate_states_map: HashMap<usize, HasherState> = HashMap::new();
  state = initial_state;
  for i in 0..TWO_POW_K {
    let x_block: [u8; BLOCK_SIZE] = x[BLOCK_SIZE * i..BLOCK_SIZE * (i + 1)].try_into().unwrap();
    state = hasher.md(&x_block, state);
    intermediate_states_set.insert(state);
    intermediate_states_map.insert(i, state);
  }

  // 3) Find block b such that H_z(b) belongs to the intermediate states
  let mut found: Option<Vec<u8>> = None;
  state = z;
  while found.is_none() {
    let (mi_, hmi_) = random_message_of_blocks(&hasher, &mut rng, 1, state);
    if intermediate_states_set.contains(&hmi_) {
      found = Some(mi_);
      state = hmi_;
    }
  }
  let block = &found.unwrap();

  // 4) Get i from the block
  let j = intermediate_states_map
    .iter()
    .find(|(_, &v)| v == state)
    .map(|(k, _)| k.clone())
    .unwrap();
  assert!(j > K); // Precondition for the next part to work, happens w.h.p.

  // 5) Construct a message of size j with msgs_1 and msgs_2 and extend to have the same image as x
  let mut msg: Vec<u8> = vec![];
  let v = j - K;
  for i in 0..K {
    let bit = (v >> (K - 1 - i)) & 1; // Get the i-th bit
    println!("Bit {}: {}", i, bit);
    if bit == 1 {
      msg.extend_from_slice(&msgs_2[i]);
    } else {
      msg.extend_from_slice(&msgs_1[i]);
    }
  }
  assert_eq!(hasher.md(&msg, initial_state), z);
  msg.extend_from_slice(&block);
  msg.extend_from_slice(&x[(j + 1) * BLOCK_SIZE..]);
  assert_eq!(x.len(), msg.len());

  let h_msg = hasher.md(&msg, initial_state);
  assert_eq!(h_x, h_msg);
}
