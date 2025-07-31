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
use rand::{rngs::ThreadRng, thread_rng, Rng};
use std::collections::{HashMap, HashSet};

type HasherState = u16;
const HASHER_STATE_BYTES: usize = 2;
type Collision = (Vec<u8>, Vec<u8>); // Represent a collision as a pair of byte vectors

const K: usize = 8; // x will be a message of size 2^k
const TWO_POW_K: usize = 256;
const INITIAL_STATE: HasherState = 0;
const BLOCK_SIZE: usize = 16;

struct Challenge53 {
  key: AESKey,
}

impl Challenge53 {
  fn new() -> Self {
    Self {
      key: AESKey::random_key(AES128_KEY_SIZE).unwrap(),
    }
  }

  fn md<S: AsRef<[u8]>>(&self, msg: &S, h: HasherState) -> HasherState {
    let padded_msg = pkcs_padding(msg, BLOCK_SIZE as u8);
    let mut h_ = h;
    for &m in padded_msg.iter() {
      let pt = [h_.to_be_bytes().as_ref(), [m].as_ref()].concat();
      let ct = AES::encode(&pt, &self.key, AESMode::ECB).unwrap(); // I choose this compression fn
      h_ = HasherState::from_be_bytes(ct[..HASHER_STATE_BYTES].try_into().unwrap());
      // h := C(M[i], h)
    }
    h_
  }
}

/// Generate a random message of `blocks` AES blocks and hash it
/// This returns (x, H(x)) with |x| = blocks
fn random_message_of_blocks(
  hasher: &Challenge53,
  rng: &mut ThreadRng,
  blocks: usize,
  initial_state: HasherState,
) -> (Vec<u8>, HasherState) {
  let mut x: Vec<u8> = vec![];
  for _ in 0..blocks {
    let new_block: [u8; BLOCK_SIZE] = rng.gen();
    x.extend_from_slice(&new_block);
  }
  let hx = hasher.md(&x, initial_state);
  (x, hx)
}

/// This finds a collision between one message of one block and another message of `blocks` blocks.
fn find_collision(
  hasher: &Challenge53,
  rng: &mut ThreadRng,
  previous_state: HasherState,
  blocks: usize,
) -> (HasherState, Collision) {
  // We generate many (m, H(m)) with |m| = 1 (in blocks). This will allow us to obtain collisions of any given length later.
  // one_block_map contains an injective map M -> H(M) such that |M| = 1
  let mut one_block_set: HashSet<HasherState> = HashSet::new(); // Set of H(m) with fixed initial state `previous_state`.
  let mut one_block_map: HashMap<Vec<u8>, HasherState> = HashMap::new(); // Injective map m -> H(m)
  let iters = pow(2, HASHER_STATE_BYTES / 2 + 4);
  for _ in 0..iters {
    let (m, h_m) = random_message_of_blocks(&hasher, rng, 1, previous_state); // |m| = 1
    if !one_block_set.contains(&h_m) {
      // this guarantees that the map is injective
      one_block_set.insert(h_m);
      one_block_map.insert(m, h_m);
    }
  }

  let mut found_collision: bool = false;
  let mut collision: Collision = (vec![], vec![]);
  let mut collision_state: HasherState = 0;
  let (start_point, start_state) =
    random_message_of_blocks(&hasher, rng, blocks - 1, previous_state); // (B, H(B)) with |B| = blocks - 1

  while !found_collision {
    // We generate messages M' of 1 block to find a collision with the one_block_set, but starting from state H(B)
    // This means we are calculating (M', H(B || M')) with |M'| = 1
    let (m, h_m) = random_message_of_blocks(&hasher, rng, 1, start_state);
    // Suppose we find M in one_block set such that H(M) = H(B || M') -> collision with sizes 1, blocks (from fixed previous_state)
    found_collision = one_block_set.contains(&h_m);
    // We do not update the set if it does not contain H(M), since it is not for the same initial_state
    if found_collision {
      collision.0 = one_block_map
        .iter()
        .find(|(_, &v)| v == h_m)
        .map(|(k, _)| k.clone())
        .unwrap(); // this will never fail since one_block_set contains H(M)
      collision.1 = [start_point.clone(), m].concat();
      collision_state = h_m;
    }
  }
  (collision_state, collision)
}

fn main() {
  let hasher = Challenge53::new();
  let initial_state: HasherState = INITIAL_STATE;
  let mut state: HasherState = initial_state;
  let mut rng = thread_rng();
  // We will attack the message x of hash H(x) and size |x| = 2^k blocks
  let (x, h_x) = random_message_of_blocks(&hasher, &mut rng, TWO_POW_K, state);
  println!(
    "Message: {}\nMessage hash: {}",
    HexString::from(x.clone()),
    h_x
  );

  // We want to find x' such that H(x') = H(x). i.e. this is a SECOND PREIMAGE ATTACK
  // The first thing we want to do is to produce a set of multicollision messages of length (k, k + 2^k - 1) for a given k
  // We will generate many collisions (M1, M2) (i.e. such that H(M1) = H(M2)), with |M1| = 1, |M2| = 2^{k-1-i} + 1
  let mut msgs_1 = vec![];
  let mut msgs_2 = vec![];
  for i in (0..K).rev() {
    println!("i: {}", i);
    // we generate a collision of messages of |a| = 1 blocks and |b| = 2^{k-1-i} + 1 blocks respectively.
    let (obtained_state, (a, b)) = find_collision(&hasher, &mut rng, state, pow(2, K - 1 - i) + 1);
    //println!("Obtained state: {}", obtained_state);
    assert_eq!(hasher.md(&a, state), hasher.md(&b, state));
    assert_eq!(hasher.md(&a, state), obtained_state);
    msgs_1.push(a);
    msgs_2.push(b);
    state = obtained_state;
  }
  // We have two vectors of messages MSGS_1, MSGS_2 with MSGS_1[i] = 1, MSGS_2[i] = 2^{k-1-i} + 1.
  // Any message of the form X0X1...Xi with fixed 0 <= i < k and Xi E {MSGS_1[i], MSGS_2[i]} will hash to the same value
  // In particular, for i = k-1 we will have a multicollision of 2^k messages that hash to the same value z.
  // And we will have EXACTLY one of the 2^k messages to be of size j, for each k <= j <= k + 2^k - 1

  let z = state;
  state = initial_state;
  for i in 0..K {
    // SHOULD NOT be a reverse loop
    // Test that H(M) = z for some message M of the 2^k messages
    let chosen: &Vec<u8> = if rng.gen() { &msgs_1[i] } else { &msgs_2[i] };
    state = hasher.md(chosen, state);
  }
  assert_eq!(z, state);
  println!(
    "The multicollision was correctly generated, for sizes between {} and {}, and final state {}",
    K,
    K + TWO_POW_K - 1,
    z
  );
  let z = state;

  // Generate a map of intermediate hash states to the block indices that they correspond to
  // remember that we are trying to find a second preimage of x with |x| = 2^k
  let mut intermediate_states_set: HashSet<HasherState> = HashSet::new();
  let mut intermediate_states_map: HashMap<usize, HasherState> = HashMap::new();
  state = initial_state;
  for i in 0..TWO_POW_K {
    // For each X0...Xj with 0 <= j < 2^k, we compute H(X') and save both a set and a map X' -> H(X')
    let x_block: [u8; BLOCK_SIZE] = x[BLOCK_SIZE * i..BLOCK_SIZE * (i + 1)].try_into().unwrap();
    state = hasher.md(&x_block, state);
    intermediate_states_set.insert(state);
    intermediate_states_map.insert(i, state);
  }
  println!("Finished generating the intermediate states map of X.");

  // Search for a message M such that |M| = 1 and H(M) = H(X') for some X0...Xj with 0 <= j < 2^k
  // And determine which is j. It is mandatory that j >= k, but that happens w.h.p
  let mut found: Option<Vec<u8>> = None;
  state = z;
  while found.is_none() {
    let (m, h_m) = random_message_of_blocks(&hasher, &mut rng, 1, state);
    if intermediate_states_set.contains(&h_m) {
      found = Some(m);
      state = h_m;
    }
  }
  let block = &found.unwrap();
  let j = intermediate_states_map
    .iter()
    .find(|(_, &v)| v == state)
    .map(|(k, _)| k.clone())
    .unwrap();
  assert!(j >= K);
  println!(
    "Found message {} of one block with hash {}",
    HexString::from(block.clone()),
    state
  );
  println!(
    "Found that the original message truncated to its first {} blocks has hash {}",
    j, state
  );

  // Since k <= j <= 2^k we can construct a message M such that |M| = j and H(m) = z.
  // We have to use MSGS_1 and MSGS_2. Observe that we have to use the binary representation of j - k
  let mut msg: Vec<u8> = vec![];
  let v = j - K;
  for i in 0..K {
    let bit = (v >> (K - i - 1)) & 1; // Get the i-th bit
    //println!("Bit {}: {}", K - i - 1, bit);
    if bit == 1 {
      msg.extend_from_slice(&msgs_2[i]); // Add 2^{k-i-1} + 1 blocks
    } else {
      msg.extend_from_slice(&msgs_1[i]); // Add 1 block
    }
  }
  assert_eq!(hasher.md(&msg, initial_state), z);
  msg.extend_from_slice(&block);
  msg.extend_from_slice(&x[(j + 1) * BLOCK_SIZE..]);

  let h_msg = hasher.md(&msg, initial_state);
  assert_eq!(h_x, h_msg);
  println!("Found second preimage of x: {}", HexString::from(msg));
}
