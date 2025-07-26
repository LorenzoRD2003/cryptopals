use std::{
  collections::{HashMap, HashSet},
  vec,
};

use cryptopals::utils::aes::{
  aes::AES, aes_key::AESKey, constants::sizes::AES128_KEY_SIZE, utils::{pkcs_padding, AESMode}
};
use num::pow;
use rand::{rngs::ThreadRng, thread_rng, Rng};

type HasherState = u16;
type Collision = (Vec<u8>, Vec<u8>, HasherState); // (msg1, msg2, collided_state)
type MdBlock = [u8; 16];

const K: usize = 4;
const BLOCK_SIZE: usize = 16;
const PREFIX_SIZE: usize = 24;

#[derive(Debug, Clone)]
struct HashMD {
  key: AESKey,
}

impl HashMD {
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
      let ct = AES::encode(&pt, &self.key, AESMode::ECB).unwrap();
      h_ = u16::from_be_bytes([ct[0], ct[1]]);
    }
    h_
  }
}

struct DiamondStructure {
  k: usize,
  hash_fn: HashMD,
  collidable_options: HashSet<Collision>,
  tree: Vec<Vec<Collision>>,
}

impl DiamondStructure {
  pub fn init(k: usize, hash_fn: &HashMD) -> Self {
    let collidable_states: HashSet<Collision> = HashSet::new();
    let tree: Vec<Vec<Collision>> = (0..=k).map(|_i| vec![]).collect();
    Self {
      k,
      hash_fn: hash_fn.clone(),
      collidable_options: collidable_states,
      tree,
    }
  }

  pub fn construct_and_get_commit(&mut self, rng: &mut ThreadRng) -> HasherState {
    self.tree[0] = self.get_initial_random_states(rng);

    for i in 1..=self.k {
      let elems = pow(2, self.k - i);
      for j in 0..elems {
        dbg!(i, j);
        let collision: Collision = self.find_sb_collision(
          rng,
          self.tree[i - 1][2 * j].2,
          self.tree[i - 1][2 * j + 1].2
        );
        self.collidable_options.insert(collision.clone());
        self.tree[i].push(collision);
      }
    }
    
    self.tree[self.k][0].2
  }

  pub fn obtain_suffix(&self, _prefix: &Vec<u8>) -> Vec<u8> {
    unimplemented!()
  }

  fn get_initial_random_states(&self, rng: &mut ThreadRng) -> Vec<Collision> {
    let two_power_k = pow(2, self.k);
    (0..two_power_k)
      .map(|_i| (vec![], vec![], rng.gen::<HasherState>()))
      .collect()
  }

  // Naive algorithm for finding a single block collision
  fn find_sb_collision(
    &self,
    rng: &mut ThreadRng,
    state1: HasherState,
    state2: HasherState,
  ) -> Collision {
    let mut set1: HashSet<HasherState> = HashSet::new();
    let mut map1: HashMap<MdBlock, HasherState> = HashMap::new();
    let mut set2: HashSet<HasherState> = HashSet::new();
    let mut map2: HashMap<MdBlock, HasherState> = HashMap::new();

    let mut collision: Collision = (vec![], vec![], 0);
    let mut found_collision: bool = false;

    while !found_collision {
      let block1: MdBlock = rng.gen::<MdBlock>();
      let digest1: HasherState = self.hash_fn.md(&block1, state1);
      let block2: MdBlock = rng.gen::<MdBlock>();
      let digest2: HasherState = self.hash_fn.md(&block2, state2);

      set1.insert(digest1);
      map1.insert(block1, digest1);
      set2.insert(digest2);
      map2.insert(block2, digest2);

      if set2.contains(&digest1) {
        collision.0 = block1.to_vec();
        collision.1 = map2
          .iter()
          .find(|(_, &v)| v == digest1)
          .map(|(k, _)| k.clone())
          .unwrap()
          .to_vec();
        collision.2 = digest1;
        found_collision = true;
      } else if set1.contains(&digest2) {
        collision.0 = map1
          .iter()
          .find(|(_, &v)| v == digest2)
          .map(|(k, _)| k.clone())
          .unwrap()
          .to_vec();
        collision.1 = block2.to_vec();
        collision.2 = digest2;
        found_collision = true;
      }
    }
    collision
  }

}

fn main() {
  let hash_fn: HashMD = HashMD::new();
  let mut diamond: DiamondStructure = DiamondStructure::init(K, &hash_fn);
  let mut rng = thread_rng();
  let commit: HasherState = diamond.construct_and_get_commit(&mut rng);
  dbg!(commit);
  // Save commit and diamond structure in a file to access it later
  let prefix: Vec<u8> = thread_rng().gen::<[u8; PREFIX_SIZE]>().to_vec();
  let suffix: Vec<u8> = diamond.obtain_suffix(&prefix);

  // hash(P || S) = H
  let _msg: Vec<u8> = [prefix, suffix].concat();
  //assert_eq!(hash_fn.md(&msg, INITIAL_STATE), commit);
}
