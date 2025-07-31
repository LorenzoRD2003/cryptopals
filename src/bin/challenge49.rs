/*
  LENGTH EXTENSION ATTACK
  attacker knows H(P1) and |P1|, controls P2 and is able to calculate H(P1 || P2)
  Because it is possible to reconstruct the internal state of the hash function
  from the hash digest H(P1). And then process new data (P2)
*/

/*
  PART 1
  CBC-MAC(K, P) = Cn (meaning it uses the last block of the result C as the MAC)
  For a plaintext with length two blocks
  C1 = E(K, P1 ^ IV)
  C2 = E(K, P2 ^ C1) → C2 would be the MAC

  The server S recieves data of the form: message || IV || MAC
  message: from=#{from_id}&to=#{to_id}&amount=#{amount}
  The attacker should be able to generate valid (message, MAC) for his accounts (i.e. from_id = attacker).
  But since they can choose the IV, they are in fact able to generate valid (message, MAC) for whichever message

  If the IV is generated per-message and sent alone with the MAC, the attacker
  can exploit it as it gives full control over C1. Suppose attacker_id = 1, victim_id = 2, amount=1000000
  P = from=1&to=2&amount=1000000
  P1 = from=1&to=2&amou

  P1 ^ IV = D(K, C1). Attacker modifies the IV so that it interexchanges attacker_id and victim_id.
  So we search for a byte b such that b ^ 1 = 2 (it is b = 1 ^ 2 = 3).
  In fact, we can do it for every byte values of the ids (doing their xor) and we put that byte in the correct IV positions.
*/

use cryptopals::utils::{
  aes::{
    aes::AES,
    aes_key::AESKey,
    constants::sizes::{AES128_KEY_SIZE, AES_BLOCK_SIZE},
    utils::{pkcs_padding, AESMode},
  },
  conversion::hex_string::HexString
};
use regex::Regex;

type MessageT = String;
type MacT = Vec<u8>;
type IvT = [u8; AES_BLOCK_SIZE];
type TransactionT = (u8, u64);

trait Challenge49Server {
  fn new() -> Self;
  /// get_key_to_sign is a simplification. In the real world, Server and Client should exchange certificates/keys to obtain asymmetric key
  fn get_key_to_sign(&self) -> AESKey;
  fn verify_signature<S: AsRef<[u8]>>(&self, msg: &S, iv: IvT, mac: &MacT) -> bool;
}

struct Client {
  id: u8,
}

impl Client {
  fn get_mac_for<S: Challenge49Server>(&self, msg: &String, server: &S, iv: IvT) -> MacT {
    // CBC-MAC(K, P) = Cn (meaning it uses the last block of the result C as the MAC)
    let c = AES::encode(&msg, &server.get_key_to_sign(), AESMode::CBC(iv)).unwrap();
    c[c.len() - AES_BLOCK_SIZE..].to_vec()
  }

  fn sign_part1<S: Challenge49Server>(
    &self,
    server: &S,
    iv: IvT,
    to: u8,
    amount: u64,
  ) -> (MessageT, MacT) {
    let msg = format!("from={}&to={}&amount={}", self.id, to, amount);
    let mac = self.get_mac_for(&msg, server, iv);
    (msg, mac)
  }

  fn sign_part2<S: Challenge49Server>(
    &self,
    server: &S,
    iv: IvT,
    txs: &Vec<TransactionT>,
  ) -> (MessageT, MacT) {
    let txs_string = txs
      .into_iter()
      .map(|(to, amount)| format!("{}:{};", to, amount))
      .collect::<Vec<String>>()
      .join("");
    let msg = format!("from={}&tx_list={}", self.id, txs_string);
    let mac = self.get_mac_for(&msg, server, iv);
    (msg, mac)
  }
}

struct ServerPart1 {
  key: AESKey,
}

impl Challenge49Server for ServerPart1 {
  fn new() -> Self {
    let key = AESKey::random_key(AES128_KEY_SIZE).unwrap();
    Self { key }
  }

  fn get_key_to_sign(&self) -> AESKey {
    self.key.to_owned()
  }

  fn verify_signature<S: AsRef<[u8]>>(&self, msg: &S, iv: IvT, mac: &MacT) -> bool {
    let re = Regex::new(r"^from=(\d+)&to=(\d+)&amount=(\d+)").unwrap();
    let input = String::from_utf8_lossy(msg.as_ref());
    if re.captures(&input).is_none() {
      return false;
    }
    let ciphertext = AES::encode(&msg, &self.key, AESMode::CBC(iv)).unwrap();
    mac == &ciphertext[ciphertext.len() - AES_BLOCK_SIZE..]
  }
}

/*
  PART 2
  Now for the second version, it should be clear that the IV should be fixed. For example IV = 0
  The server S recieves data of the form: message || MAC
  message: from=#{from_id}&tx_list=#{transactions}
  transactions: to:amount(;to:amount)*  (do the regex)
  ^from=(\d+)&tx_list=((\d+:\d+)(;to:\d+:\d+)*)$

  An attacker could extend the message. Because the MAC = Cn would be a valid IV to add transactions
*/

struct ServerPart2 {
  key: AESKey,
  iv: IvT,
}

impl Challenge49Server for ServerPart2 {
  fn new() -> Self {
    Self {
      key: AESKey::random_key(AES128_KEY_SIZE).unwrap(),
      iv: [0; 16], // IV has to be fixed
    }
  }

  fn get_key_to_sign(&self) -> AESKey {
    self.key.to_owned()
  }

  fn verify_signature<S: AsRef<[u8]>>(&self, msg: &S, _iv: IvT, mac: &MacT) -> bool {
    let re = Regex::new(r"^from=(\d+)&tx_list=(\d+:\d+)(;\d+:\d+)*").unwrap();
    let input = String::from_utf8_lossy(msg.as_ref());
    if re.captures(&input).is_none() {
      return false;
    }
    let ciphertext = AES::encode(&msg, &self.key, AESMode::CBC(self.iv)).unwrap();
    //println!("Computed CBC-MAC: {}", HexString::from(ciphertext[ciphertext.len() - AES_BLOCK_SIZE..].to_vec()));
    mac == &ciphertext[ciphertext.len() - AES_BLOCK_SIZE..]
  }
}

fn main() {
  // PART 1
  let (attacker_id, victim_id, third_id) = (1, 2, 3);
  let attacker = Client { id: attacker_id };
  let victim = Client { id: victim_id };
  let server1 = ServerPart1::new();
  let (low_amount, high_amount) = (100, 1000000);

  let iv1 = [0; AES_BLOCK_SIZE];
  let (msg1, mac1) = attacker.sign_part1(&server1, iv1, victim_id, high_amount);
  assert!(server1.verify_signature(&msg1, iv1, &mac1));

  // P1 ^ IV = D(K, C1). Attacker modifies the IV so that it interexchanges attacker_id and victim_id.
  // So we search for a byte b such that b ^ 1 = 2 (it is b = 1 ^ 2 = 3).
  let mut msg1_bytes = msg1.into_bytes();
  let (attacker_byte, victim_byte) = (msg1_bytes[6], msg1_bytes[11]);
  let b = attacker_byte ^ victim_byte;
  let mut forged_iv1 = iv1.clone();
  forged_iv1[6] = b;
  forged_iv1[11] = b;
  msg1_bytes.swap(6, 11);
  let forged_msg1 = String::from_utf8(msg1_bytes.to_vec()).unwrap();
  assert!(server1.verify_signature(&forged_msg1, forged_iv1, &mac1));
  println!("Part 1 works correctly.");

  // PART 2
  let server2 = ServerPart2::new();
  let iv2 = [0; 16];
  let (victim_msg, victim_mac) = victim.sign_part2(&server2, iv2, &vec![(third_id, low_amount), (third_id, low_amount)]);
  assert!(server2.verify_signature(&victim_msg, iv2, &victim_mac));

  // Here, we suppose that the attacker captured victim_msg M_V and victim_mac MAC_V.
  println!(
    "Captured message: {}\nCaptured MAC: {}",
    victim_msg,
    HexString::from(victim_mac.clone())
  );
  // Captured message: from:2&tx_list=3:100; separated in blocks from:2&tx_list=3 :100;\0x11...\0x11 (with PKCS padding)
  let victim_padded_msg = pkcs_padding(&victim_msg, AES_BLOCK_SIZE as u8); // M_V

  // The attacker constructs an attacker_message M_A with attacker_mac MAC_A.
  let (attacker_msg, attacker_mac) =
    attacker.sign_part2(&server2, iv2, &vec![(attacker_id, high_amount)]);
  println!("Attacker message: {}\nAttacker MAC: {}", attacker_msg, HexString::from(attacker_mac.clone()));

  // The idea is to use MAC_V as the IV for M_A. We separate M_A in blocks: M_A1 | M_A2
  //let padded_attacker_msg = pkcs_padding(&attacker_msg, AES_BLOCK_SIZE as u8);
  let attacker_msg1 = &attacker_msg.as_bytes()[..AES_BLOCK_SIZE]; // M_A1
  let attacker_msg2 = &attacker_msg.as_bytes()[AES_BLOCK_SIZE..]; // M_A2

  // The forged block is F = MAC_V ^ M_A1. Therefore CBC-MAC(K, M_V | F) = CBC-MAC(K, MAC ^ F) = CBC-MAC(K, M_A1)
  let forged_block: Vec<u8> = victim_mac
    .iter()
    .zip(attacker_msg1.iter())
    .map(|(a, b)| a ^ b)
    .collect(); // forged = MAC ^ Q1
  println!("Forged block: {}", HexString::from(forged_block.clone()));

  // It follows that CBC-MAC(K, M_V | F | M_A2) = CBC-MAC(K, M_A) = MAC_A
  // and thus we have a length extension attack for the message M_V with valid code MAC_A
  let forged_message = [
    victim_padded_msg.as_ref(),
    forged_block.as_ref(),
    attacker_msg2
  ].concat();
  println!("Forged message: {}", String::from_utf8_lossy(&forged_message));

  // Determine if we completed the challenge
  assert!(server2.verify_signature(&forged_message, iv2, &attacker_mac));
  println!("Part 2 works correctly.");
}
