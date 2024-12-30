/*
  LENGTH EXTENSION ATTACK
  attacker knows H(P1) and |P1|, controls P2 and is able to calculate H(P1 || P2)
  Because it is possible to reconstruct the internal state of the hash function
  from the hash digest H(P1). And then process new data (P2)
*/

/*
  PART 1
  CBC-MAC(K, P) = Cn (meaning it uses the last block of the result C as the MAC)
  C1 = E(K, P1 ^ IV)
  C2 = E(K, P2 ^ C1) → C2 would be the MAC

  The server S recieves data of the form: message || IV || MAC
  message: from=#{from_id}&to=#{to_id}&amount=#{amount}
  The attacker should be able to generate valid (message, MAC) for his accounts (i.e. from_id = attacker)

  If the IV is generated per-message and sent alone with the MAC, the attacker
  can exploit it as it gives full control over C1. Suppose attacker_id = 1, victim_id = 2, amount=1000000
  P = from=1&to=2&amount=1000000
  P1 = from=1&to=2&amou

  P1 ^ IV = D(K, C1). The adversary modifies the IV so that it interexchanges attacker_id and victim_id.
  So we search for a byte b such that b ^ 1 = 2 (it is b = 1 ^ 2 = 3).
  In fact, we can do it for every byte values of the ids (doing their xor) and we put that byte in the correct IV positions.
*/

use cryptopals::utils::aes::{aes::AES, aes_key::AESKey, utils::AESMode};
use regex::Regex;

type MessageT = String;
type MacT = Vec<u8>;
type IvT = [u8; 16];
type TransactionT = (u8, u64);

trait Challenge49Server {
  fn new() -> Self;
  fn get_key_to_sign(&self) -> AESKey;
  fn verify_signature(&self, msg: &MessageT, iv: IvT, mac: &MacT) -> bool;
}

struct Client {
  id: u8,
}

impl Client {
  fn sign_part1<S: Challenge49Server>(
    &self,
    server: &S,
    iv: IvT,
    to: u8,
    amount: u64,
  ) -> (MessageT, MacT) {
    let msg = format!("from={}&to={}&amount={}", self.id, to, amount);
    let mac = AES::encode(&msg, &server.get_key_to_sign(), AESMode::CBC(iv)).unwrap();
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
    let msg = format!("from:{}&tx_list={}", self.id, txs_string);
    let mac = AES::encode(&msg, &server.get_key_to_sign(), AESMode::CBC(iv)).unwrap();
    (msg, mac)
  }
}

struct ServerPart1 {
  key: AESKey,
}

impl Challenge49Server for ServerPart1 {
  fn new() -> Self {
    let key = AESKey::random_key();
    Self { key }
  }

  fn get_key_to_sign(&self) -> AESKey {
    self.key.clone()
  }

  fn verify_signature(&self, msg: &MessageT, iv: IvT, mac: &MacT) -> bool {
    let re = Regex::new(r"^from=(\d+)&to=(\d+)&amount=(\d+)").unwrap();
    let input = String::from_utf8_lossy(msg.as_ref());
    if re.captures(&input).is_none() {
      return false;
    }
    let ciphertext = AES::encode(&msg, &self.key, AESMode::CBC(iv)).unwrap();
    mac == &ciphertext[ciphertext.len() - 32..]
  }
}

/*
  PART 2
  Now for the second version, it should be clear that the IV should be fixed. So IV = 0
  The server S recieves data of the form: message || MAC
  message: from=#{from_id}&tx_list=#{transactions}
  transactions: to:amount(;to:amount)*  (do the regex)
  ^from=(\d+)&tx_list=((\d+:\d+)(;to:\d+:\d+)*)$

  An attacker could extend the message. Because the MAC = Cn would be a valid IV to add transactions
  Cn+1 = E(K, Pn+1 xor MAC) where Pn+1 = 1:1000000 (and the padding)
  Then message' = message || pkcs(message) || Pn+1, MAC' = Cn+1 (we suppose the server ignores the padding bytes)
*/

struct ServerPart2 {
  key: AESKey,
  iv: IvT,
}

impl Challenge49Server for ServerPart2 {
  fn new() -> Self {
    Self {
      key: AESKey::random_key(),
      iv: [0; 16],
    }
  }

  fn get_key_to_sign(&self) -> AESKey {
    self.key.clone()
  }

  fn verify_signature(&self, msg: &MessageT, _iv: IvT, mac: &MacT) -> bool {
    let re = Regex::new(r"^from=(\d+)&tx_list=((\d+:\d+)(;to:\d+:\d+)*)$").unwrap();
    let input = String::from_utf8_lossy(msg.as_ref());
    if re.captures(&input).is_none() {
      return false;
    }
    let ciphertext = AES::encode(&msg, &self.key, AESMode::CBC(self.iv)).unwrap();
    mac == &ciphertext[ciphertext.len() - 32..]
  }
}

fn main() {
  // PART 1
  let (attacker_id, victim_id, third_id) = (1, 2, 3);
  let attacker = Client { id: attacker_id };
  let victim = Client { id: victim_id };
  let server1 = ServerPart1::new();
  let (low_amount, high_amount) = (100, 1000000);

  let iv1 = [0; 16];
  let (msg1, mac1) = attacker.sign_part1(&server1, iv1, victim_id, high_amount);
  assert!(server1.verify_signature(&msg1, iv1, &mac1));

  let mut msg1_bytes = msg1.into_bytes();
  let (attacker_byte, victim_byte) = (msg1_bytes[6], msg1_bytes[11]);
  let b = attacker_byte ^ victim_byte;
  let mut forged_iv1 = iv1.clone();
  forged_iv1[6] = b;
  forged_iv1[11] = b;
  msg1_bytes.swap(6, 11);
  let forged_msg1 = String::from_utf8(msg1_bytes.to_vec()).unwrap();
  assert!(server1.verify_signature(&forged_msg1, forged_iv1, &mac1));

  // PART 2
  let server2 = ServerPart2::new();
  let iv2 = [0; 16];
  let (msg2, mac2) = victim.sign_part2(&server2, iv2, &vec![(third_id, low_amount)]);
  server2.verify_signature(&msg2, iv2, &mac2);
  
}
