use cryptopals::utils::{
  aes::{aes::AES, aes_error::AESError, utils::AESMode},
  dh::{dh::{DiffieHellmanParty, DiffieHellmanSession}, utils::get_dh_p},
  mac::sha1::Sha1,
};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha256};

fn dh_with_ack() -> Result<(), AESError> {
  let (p, g) = (get_dh_p(), BigUint::from(2u32));
  let alice = DiffieHellmanParty::new(&p, &g);

  // Alice sends (p,g) to Bob
  let bob = DiffieHellmanParty::new(&p, &g);

  // Bob sends an ACK to Alice
  // Alice sends A to Bob
  let b_session = bob.create_session_with(&alice.pk);

  // Bob sends B to Alice
  let a_session = alice.create_session_with(&bob.pk);
  assert_eq!(a_session, b_session);

  // Alice sends AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv to Bob
  let a_key_bytes: [u8; 16] = Sha1::hash(&a_session.encryption_key)[..16]
    .try_into()
    .unwrap();
  let random_iv: [u8; 16] = thread_rng().gen();
  let message: [u8; 16] = thread_rng().gen();
  let ciphertext = AES::encode(&message, &a_key_bytes, AESMode::CBC(random_iv))?;
  // Now Bob has (ciphertext, random_iv)

  // Bob decrypts Alice's message and is able to send it back to Alice
  let b_key_bytes: [u8; 16] = Sha1::hash(&a_session.encryption_key)[..16]
    .try_into()
    .unwrap();
  assert_eq!(a_key_bytes, b_key_bytes);
  let alice_message = AES::decode(&ciphertext, &b_key_bytes, AESMode::CBC(random_iv))?;
  assert_eq!(message.to_vec(), alice_message);

  Ok(())
}

fn mitm_attack_with_g_one() -> Result<(), AESError> {
  let (p, g) = (get_dh_p(), BigUint::from(2u32));
  let alice = DiffieHellmanParty::new(&p, &g);

  // Alice sends (p,g) to Bob. M modifies g to 1
  let bob = DiffieHellmanParty::new(&p, &BigUint::one());

  // Bob sends an ACK to Alice
  // Alice sends A to Bob
  let b_session = bob.create_session_with(&alice.pk);

  // Bob sends B to Alice. Here, B = g^b = 1^b = 1
  let a_session = alice.create_session_with(&bob.pk);
  assert_ne!(a_session, b_session); // This time the sessions will NOT be equal

  // Alice sends AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv to Bob
  // If M intercepts the attack, it is s = B^a = 1^a = 1.
  // So M is able to intercept and decode Alice's messages (and Bob is not).
  
  let a_key_bytes: [u8; 16] = Sha1::hash(&a_session.encryption_key)[..16]
    .try_into()
    .unwrap();
  let random_iv: [u8; 16] = thread_rng().gen();
  let message: [u8; 16] = thread_rng().gen();
  let ciphertext = AES::encode(&message, &a_key_bytes, AESMode::CBC(random_iv))?;
  
  // M decodes the message
  let m_message = decode_message_with(&ciphertext, BigUint::one(), &random_iv)?;
  assert_eq!(message.to_vec(), m_message);
  Ok(())
}

fn mitm_attack_with_g_p() -> Result<(), AESError> {
  let (p, g) = (get_dh_p(), BigUint::from(2u32));
  let alice = DiffieHellmanParty::new(&p, &g);

  // Alice sends (p,g) to Bob. M modifies g to p
  let bob = DiffieHellmanParty::new(&p, &p);

  // Bob sends an ACK to Alice
  // Alice sends A to Bob
  let b_session = bob.create_session_with(&alice.pk);

  // Bob sends B to Alice. Here, B = p^b % p = 0^b = 0
  let a_session = alice.create_session_with(&bob.pk);
  assert_ne!(a_session, b_session); // This time the sessions will NOT be equal

  // Alice sends AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv to Bob
  // If M intercepts the attack, it is s = 0^a = 0
  // So M is able to intercept and decode Alice's messages (and Bob is not).
  let a_key_bytes: [u8; 16] = Sha1::hash(&a_session.encryption_key)[..16]
    .try_into()
    .unwrap();
  let random_iv: [u8; 16] = thread_rng().gen();
  let message: [u8; 16] = thread_rng().gen();
  let ciphertext = AES::encode(&message, &a_key_bytes, AESMode::CBC(random_iv))?;
  
  // M decodes the message
  let m_message = decode_message_with(&ciphertext, BigUint::zero(), &random_iv)?;
  assert_eq!(message.to_vec(), m_message);
  Ok(())
}

fn mitm_attack_with_g_p_minus_one() -> Result<(), AESError> {
  let (p, g) = (get_dh_p(), BigUint::from(2u32));
  let alice = DiffieHellmanParty::new(&p, &g);

  // Alice sends (p,g) to Bob. M modifies g to p - 1
  let bob = DiffieHellmanParty::new(&p, &(&p - BigUint::one()));

  // Bob sends an ACK to Alice
  // Alice sends A to Bob
  let b_session = bob.create_session_with(&alice.pk);

  // Bob sends B to Alice. Here, B = (p - 1)^b % p = (-1)^b = 1 or p-1
  let a_session = alice.create_session_with(&bob.pk);
  assert_ne!(a_session, b_session); // This time the sessions will NOT be equal

  // Alice sends AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv to Bob
  // If M intercepts the attack, it is s = 1 or p-1
  // So M is able to intercept and decode Alice's messages (and Bob is not).
  let a_key_bytes: [u8; 16] = Sha1::hash(&a_session.encryption_key)[..16]
    .try_into()
    .unwrap();
  let random_iv: [u8; 16] = thread_rng().gen();
  let message: [u8; 16] = thread_rng().gen();
  let ciphertext = AES::encode(&message, &a_key_bytes, AESMode::CBC(random_iv))?;
  
  // M decodes the message
  let m1 = decode_message_with(&ciphertext, BigUint::one(), &random_iv)?; // try with s = 1
  let m2 = decode_message_with(&ciphertext, p - BigUint::one(), &random_iv)?; // try with s = p - 1
  assert!(message.to_vec() == m1 || message.to_vec() == m2);
  
  Ok(())
}

fn decode_message_with(ciphertext: &Vec<u8>, s: BigUint, iv: &[u8; 16]) -> Result<Vec<u8>, AESError> { 
  let mut hasher = Sha256::new();
  hasher.update(s.to_bytes_be());
  let digest = hasher.finalize();
  let m_session = DiffieHellmanSession {
    encryption_key: digest[..16].try_into().unwrap(),
    mac_key: digest[16..32].try_into().unwrap(),
  };
  let m_key_bytes: [u8; 16] = Sha1::hash(&m_session.encryption_key)[..16].try_into().unwrap();
  AES::decode(&ciphertext, &m_key_bytes, AESMode::CBC(iv.clone()))
}

// In addition, A = g^a then because of DLP, M will not be able to decrypt Bob's messages
fn main() -> Result<(), AESError> {
  dh_with_ack()?;
  mitm_attack_with_g_one()?;
  mitm_attack_with_g_p()?;
  mitm_attack_with_g_p_minus_one()?;
  Ok(())
}
