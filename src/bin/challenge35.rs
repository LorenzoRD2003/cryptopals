use cryptopals::utils::{
  aes::{
    aes::AES,
    aes_error::AESError,
    constants::sizes::{AES128_KEY_SIZE, AES_BLOCK_SIZE},
    utils::AESMode,
  },
  algebra::primes::get_nist_prime,
  dh::{DiffieHellmanParty, DiffieHellmanSession},
  mac::sha1::Sha1,
};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha256};

fn dh_with_ack() -> Result<(), AESError> {
  let (p, g) = (get_nist_prime(), BigUint::from(2u32));
  let alice = DiffieHellmanParty::new(&p, &g);

  // Alice sends (p,g) to Bob
  let bob = DiffieHellmanParty::new(&p, &g);

  // Bob sends an ACK to Alice
  // Alice sends A to Bob
  let bob_sesion = bob.create_session_with(&alice.pk);

  // Bob sends B to Alice
  let alice_session = alice.create_session_with(&bob.pk);
  assert_eq!(alice_session, bob_sesion);

  // Alice sends AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv to Bob
  let alice_key_bytes: [u8; AES128_KEY_SIZE] = Sha1::hash(&alice_session.encryption_key)
    [..AES128_KEY_SIZE]
    .try_into()
    .unwrap();
  let iv: [u8; AES_BLOCK_SIZE] = thread_rng().gen();
  let message: [u8; AES_BLOCK_SIZE] = thread_rng().gen();
  let ciphertext = AES::encode(&message, &alice_key_bytes, AESMode::CBC(iv))?;
  // Now Bob has (ciphertext, random_iv)

  // Bob decrypts Alice's message and is able to send it back to Alice
  let bob_key_bytes: [u8; 16] = Sha1::hash(&alice_session.encryption_key)[..AES128_KEY_SIZE]
    .try_into()
    .unwrap();
  assert_eq!(alice_key_bytes, bob_key_bytes);
  let alice_message = AES::decode(&ciphertext, &bob_key_bytes, AESMode::CBC(iv))?;
  assert_eq!(message.to_vec(), alice_message);

  Ok(())
}

fn encrypt_random_message(
  key: &[u8; AES128_KEY_SIZE],
) -> (Vec<u8>, [u8; AES_BLOCK_SIZE], [u8; AES_BLOCK_SIZE]) {
  let iv = thread_rng().gen();
  let message = thread_rng().gen();
  let ciphertext = AES::encode(&message, key, AESMode::CBC(iv)).unwrap();
  (ciphertext, iv, message)
}

fn mitm_attack_with_g_one() -> Result<(), AESError> {
  let (p, g) = (get_nist_prime(), BigUint::from(2u32));
  let alice = DiffieHellmanParty::new(&p, &g);

  // Alice sends (p,g) to Bob. M modifies g to 1
  let g_ = BigUint::one();
  let bob = DiffieHellmanParty::new(&p, &g_);

  // Bob sends an ACK to Alice
  // Alice sends A to Bob
  let bob_session = bob.create_session_with(&alice.pk);

  // Bob sends B to Alice. Here, B = g^b = 1^b = 1
  let alice_session = alice.create_session_with(&bob.pk);
  assert_ne!(alice_session, bob_session); // This time the sessions will NOT be equal

  // Alice sends AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv to Bob
  // If M intercepts the attack, it is s = B^a = 1^a = 1.
  // So M is able to intercept and decode Alice's messages (and Bob is not).
  let alice_key_bytes: [u8; AES128_KEY_SIZE] = Sha1::hash(&alice_session.encryption_key)
    [..AES128_KEY_SIZE]
    .try_into()
    .unwrap();
  let (ciphertext, iv, message) = encrypt_random_message(&alice_key_bytes);

  // M decodes the message
  let mitm_message = decode_message_with(&ciphertext, &BigUint::one(), &iv)?;
  assert_eq!(message.to_vec(), mitm_message);
  Ok(())
}

fn mitm_attack_with_g_p() -> Result<(), AESError> {
  let (p, g) = (get_nist_prime(), BigUint::from(2u32));
  let alice = DiffieHellmanParty::new(&p, &g);

  // Alice sends (p,g) to Bob. M modifies g to p
  let g_ = p.clone();
  let bob = DiffieHellmanParty::new(&p, &g_);

  // Bob sends an ACK to Alice
  // Alice sends A to Bob
  let bob_session = bob.create_session_with(&alice.pk);

  // Bob sends B to Alice. Here, B = p^b % p = 0^b = 0
  let alice_session = alice.create_session_with(&bob.pk);
  assert_ne!(alice_session, bob_session); // This time the sessions will NOT be equal

  // Alice sends AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv to Bob
  // If M intercepts the attack, it is s = 0^a = 0
  // So M is able to intercept and decode Alice's messages (and Bob is not).
  let alice_key_bytes: [u8; AES128_KEY_SIZE] = Sha1::hash(&alice_session.encryption_key)
    [..AES128_KEY_SIZE]
    .try_into()
    .unwrap();
  let (ciphertext, iv, message) = encrypt_random_message(&alice_key_bytes);

  // M decodes the message
  let mitm_message = decode_message_with(&ciphertext, &BigUint::zero(), &iv)?;
  assert_eq!(message.to_vec(), mitm_message);
  Ok(())
}

fn mitm_attack_with_g_p_minus_one() -> Result<(), AESError> {
  let (p, g) = (get_nist_prime(), BigUint::from(2u32));
  let alice = DiffieHellmanParty::new(&p, &g);

  // Alice sends (p,g) to Bob. M modifies g to p - 1
  let g_ = &p - BigUint::one();
  let bob = DiffieHellmanParty::new(&p, &g_);

  // Bob sends an ACK to Alice
  // Alice sends A to Bob
  let bob_session = bob.create_session_with(&alice.pk);

  // Bob sends B to Alice. Here, B = (p - 1)^b % p = (-1)^b = 1 or p-1
  let alice_session = alice.create_session_with(&bob.pk);
  assert_ne!(alice_session, bob_session); // This time the sessions will NOT be equal

  // Alice sends AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv to Bob
  // If M intercepts the attack, it is s = 1 or p - 1, depending on the parity.
  // So M is able to intercept and decode Alice's messages (and Bob is not).
  let alice_key_bytes: [u8; AES128_KEY_SIZE] = Sha1::hash(&alice_session.encryption_key)
    [..AES128_KEY_SIZE]
    .try_into()
    .unwrap();
  let (ciphertext, iv, message) = encrypt_random_message(&alice_key_bytes);

  // M decodes the message
  let mitm_possible_message_1 = decode_message_with(&ciphertext, &BigUint::one(), &iv)?; // try with s = 1
  let mitm_possible_message_2 = decode_message_with(&ciphertext, &(&p - BigUint::one()), &iv)?; // try with s = p - 1
  assert!(
    message.to_vec() == mitm_possible_message_1 || message.to_vec() == mitm_possible_message_2
  );

  Ok(())
}

fn decode_message_with(
  ciphertext: &Vec<u8>,
  s: &BigUint,
  iv: &[u8; AES_BLOCK_SIZE],
) -> Result<Vec<u8>, AESError> {
  let mut hasher = Sha256::new();
  hasher.update(s.to_bytes_be());
  let digest = hasher.finalize();
  let mitm_session = DiffieHellmanSession {
    encryption_key: digest[..AES128_KEY_SIZE].try_into().unwrap(),
    mac_key: digest[AES128_KEY_SIZE..2 * AES128_KEY_SIZE].try_into().unwrap(),
  };
  let mitm_key_bytes: [u8; AES128_KEY_SIZE] = Sha1::hash(&mitm_session.encryption_key)[..AES128_KEY_SIZE]
    .try_into()
    .unwrap();
  AES::decode(&ciphertext, &mitm_key_bytes, AESMode::CBC(iv.clone()))
}

// In addition, A = g^a then because of DLP, M will not be able to decrypt Bob's messages
fn main() -> Result<(), AESError> {
  dh_with_ack()?;
  println!("DH with ACK works!");
  mitm_attack_with_g_one()?;
  println!("MITM attack with g = 1 works!");
  mitm_attack_with_g_p()?;
  println!("MITM attack with g = p works!");
  mitm_attack_with_g_p_minus_one()?;
  println!("MITM attack with g = p - 1 works!");
  Ok(())
}
