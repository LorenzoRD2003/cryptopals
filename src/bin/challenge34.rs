use cryptopals::utils::{
  algebra::get_nist_prime,
  aes::{aes::AES, aes_error::AESError, utils::AESMode},
  dh::{DiffieHellmanParty, DiffieHellmanSession},
  mac::sha1::Sha1,
};
use num_bigint::BigUint;
use num_traits::Zero;
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha256};

fn dh_protocol() -> Result<(), AESError> {
  let (p, g) = (get_nist_prime(), BigUint::from(2u32));
  let alice = DiffieHellmanParty::new(&p, &g);

  // Alice sends (p, g, A) to Bob
  let (bob, b_session) = DiffieHellmanParty::from_other_party_params(&p, &g, &alice.pk);

  // Bob sends B to Alice
  let a_session = alice.create_session_with(&bob.pk);
  assert_eq!(a_session, b_session);

  // Alice sends AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv to Bob
  let a_key_bytes: [u8; 16] = Sha1::hash(&a_session.encryption_key)[..16]
    .try_into()
    .unwrap();
  let random_iv: [u8; 16] = thread_rng().gen();
  let message: [u8; 16] = thread_rng().gen(); // We send a random message so we do not have to input it
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

fn mitm_attack_simulation() -> Result<(), AESError> {
  let (p, g) = (get_nist_prime(), BigUint::from(2u32));
  let alice = DiffieHellmanParty::new(&p, &g);

  // M modifies what Alice sent to Bob. Replacing A by p
  let (_bob, b_session) = DiffieHellmanParty::from_other_party_params(&p, &g, &p);

  // M modifies what Bob sent to Alice. Replacing B by p
  let a_session = alice.create_session_with(&p);
  assert_eq!(a_session, b_session); // The session is still valid

  // Now M should be able to decrypt the messages
  // Alice sends AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv to M
  let a_key_bytes: [u8; 16] = Sha1::hash(&a_session.encryption_key)[..16]
    .try_into()
    .unwrap();
  let random_iv: [u8; 16] = thread_rng().gen();
  let message: [u8; 16] = thread_rng().gen();
  let ciphertext = AES::encode(&message, &a_key_bytes, AESMode::CBC(random_iv))?;
  
  // M sees (ciphertext, random_iv) and wants to recover plaintext.
  // M is able to deduce the session. its s = A^b = B^a = g^(ab) % p and he was able to replace A and B with p
  // So s = p^a % p = 0. And we replicate the process
  let s = BigUint::zero();
  let mut hasher = Sha256::new();
  hasher.update(s.to_bytes_be());
  let digest = hasher.finalize();
  let m_session = DiffieHellmanSession {
    encryption_key: digest[..16].try_into().unwrap(),
    mac_key: digest[16..32].try_into().unwrap(),
  };
  let m_key_bytes: [u8; 16] = Sha1::hash(&m_session.encryption_key)[..16].try_into().unwrap();
  let m_message = AES::decode(&ciphertext, &m_key_bytes, AESMode::CBC(random_iv))?;
  assert_eq!(message.to_vec(), m_message);

  Ok(())
}

fn main() -> Result<(), AESError> {
  dh_protocol()?;
  mitm_attack_simulation()?;
  Ok(())
}
