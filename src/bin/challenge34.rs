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
use num_traits::Zero;
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha256};

fn dh_protocol() -> Result<(), AESError> {
  let (p, g) = (get_nist_prime(), BigUint::from(2u32));
  let alice = DiffieHellmanParty::new(&p, &g);

  // Alice sends (p, g, A) to Bob
  let (bob, bob_session) = DiffieHellmanParty::from_other_party_params(&p, &g, &alice.pk);

  // Bob sends B to Alice
  let alice_session = alice.create_session_with(&bob.pk);
  assert_eq!(alice_session, bob_session);

  // Alice sends AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv to Bob
  let alice_key_bytes: [u8; AES128_KEY_SIZE] = Sha1::hash(&alice_session.encryption_key)[..AES128_KEY_SIZE]
    .try_into()
    .unwrap();
  let random_iv: [u8; AES_BLOCK_SIZE] = thread_rng().gen();
  let message: [u8; AES_BLOCK_SIZE] = thread_rng().gen(); // We send a random message so we do not have to input it
  let ciphertext = AES::encode(&message, &alice_key_bytes, AESMode::CBC(random_iv))?;
  // Now Bob has (ciphertext, random_iv)

  // Bob decrypts Alice's message and is able to send it back to Alice
  let bob_key_bytes: [u8; AES128_KEY_SIZE] = Sha1::hash(&alice_session.encryption_key)[..AES128_KEY_SIZE]
    .try_into()
    .unwrap();
  assert_eq!(alice_key_bytes, bob_key_bytes);
  let alice_message = AES::decode(&ciphertext, &bob_key_bytes, AESMode::CBC(random_iv))?;
  assert_eq!(message.to_vec(), alice_message);

  Ok(())
}

fn mitm_attack_simulation() -> Result<(), AESError> {
  let (p, g) = (get_nist_prime(), BigUint::from(2u32));
  let alice = DiffieHellmanParty::new(&p, &g);

  // M modifies what Alice sent to Bob. Replacing A by p
  // Replacing A and B with p causes: s mod p = 0
  let (_bob, bob_session) = DiffieHellmanParty::from_other_party_params(&p, &g, &p);

  // M modifies what Bob sent to Alice. Replacing B by p
  let alice_session = alice.create_session_with(&p);
  assert_eq!(alice_session, bob_session); // The session is still valid

  // Now M should be able to decrypt the messages
  // Alice sends AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv to M
  let alice_key_bytes: [u8; AES128_KEY_SIZE] = Sha1::hash(&alice_session.encryption_key)[..AES128_KEY_SIZE]
    .try_into()
    .unwrap();
  let random_iv: [u8; AES_BLOCK_SIZE] = thread_rng().gen();
  let message: [u8; AES_BLOCK_SIZE] = thread_rng().gen();
  let ciphertext = AES::encode(&message, &alice_key_bytes, AESMode::CBC(random_iv))?;

  // M sees (ciphertext, random_iv) and wants to recover plaintext.
  // M is able to deduce the session. its s = A^b = B^a = g^(ab) % p and he was able to replace A and B with p
  // So s = p^a % p = 0. And we replicate the process
  let s = BigUint::zero();
  let mut hasher = Sha256::new();
  hasher.update(s.to_bytes_be());
  let digest = hasher.finalize();
  let mitm_session = DiffieHellmanSession {
    encryption_key: digest[..AES128_KEY_SIZE].try_into().unwrap(),
    mac_key: digest[AES128_KEY_SIZE..2 * AES128_KEY_SIZE]
      .try_into()
      .unwrap(),
  };
  let mitm_key_bytes: [u8; AES128_KEY_SIZE] = Sha1::hash(&mitm_session.encryption_key)[..AES128_KEY_SIZE]
    .try_into()
    .unwrap();
  let m_message = AES::decode(&ciphertext, &mitm_key_bytes, AESMode::CBC(random_iv))?;
  assert_eq!(message.to_vec(), m_message);

  Ok(())
}

fn main() -> Result<(), AESError> {
  dh_protocol()?;
  mitm_attack_simulation()?;
  Ok(())
}
