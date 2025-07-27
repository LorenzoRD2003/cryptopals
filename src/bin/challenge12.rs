use cryptopals::utils::aes::aes::AES;
use cryptopals::utils::aes::utils::AESMode;
use cryptopals::utils::conversion::conversion::base64_to_bytes_vector;
use rand::thread_rng;
use rand::Rng;

struct EncryptionOracle {
  key: [u8; 16],
  post_bytes: Vec<u8>,
}

impl EncryptionOracle {
  fn init() -> Self {
    const UNKNOWN_STRING: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    Self {
      key: thread_rng().gen(),
      post_bytes: base64_to_bytes_vector(UNKNOWN_STRING).unwrap(),
    }
  }

  fn encrypt<S: AsRef<[u8]>>(&self, input: &S) -> Vec<u8> {
    let mut plaintext = input.as_ref().to_vec();
    plaintext.extend(&self.post_bytes);
    AES::encode(&plaintext, &self.key, AESMode::ECB).unwrap()
  }
}

// Determine block size by observing ciphertext length changes
fn detect_block_size(oracle: &EncryptionOracle) -> usize {
  let original_len = oracle.encrypt(&[]).len();
  for i in 1..48 {
    let input = vec![b'A'; i];
    let len = oracle.encrypt(&input).len();
    if len > original_len {
      return len - original_len;
    }
  }
  panic!("Unable to detect block size");
}

// Detect if oracle uses ECB by checking for repeated blocks
fn is_ecb_mode(oracle: &EncryptionOracle, cipher_block_size: usize) -> bool {
  // It is using ECB because the first two blocks are equal when the known string is bigger than or equal to two blocks
  let input = vec![b'A'; cipher_block_size * 3];
  let ciphertext = oracle.encrypt(&input);
  let chunks = ciphertext.chunks(cipher_block_size).collect::<Vec<_>>();
  chunks[0] == chunks[1]
}

fn decrypt_unknown_string_with_suffix(
  oracle: &EncryptionOracle,
  cipher_block_size: usize,
) -> Vec<u8> {
  let mut result: Vec<u8> = vec![];
  let total_length = oracle.encrypt(&[]).len();

  for _ in 0..total_length {
    let padding_length = cipher_block_size - (result.len() % cipher_block_size) - 1; // Amount of 'a' to add
    let input = vec![b'a'; padding_length];
    let block_number = result.len() / cipher_block_size; // Block number to look at to learn a new byte of the unknown string
    let ciphertext = oracle.encrypt(&input);
    let reference_block =
      &ciphertext[block_number * cipher_block_size..(block_number + 1) * cipher_block_size];
    // Now, reference_block contains the block to compare at

    // We have to test all possible bytes
    for b in 0..=255 {
      let mut guess_plaintext = input.clone();
      guess_plaintext.extend_from_slice(&result);
      guess_plaintext.push(b);
      let guess_ciphertext = oracle.encrypt(&guess_plaintext);
      let guess_block =
        &guess_ciphertext[block_number * cipher_block_size..(block_number + 1) * cipher_block_size];
      if guess_block == reference_block {
        result.push(b);
        println!("{}", b as char);
        break;
      }
    }
  }
  result
}

fn main() {
  let oracle = EncryptionOracle::init();

  // Discover block-size of the cipher (it is 16 bytes)
  let cipher_block_size = detect_block_size(&oracle); // The ciphertext length changes at 6 bytes
  println!("Detected block size: {}", cipher_block_size);

  // Detect that the function is doing ECB
  assert!(is_ecb_mode(&oracle, cipher_block_size));
  println!("Detected ECB mode");

  // Decrypt and print unknown string
  match String::from_utf8(decrypt_unknown_string_with_suffix(
    &oracle,
    cipher_block_size,
  )) {
    Ok(s) => println!("\n{}", s),
    Err(_) => println!("Decryption result is not valid UTF-8"),
  }
}
