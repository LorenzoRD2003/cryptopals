use cryptopals::utils::aes::aes::AES;
use cryptopals::utils::aes::aes_block::AESBlock;
use cryptopals::utils::aes::aes_error::AESError;
use cryptopals::utils::aes::utils::AESMode;
use cryptopals::utils::conversion::conversion::base64_to_bytes_vector;
use rand::{thread_rng, Rng};

struct EncryptionOracle {
  key: [u8; 16],
  pre_bytes: Vec<u8>,
  post_bytes: Vec<u8>,
}

impl EncryptionOracle {
  pub fn init() -> Self {
    let mut rng = thread_rng();
    let pre_len: usize = rng.gen_range(1..=20);
    let pre_bytes: Vec<u8> = (0..pre_len).map(|_| rng.gen()).collect();
    const UNKNOWN_STRING: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    let post_bytes = base64_to_bytes_vector(UNKNOWN_STRING).unwrap();
    Self {
      key: rng.gen(),
      pre_bytes,
      post_bytes,
    }
  }

  pub fn encrypt<S: AsRef<[u8]>>(&self, input: &S) -> Vec<u8> {
    let mut plaintext = self.pre_bytes.clone();
    plaintext.extend(input.as_ref());
    plaintext.extend(&self.post_bytes);
    AES::encode(&plaintext, &self.key, AESMode::ECB).unwrap()
  }
}

/// Determine block size by observing ciphertext length changes
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

/// Detect if oracle uses ECB by checking for repeated blocks
fn is_ecb_mode(oracle: &EncryptionOracle, cipher_block_size: usize) -> bool {
  // It is using ECB because two blocks are equal
  let input = vec![b'A'; cipher_block_size * 5];
  let ciphertext = oracle.encrypt(&input);
  let chunks = ciphertext.chunks(cipher_block_size).collect::<Vec<_>>();
  chunks[2] == chunks[3]
}

/// Determines the length of the random prefix by aligning known repeating blocks
fn get_pre_len(oracle: &EncryptionOracle, cipher_block_size: usize) -> Result<usize, AESError> {
  let controlled_input = vec!['a' as u8; cipher_block_size * 4];
  let encrypted = oracle.encrypt(&controlled_input);
  let blocks = AESBlock::from_bytes(&encrypted)?;

  // Obtain the alignment index of the first block composed by all 'a' (it is the first such that there are two equal blocks next to each other)
  let alignment_index = (0..blocks.len() - 1)
    .find(|&i| blocks[i] == blocks[i + 1])
    .expect("Could not find repeating block");

  // Try to find out how many padding bytes caused the alignment
  let mut padding: usize = 0;
  for i in cipher_block_size..2 * cipher_block_size {
    // size <= i < 2*size
    let obtained_blocks = AESBlock::from_bytes(&oracle.encrypt(&vec![b'a'; i]))?;
    if obtained_blocks[alignment_index] == blocks[alignment_index] {
      padding = i;
      break;
    }
  }
  // with j, we determine the remainder of the pre_bytes length modulo cipher_block_size. j -> (32 - j) % 16
  // 16 -> 0, 17 -> 15, 18 -> 14, ..., 31 -> 1
  let remainder = (2 * cipher_block_size - padding) % cipher_block_size;
  let quotient = if remainder == 0 {
    alignment_index
  } else {
    alignment_index - 1
  };

  Ok(quotient * cipher_block_size + remainder)
}

fn decrypt_unknown_string_with_suffix(
  oracle: &EncryptionOracle,
  cipher_block_size: usize,
  pre_len: usize,
) -> Vec<u8> {
  let mut result: Vec<u8> = vec![];
  // Unlike challenge 12, we start with an an `alignment_padding` of 'a' so that pre_bytes do not affect the output
  let alignment_padding = (cipher_block_size - (pre_len % cipher_block_size)) % cipher_block_size;
  let total_length = oracle.encrypt(&vec![b'a'; alignment_padding]).len();
  let start_block = (pre_len / cipher_block_size) + 1;

  for _ in 0..total_length {
    let padding_length =
      alignment_padding + cipher_block_size - (result.len() % cipher_block_size) - 1; // Amount of 'a' to add
    let input = vec![b'a'; padding_length];
    let block_number = start_block + result.len() / cipher_block_size; // Block number to look at to learn a new byte of the unknown string
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
        //print!("{}", b as char);
        break;
      }
    }
  }
  result
}

fn main() -> Result<(), AESError> {
  let oracle = EncryptionOracle::init();

  // Discover block-size of the cipher (it is 16 bytes)
  let cipher_block_size = detect_block_size(&oracle);
  println!("Detected block size: {}", cipher_block_size);

  // Detect that the function is doing ECB
  assert!(is_ecb_mode(&oracle, cipher_block_size));
  println!("Detected ECB mode");

  // Obtain the length of the random prefix
  let pre_len = get_pre_len(&oracle, cipher_block_size)?;
  assert_eq!(oracle.pre_bytes.len(), pre_len);
  println!("Detected pre_bytes length: {}", pre_len);

  // Decrypt and print unknown string
  match String::from_utf8(decrypt_unknown_string_with_suffix(
    &oracle,
    cipher_block_size,
    pre_len,
  )) {
    Ok(s) => println!("\n Correctly decrypted the string:\n\n{}", s),
    Err(_) => println!("Decryption result is not valid UTF-8"),
  };
  Ok(())
}
