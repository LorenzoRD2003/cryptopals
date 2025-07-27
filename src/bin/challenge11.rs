use cryptopals::utils::aes::aes::AES;
use cryptopals::utils::aes::utils::AESMode;
use rand::thread_rng;
use rand::Rng;

fn random_text_modifier<S: AsRef<[u8]>>(plaintext: &S) -> Vec<u8> {
  let mut text = plaintext.as_ref().to_vec();
  let pre_len = thread_rng().gen_range(5..=10);
  let post_len = thread_rng().gen_range(5..=10);
  let pre_bytes: Vec<u8> = (0..pre_len).map(|_| thread_rng().gen()).collect();
  let post_bytes: Vec<u8> = (0..post_len).map(|_| thread_rng().gen()).collect();
  text.splice(0..0, pre_bytes);
  text.extend(post_bytes);
  text
}

fn random_aes_mode() -> AESMode {
  let rand = thread_rng().gen_bool(0.5);
  if rand {
    AESMode::ECB
  } else {
    AESMode::CBC([0; 16])
  }
}

fn encryption_oracle<S: AsRef<[u8]>>(plaintext: &S) -> Vec<u8> {
  let text = random_text_modifier(plaintext);
  let random_key: &[u8; 16] = &thread_rng().gen();
  AES::encode(&text, random_key, random_aes_mode()).unwrap()
}

fn main() {
  // We have to create a message which is long enough such that even there is pre-padding and post-padding
  let my_input = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

  for _ in 0..10 {
    let ciphertext = encryption_oracle(&my_input);
    let ciphertext_blocks: Vec<&[u8]> = ciphertext.chunks(16).collect();
    // the plaintext has two equal blocks -> if ECB, then the ciphertext has two equal blocks. if CBC, probably they are different
    if ciphertext_blocks[1] == ciphertext_blocks[2] {
      println!("Detected mode: ECB");
    } else {
      println!("Detected mode: CBC");
    }
  }
}
