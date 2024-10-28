use cryptopals::utils::aes::utils::AESMode;
use cryptopals::utils::aes::aes::AES;
use rand::thread_rng;
use rand::Rng;

fn random_text_modifier(plaintext: &Vec<u8>) -> Vec<u8> {
  let mut text = plaintext.clone();
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

fn encryption_oracle(plaintext: &Vec<u8>) -> Vec<u8> {
  let text = random_text_modifier(plaintext);
  let random_key: &[u8; 16] = &thread_rng().gen();
  AES::encode(
    &text,
    random_key,
    random_aes_mode()
  )
  .unwrap()
}

fn main() {
  let text = &b"Aguante Bocaaaaa".to_vec();
  dbg!(encryption_oracle(text));
}
