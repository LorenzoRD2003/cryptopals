use cryptopals::utils::aes::{
  aes::AES,
  aes_error::AESError,
  constants::sizes::AES_BLOCK_SIZE,
  utils::{pkcs_padding, AESMode},
};
use rand::{thread_rng, Rng};

struct Oracle {
  key: [u8; 16],
  iv: [u8; 16]
}

impl Default for Oracle {
  fn default() -> Self {
    let mut rng = thread_rng();
    Self {
      key: rng.gen(),
      iv: rng.gen()
    }
  }
}

impl Oracle {
  pub fn modify_and_encrypt_string<S: AsRef<[u8]>>(&self, input: &S) -> Result<Vec<u8>, AESError> {
    let sanitized_input = Self::sanitize_input(input);
    let plaintext = Self::prepare_plaintext(&sanitized_input);
    AES::encode(&plaintext, &self.key, AESMode::CBC(self.iv))
  }

  fn sanitize_input<S: AsRef<[u8]>>(input: &S) -> Vec<u8> {
    input
      .as_ref()
      .iter()
      .filter(|&&c| c != b';' && c != b'=')
      .copied()
      .collect()
  }

  fn prepare_plaintext<S: AsRef<[u8]>>(input: &S) -> Vec<u8> {
    let plaintext = [
      b"comment1=cooking%20MCs;userdata=".to_vec(),
      input.as_ref().to_vec(),
      b";comment2=%20like%20a%20pound%20of%20bacon".to_vec(),
    ]
    .concat();
    pkcs_padding(&plaintext, AES_BLOCK_SIZE as u8)
  }

  pub fn decrypt_and_look_for_admin_true<S: AsRef<[u8]>>(&self, ciphertext: &S) -> Result<bool, AESError> {
    let plaintext_bytes = AES::decode(ciphertext, &self.key, AESMode::CBC(self.iv))?;
    let target: &[u8; 12] = b";admin=true;";
    let result = plaintext_bytes
      .windows(target.len())
      .any(|window| window == target);
    Ok(result)
  }
}

fn main() -> Result<(), AESError> {
  /*
  ANALISIS TEORICO. El pre-texto ocupa exactamente dos bloques b0, b1. ^ es xor.
  Notacion:
    - E(k, .) para encriptar en modo ECB, E'(k, .) para el modo CBC. (es por bloque, se usa la definicion recursiva de E')
    - D(k, .) para decriptar en modo ECB, D'(k, .) para el modo CBC.
  Podemos encriptar todo bloque que no tenga = o ;
  Y queremos obtener un bloque b2 = "abcde;admin=true" mediante modificacion del encriptado.
  i.e. queremos obtener y2 tal que D'(k, y2) = b2
  Tenemos la ventaja de saber y0, y1 porque son FIJOS al ser fijos b0, b1 → y0y1 = E'(k, b0b1) es un valor fijo

  Consideramos b2', c tales que b2' = b2 ^ c, pero donde b2' es valido (y c tiene pocos bits 1)
  En particular usamos lo siguiente para definir el c que queremos
    ';' == '9' ^ \0x02
    '=' == '9' ^ \0x04
  Tenemos E(k, b0b1b2') = y0y1y2 (y lo podemos hacer).
  Ahora, sea y1' tal que y1' = y1 ^ c.
  D'(k, y0y1'y2) → b0 (D(k, y1') ^ y0) (D(k, y2) ^ y1')
    donde el segundo bloque será cualquier cosa pero el tercero es
    D(k, y2) ^ y1 ^ c = b2' ^ c = b2
  Como queriamos.
  */
  let oracle = Oracle::default();
  let b2_: &[u8; 16] = b"abcde9admin9true";
  let mut ciphertext = oracle.modify_and_encrypt_string(b2_)?;

  // Flip bit in the previous ciphertext block to inject ';' at position 5 of the next block
  ciphertext[AES_BLOCK_SIZE + 5] ^= b'9' ^ b';'; // \0x02
  // Flip bit in the previous ciphertext block to inject ';' at position 11 of the next block
  ciphertext[AES_BLOCK_SIZE + 11] ^= b'9' ^ b'='; // \0x04

  let is_admin = oracle.decrypt_and_look_for_admin_true(&ciphertext)?;
  assert!(is_admin);
  println!("Obtained admin access!");
  Ok(())
}
