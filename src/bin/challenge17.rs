use cryptopals::utils::aes::{
  aes::AES,
  aes_error::AESError,
  constants::sizes::AES_BLOCK_SIZE,
  utils::{has_valid_pkcs_padding, pkcs_padding, AESMode},
};
use rand::{thread_rng, Rng};

/*
  C = Enc(k, P xor IV)
  P = Dec(k, C) xor IV
  Sabemos C y sabemos IV. Pero para decriptar necesitariamos k y no lo tenemos

  Idea de ataque: Modificar IV para modificar predeciblemente el P obtenido
  ¿Por qué? Porque cambiar un bit en IV lo va a cambiar en P.
  Entonces podemos cambiar el último byte en IV y tratar de conseguir un padding válido.
  O sea hacer que el ultimo byte de P sea 0x01.

  Considerando solo el ultimo byte
  p0 = Dec(k, C)[0] xor IV
  Si quiero que del otro lado haya un 0x01
  Busco byte b0 tal que p0 xor b0 = 0x01
  Entonces seria IV → (IV xor b0)
  0x01 = Dec(k, C)[0] xor (IV xor b0)
  Y b0 es un byte, podemos probar los 256 bytes.
  ¿Por qué hace falta probar los 256 bytes? Porque en ninguna query al oraculo vamos a poder
  ver cuál es el P obtenido, solamente veremos si tiene padding valido.

  Cuando hallemos b0, sabemos que usar b0' = b0 xor 0x01 convierte el último byte de P en 0,
  y b0' nos va a servir para tener más control sobre la salida del plaintext.
  Porque despues queremos que al final sea 0x02, 0x03, 0x04, etc.

  Potencial problema: Caso borde si el penultimo byte p1 de P es 0x02. En ese caso habra un
  padding valido tanto cuando logremos que el ultimo byte sea 0x01 como 0x02, y si encontramos
  el que da 0x02 primero, el ataque no va a funcionar.
  Este problema se soluciona haciendo xor del penultimo byte del IV cuando hallemos un padding valido,
  con cualquier valor != 0 y volviendo a testear padding valido.

  Seguir haciendo esto hasta terminar con todo el bloque.
*/

const BLOCK_SIZE: usize = 16;
const STRINGS: [&[u8]; 10] = [
  b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
  b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
  b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
  b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
  b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
  b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
  b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
  b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
  b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
  b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
];

struct PaddingOracle {
  key: [u8; 16],
  encr_iv: [u8; 16],
}

impl PaddingOracle {
  fn new() -> Self {
    let key: [u8; 16] = thread_rng().gen();
    let iv: [u8; 16] = rand::thread_rng().gen();
    PaddingOracle { key, encr_iv: iv }
  }

  fn select_random_and_encrypt(&self) -> Result<(Vec<u8>, [u8; 16]), AESError> {
    let random_index: usize = thread_rng().gen_range(0..10);
    let plaintext = pkcs_padding(&STRINGS[random_index], AES_BLOCK_SIZE as u8);
    let ciphertext = AES::encode(&plaintext, &self.key, AESMode::CBC(self.encr_iv))?;
    Ok((ciphertext, self.encr_iv))
  }

  fn check_padding<S: AsRef<[u8]>>(&self, ciphertext: &S, iv: &[u8; 16]) -> Result<bool, AESError> {
    let plaintext = AES::decode(ciphertext, &self.key, AESMode::CBC(iv.clone()))?;
    Ok(has_valid_pkcs_padding(&plaintext, AES_BLOCK_SIZE as u8).is_ok())
  }
}

fn check_every_possible_byte(
  block: &[u8; 16],
  oracle: &PaddingOracle,
  padding_iv: &mut [u8; 16],
  padding_value: u8,
) -> Result<u8, AESError> {
  for b in 0u8..=255 {
    padding_iv[BLOCK_SIZE - padding_value as usize] = b;

    if oracle.check_padding(block, &padding_iv)? {
      if padding_value == 1 {
        // because of the potential problem
        padding_iv[BLOCK_SIZE - 2] ^= 0x01;
        if !oracle.check_padding(block, &padding_iv)? {
          continue; // false positive case
        }
      }
      return Ok(b);
    }
  }
  Err(AESError::UnexpectedError("Unexpected error".into()))
}

fn single_block_poa(block: &[u8; 16], oracle: &PaddingOracle) -> Result<[u8; 16], AESError> {
  let mut zeroing_iv = [0u8; BLOCK_SIZE]; // Read explanation
                                          // padding value will be 0x01 in the first iteration, 0x02 in the second, and so on.
  for padding_value in 1..=BLOCK_SIZE as u8 {
    let mut padding_iv: [u8; 16] = zeroing_iv.map(|b| padding_value ^ b);
    let b = check_every_possible_byte(block, &oracle, &mut padding_iv, padding_value)?;
    zeroing_iv[BLOCK_SIZE - padding_value as usize] = b ^ padding_value;
  }
  Ok(zeroing_iv)
}

fn main() -> Result<(), AESError> {
  let oracle: PaddingOracle = PaddingOracle::new();
  let (ciphertext, mut iv) = oracle.select_random_and_encrypt()?;
  assert_eq!(ciphertext.len() % BLOCK_SIZE, 0);
  assert_eq!(iv.len() % BLOCK_SIZE, 0);

  let mut plaintext: Vec<u8> = vec![];
  let cipherblocks: Vec<[u8; 16]> = ciphertext
    .chunks(BLOCK_SIZE)
    .map(|chunk| {
      let mut arr = [0u8; 16];
      arr[0..BLOCK_SIZE].copy_from_slice(chunk);
      arr
    })
    .collect();

  for cipherblock in cipherblocks {
    let decrypted = single_block_poa(&cipherblock, &oracle)?;
    let plainblock: Vec<u8> = iv
      .iter()
      .zip(decrypted.iter())
      .map(|(&iv_byte, &dec_byte)| iv_byte ^ dec_byte)
      .collect(); 
    plaintext.extend(plainblock);
    iv = cipherblock;
  }
  dbg!(&plaintext, String::from_utf8(plaintext.clone()).unwrap());

  Ok(())
}
