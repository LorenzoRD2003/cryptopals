use core::fmt;
use cryptopals::utils::aes::{
  aes::AES, aes_error::AESError, aes_key::AESKey, constants::sizes::AES128_KEY_SIZE, utils::AESMode,
};
use flate2::{write::ZlibEncoder, Compression};
use rand::{thread_rng, Rng};
use std::{collections::HashMap, io::Write};

/*
  Compression Ratio Side-Channel Attacks
  The objective is to steal secure session cookies.
  The idea is to leak information using the compression library. We want to obtain the session id
  A payload of "sessionid=T" should compress a little bit better than "sessionid=S".

*/

#[derive(Debug)]
enum CompressionOracleError {
  IOError(std::io::Error),
  EncryptionError(AESError),
}

impl From<std::io::Error> for CompressionOracleError {
  fn from(error: std::io::Error) -> Self {
    Self::IOError(error)
  }
}

impl From<AESError> for CompressionOracleError {
  fn from(error: AESError) -> Self {
    Self::EncryptionError(error)
  }
}

impl fmt::Display for CompressionOracleError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::IOError(err) => write!(f, "IO error: {}", err),
      Self::EncryptionError(err) => write!(f, "Encryption error: {}", err),
    }
  }
}

struct CompressionOracle {
  secret: String,
}

impl CompressionOracle {
  fn new() -> Self {
    Self {
      secret: String::from("TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE="),
    }
  }

  fn format_request<S: AsRef<[u8]>>(&self, plaintext: &S) -> String {
    format!(
      "POST / HTTP/1.1
      Host: hapless.com
      Cookie: sessionid={}
      Content-Length: {}
      {}",
      self.secret,
      plaintext.as_ref().len(),
      String::from_utf8_lossy(plaintext.as_ref())
    )
  }

  fn compress_data<S: AsRef<[u8]>>(&self, data: &S) -> Result<Vec<u8>, CompressionOracleError> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data.as_ref())?;
    let encoded_bytes = encoder.finish()?;
    Ok(encoded_bytes)
  }

  fn call<S: AsRef<[u8]>>(&self, plaintext: &S) -> Result<usize, CompressionOracleError> {
    let formatted_request = self.format_request(plaintext);
    let compressed_request = self.compress_data(&formatted_request)?;
    let encoded = AES::encode(
      &compressed_request,
      &AESKey::random_key(AES128_KEY_SIZE).unwrap(),
      //AESMode::CTR(thread_rng().gen()), // Stream cipher!
      AESMode::CBC(thread_rng().gen()), // Block cipher!
    )?;
    Ok(encoded.len())
  }
}

const BASE64_CHARS: [char; 63] = [
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
  'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
  'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
  '5', '6', '7', '8', '9', '=',
];

fn get_possible_strings(
  oracle: &CompressionOracle,
  strings: &Vec<String>,
  flag: bool,
) -> Result<Vec<String>, CompressionOracleError> {
  let mut sizes: HashMap<String, usize> = HashMap::new();
  for s in strings {
    for c in BASE64_CHARS {
      let msg = format!("sessionid={}{}", s, c);
      let e = oracle.call(&msg)?;
      sizes.insert(format!("{}{}", s, c), e);
    }
  }
  let min_len = *sizes.values().min().unwrap();
  Ok(
    sizes
      .into_iter()
      .filter(|&(_, v)| v == min_len || (flag && v == min_len + 1))
      .map(|(k, _)| k)
      .collect::<Vec<String>>(),
  )
}

fn main() -> Result<(), CompressionOracleError> {
  let oracle = CompressionOracle::new();
  let mut possible_strings: Vec<String> = vec!["".to_string()];
  for i in 1..=44 {
    possible_strings =
      get_possible_strings(&oracle, &possible_strings, possible_strings.len() < 10)?;
    //possible_strings = get_possible_strings(&oracle, &possible_strings, false)?;
    println!("Round {i} finished.");
  }
  dbg!(&possible_strings);

  Ok(())
}
