use cryptopals::utils::{
  conversion::hex_string::HexString,
  mac::{hmac::Sha1HMac, sha1::Sha1Digest},
};
use rand::{thread_rng, Rng};
use regex::Regex;
use std::{
  fmt,
  thread::sleep,
  time::{Duration, SystemTime, SystemTimeError},
};

#[derive(Debug, Clone, PartialEq)]
enum HTTPResponseCode {
  Success,
  BadRequest,
  InternalServerError,
}

impl fmt::Display for HTTPResponseCode {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match self {
      Self::Success => {
        write!(f, "200. Success.")
      }
      Self::BadRequest => {
        write!(f, "400. Invalid request format.")
      }
      Self::InternalServerError => {
        write!(f, "500. Internal server error.")
      }
    }
  }
}

#[derive(Debug)]
struct BadRequestError;

struct RequestParams {
  file: String,
  signature: Sha1Digest,
}

struct Server {
  hash: Sha1HMac,
}

impl Server {
  fn start() -> Self {
    let random_len: u8 = thread_rng().gen_range(16..=32);
    let random_key: Vec<u8> = (0..random_len).map(|_| thread_rng().gen()).collect();
    Self {
      hash: Sha1HMac::new(&random_key),
    }
  }

  // Only for testing purposes
  fn get_signature_for(&self, file: String) -> HexString {
    let digest: Sha1Digest = self.hash.authenticate(&file);
    HexString::try_from(digest.to_vec()).unwrap()
  }

  // timing leak
  fn process_request(&self, args: String) -> HTTPResponseCode {
    let p = Self::get_params(args);
    if p.is_err() {
      return HTTPResponseCode::BadRequest;
    }
    let params = p.unwrap();
    let expected_signature = self.hash.authenticate(&params.file);
    if Self::insecure_compare(&params.signature, &expected_signature) {
      HTTPResponseCode::Success
    } else {
      HTTPResponseCode::InternalServerError
    }
  }

  /*fn buffered_process_request(&mut self, params: &RequestParams) -> HTTPResponseCode {
    let expected_signature = self.buffer.entry(params.file.as_bytes().to_vec()).or_insert(self.hash.authenticate(&params.file));
    if Self::insecure_compare(&params.signature, &expected_signature) {
      HTTPResponseCode::Success
    } else {
      HTTPResponseCode::InternalServerError
    }
  }*/

  fn get_params(args: String) -> Result<RequestParams, BadRequestError> {
    let re =
      Regex::new(r"^\?file=([^&]+)&signature=([0-9a-fA-F]{40})$").map_err(|_| BadRequestError)?;
    let captures = re.captures(&args);
    if captures.is_none() {
      return Err(BadRequestError);
    }
    let params = captures.unwrap();
    let file = params[1].to_string();
    let signature_str = params[2].to_string();
    let signature = HexString::try_from(signature_str)
      .map_err(|_| BadRequestError)?
      .as_vector_of_bytes()
      .map_err(|_| BadRequestError)?;
    assert_eq!(signature.len(), 20);
    Ok(RequestParams {
      file,
      signature: signature.try_into().unwrap(),
    })
  }

  fn insecure_compare(digest: &Sha1Digest, expected_digest: &Sha1Digest) -> bool {
    for i in 0..20 {
      if digest[i] != expected_digest[i] {
        return false;
      }
      sleep(Duration::from_millis(50)); // Change this value
    }
    return true;
  }
}

fn main() -> Result<(), SystemTimeError> {
  let server = Server::start();
  let file = String::from("foo");
  let expected_signature: HexString = server.get_signature_for(file.clone());
  let args = format!("?file={}&signature={}", file, expected_signature);
  let response = server.process_request(args);
  println!("Initial tests: {}", response);

  let file: String = String::from("BOCAJRS");
  let mut obtained_signature: Sha1Digest = [0u8; 20];
  // we want to obtain the true signature of this file by using timing leaks
  for i in 0..20 {
    let (mut max_byte, mut max_duration): (u8, Duration) = (0, Duration::new(0, 0));
    for byte in 0u8..=255 {
      obtained_signature[i] = byte;
      let hex = HexString::try_from(obtained_signature.to_vec()).unwrap();
      let args = format!("?file={}&signature={}", file, hex);
      /*let params = RequestParams {
        file: file.clone(),
        signature: obtained_signature,
      };*/
      let initial_time = SystemTime::now();
      server.process_request(args);
      let end_time = SystemTime::now();
      let response_duration: Duration = end_time.duration_since(initial_time)?;
      if response_duration > max_duration {
        (max_byte, max_duration) = (byte, response_duration);
      }
    }
    obtained_signature[i] = max_byte;
    dbg!(i, max_byte, max_duration);
  }

  // Verify it was correct!
  let hex = HexString::try_from(obtained_signature.to_vec()).unwrap();
  let args = format!("?file={}&signature={}", file, hex);
  assert_eq!(server.process_request(args), HTTPResponseCode::Success);

  Ok(())
}
