use cryptopals::utils::aes::{
  aes::AES,
  aes_error::AESError, utils::AESMode,
};
use rand::Rng;

fn convert_to_json_string(data: String) -> String {
  let mut result = String::from("{\n");

  for pair in data.split('&') {
    let mut key_value = pair.split('=');
    if let (Some(key), Some(value)) = (key_value.next(), key_value.next()) {
      result.push_str(&format!("  {}: '{}',\n", key, value));
    }
  }
  if result.ends_with(",\n") {
    result.truncate(result.len() - 2);
  }
  result.push_str("\n}");

  result
}

fn generate_uid() -> u32 {
  static mut UID: u32 = 10;
  unsafe {
    UID += 1;
    UID
  }
}

fn profile_for(email: String) -> String {
  let without_invalid_chars: String = email.chars().filter(|&c| c != '&' && c != '=').collect();
  let mut profile = String::from("email=");
  profile.push_str(&without_invalid_chars);
  profile.push_str("&uid=");
  profile.push_str(&generate_uid().to_string());
  profile.push_str("&role=user");
  profile
}

fn encrypt_user_profile(email: String, key_bytes: &[u8; 16]) -> Result<Vec<u8>, AESError> {
  AES::encode(
    &profile_for(email),
    key_bytes,
    AESMode::ECB
  )
}

fn decrypt_user_profile(
  encoded_profile: Vec<u8>,
  key_bytes: &[u8; 16],
) -> Result<String, AESError> {
  let decoded_bytes = AES::decode(
    &encoded_profile,
    key_bytes,
    AESMode::ECB
  )?;
  let decoded_string = String::from_utf8(decoded_bytes).unwrap();
  Ok(convert_to_json_string(decoded_string))
}

fn main() -> Result<(), AESError> {
  let query_string = String::from("foo=bar&baz=qux&zap=zazzle");
  assert_eq!(
    convert_to_json_string(query_string),
    String::from("{\n  foo: 'bar',\n  baz: 'qux',\n  zap: 'zazzle'\n}")
  );

  let email = String::from("foo@bar.com");
  let profile = profile_for(email);
  assert_eq!(profile, String::from("email=foo@bar.com&uid=11&role=user"));
  /*
    If we know:
      - c1 = E(k, email=lorenzo@rd)
      - c2 = E(k, .me&uid=12&role=)
      - c3 = E(k, admin&uid=13&rol)
      - c4 = E(k, =user\0x11\0x11\0x11\0x11\0x11\0x11\0x11\0x11\0x11\0x11\0x11)
    Then we can craft c = c1c2c3c4 and D(k, c1c2c3c4) give us an admin profile:
    email=lorenzo@rd.com&uid=12&role=admin&uid=13&rol=user\0x11\0x11\0x11\0x11\0x11\0x11\0x11\0x11\0x11\0x11\0x11
  */
  let random_key: [u8; 16] = rand::thread_rng().gen();
  let mut c: Vec<u8> = vec![];

  let first_cipher = encrypt_user_profile(String::from("lorenzo@rd.me"), &random_key)?;
  c.extend(first_cipher[..32].to_vec());

  let second_cipher = encrypt_user_profile(String::from("abcdefghijadmin"), &random_key)?;
  c.extend(second_cipher[16..32].to_vec());

  let third_cipher = encrypt_user_profile(String::from("lorenzo@bar.me"), &random_key)?;
  c.extend(third_cipher[32..48].to_vec());

  println!("{}", decrypt_user_profile(c, &random_key)?);
  Ok(())
}
