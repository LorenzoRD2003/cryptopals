use cryptopals::utils::mac::sha1::{Sha1, Sha1Mac, SHA1_BLOCK_SIZE};
use rand::{thread_rng, Rng};

fn md_padding(key_len: usize, v: &mut Vec<u8>) {
  let len = (key_len + v.len()) * 8;
  v.push(0x80);
  while (key_len + v.len()) % SHA1_BLOCK_SIZE != 56 {
    v.push(0);
  }
  v.extend_from_slice(&len.to_be_bytes());
}

fn main() {
  let mut rng = thread_rng();
  let random_length: u8 = rng.gen_range(16..=32);
  let random_key: Vec<u8> = (0..random_length).map(|_| rng.gen()).collect();

  // We will try all different possible key_sizes
  for key_len in 16..32 {
    let mut message =
      b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon".to_vec();

    // Obtain a hash of the message with the corresponding padding
    md_padding(key_len, &mut message);
    let mac = Sha1Mac::new(&random_key);
    let padding_digest = mac.authenticate(&message);

    // We have to add this block because of "" string in the last block
    let mut fixed_block: [u8; SHA1_BLOCK_SIZE] = [0u8; SHA1_BLOCK_SIZE];
    fixed_block[0] = 0x80;
    fixed_block[SHA1_BLOCK_SIZE - 2] = 0x04; // This depends on the length of our message
    message.extend_from_slice(&fixed_block);

    // Construct SHA1 with fixed state and make it process the sneaked data
    let h: [u32; 5] = [
      u32::from_be_bytes(padding_digest[..4].try_into().unwrap()),
      u32::from_be_bytes(padding_digest[4..8].try_into().unwrap()),
      u32::from_be_bytes(padding_digest[8..12].try_into().unwrap()),
      u32::from_be_bytes(padding_digest[12..16].try_into().unwrap()),
      u32::from_be_bytes(padding_digest[16..20].try_into().unwrap()),
    ];
    let data_len = key_len + message.len();
    let mut fixed_state_sha1 = Sha1::new_with_fixed_state(h, data_len as u64);

    // Add the data you want and process it with the fixed-state SHA1 fn
    let sneaked_data = b";admin=true";
    message.extend_from_slice(sneaked_data);
    fixed_state_sha1.update(sneaked_data);
    let admin_digest = fixed_state_sha1.finalize();

    // Check it is a valid MAC
    if mac.verify(&message, admin_digest) {
      println!("Broken successfully!");
      break;
    }
  }
}
