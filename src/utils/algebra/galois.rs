pub fn galois_multiplication(x: u8, y: u8) -> u8 {
  let mut p = 0u8;
  let (mut a, mut b) = (x, y); // mutable copies of x,y
  for _ in 0..8 {
    if b & 1 != 0 {
      p ^= a;
    }
    let hi_bit_set = a & 0x80;
    a <<= 1;
    if hi_bit_set != 0 {
      a ^= 0x1b; // Reduce modulo the irreducible polynomial x^8 + x^4 + x^3 + x^2 + 1
    }
    b >>= 1;
  }
  p
}