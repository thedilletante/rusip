use super::Binary;
use super::Byte;

pub type Result = std::result::Result<usize, ()>;

pub fn token(input: &Binary, output: &mut Binary) -> usize  {
  generate(input, output, TOKEN_LOOKUP_TABLE)
}

pub fn word(input: &Binary, output: &mut Binary) -> usize {
  generate(input, output, WORD_LOOKUP_TABLE)
}

fn generate(input: &Binary, output: &mut Binary, lookup: &'static Binary) -> usize {
  Hasher::new(input.into_iter(), lookup, 256)
    .zip(output)
    .fold(0, |cnt, (i, o)|{
      *o = i;
      cnt + 1
    }
  )
}

struct Hasher<'a, T>
  where T : Iterator<Item=&'a Byte> {
  input: T,
  lookup: &'static Binary,
  acc: usize,
  multiplier: usize
}

impl<'a, T> Hasher<'a, T>
  where T : Iterator<Item=&'a Byte>  {
  fn new(input: T, lookup: &'static Binary, multiplier: usize) -> Hasher<'a, T> {
    Hasher {
      input,
      lookup,
      acc: 0,
      multiplier
    }
  }

  fn calculate(&mut self) -> u8 {
    let ret = self.lookup[self.acc % self.lookup.len()];
    self.acc /= self.lookup.len();
    ret
  }
}

impl<'a, T> Iterator for Hasher<'a, T>
  where T : Iterator<Item=&'a Byte>  {
  type Item = u8;

  fn next(&mut self) -> Option<Self::Item> {
    loop {
      if self.acc > self.lookup.len() {
        return Some(self.calculate());
      }

      if let Some(i) = self.input.next() {
        self.acc *= self.multiplier;
        self.acc += *i as usize;
      } else {
        break;
      }
    }

    if self.acc > 0 {
      return Some(self.calculate())
    } else {
      None
    }
  }
}

static TOKEN_LOOKUP_TABLE: &'static Binary = &[
  // other symbols
  '-' as u8, '.' as u8, '!' as u8, '*' as u8, '_' as u8, '+' as u8, '`' as u8, '\'' as u8, '~' as u8,
  // numbers
  '0' as u8, '1' as u8, '2' as u8, '3' as u8, '4' as u8, '5' as u8, '6' as u8, '7' as u8, '8' as u8, '9' as u8,
  // lower case letters
  'a' as u8, 'b' as u8, 'c' as u8, 'd' as u8, 'e' as u8, 'f' as u8, 'g' as u8, 'h' as u8, 'i' as u8, 'j' as u8,
  'k' as u8, 'l' as u8, 'm' as u8, 'n' as u8, 'o' as u8, 'p' as u8, 'q' as u8, 'r' as u8, 's' as u8, 't' as u8,
  'u' as u8, 'v' as u8, 'w' as u8, 'x' as u8, 'y' as u8, 'z' as u8,
  // upper case letters
  'A' as u8, 'B' as u8, 'C' as u8, 'D' as u8, 'E' as u8, 'F' as u8, 'G' as u8, 'H' as u8, 'I' as u8, 'J' as u8,
  'K' as u8, 'L' as u8, 'M' as u8, 'N' as u8, 'O' as u8, 'P' as u8, 'Q' as u8, 'R' as u8, 'S' as u8, 'T' as u8,
  'U' as u8, 'V' as u8, 'W' as u8, 'X' as u8, 'Y' as u8, 'Z' as u8
];

static WORD_LOOKUP_TABLE: &'static Binary = &[
  // other symbols
  '-' as u8, '.' as u8, '!' as u8, '*' as u8, '_' as u8, '+' as u8, '`' as u8, '\'' as u8, '~' as u8, '(' as u8, ')' as u8,
  '<' as u8, '>' as u8, ':' as u8, '\\' as u8, '"' as u8, '/' as u8, '[' as u8, ']' as u8, '?' as u8, '{' as u8, '}' as u8,
  // numbers
  '0' as u8, '1' as u8, '2' as u8, '3' as u8, '4' as u8, '5' as u8, '6' as u8, '7' as u8, '8' as u8, '9' as u8,
  // lower case letters
  'a' as u8, 'b' as u8, 'c' as u8, 'd' as u8, 'e' as u8, 'f' as u8, 'g' as u8, 'h' as u8, 'i' as u8, 'j' as u8,
  'k' as u8, 'l' as u8, 'm' as u8, 'n' as u8, 'o' as u8, 'p' as u8, 'q' as u8, 'r' as u8, 's' as u8, 't' as u8,
  'u' as u8, 'v' as u8, 'w' as u8, 'x' as u8, 'y' as u8, 'z' as u8,
  // upper case letters
  'A' as u8, 'B' as u8, 'C' as u8, 'D' as u8, 'E' as u8, 'F' as u8, 'G' as u8, 'H' as u8, 'I' as u8, 'J' as u8,
  'K' as u8, 'L' as u8, 'M' as u8, 'N' as u8, 'O' as u8, 'P' as u8, 'Q' as u8, 'R' as u8, 'S' as u8, 'T' as u8,
  'U' as u8, 'V' as u8, 'W' as u8, 'X' as u8, 'Y' as u8, 'Z' as u8
];


#[cfg(test)]
mod tests {
  extern crate rand;

  use rand::Rng;
  use super::*;

  #[test]
  fn empty_test() {
    assert_eq!(token(&[], &mut []), 0);
    assert_eq!(word(&[], &mut []), 0);
  }

  fn is_token_char(ch: &u8) -> bool {
    TOKEN_LOOKUP_TABLE.contains(&ch)
  }

  fn is_word_char(ch: &u8) -> bool {
    WORD_LOOKUP_TABLE.contains(ch)
  }

  #[test]
  fn token_test() {
    let mut rnd = rand::thread_rng();
    let mut output = vec![0; 100];
    for _ in 0..100 {
      let input: [u8; 30] = rand::random();
      let size = token(&input[..rnd.gen_range(1, 30)], &mut output);
      assert!(size > 0);
      println!("token is {}", String::from_utf8(output[0..size].to_vec()).unwrap());
      output[0..size].into_iter().for_each(|ch| assert!(is_token_char(ch)));
    }
  }

  #[test]
  fn word_test() {
    let mut rnd = rand::thread_rng();
    let mut output = vec![0; 100];
    for _ in 0..100 {
      let input: [u8; 30] = rand::random();
      let size = word(&input[..rnd.gen_range(1, 30)], &mut output);
      assert!(size > 0);
      println!("word is {}", String::from_utf8(output[0..size].to_vec()).unwrap());
      output[0..size].into_iter().for_each(|ch| assert!(is_word_char(ch)));
    }
  }

  #[test]
  fn output_is_not_enough_test() {
    assert_eq!(token(&[1], &mut[]), 0);
    assert_eq!(word(&[4, 6], &mut[]), 0);

    let mut output = vec![0; 2];
    assert_eq!(token(&[1, 3, 4], &mut output), 2);
    assert_eq!(word(&[223, 45], &mut output), 2);
  }
}