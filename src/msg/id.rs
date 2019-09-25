
type Byte = u8;
type Binary = [Byte];
type Result = std::result::Result<usize, ()>;

pub fn token(input: &Binary, output: &mut Binary) -> Result  {
  Generator { input, output, lookup: TOKEN_LOOKUP_TABLE }.generate()
}

pub fn word(input: &Binary, output: &mut Binary) -> Result {
  Generator { input, output, lookup: WORD_LOOKUP_TABLE }.generate()
}


struct Generator <'a, 'b> {
  input: &'a Binary,
  output: &'b mut Binary,
  lookup: &'static Binary
}

impl <'a, 'b> Generator <'a, 'b> {

  fn put(&mut self, i: &mut usize, acc: &mut usize) -> std::result::Result<(), ()> {
    if *i >= self.output.len() {
      Err(())
    } else {
      self.output[*i] = self.lookup[*acc % self.lookup.len()] as u8;
      *acc /= self.lookup.len();
      *i += 1;
      Ok(())
    }
  }

  fn generate(&mut self) -> Result {
    let mut i = 0;

    if !self.input.is_empty() {
      let mut acc : usize = 0;
      for x in self.input {
        acc *= 256;
        acc += *x as usize;

        while acc > self.lookup.len() {
          self.put(&mut i, &mut acc)?
        }
      }

      while acc > 0 {
        self.put(&mut i, &mut acc)?
      }
    }

    Ok(i)
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
    assert_eq!(token(&[], &mut []), Ok(0));
    assert_eq!(word(&[], &mut []), Ok(0));
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
      assert!(size.is_ok());
      assert!(size.unwrap() > 0);
      println!("token is {}", String::from_utf8(output[0..size.unwrap()].to_vec()).unwrap());
      output[0..size.unwrap()].into_iter().for_each(|ch| assert!(is_token_char(ch)));
    }
  }

  #[test]
  fn word_test() {
    let mut rnd = rand::thread_rng();
    let mut output = vec![0; 100];
    for _ in 0..100 {
      let input: [u8; 30] = rand::random();
      let size = word(&input[..rnd.gen_range(1, 30)], &mut output);
      assert!(size.is_ok());
      assert!(size.unwrap() > 0);
      println!("word is {}", String::from_utf8(output[0..size.unwrap()].to_vec()).unwrap());
      output[0..size.unwrap()].into_iter().for_each(|ch| assert!(is_word_char(ch)));
    }
  }

  #[test]
  fn output_is_not_enough_test() {
    assert_eq!(token(&[1], &mut[]), Err(()));
    assert_eq!(word(&[4, 6], &mut[]), Err(()));

    let mut output = vec![0; 2];
    assert_eq!(token(&[1, 3, 4], &mut output), Err(()));
    assert_eq!(word(&[223, 45], &mut output), Err(()));
  }
}