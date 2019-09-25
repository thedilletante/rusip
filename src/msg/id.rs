fn generate(input: &[u8], output: &mut [char], lookup_table: &'static [char]) -> Result<usize, ()> {
  let mut i: usize = 0;

  if !input.is_empty() {
    let mut num : usize = 0;
    for x in input {
      num *= 256;
      num += *x as usize;

      while num > lookup_table.len() {
        if i >= output.len() {
          return Err(())
        }
        output[i] = lookup_table[num % lookup_table.len()];
        num /= lookup_table.len();
        i += 1;
      }
    }
    if num > 0 {
      if i >= output.len() {
        return Err(())
      }
      output[i] = lookup_table[num % lookup_table.len()];
      i += 1;
    }
  }

  Ok(i)
}

static TOKEN_LOOKUP_TABLE: &'static [char] = &[
  // other symbols
  '-', '.', '!', '*', '_', '+', '`', '\'', '~',
  // numbers
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  // lower case letters
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
  'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
  'u', 'v', 'w', 'x', 'y', 'z',
  // upper case letters
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
  'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
  'U', 'V', 'W', 'X', 'Y', 'Z'
];

pub fn token(input: &[u8], output: &mut [char]) -> Result<usize, ()>  {
  generate(input, output, TOKEN_LOOKUP_TABLE)
}

static WORD_LOOKUP_TABLE: &'static [char] = &[
  // other symbols
  '-', '.', '!', '*', '_', '+', '`', '\'', '~', '(', ')',
  '<', '>', ':', '\\', '"', '/', '[', ']', '?', '{', '}',
  // numbers
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  // lower case letters
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
  'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
  'u', 'v', 'w', 'x', 'y', 'z',
  // upper case letters
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
  'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
  'U', 'V', 'W', 'X', 'Y', 'Z'
];

pub fn word(input: &[u8], output: &mut [char]) -> Result<usize, ()> {
  generate(input, output, WORD_LOOKUP_TABLE)
}

#[cfg(test)]
mod tests {
  extern crate rand;

  use super::*;

  #[test]
  fn empty_test() {
    assert_eq!(token(&[], &mut []), Ok(0));
    assert_eq!(word(&[], &mut []), Ok(0));
  }

  fn is_token_char(ch: &char) -> bool {
    TOKEN_LOOKUP_TABLE.contains(&ch)
  }

  fn is_word_char(ch: &char) -> bool {
    WORD_LOOKUP_TABLE.contains(ch)
  }

  #[test]
  fn token_test() {
    for _ in 0..100 {
      let input: [u8; 30] = rand::random();
      let mut output = vec!['0'; 100];
      let size = token(&input, &mut output);
      assert!(size.is_ok());
      assert!(size.unwrap() > 0);
      output[0..size.unwrap()].into_iter().for_each(|ch| assert!(is_token_char(ch)));
    }
  }

  #[test]
  fn word_test() {
    for _ in 0..100 {
      let input: [u8; 30] = rand::random();
      let mut output = vec!['0'; 100];
      let size = word(&input, &mut output);
      assert!(size.is_ok());
      assert!(size.unwrap() > 0);
      output[0..size.unwrap()].into_iter().for_each(|ch| assert!(is_word_char(ch)));
    }
  }

  #[test]
  fn output_is_not_enough_test() {
    assert_eq!(token(&[1], &mut[]), Err(()));
    assert_eq!(word(&[4, 6], &mut[]), Err(()));

    let mut output = vec!['0'; 2];
    assert_eq!(token(&[1, 3, 4], &mut output), Err(()));
    assert_eq!(word(&[223, 45], &mut output), Err(()));
  }
}