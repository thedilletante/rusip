use super::id_translate_generated::TOKEN_TRANSLATE;


pub fn token(input: &[u8]) -> String  {
  if input.is_empty() {
    String::default()
  } else {
    let len = input.len() + 1;
    let mut res = vec!['0'; len];  

    let mut num : usize = 0;
    let mut i: usize = 0;
    for x in input {
      num *= 256;
      num += *x as usize;

      while num > TOKEN_TRANSLATE.len() {
        res[len - i - 1] = TOKEN_TRANSLATE[num % TOKEN_TRANSLATE.len()];
        num /= TOKEN_TRANSLATE.len();
        i += 1;
      }
    }
    if num > 0 {
      res[len - i - 1] = TOKEN_TRANSLATE[num % TOKEN_TRANSLATE.len()];
      i += 1;
    }

    res.into_iter().skip(len - i).collect()
  }
}

// pub fn word(input: &mut [char]) {

// }

#[cfg(test)]
mod tests {

  use super::*;

  #[test]
  fn token_test() {
    assert_eq!(token(&[]), String::default());
    println!("{}", token(&[14, 5, 3, 45, 7]));
  }
}