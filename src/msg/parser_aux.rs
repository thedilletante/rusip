
use super::Binary;

use std::io::{self, ErrorKind, Read};
use std::result;
use std::str;

use crate::sip_abnf::Token;

#[derive(Debug)]
pub enum Error {
  NotAToken
}

pub type Result<'a> = result::Result<&'a Binary, Error>;

// parse SIP token
pub fn parse_token(input: &Binary) -> Result {
  let len = MyReader{ inner: input, i: 0 }
    .take_while(Token::is_token)
    .map(<[u8]>::len)
    .sum();

  if len == 0 {
    Err(Error::NotAToken)
  } else {
    Ok(&input[0..len])
  }
}

struct MyReader<'a> {
  inner: &'a Binary,
  i: usize
}

impl<'a> Iterator for MyReader<'a> {
  type Item = &'a Binary;

  fn next(&mut self) -> Option<Self::Item> {
    let MyReader { inner, ref mut i } = *self;
    if *i >= inner.len() {
      return None
    }

    let first = unsafe { inner.get_unchecked(*i) };
    *i += 1;

    println!("i: {}", *i);

    match utf8_char_width(*first) {
      1 => Some(&inner[*i-1..*i]),
      w @ 2..=4 => {
        if *i + w >= inner.len() {
          None
        } else {
          *i += w - 1;
          str::from_utf8(&inner[*i-w..*i]).ok().map(|_| &inner[*i-w..*i])
        }
      }
      _ => None
    }
  }
}

static UTF8_CHAR_WIDTH: [u8; 256] = [
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, // 0x1F
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, // 0x3F
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, // 0x5F
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, // 0x7F
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 0x9F
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 0xBF
  0,0,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
  2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2, // 0xDF
  3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3, // 0xEF
  4,4,4,4,4,0,0,0,0,0,0,0,0,0,0,0, // 0xFF
];

fn utf8_char_width(b: u8) -> usize {
  return UTF8_CHAR_WIDTH[b as usize] as usize;
}


#[cfg(test)]
mod tests {

  use super::parse_token;

  #[test]
  fn token_parsed_properly() {
    assert_eq!(parse_token(b"one123").unwrap(), b"one123");
    assert_eq!(parse_token(b"hello world").unwrap(), b"hello");
    assert!(parse_token("😀".as_bytes()).is_err());
    assert_eq!(parse_token("-!%~😅".as_bytes()).unwrap(), b"-!%~");
  }
}