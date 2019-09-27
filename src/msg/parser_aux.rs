
use super::Binary;
use super::Utf8Str;

use std::io::{self, ErrorKind, Read};
use std::result;
use std::str;

use crate::sip_abnf::Token;

#[derive(Debug)]
pub enum Error {
  NotAToken
}

pub type Result<'a> = result::Result<&'a Utf8Str, Error>;

// parse SIP token
pub fn parse_token(input: &Binary) -> Result {
  let len = MyReader::new(input)
    .take_while(|e| {
      match e {
        Ok(ch) => ch.is_token(),
        _ => false
      }
    })
    .map(result::Result::unwrap)
    .map(char::len_utf8)
    .sum();

  if len == 0 {
    Err(Error::NotAToken)
  } else {
    unsafe {
      Ok(str::from_utf8_unchecked(&input[0..len]))
    }
  }

}

struct MyReader<R> {
  inner: R,
}

impl<R: Read> MyReader<R> {
  fn new(inner: R) -> MyReader<R> {
    MyReader {
      inner,
    }
  }
}

#[derive(Debug)]
enum MyReaderError {
  NotUtf8,
  Other(io::Error),
}

impl<R: Read> Iterator for MyReader<R> {
  type Item = result::Result<char, MyReaderError>;

  fn next(&mut self) -> Option<result::Result<char, MyReaderError>> {
    let first_byte = match read_one_byte(&mut self.inner)? {
      Ok(b) => b,
      Err(e) => return Some(Err(MyReaderError::Other(e))),
    };
    let width = utf8_char_width(first_byte);
    if width == 1 {
      return Some(Ok(first_byte as char));
    }
    if width == 0 {
      return Some(Err(MyReaderError::NotUtf8));
    }
    let mut buf = [first_byte, 0, 0, 0];
    {
      let mut start = 1;
      while start < width {
        match self.inner.read(&mut buf[start..width]) {
          Ok(0) => return Some(Err(MyReaderError::NotUtf8)),
          Ok(n) => start += n,
          Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
          Err(e) => return Some(Err(MyReaderError::Other(e))),
        }
      }
    }
    Some(match str::from_utf8(&buf[..width]).ok() {
      Some(s) => Ok(s.chars().next().unwrap()),
      None => Err(MyReaderError::NotUtf8),
    })
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

fn read_one_byte(reader: &mut dyn Read) -> Option<io::Result<u8>> {
  let mut buf = [0];
  loop {
    return match reader.read(&mut buf) {
      Ok(0) => None,
      Ok(..) => Some(Ok(buf[0])),
      Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
      Err(e) => Some(Err(e)),
    };
  }
}


#[cfg(test)]
mod tests {

  use super::parse_token;

  #[test]
  fn token_parsed_properly() {
    assert_eq!(parse_token("one123".as_bytes()).unwrap(), "one123");
    assert_eq!(parse_token("hello world".as_bytes()).unwrap(), "hello");
    assert!(parse_token("😀".as_bytes()).is_err());
    assert_eq!(parse_token("-!%~😅".as_bytes()).unwrap(), "-!%~");
  }
}