use super::super::Byte;
use super::map_byte;
use super::digit::single_hex;
use crate::msg::Binary;
use super::one_byte;
use nom::IResult;
use nom::Err::Error;
use nom::error::ErrorKind;

named!(#[inline], pub alpha<u8>, call!(map_byte, |i| i.is_ascii_alphabetic()));

named!(#[inline], pub alphanum<u8>, call!(map_byte, |i| i.is_ascii_alphanumeric()));

// mark           =  "-" / "_" / "." / "!" / "~" / "*" / "'"
//                   / "(" / ")"
named!(#[inline],
  pub mark<u8>,
  one_of_byte!(b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')')
);

// unreserved  =  alphanum / mark
named!(#[inline], pub unreserved<u8>, alt!(alphanum | mark));

// escaped     =  "%" HEXDIG HEXDIG
named!(#[inline],
  pub escaped<u8>,
  map!(preceded!(byte!(b'%'), tuple!(single_hex, single_hex)), |(a, b)| a * 16 + b)
);

// user-unreserved  =  "&" / "=" / "+" / "$" / "," / ";" / "?" / "/"
named!(#[inline], pub user_unreserved<u8>, call!(map_byte, |i| match i {
  b'&' | b'=' | b'+' | b'$' | b',' | b';' | b'?' | b'/' => true,
  _ => false
}));


// token       =  1*(alphanum / "-" / "." / "!" / "%" / "*"
//                   / "_" / "+" / "`" / "'" / "~" )
named!(#[inline], pub token, take_while1!(|i: Byte| {
  i.is_ascii_alphanumeric() || match i {
    b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' | b'`' | b'\'' | b'~' => true,
    _ => false
  }
}));

// word     =  1*(alphanum / "-" / "." / "!" / "%" / "*" /
//             "_" / "+" / "`" / "'" / "~" /
//             "(" / ")" / "<" / ">" /
//             ":" / "\" / DQUOTE /
//             "/" / "[" / "]" / "?" /
//             "{" / "}" )
named!(#[inline], pub word, take_while1!(|i: Byte| {
  i.is_ascii_alphanumeric() || match i {
    b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' |
    b'`' | b'\'' | b'~' | b'(' | b')' | b'<' | b'>' |
    b':' | b'\\' | b'"' | b'/' | b'[' | b']' | b'?' |
    b'{' | b'}' => true,
    _ => false
  }
}));

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

#[inline]
pub fn utf8_char_width(b: Byte) -> usize {
  return UTF8_CHAR_WIDTH[b as usize] as usize;
}

#[inline]
pub fn utf8(input: &Binary) -> IResult<&Binary, char> {
  let (rest, first_byte) = one_byte(input)?;
  match utf8_char_width(first_byte) {
    1 => {
      Ok((&rest, first_byte as char))
    }
    len@ 2..=4 => {
      if input.len() < len {
        Err(Error((input, ErrorKind::Char)))
      } else {
        match std::str::from_utf8(&input[..len]).ok() {
          Some(s) => Ok((&input[len..], s.chars().next().unwrap())),
          None => Err(Error((input, ErrorKind::Char)))
        }
      }
    }
    _ => {
      Err(Error((input, ErrorKind::Char)))
    }
  }
}


#[cfg(test)]
mod tests {

  use super::token;
  use super::utf8;
  use nom::Err::{Incomplete, Error};
  use nom::Needed;
  use nom::error::ErrorKind::TakeWhile1;

  #[test]
  fn token_parse_test() {
    assert_eq!(token("one123".as_bytes()), Err(Incomplete(Needed::Size(1))));
    assert_eq!(token("hello world".as_bytes()), Ok((" world".as_bytes(), "hello".as_bytes())));
    assert_eq!(token("😀".as_bytes()), Err(Error(("😀".as_bytes(), TakeWhile1))));
    assert_eq!(token("-!%~😅".as_bytes()), Ok(("😅".as_bytes(), "-!%~".as_bytes())));
  }

  #[test]
  fn utf8_parse_test() {
    assert_eq!(utf8("hh".as_bytes()), Ok(("h".as_bytes(), 'h')));
    assert_eq!(utf8("🤣😄".as_bytes()), Ok(("😄".as_bytes(), '🤣')));
    assert_eq!(utf8("".as_bytes()), Err(Incomplete(Needed::Size(1))));
  }
}