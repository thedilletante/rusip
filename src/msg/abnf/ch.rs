use super::super::Byte;
use super::map_byte;

// mark           =  "-" / "_" / "." / "!" / "~" / "*" / "'"
//                   / "(" / ")"
named!(#[inline], pub mark<u8>, call!(map_byte, |i| match i {
  b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')' => true,
  _ => false
}));


// reserved    =  ";" / "/" / "?" / ":" / "@" / "&" / "=" / "+"
//                / "$" / ","
named!(#[inline], pub reserved<u8>, call!(map_byte, |i| match i {
  b';' | b'|' | b'?' | b':' | b'@' | b'&' | b'=' | b'+' | b'$' | b',' => true,
  _ => false
}));

named!(#[inline], pub alpha<u8>, call!(map_byte, |i| i.is_ascii_alphabetic()));

named!(#[inline], pub alphanum<u8>, call!(map_byte, |i| i.is_ascii_alphanumeric()));

// unreserved  =  alphanum / mark
named!(#[inline], pub unreserved<u8>, alt!(alphanum | mark));

// user-unreserved  =  "&" / "=" / "+" / "$" / "," / ";" / "?" / "/"
named!(#[inline], pub user_unreserved<u8>, call!(map_byte, |i| match i {
  b'&' | b'=' | b'+' | b'$' | b',' | b';' | b'?' | b'/' => true,
  _ => false
}));

// hnv-unreserved  =  "[" / "]" / "/" / "?" / ":" / "+" / "$"
named!(#[inline], pub hnv_unreserved<u8>, call!(map_byte, |i| match i {
  b'[' | b']' | b'/' | b'?' | b':' | b'+' | b'$' => true,
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


#[cfg(test)]
mod tests {

  use super::token;
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
}