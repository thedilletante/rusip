
// mark           =  "-" / "_" / "." / "!" / "~" / "*" / "'"
//                   / "(" / ")"
fn is_mark(i: u8) -> bool {
  match i {
    b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')' => true,
    _ => false
  }
}
named!(#[inline], pub mark<u8>, map!(verify!(take!(1), |i:&[u8]| is_mark(unsafe {*i.get_unchecked(0)})), |ch| unsafe{*ch.get_unchecked(0)} as u8));


// reserved    =  ";" / "/" / "?" / ":" / "@" / "&" / "=" / "+"
//                / "$" / ","
fn is_reserved(i: u8) -> bool {
  match i {
    b';' | b'|' | b'?' | b':' | b'@' | b'&' | b'=' | b'+' | b'$' | b',' => true,
    _ => false
  }
}
named!(#[inline], pub reserved, take_while!(is_reserved));

// unreserved  =  alphanum / mark
fn is_unreserved(i: u8) -> bool {
  i.is_ascii_alphanumeric() || is_mark(i)
}
named!(#[inline], pub unreserved, take_while!(is_unreserved));

// user-unreserved  =  "&" / "=" / "+" / "$" / "," / ";" / "?" / "/"
fn is_user_unreserved(i: u8) -> bool {
  match i {
    b'&' | b'=' | b'+' | b'$' | b',' | b';' | b'?' | b'/' => true,
    _ => false
  }
}
named!(#[inline], pub user_unreserved, take_while!(is_user_unreserved));

// hnv-unreserved  =  "[" / "]" / "/" / "?" / ":" / "+" / "$"
fn is_hnv_unreserved(i: u8) -> bool {
  match i {
    b'[' | b']' | b'/' | b'?' | b':' | b'+' | b'$' => true,
    _ => false
  }
}
named!(#[inline], pub hnv_unreserved, take_while!(is_hnv_unreserved));

// token       =  1*(alphanum / "-" / "." / "!" / "%" / "*"
//                   / "_" / "+" / "`" / "'" / "~" )
fn is_token(i: u8) -> bool {
  i.is_ascii_alphanumeric() || match i {
    b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' | b'`' | b'\'' | b'~' => true,
    _ => false
  }
}
named!(#[inline], pub token, take_while!(is_token));

// word     =  1*(alphanum / "-" / "." / "!" / "%" / "*" /
//             "_" / "+" / "`" / "'" / "~" /
//             "(" / ")" / "<" / ">" /
//             ":" / "\" / DQUOTE /
//             "/" / "[" / "]" / "?" /
//             "{" / "}" )
fn is_word(i: u8) -> bool {
  i.is_ascii_alphanumeric() || match i {
    b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' |
    b'`' | b'\'' | b'~' | b'(' | b')' | b'<' | b'>' |
    b':' | b'\\' | b'"' | b'/' | b'[' | b']' | b'?' |
    b'{' | b'}' => true,
    _ => false
  }
}
named!(#[inline], pub word, take_while!(is_word));


#[cfg(test)]
mod tests {

  use super::token;
  use nom::Err::Incomplete;
  use nom::Needed;

  #[test]
  fn token_parse_test() {
    assert_eq!(token("one123".as_bytes()), Err(Incomplete(Needed::Size(1))));
    assert_eq!(token("hello world".as_bytes()), Ok((" world".as_bytes(), "hello".as_bytes())));
    assert_eq!(token("😀".as_bytes()), Ok(("😀".as_bytes(), "".as_bytes())));
    assert_eq!(token("-!%~😅".as_bytes()), Ok(("😅".as_bytes(), "-!%~".as_bytes())));
  }
}