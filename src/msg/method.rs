
use super::Binary;

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum Method <'a> {
  Register,
  Invite,
  Ack,
  Cancel,
  Bye,
  Options,
  Token(&'a Binary)
}

pub mod parse {
  use crate::msg::abnf::token;
  use crate::msg::method::Method;
  //  INVITEm           =  %x49.4E.56.49.54.45 ; INVITE in caps
  //  ACKm              =  %x41.43.4B ; ACK in caps
  //  OPTIONSm          =  %x4F.50.54.49.4F.4E.53 ; OPTIONS in caps
  //  BYEm              =  %x42.59.45 ; BYE in caps
  //  CANCELm           =  %x43.41.4E.43.45.4C ; CANCEL in caps
  //  REGISTERm         =  %x52.45.47.49.53.54.45.52 ; REGISTER in caps
  //  Method            =  INVITEm / ACKm / OPTIONSm / BYEm
  //                       / CANCELm / REGISTERm
  //                       / extension-method
  //  extension-method  =  token
  named!(#[inline], pub method<Method>,
    alt!(
        tag!(b"REGISTER") => { |_| Method::Register } |
        tag!(b"INVITE") => { |_| Method::Invite } |
        tag!(b"ACK") => { |_| Method::Ack } |
        tag!(b"CANCEL") => { |_| Method::Cancel } |
        tag!(b"BYE") => { |_| Method::Bye } |
        tag!(b"OPTIONS") => { |_| Method::Options } |
        token => { |t| Method::Token(t) }
      )
  );
}

pub mod assemble {
  use crate::msg::Binary;
  use crate::msg::method::Method;
  use std::io::Write;

  pub fn method(m: Method, mut buf: &mut Binary) -> std::io::Result<usize> {
    match m {
      Method::Token(token) => buf.write(token),
      Method::Register => buf.write(b"REGISTER"),
      Method::Invite => buf.write(b"INVITE"),
      Method::Ack => buf.write(b"ACK"),
      Method::Cancel => buf.write(b"CANCEL"),
      Method::Bye => buf.write(b"BYE"),
      Method::Options => buf.write(b"OPTIONS"),
    }
  }

}

#[cfg(test)]
mod tests {
  use super::{
    Method,
    parse,
    assemble
  };
  use nom::{
    Err::Incomplete,
    Needed
  };

  #[test]
  fn method_parse_test() {
    assert_eq!(parse::method("INVITE".as_bytes()), Ok(("".as_bytes(), Method::Invite)));
    assert_eq!(parse::method("REGISTER".as_bytes()), Ok(("".as_bytes(), Method::Register)));
    assert_eq!(parse::method("AC".as_bytes()), Err(Incomplete(Needed::Size(3))));
    assert_eq!(parse::method("BYE some".as_bytes()), Ok((" some".as_bytes(), Method::Bye)));
    assert_eq!(parse::method("asdf-sdf .".as_bytes()), Ok((" .".as_bytes(), Method::Token("asdf-sdf".as_bytes()))));
  }

  #[test]
  fn method_assemble_test() {
    let mut output = [0 as u8; 21];
    assert_eq!(assemble::method(Method::Invite, &mut output).unwrap(), 6);
    assert_eq!(std::str::from_utf8(&output[0..6]).unwrap(), "INVITE");

    assert_eq!(assemble::method(Method::Token(b"REFER"), &mut output[6..]).unwrap(), 5);
    assert_eq!(std::str::from_utf8(&output[0..11]).unwrap(), "INVITEREFER");

    assert_eq!(assemble::method(Method::Token(b"SUBSCRIBE"), &mut output[11..]).unwrap(), 9);
    assert_eq!(std::str::from_utf8(&output[0..20]).unwrap(), "INVITEREFERSUBSCRIBE");

    assert_eq!(assemble::method(Method::Options, &mut output[20..]).unwrap(), 1);
    assert_eq!(std::str::from_utf8(&output).unwrap(), "INVITEREFERSUBSCRIBEO");

    assert_eq!(assemble::method(Method::Bye, &mut output[21..]).unwrap(), 0);
  }
}