
// Unlike HTTP/1.1, SIP treats the version number as a literal
// string.  In practice, this should make no difference.
// ...
// The SIP-Version string is case-insensitive,
// but implementations MUST send upper-case.
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct Version(pub u8, pub u8);

pub const DEFAULT_VERSION: Version = Version(2, 2);

pub mod parse {
  use crate::msg::abnf::single_digit;
  use crate::msg::version::Version;

  // SIP-Version    =  "SIP" "/" 1*DIGIT "." 1*DIGIT
  named!(#[inline], pub version<Version>, do_parse!(
    tag_no_case!(b"SIP") >> char!('/') >>
    major: single_digit >>
    char!('.') >>
    minor: single_digit >>
    ( Version(major, minor) )
  ));

}

pub mod assemble {
  use crate::msg::Binary;
  use crate::msg::version::Version;
  use std::io::Write;

  pub fn version(v: Version, mut buf: &mut Binary) -> std::io::Result<usize> {
    let mut sum = buf.write(b"SIP/")?;
    sum += buf.write(&[v.0 + b'0'; 1])?;
    sum += buf.write(b".")?;
    sum += buf.write(&[v.1 + b'0'; 1])?;
    Ok(sum)
  }
}

#[cfg(test)]
mod tests {

  use super::{Version, parse, assemble};
  use nom::{
    Err::{
      Incomplete, Error
    },
    Needed,
    error::ErrorKind::{
      Tag, Char
    }
  };
  use std::str::from_utf8;

  #[test]
  fn version_parse_test() {
    assert_eq!(parse::version("S".as_bytes()), Err(Incomplete(Needed::Size(3))));
    assert_eq!(parse::version("Si".as_bytes()), Err(Incomplete(Needed::Size(3))));
    assert_eq!(parse::version("siP".as_bytes()), Err(Incomplete(Needed::Size(1))));
    assert_eq!(parse::version("sip/".as_bytes()), Err(Incomplete(Needed::Size(1))));
    assert_eq!(parse::version("sip/2".as_bytes()), Err(Incomplete(Needed::Size(1))));
    assert_eq!(parse::version("sip/4.".as_bytes()), Err(Incomplete(Needed::Size(1))));

    assert_eq!(parse::version("SIP/1.1".as_bytes()), Ok(("".as_bytes(), Version(1, 1))));
    assert_eq!(parse::version("SIP/2.1 ".as_bytes()), Ok((" ".as_bytes(), Version(2, 1))));
    assert_eq!(parse::version(" SIP/2.1 ".as_bytes()), Err(Error((" SIP/2.1 ".as_bytes(), Tag))));
    assert_eq!(parse::version("SiP/1.2 ".as_bytes()), Ok((" ".as_bytes(), Version(1, 2))));
    assert_eq!(parse::version("sip/2,1 ".as_bytes()), Err(Error((",1 ".as_bytes(), Char))));
    assert_eq!(parse::version("sip/245.1 ".as_bytes()), Err(Error(("45.1 ".as_bytes(), Char))));
    assert_eq!(parse::version("sip/23454,1 ".as_bytes()), Err(Error(("3454,1 ".as_bytes(), Char))));
  }

  #[test]
  fn version_assemble_test() {
    let mut buffer = [0u8; 100];

    assert_eq!(assemble::version(Version(1, 2), &mut buffer).unwrap(), 7);
    assert_eq!("SIP/1.2", from_utf8(&buffer[..7]).unwrap());

    assert_eq!(assemble::version(Version(5, 3), &mut buffer[7..]).unwrap(), 7);
    assert_eq!("SIP/1.2SIP/5.3", from_utf8(&buffer[..14]).unwrap());

  }
}
