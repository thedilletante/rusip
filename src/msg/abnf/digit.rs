use super::map_byte;

use super::super::Binary;
use nom::IResult;

named!(#[inline],
  pub single<u8>,
  map!(
    call!(map_byte, |c| c >= b'0' && c <= b'9'),
    |c| c - b'0'
  )
);

named!(#[inline],
  pub single_hex<u8>,
  map!(
    call!(map_byte, |c| c.is_ascii_hexdigit()),
    |c| match c {
      b'a' | b'A' => 10,
      b'b' | b'B' => 11,
      b'c' | b'C' => 12,
      b'd' | b'D' => 13,
      b'e' | b'E' => 14,
      b'f' | b'F' => 15,
      v => v - b'0'
    }
  )
);

// h16           = 1*4HEXDIG
#[inline]
pub fn h16(input: &Binary) -> IResult<&Binary, u16> {
  let (mut input, a) = single_hex(input)?;

  let mut acc = a as u64;

  'forloop: for _ in 0..3 {
    match single_hex(input) {
      Ok((i, a)) => {
        acc *= 16;
        acc += a as u64;
        input = i;
      },
      Err(_) => {
        break 'forloop;
      },
    }
  }

  Ok((input, acc as u16))
}

#[cfg(test)]
mod tests {

  use super::{single, h16};
  use nom::Err::{Incomplete, Error};
  use nom::Needed;
  use nom::error::ErrorKind::Verify;

  #[test]
  fn single_digit_test() {
    assert_eq!(single("0".as_bytes()), Ok(("".as_bytes(), 0)));
    assert_eq!(single("9".as_bytes()), Ok(("".as_bytes(), 9)));
    assert_eq!(single("1".as_bytes()), Ok(("".as_bytes(), 1)));
    assert_eq!(single("35".as_bytes()), Ok(("5".as_bytes(), 3)));
    assert_eq!(single("s5".as_bytes()), Err(Error(("s5".as_bytes(), Verify))));
    assert_eq!(single("-".as_bytes()), Err(Error(("-".as_bytes(), Verify))));
    assert_eq!(single("".as_bytes()), Err(Incomplete(Needed::Size(1))));
  }

  #[test]
  fn h16_parse_test() {
    assert_eq!(h16("0".as_bytes()), Ok(("".as_bytes(), 0)));
    assert_eq!(h16("a".as_bytes()), Ok(("".as_bytes(), 0xa)));
    assert_eq!(h16("F".as_bytes()), Ok(("".as_bytes(), 0xf)));
    assert_eq!(h16("aBx".as_bytes()), Ok(("x".as_bytes(), 0xab)));
    assert_eq!(h16("aB12x".as_bytes()), Ok(("x".as_bytes(), 0xab12)));
    assert_eq!(h16("ce0x".as_bytes()), Ok(("x".as_bytes(), 0xce0)));
    assert_eq!(h16("77777".as_bytes()), Ok(("7".as_bytes(), 0x7777)));
    assert!(h16("".as_bytes()).is_err());
    assert!(h16("r".as_bytes()).is_err());
  }
}
