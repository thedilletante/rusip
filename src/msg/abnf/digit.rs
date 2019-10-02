
use super::super::Binary;

named!(#[inline], pub single<u8>,
  map!(verify!(take!(1), |ch: &Binary| {ch[0] > b'0' && ch[0] < b'9'}), |ch| ch[0] - b'0')
);


#[cfg(test)]
mod tests {

  use super::single;
  use nom::Err::{Incomplete, Error};
  use nom::Needed;
  use nom::error::ErrorKind::Verify;

  #[test]
  fn single_digit_test() {
    assert_eq!(single("1".as_bytes()), Ok(("".as_bytes(), 1)));
    assert_eq!(single("35".as_bytes()), Ok(("5".as_bytes(), 3)));
    assert_eq!(single("s5".as_bytes()), Err(Error(("s5".as_bytes(), Verify))));
    assert_eq!(single("-".as_bytes()), Err(Error(("-".as_bytes(), Verify))));
    assert_eq!(single("".as_bytes()), Err(Incomplete(Needed::Size(1))));
  }
}