use super::ch::{unreserved, escaped};
use crate::msg::Binary;

// hnv-unreserved  =  "[" / "]" / "/" / "?" / ":" / "+" / "$"
named!(#[inline],
  pub hnv_unreserved<u8>,
  one_of_byte!(b'[' | b']' | b'/' | b'?' | b':' | b'+' | b'$')
);

struct Digits(usize);

impl super::Consumed for Digits {
  fn consumed(&self) -> usize {
    self.0
  }
}

// hname           =  1*( hnv-unreserved / unreserved / escaped )
named!(#[inline],
  hname,
  at_least_one!(alt!(
    hnv_unreserved => { |_| Digits(1) } |
    unreserved => { |_| Digits(1) } |
    escaped => { |_| Digits(3) }
  ))
);

// hvalue          =  *( hnv-unreserved / unreserved / escaped )
named!(#[inline],
  hvalue,
  many_times!(alt!(
    hnv_unreserved => { |_| Digits(1) } |
    unreserved => { |_| Digits(1) } |
    escaped => { |_| Digits(3) }
  ))
);

// header          =  hname "=" hvalue
named!(#[inline],
  header<(&Binary, &Binary)>,
  tuple!(hname, preceded!(byte!(b'='), hvalue))
);

#[derive(Debug, Eq, PartialEq)]
pub enum ParseError {
  NotEnoughOutSpace {
    written: usize
  }
}

// headers         =  "?" header *( "&" header )
#[inline]
pub fn headers<'a, 'b>(input: &'a Binary, out: &'b mut [&'a Binary])
  -> Result<(&'a Binary, usize), ParseError> {

  let mut i = 0usize;
  let mut rest = input;
  if let Ok((r, _)) = byte!(rest, b'?') {
    rest = r;
    if let Ok((r, (hname, hvalue))) = header(rest) {
      if i + 1 >= out.len() {
        return Err(ParseError::NotEnoughOutSpace { written: i });
      }

      rest = r;
      out[i] = hname;
      out[i + 1] = hvalue;
      i += 2;

      while let Ok((r, (hname, hvalue))) = preceded!(rest, byte!(b'&'), header) {
        if i + 1 >= out.len() {
          return Err(ParseError::NotEnoughOutSpace { written: i });
        }

        rest = r;
        out[i] = hname;
        out[i + 1] = hvalue;
        i += 2;
      }
    }
  }
  Ok((rest, i))
}



#[cfg(test)]
mod tests {
  use super::headers;
  use crate::msg::abnf::uri_headers::ParseError;

  #[test]
  fn headers_test() {
    let mut hdrs = ["".as_bytes(); 10];
    assert_eq!(headers("?a=b&cdf=&[%ff]=_/.?".as_bytes(), &mut hdrs), Ok(("".as_bytes(), 6)));

    assert_eq!(hdrs[0], "a".as_bytes());
    assert_eq!(hdrs[1], "b".as_bytes());
    assert_eq!(hdrs[2], "cdf".as_bytes());
    assert_eq!(hdrs[3], "".as_bytes());
    assert_eq!(hdrs[4], "[%ff]".as_bytes());
    assert_eq!(hdrs[5], "_/.?".as_bytes());

    assert_eq!(headers("?a=b".as_bytes(), &mut []), Err(ParseError::NotEnoughOutSpace { written: 0 }));
    assert_eq!(headers("?a=b&c=d".as_bytes(), &mut hdrs[..1]), Err(ParseError::NotEnoughOutSpace { written: 0 }));
    assert_eq!(headers("?a=b&c=d".as_bytes(), &mut hdrs[..2]), Err(ParseError::NotEnoughOutSpace { written: 2 }));
  }


}