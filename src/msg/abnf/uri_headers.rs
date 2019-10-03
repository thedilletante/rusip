use super::map_byte;
use super::digit::single_hex;
use super::ch::alphanum;
use crate::msg::Binary;
use nom::{IResult, Needed};
use nom::Err::{Incomplete};

// hnv-unreserved  =  "[" / "]" / "/" / "?" / ":" / "+" / "$"
named!(#[inline],
  pub hnv_unreserved<u8>,
  one_of_byte!(b'[' | b']' | b'/' | b'?' | b':' | b'+' | b'$')
);

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

named!(#[inline],
  header_elem_len<u8>,
  alt!(
    hnv_unreserved => { |_| 1 } |
    unreserved => { |_| 1 } |
    escaped => { |_| 3 }
  )
);

// hname           =  1*( hnv-unreserved / unreserved / escaped )
#[inline]
pub fn hname(input: &Binary) -> IResult<&Binary, &Binary> {
  let (mut rest, l) = header_elem_len(input)?;
  let mut len = l as usize;

  while let Ok((r, l)) = header_elem_len(rest) {
    rest = r;
    len += l as usize;
  }

  Ok((rest, &input[..len]))
}

// hvalue          =  *( hnv-unreserved / unreserved / escaped )
#[inline]
pub fn hvalue(input: &Binary) -> IResult<&Binary, &Binary> {
  let mut rest = input;
  let mut len = 0usize;
  while let Ok((r, l)) = header_elem_len(rest) {
    rest = r;
    len += l as usize;
  }

  Ok((rest, &input[..len]))
}

// header          =  hname "=" hvalue
named!(#[inline],
  header<(&Binary, &Binary)>,
  tuple!(hname, preceded!(byte!(b'='), hvalue))
);

// headers         =  "?" header *( "&" header )
#[inline]
pub fn headers<'a, 'b>(input: &'a Binary, out: &'b mut [(&'a Binary, &'a Binary)]) -> IResult<&'a Binary, usize> {
  let mut i = 0usize;
  let mut rest = input;
  if let Ok((r, _)) = byte!(rest, b'?') {
    rest = r;
    if let Ok((r, h)) = header(rest) {
      if i >= out.len() {
        return Err(Incomplete(Needed::Size(1)));
      }

      rest = r;
      out[i] = h;
      i += 1;

      while let Ok((r, h)) = preceded!(rest, byte!(b'&'), header) {
        if i >= out.len() {
          return Err(Incomplete(Needed::Size(1)));
        }

        rest = r;
        out[i] = h;
        i += 1;
      }
    }
  }
  Ok((rest, i))
}



#[cfg(test)]
mod tests {
  use super::headers;
  use crate::msg::Binary;

  #[test]
  fn headers_test() {
    let mut hdrs: [(&Binary, &Binary); 10] = [(&[], &[]); 10];
    assert_eq!(headers("?a=b&c=&%ff=_/.?".as_bytes(), &mut hdrs), Ok(("".as_bytes(), 3)));

    assert_eq!(hdrs[0].0, "a".as_bytes());
    assert_eq!(hdrs[0].1, "b".as_bytes());
    assert_eq!(hdrs[1].0, "c".as_bytes());
    assert_eq!(hdrs[1].1, "".as_bytes());
    assert_eq!(hdrs[2].0, "%ff".as_bytes());
    assert_eq!(hdrs[2].1, "_/.?".as_bytes());
  }


}