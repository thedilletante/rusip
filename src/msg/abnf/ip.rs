
use std::net::{
  Ipv4Addr,
  Ipv6Addr
};


use nom::character::streaming;
use nom::character::complete;
use super::super::Binary;
use super::digit::h16;


fn fold_number(input: &Binary) -> Option<u8> {
  match input.into_iter()
    .map(|ch| ch - b'0')
    .fold(0u64, |acc, i| acc * 10 + i as u64) {
    i@ 0..=255 => Some(i as u8),
    _ => None
  }
}

named!(#[inline], pub complete_digits1_3<u8>, do_parse!(
  res:
    verify!(
      map!(
        verify!(
          complete::digit1,
          |c: &Binary| c.len() <= 3
        ),
        fold_number
      ),
    |r: &Option<u8>| r.is_some()
    )  >>
  ( res.unwrap() )
));

named!(#[inline], pub streaming_digits1_3<u8>, do_parse!(
  res:
    verify!(
      map!(
        verify!(
          streaming::digit1,
          |c: &Binary| c.len() <= 3
        ),
        fold_number
      ),
    |r: &Option<u8>| r.is_some()
    )  >>
  ( res.unwrap() )
));

// IPv4address   =  1*3DIGIT "." 1*3DIGIT "." 1*3DIGIT "." 1*3DIGIT
named!(#[inline], pub ipv4address<Ipv4Addr>, do_parse!(
    a: streaming_digits1_3 >>
    char!('.') >>
    b: streaming_digits1_3 >>
    char!('.') >>
    c: streaming_digits1_3 >>
    char!('.') >>
    d: complete_digits1_3 >>
    ( Ipv4Addr::new(a, b, c, d) )
));



named!(#[inline], pub colon_and_h16<u16>, preceded!(char!(':'), h16));

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum Ls32 {
  Hex(u16, u16),
  V4(Ipv4Addr)
}

impl Ls32 {
  pub fn segments(self) -> (u16, u16) {
    match self {
      Ls32::Hex(a, b) => (a, b),
      Ls32::V4(addr) => {
        let [a, b, c, d] = addr.octets();
        (((a as u16) << 8) + b as u16, ((c as u16) << 8) + d as u16)
      }
    }
  }
}

//ls32          = ( h16 ":" h16 ) / IPv4address
named!(#[inline], pub ls32<Ls32>, alt!(
  map!(tuple!(h16, colon_and_h16), |(a, b)| Ls32::Hex(a, b)) |
  map!(ipv4address, |a| Ls32::V4(a))
));

named!(#[inline], pub colon_and_ls32<Ls32>, preceded!(char!(':'), ls32));

// hex4             =  1*4HEXDIG
// hexseq           =  hex4 *( ":" hex4)
// hexpart          =  hexseq / hexseq "::" [ hexseq ] / "::" [ hexseq ]
// IPv6address      =  hexpart [ ":" IPv4address ]

// Following ABNF is taken from [RFC 5954](Section 4.1 - Resolution for Extra Colon in IPv4-Mapped IPv6 Address)
named!(#[inline], pub ipv6address<Ipv6Addr>, alt!(
  // IPv6address   =                             6( h16 ":" ) ls32
  tuple!(h16, colon_and_h16, colon_and_h16, colon_and_h16, colon_and_h16, colon_and_h16, colon_and_ls32) => {
    |(h1, h2, h3, h4, h5, h6, ls): (u16, u16, u16, u16, u16, u16, Ls32)| {
      let (h7, h8) = ls.segments();
      Ipv6Addr::new(h1, h2, h3, h4, h5, h6, h7, h8)
    }
  }
  |
  //                /                       "::" 5( h16 ":" ) ls32
  preceded!(tag!("::"), tuple!(h16, colon_and_h16, colon_and_h16, colon_and_h16, colon_and_h16, colon_and_ls32)) => {
    |(h2, h3, h4, h5, h6, ls): (u16, u16, u16, u16, u16, Ls32)| {
      let (h7, h8) = ls.segments();
      Ipv6Addr::new(0, h2, h3, h4, h5, h6, h7, h8)
    }
  }
  |
  //                / [               h16 ] "::" 4( h16 ":" ) ls32
  tuple!(opt!(h16), preceded!(tag!("::"), tuple!(h16, colon_and_h16, colon_and_h16, colon_and_h16, colon_and_ls32))) => {
    |(opt, (h3, h4, h5, h6, ls)): (Option<u16>, (u16, u16, u16, u16, Ls32))| {
      let (h7, h8) = ls.segments();
      Ipv6Addr::new(opt.unwrap_or(0), 0, h3, h4, h5, h6, h7, h8)
    }
  }
  |
  //                / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
  tuple!(opt!(tuple!(h16, opt!(colon_and_h16))), preceded!(tag!("::"), tuple!(h16, colon_and_h16, colon_and_h16, colon_and_ls32))) => {
    |(opt, (h4, h5, h6, ls)): (Option<(u16, Option<u16>)>, (u16, u16, u16, Ls32))| {
      let (h1, h2) = opt.unwrap_or((0, None));
      let (h7, h8) = ls.segments();
      Ipv6Addr::new(h1, h2.unwrap_or(0), 0, h4, h5, h6, h7, h8)
    }
  }
  |
  //                / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
  tuple!(opt!(tuple!(h16, opt!(colon_and_h16), opt!(colon_and_h16))), preceded!(tag!("::"), tuple!(h16, colon_and_h16, colon_and_ls32))) => {
    |(opt, (h5, h6, ls)): (Option<(u16, Option<u16>, Option<u16>)>, (u16, u16, Ls32))| {
      let (h1, h2, h3) = opt.unwrap_or((0, None, None));
      let (h7, h8) = ls.segments();
      Ipv6Addr::new(h1, h2.unwrap_or(0), h3.unwrap_or(0), 0, h5, h6, h7, h8)
    }
  }
  |
  //                / [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
  tuple!(opt!(tuple!(h16, opt!(colon_and_h16), opt!(colon_and_h16), opt!(colon_and_h16))), preceded!(tag!(b"::"), tuple!(h16, colon_and_ls32))) => {
    |(opt, (h6, ls)): (Option<(u16, Option<u16>, Option<u16>, Option<u16>)>, (u16, Ls32))| {
      let (h1, h2, h3, h4) = opt.unwrap_or((0, None, None, None));
      let (h7, h8) = ls.segments();
      Ipv6Addr::new(h1, h2.unwrap_or(0), h3.unwrap_or(0), h4.unwrap_or(0), 0, h6, h7, h8)
    }
  }
  |
  //                / [ *4( h16 ":" ) h16 ] "::"              ls32
  tuple!(opt!(tuple!(h16, opt!(colon_and_h16), opt!(colon_and_h16), opt!(colon_and_h16), opt!(colon_and_h16))), preceded!(tag!("::"), ls32)) => {
    |(opt, ls): (Option<(u16, Option<u16>, Option<u16>, Option<u16>, Option<u16>)>, Ls32)| {
      let (h1, h2, h3, h4, h5) = opt.unwrap_or((0, None, None, None, None));
      let (h7, h8) = ls.segments();
      Ipv6Addr::new(h1, h2.unwrap_or(0), h3.unwrap_or(0), h4.unwrap_or(0), h5.unwrap_or(0), 0, h7, h8)
    }
  }
  |
  //                / [ *5( h16 ":" ) h16 ] "::"              h16
  tuple!(opt!(tuple!(h16, opt!(colon_and_h16), opt!(colon_and_h16), opt!(colon_and_h16), opt!(colon_and_h16), opt!(colon_and_h16))), preceded!(tag!("::"), h16)) => {
    |(opt, h8): (Option<(u16, Option<u16>, Option<u16>, Option<u16>, Option<u16>, Option<u16>)>, u16)| {
      let (h1, h2, h3, h4, h5, h6) = opt.unwrap_or((0, None, None, None, None, None));
      Ipv6Addr::new(h1, h2.unwrap_or(0), h3.unwrap_or(0), h4.unwrap_or(0), h5.unwrap_or(0), h6.unwrap_or(0), 0, h8)
    }
  }
  |
  //                / [ *6( h16 ":" ) h16 ] "::"
  terminated!(
    opt!(
      tuple!(h16,
        opt!(colon_and_h16),
        opt!(colon_and_h16),
        opt!(colon_and_h16),
        opt!(colon_and_h16),
        opt!(colon_and_h16),
        opt!(colon_and_h16)
      )
    ),
    tag!("::")
  ) => {
    |opt: Option<(u16, Option<u16>, Option<u16>, Option<u16>, Option<u16>, Option<u16>, Option<u16>)>| {
      let (h1, h2, h3, h4, h5, h6, h7) = opt.unwrap_or((0, None, None, None, None, None, None));
      Ipv6Addr::new(h1, h2.unwrap_or(0), h3.unwrap_or(0), h4.unwrap_or(0), h5.unwrap_or(0), h6.unwrap_or(0), h7.unwrap_or(0), 0)
    }
  }
));

// IPv6reference    =  "[" IPv6address "]"
named!(#[inline], pub ipv6reference<Ipv6Addr>,
  delimited!(char!('['), ipv6address, char!(']'))
);

#[cfg(test)]
mod tests {

  use super::{ipv4address, ipv6reference, complete_digits1_3};
  use std::net::{Ipv4Addr, Ipv6Addr};
  use nom::{Err::Error, error::ErrorKind::Verify, Needed};
  use nom::Err::Incomplete;
  use nom::error::ErrorKind::Digit;
  use std::str::FromStr;

  #[test]
  fn parse_digits1_3_test() {
    assert_eq!(complete_digits1_3("1".as_bytes()), Ok(("".as_bytes(), 1)));
  }

  #[test]
  fn ipv4_parse_test() {
    assert_eq!(ipv4address("1.1.1.1".as_bytes()), Ok(("".as_bytes(), Ipv4Addr::new(1, 1, 1, 1))));
    assert_eq!(ipv4address("1.1.1.13".as_bytes()), Ok(("".as_bytes(), Ipv4Addr::new(1, 1, 1, 13))));
    assert_eq!(ipv4address("255.255.255.255".as_bytes()), Ok(("".as_bytes(), Ipv4Addr::new(!0, !0, !0, !0))));
    assert_eq!(ipv4address("255.255.255.256".as_bytes()), Err(Error(("256".as_bytes(), Verify))));

    assert_eq!(ipv4address("2".as_bytes()), Err(Incomplete(Needed::Size(1))));
    assert_eq!(ipv4address("22".as_bytes()), Err(Incomplete(Needed::Size(1))));
    assert_eq!(ipv4address("222".as_bytes()), Err(Incomplete(Needed::Size(1))));
    assert_eq!(ipv4address("222.".as_bytes()), Err(Incomplete(Needed::Size(1))));
    assert_eq!(ipv4address("222.1".as_bytes()), Err(Incomplete(Needed::Size(1))));
    assert_eq!(ipv4address("222.13".as_bytes()), Err(Incomplete(Needed::Size(1))));
    assert_eq!(ipv4address("222.233".as_bytes()), Err(Incomplete(Needed::Size(1))));
    assert_eq!(ipv4address("222.121.".as_bytes()), Err(Incomplete(Needed::Size(1))));
    assert_eq!(ipv4address("222.121.4".as_bytes()), Err(Incomplete(Needed::Size(1))));
    assert_eq!(ipv4address("222.121.43".as_bytes()), Err(Incomplete(Needed::Size(1))));
    assert_eq!(ipv4address("222.121.4.".as_bytes()), Err(Error(("".as_bytes(), Digit))));

    assert_eq!(ipv4address("222.23.2.2".as_bytes()), Ok(("".as_bytes(), Ipv4Addr::new(222, 23, 2, 2))));

    assert_eq!(ipv4address("2345.2.2.3".as_bytes()), Err(Error(("2345.2.2.3".as_bytes(), Verify))));
    assert_eq!(ipv4address("127.0.0.1098".as_bytes()), Err(Error(("1098".as_bytes(), Verify))));
  }

  #[test]
  fn ipv6() {
    assert_eq!(
      ipv6reference("[::ffff:192.0.2.10]".as_bytes()),
      Ok(("".as_bytes(), Ipv6Addr::from_str("::ffff:192.0.2.10").unwrap()))
    );
    assert_eq!(
      ipv6reference("[::ffff:c000:280]".as_bytes()),
      Ok(("".as_bytes(), Ipv6Addr::from_str("::ffff:c000:280").unwrap()))
    );
    assert_eq!(
      ipv6reference("[2001:db8::9:1]".as_bytes()),
      Ok(("".as_bytes(), Ipv6Addr::from_str("2001:db8::9:1").unwrap()))
    );
    assert_eq!(
      ipv6reference("[2001:db8::9:01]".as_bytes()),
      Ok(("".as_bytes(), Ipv6Addr::from_str("2001:db8::9:01").unwrap()))
    );
    assert_eq!(
      ipv6reference("[0:0:0:0:0:FFFF:129.144.52.38]".as_bytes()),
      Ok(("".as_bytes(), Ipv6Addr::from_str("0:0:0:0:0:FFFF:129.144.52.38").unwrap()))
    );
    assert_eq!(
      ipv6reference("[::FFFF:129.144.52.38]".as_bytes()),
      Ok(("".as_bytes(), Ipv6Addr::from_str("::FFFF:129.144.52.38").unwrap()))
    );
  }
}
