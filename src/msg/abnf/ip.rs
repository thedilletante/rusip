
use std::net::{
  Ipv4Addr,
  Ipv6Addr
};
use super::digit::{dec_u8, h16};

named!(#[inline], pub ipv4address<Ipv4Addr>, do_parse!(
    a: dec_u8 >>
    char!('.') >>
    b: dec_u8 >>
    char!('.') >>
    c: dec_u8 >>
    char!('.') >>
    d: dec_u8 >>
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
  tuple!(h16, colon_and_h16) => {
    |(a, b)| Ls32::Hex(a, b)
  }
  |
  ipv4address => {
    |a| Ls32::V4(a)
  }
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

  use super::{ipv4address, ipv6reference};
  use std::net::{Ipv4Addr, Ipv6Addr};
  use nom::{Err::Error, Needed};
  use nom::Err::Incomplete;
  use nom::error::ErrorKind::{Digit, Char};
  use std::str::FromStr;

  #[test]
  fn ipv4_parse_test() {
    assert_eq!(ipv4address("1.1.1.1".as_bytes()), Ok(("".as_bytes(), Ipv4Addr::new(1, 1, 1, 1))));
    assert_eq!(ipv4address("1.1.1.13".as_bytes()), Ok(("".as_bytes(), Ipv4Addr::new(1, 1, 1, 13))));
    assert_eq!(ipv4address("255.255.255.255".as_bytes()), Ok(("".as_bytes(), Ipv4Addr::new(!0, !0, !0, !0))));
    assert_eq!(ipv4address("255.255.255.256".as_bytes()), Err(Error(("6".as_bytes(), Digit))));

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
    assert_eq!(ipv4address("222.121.4.".as_bytes()), Err(Incomplete(Needed::Size(1))));

    assert_eq!(ipv4address("222.23.2.2".as_bytes()), Ok(("".as_bytes(), Ipv4Addr::new(222, 23, 2, 2))));

    assert_eq!(ipv4address("2345.2.2.3".as_bytes()), Err(Error(("5.2.2.3".as_bytes(), Char))));
    assert_eq!(ipv4address("127.0.0.1098".as_bytes()), Ok(("8".as_bytes(), Ipv4Addr::new(127, 0, 0, 109))));
  }

  macro_rules! ipv4_success {
    ( $ip:expr ) => {
      assert_eq!(
        ipv6reference(format!("[{}]", $ip).as_bytes()),
        Ok(("".as_bytes(), Ipv6Addr::from_str($ip).unwrap()))
      );
    };
  }

  #[test]
  fn ipv6() {
    ipv4_success!("::ffff:192.0.2.10");
    ipv4_success!("::ffff:c000:280");
    ipv4_success!("2001:db8::9:1");
    ipv4_success!("2001:db8::9:01");
    ipv4_success!("fa:2001:db8::9:01");
    ipv4_success!("34:fa:2001:db8::9:01");
    ipv4_success!("34:fa:2001:db8::127.0.0.1");
    ipv4_success!("0:0:0:0:0:FFFF:129.144.52.38");
    ipv4_success!("2001:db8::10:5070");

    assert_eq!(ipv6reference("[2001:db8:::192.0.2.1]".as_bytes()), Err(Error((":192.0.2.1]".as_bytes(), Char))));
  }
}
