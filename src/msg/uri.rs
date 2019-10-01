
// SIP elements MAY support Request-URIs with schemes other than
// "sip" and "sips", for example the "tel" URI scheme of RFC
// 2806 [9].  SIP elements MAY translate non-SIP URIs using any
// mechanism at their disposal, resulting in SIP URI, SIPS URI,
// or some other scheme.

use std::net::{
  Ipv4Addr,
  Ipv6Addr
};


use nom::character::streaming;
use nom::character::complete;
use crate::msg::Binary;


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


fn hex_to_number(h: &u8) -> u8 {
  match h {
    b'a' | b'A' => 10,
    b'b' | b'B' => 11,
    b'c' | b'C' => 12,
    b'd' | b'D' => 13,
    b'e' | b'E' => 14,
    b'f' | b'F' => 15,
    v => v - b'0'
  }
}

fn fold_hex_number(input: &Binary) -> Option<u16> {
  let res = input.into_iter()
    .map(hex_to_number)
    .fold(0u64, |acc, i| acc * 16 + i as u64);

  if res <= std::u16::MAX as u64 {
    Some(res as u16)
  } else {
    None
  }
}

// h16           = 1*4HEXDIG
named!(#[inline], pub h16<u16>, do_parse!(
  res:
    verify!(
      map!(
        verify!(
          streaming::hex_digit1,
          |c: &Binary| c.len() <= 4
        ),
        fold_hex_number
      ),
    |r: &Option<u16>| r.is_some()
    )  >>
  ( res.unwrap() )
));

named!(#[inline], pub h16_and_colon<u16>, do_parse!(
  h: h16 >>
  char!(':') >>
  not!(char!(':')) >>
  (h)
));

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
  map!(tuple!(h16_and_colon, h16), |(a, b)| Ls32::Hex(a, b))
  |
  map!(ipv4address, |a| Ls32::V4(a))
));

fn mix_segments1(opt: (Option<u16>, u16)) -> (u16, u16) {
  match opt {
    (Some(a), e) => (a, e),
    o => (o.1, 0,)
  }
}

fn mix_segments2(opt: (Option<u16>, Option<u16>, u16)) -> (u16, u16, u16) {
  match opt {
    (Some(a), Some(b), e) => (a, b, e),
    (Some(a), None, e) => (a, e, 0),
    o => (o.2, 0, 0)
  }
}

fn mix_segments3(opt: (Option<u16>, Option<u16>, Option<u16>, u16)) -> (u16, u16, u16, u16) {
  match opt {
    (Some(a), Some(b), Some(c), e) => (a, b, c, e),
    (Some(a), Some(b), None, e) => (a, b, e, 0),
    (Some(a), None, None, e) => (a, e, 0, 0),
    o => (o.3, 0, 0, 0)
  }
}

fn mix_segments4(opt: (Option<u16>, Option<u16>, Option<u16>, Option<u16>, u16)) -> (u16, u16, u16, u16, u16) {
  match opt {
    (Some(a), Some(b), Some(c), Some(d), e) => (a, b, c, d, e),
    (Some(a), Some(b), Some(c), None, e) => (a, b, c, e, 0),
    (Some(a), Some(b), None, None, e) => (a, b, e, 0, 0),
    (Some(a), None, None, None, e) => (a, e, 0, 0, 0),
    o => (o.4, 0, 0, 0, 0)
  }
}

fn mix_segments5(opt: (Option<u16>, Option<u16>, Option<u16>, Option<u16>, Option<u16>, u16)) -> (u16, u16, u16, u16, u16, u16) {
  match opt {
    (Some(a), Some(b), Some(c), Some(d), Some(e), f) => (a, b, c, d, e, f),
    (Some(a), Some(b), Some(c), Some(d), None, e) => (a, b, c, d, e, 0),
    (Some(a), Some(b), Some(c), None, None, d) => (a, b, c, d, 0, 0),
    (Some(a), Some(b), None, None, None, c) => (a, b, c, 0, 0, 0),
    (Some(a), None, None, None, None, b) => (a, b, 0, 0, 0, 0),
    o => (o.5, 0, 0, 0, 0, 0)
  }
}

fn mix_segments6(opt: (Option<u16>, Option<u16>, Option<u16>, Option<u16>, Option<u16>, Option<u16>, u16)) -> (u16, u16, u16, u16, u16, u16, u16) {
  match opt {
    (Some(a), Some(b), Some(c), Some(d), Some(e), Some(f), g) => (a, b, c, d, e, f, g),
    (Some(a), Some(b), Some(c), Some(d), Some(e), None, f) => (a, b, c, d, e, f, 0),
    (Some(a), Some(b), Some(c), Some(d), None, None, e) => (a, b, c, d, e, 0, 0),
    (Some(a), Some(b), Some(c), None, None, None, d) => (a, b, c, d, 0, 0, 0),
    (Some(a), Some(b), None, None, None, None, c) => (a, b, c, 0, 0, 0, 0),
    (Some(a), None, None, None, None, None, b) => (a, b, 0, 0, 0, 0, 0),
    o => (o.6, 0, 0, 0, 0, 0, 0)
  }
}
// hex4             =  1*4HEXDIG
// hexseq           =  hex4 *( ":" hex4)
// hexpart          =  hexseq / hexseq "::" [ hexseq ] / "::" [ hexseq ]
// IPv6address      =  hexpart [ ":" IPv4address ]

// Following ABNF is taken from [RFC 5954](Section 4.1 - Resolution for Extra Colon in IPv4-Mapped IPv6 Address)
named!(#[inline], pub ipv6address<Ipv6Addr>, alt!(
// IPv6address   =                             6( h16 ":" ) ls32
  map!(
    tuple!(h16_and_colon, h16_and_colon, h16_and_colon, h16_and_colon, h16_and_colon, h16_and_colon, ls32),
    |(h1, h2, h3, h4, h5, h6, ls)| {
      let (h7, h8) = ls.segments();
      Ipv6Addr::new(h1, h2, h3, h4, h5, h6, h7, h8)
    }
  )
  |
//                /                       "::" 5( h16 ":" ) ls32
  map!(
    preceded!(tag!("::"), tuple!(h16_and_colon, h16_and_colon, h16_and_colon, h16_and_colon, h16_and_colon, ls32)),
    |(h2, h3, h4, h5, h6, ls)| {
      let (h7, h8) = ls.segments();
      Ipv6Addr::new(0, h2, h3, h4, h5, h6, h7, h8)
    }
  )
  |
//                / [               h16 ] "::" 4( h16 ":" ) ls32
  map!(
    tuple!(
      terminated!(
        opt!(h16),
        tag!("::")
      ),
      tuple!(h16_and_colon, h16_and_colon, h16_and_colon, h16_and_colon, ls32)
    ),
    |(opt, (h3, h4, h5, h6, ls))| {
      let (h7, h8) = ls.segments();
      Ipv6Addr::new(opt.unwrap_or(0), 0, h3, h4, h5, h6, h7, h8)
    }
  )
  |
//                / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
  map!(
    tuple!(
      terminated!(
        opt!(tuple!(opt!(h16_and_colon), h16)),
        tag!("::")
      ),
      tuple!(h16_and_colon, h16_and_colon, h16_and_colon, ls32)
    ),
    |(opt, (h4, h5, h6, ls))| {
      let (h1, h2) = mix_segments1(opt.unwrap_or((None, 0)));
      let (h7, h8) = ls.segments();
      Ipv6Addr::new(h1, h2, 0, h4, h5, h6, h7, h8)
    }
  )
  |
//                / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
  map!(
    tuple!(
      terminated!(
        opt!(tuple!(opt!(h16_and_colon), opt!(h16_and_colon), h16)),
        tag!("::")
      ),
      tuple!(h16_and_colon, h16_and_colon, ls32)
    ),
    |(opt, (h5, h6, ls))| {
      let (h1, h2, h3) = mix_segments2(opt.unwrap_or((None, None, 0)));
      let (h7, h8) = ls.segments();
      Ipv6Addr::new(h1, h2, h3, 0, h5, h6, h7, h8)
    }
  )
  |
//                / [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
  map!(
    tuple!(
      terminated!(
        opt!(tuple!(opt!(h16_and_colon), opt!(h16_and_colon), opt!(h16_and_colon), h16)),
        tag!("::")
      ),
      tuple!(h16_and_colon, ls32)
    ),
    |(opt, (h6, ls))| {
      let (h1, h2, h3, h4) = mix_segments3(opt.unwrap_or((None, None, None, 0)));
      let (h7, h8) = ls.segments();
      Ipv6Addr::new(h1, h2, h3, h4, 0, h6, h7, h8)
    }
  )
  |
//                / [ *4( h16 ":" ) h16 ] "::"              ls32
  map!(
    tuple!(
      terminated!(
        opt!(tuple!(opt!(h16_and_colon), opt!(h16_and_colon), opt!(h16_and_colon), opt!(h16_and_colon), h16)),
        tag!("::")
      ),
      ls32
    ),
    |(opt, ls)| {
      let (h1, h2, h3, h4, h5) = mix_segments4(opt.unwrap_or((None, None, None, None, 0)));
      let (h7, h8) = ls.segments();
      Ipv6Addr::new(h1, h2, h3, h4, h5, 0, h7, h8)
    }
  )
  |
//                / [ *5( h16 ":" ) h16 ] "::"              h16
  map!(
    tuple!(
      terminated!(
        opt!(
          tuple!(
            opt!(h16_and_colon),
            opt!(h16_and_colon),
            opt!(h16_and_colon),
            opt!(h16_and_colon),
            opt!(h16_and_colon),
            h16
          )
        ),
        tag!("::")
      ),
      h16
    ),
    |(opt, h8)| {
      let (h1, h2, h3, h4, h5, h6) = mix_segments5(opt.unwrap_or((None, None, None, None, None, 0)));
      Ipv6Addr::new(h1, h2, h3, h4, h5, h6, 0, h8)
    }
  )
  |
//                / [ *6( h16 ":" ) h16 ] "::"
  map!(
    terminated!(
      opt!(
        tuple!(
          opt!(h16_and_colon),
          opt!(h16_and_colon),
          opt!(h16_and_colon),
          opt!(h16_and_colon),
          opt!(h16_and_colon),
          opt!(h16_and_colon),
          h16
        )
      ),
      tag!("::")
    ),
    |opt| {
      let (h1, h2, h3, h4, h5, h6, h7) = mix_segments6(opt.unwrap_or((None, None, None, None, None, None, 0)));
      Ipv6Addr::new(h1, h2, h3, h4, h5, h6, h7, 0)
    }
  )
));

// IPv6reference    =  "[" IPv6address "]"
named!(#[inline], pub ipv6reference<Ipv6Addr>,
  delimited!(char!('['), ipv6address, char!(']'))
);

// SIP-URI          =  "sip:" [ userinfo ] hostport
//                    uri-parameters [ headers ]
// SIPS-URI         =  "sips:" [ userinfo ] hostport
//                    uri-parameters [ headers ]
// userinfo         =  ( user / telephone-subscriber ) [ ":" password ] "@"
// user             =  1*( unreserved / escaped / user-unreserved )
// user-unreserved  =  "&" / "=" / "+" / "$" / "," / ";" / "?" / "/"
// password         =  *( unreserved / escaped /
//                    "&" / "=" / "+" / "$" / "," )
// hostport         =  host [ ":" port ]
// host             =  hostname / IPv4address / ;
// hostname         =  *( domainlabel "." ) toplabel [ "." ]
// domainlabel      =  alphanum
//                    / alphanum *( alphanum / "-" ) alphanum
// toplabel         =  ALPHA / ALPHA *( alphanum / "-" ) alphanum

// port             =  1*DIGIT
// uri-parameters   =  *( ";" uri-parameter)
// uri-parameter    =  transport-param / user-param / method-param
//                    / ttl-param / maddr-param / lr-param / other-param
// transport-param  =  "transport="
//                    ( "udp" / "tcp" / "sctp" / "tls"
//                    / other-transport)
// other-transport  =  token
// user-param       =  "user=" ( "phone" / "ip" / other-user)
// other-user       =  token
// method-param     =  "method=" Method
// ttl-param        =  "ttl=" ttl
// maddr-param      =  "maddr=" host
// lr-param         =  "lr"
// other-param      =  pname [ "=" pvalue ]
// pname            =  1*paramchar
// pvalue           =  1*paramchar
// paramchar        =  param-unreserved / unreserved / escaped
// param-unreserved =  "[" / "]" / "/" / ":" / "&" / "+" / "$"
// Request-URI      =  SIP-URI / SIPS-URI / absoluteURI
// absoluteURI      =  scheme ":" ( hier-part / opaque-part )
// hier-part        =  ( net-path / abs-path ) [ "?" query ]
// net-path         =  "//" authority [ abs-path ]
// abs-path         =  "/" path-segments
// opaque-part      =  uric-no-slash *uric
// uric             =  reserved / unreserved / escaped
// uric-no-slash    =  unreserved / escaped / ";" / "?" / ":" / "@"
//                    / "&" / "=" / "+" / "$" / ","
// path-segments    =  segment *( "/" segment )
// segment          =  *pchar *( ";" param )
// param            =  *pchar
// pchar            =  unreserved / escaped /
//                    ":" / "@" / "&" / "=" / "+" / "$" / ","
// scheme           =  ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
// authority        =  srvr / reg-name
// srvr             =  [ [ userinfo "@" ] hostport ]
// reg-name         =  1*( unreserved / escaped / "$" / ","
//                    / ";" / ":" / "@" / "&" / "=" / "+" )
// query            =  *uric

pub enum Uri {
  Absolute(),
  Sip(),
  Sips()
}



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