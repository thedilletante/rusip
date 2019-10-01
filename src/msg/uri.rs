
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

fn fold_hex_number(input: &Binary) -> u16 {
  input.into_iter()
    .map(hex_to_number)
    .fold(0u64, |acc, i| acc * 16 + i as u64) as u16
}


// h16           = 1*4HEXDIG
named!(#[inline], pub h16<u16>, do_parse!(
  a: verify!(peek!(streaming::hex_digit1), |i:&Binary| i.len() > 0 && i.len() <= 4) >>
  take!(a.len()) >>
  ( fold_hex_number(a) )
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
  map!(
    tuple!(h16, colon_and_h16, colon_and_h16, colon_and_h16, colon_and_h16, colon_and_h16, colon_and_ls32),
    |(h1, h2, h3, h4, h5, h6, ls)| {
      let (h7, h8) = ls.segments();
      Ipv6Addr::new(h1, h2, h3, h4, h5, h6, h7, h8)
    }
  )
  |
//                /                       "::" 5( h16 ":" ) ls32
  map!(
    preceded!(tag!("::"), tuple!(h16, colon_and_h16, colon_and_h16, colon_and_h16, colon_and_h16, colon_and_ls32)),
    |(h2, h3, h4, h5, h6, ls)| {
      let (h7, h8) = ls.segments();
      Ipv6Addr::new(0, h2, h3, h4, h5, h6, h7, h8)
    }
  )
  |
//                / [               h16 ] "::" 4( h16 ":" ) ls32
  map!(
    tuple!(
      opt!(h16),
      preceded!(tag!("::"), tuple!(h16, colon_and_h16, colon_and_h16, colon_and_h16, colon_and_ls32))
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
      opt!(tuple!(h16, opt!(colon_and_h16))),
      preceded!(tag!("::"), tuple!(h16, colon_and_h16, colon_and_h16, colon_and_ls32))
    ),
    |(opt, (h4, h5, h6, ls))| {
      let (h1, h2) = opt.unwrap_or((0, None));
      let (h7, h8) = ls.segments();
      Ipv6Addr::new(h1, h2.unwrap_or(0), 0, h4, h5, h6, h7, h8)
    }
  )
  |
//                / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
  map!(
    tuple!(
      opt!(tuple!(h16, opt!(colon_and_h16), opt!(colon_and_h16))),
      preceded!(tag!("::"), tuple!(h16, colon_and_h16, colon_and_ls32))
    ),
    |(opt, (h5, h6, ls))| {
      let (h1, h2, h3) = opt.unwrap_or((0, None, None));
      let (h7, h8) = ls.segments();
      Ipv6Addr::new(h1, h2.unwrap_or(0), h3.unwrap_or(0), 0, h5, h6, h7, h8)
    }
  )
  |
//                / [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
  map!(
    tuple!(
      opt!(tuple!(h16, opt!(colon_and_h16), opt!(colon_and_h16), opt!(colon_and_h16))),
      preceded!(tag!(b"::"), tuple!(h16, colon_and_ls32))
    ),
    |(opt, (h6, ls))| {
      let (h1, h2, h3, h4) = opt.unwrap_or((0, None, None, None));
      let (h7, h8) = ls.segments();
      Ipv6Addr::new(h1, h2.unwrap_or(0), h3.unwrap_or(0), h4.unwrap_or(0), 0, h6, h7, h8)
    }
  )
  |
//                / [ *4( h16 ":" ) h16 ] "::"              ls32
  map!(
    tuple!(
      opt!(tuple!(h16, opt!(colon_and_h16), opt!(colon_and_h16), opt!(colon_and_h16), opt!(colon_and_h16))),
      preceded!(tag!("::"), ls32)
    ),
    |(opt, ls)| {
      let (h1, h2, h3, h4, h5) = opt.unwrap_or((0, None, None, None, None));
      let (h7, h8) = ls.segments();
      Ipv6Addr::new(h1, h2.unwrap_or(0), h3.unwrap_or(0), h4.unwrap_or(0), h5.unwrap_or(0), 0, h7, h8)
    }
  )
  |
//                / [ *5( h16 ":" ) h16 ] "::"              h16
  map!(
    tuple!(
      opt!(
        tuple!(
          h16,
          opt!(colon_and_h16),
          opt!(colon_and_h16),
          opt!(colon_and_h16),
          opt!(colon_and_h16),
          opt!(colon_and_h16)
        )
      ),
      preceded!(tag!("::"), h16)
    ),
    |(opt, h8)| {
      let (h1, h2, h3, h4, h5, h6) = opt.unwrap_or((0, None, None, None, None, None));
      Ipv6Addr::new(h1, h2.unwrap_or(0), h3.unwrap_or(0), h4.unwrap_or(0), h5.unwrap_or(0), h6.unwrap_or(0), 0, h8)
    }
  )
  |
//                / [ *6( h16 ":" ) h16 ] "::"
  map!(
    terminated!(
      opt!(
        tuple!(
          h16,
          opt!(colon_and_h16),
          opt!(colon_and_h16),
          opt!(colon_and_h16),
          opt!(colon_and_h16),
          opt!(colon_and_h16),
          opt!(colon_and_h16)
        )
      ),
      tag!("::")
    ),
    |opt| {
      let (h1, h2, h3, h4, h5, h6, h7) = opt.unwrap_or((0, None, None, None, None, None, None));
      Ipv6Addr::new(h1, h2.unwrap_or(0), h3.unwrap_or(0), h4.unwrap_or(0), h5.unwrap_or(0), h6.unwrap_or(0), h7.unwrap_or(0), 0)
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
