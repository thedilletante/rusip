
use super::{
  super::{Byte, Binary},
  map_byte,
  ch::{alpha, alphanum},
  digit::single,
  ip::{ipv4address, ipv6reference}
};

use nom::{IResult, error::ErrorKind::{
  Verify,
  Digit
}, Err::Error, Needed};

use std::net::{Ipv4Addr, Ipv6Addr};
use nom::Err::Incomplete;

named!(#[inline], take1, take!(1));


#[inline]
fn byte_or_byte_terminated_alphanum_with_dash<F, O>(f: F, input: &Binary) -> IResult<&Binary, &Binary>
  where F: Fn(&Binary) -> IResult<&Binary, O> {
  let (mut rest, _) = f(input)?;

  let mut last_alnum_end = rest;
  let mut count = 1usize;
  let mut commited = count;

  while let Ok((r, out)) = take1(rest) {
    count += 1;
    rest = r;

    let ch: Byte = unsafe { *out.get_unchecked(0) };
    if ch.is_ascii_alphanumeric() {
      last_alnum_end = r;
      commited = count;
    } else if ch != b'-' {
      break;
    }
  }

  Ok((last_alnum_end, &input[..commited]))
}

// domainlabel      =  alphanum
//                    / alphanum *( alphanum / "-" ) alphanum
#[inline]
pub fn domainlabel(input: &Binary) -> IResult<&Binary, &Binary> {
  byte_or_byte_terminated_alphanum_with_dash(alphanum, input)
}


// toplabel         =  ALPHA / ALPHA *( alphanum / "-" ) alphanum
#[inline]
pub fn toplabel(input: &Binary) -> IResult<&Binary, &Binary> {
  byte_or_byte_terminated_alphanum_with_dash(alpha, input)
}

named!(#[inline],
  pub dot<u8>,
  call!(map_byte, |i| i == b'.')
);

// hostname         =  *( domainlabel "." ) toplabel [ "." ]
#[inline]
pub fn hostname<'a, 'b>(input: &'a Binary, domains: &'b mut [&'a Binary])
  -> IResult<&'a Binary, (&'a Binary, usize)> {
  let mut rest = input;
  let mut last_top_rest: Option<&Binary> = None;

  let mut last_top = input;
  let mut num_domains = 0usize;
  let mut commit_num_domains = num_domains;

  while let Ok((_, _)) = peek!(rest, tuple!(domainlabel, dot)) {
    if let Ok((r, o)) = toplabel(rest) {
      if num_domains >= domains.len() {
        return Err(Incomplete(Needed::Unknown));
      }
      domains[num_domains] = o;
      num_domains += 1;
      let (r, _) = dot(r)?;
      rest = r;
      commit_num_domains = num_domains;
      last_top_rest = Some(rest);
      last_top = o;
    } else {
      let (r, o) = domainlabel(rest)?;
      let (r, _) = dot(r)?;
      rest = r;
      if num_domains >= domains.len() {
        return Err(Incomplete(Needed::Unknown));
      }

      domains[num_domains] = o;
      num_domains += 1;
    }
  }

  if let Ok((r, o)) = toplabel(rest) {
    rest = r;
    last_top = o;
    commit_num_domains = num_domains;
  } else {
    match last_top_rest {
      None => {
        return Err(Error((input, Verify)));
      },
      Some(r) => {
        return Ok((r, (last_top, commit_num_domains - 1)));
      }
    }
  }

  if let Ok((r, _)) = dot(input) {
    rest = r;
  }

  Ok((rest, (last_top, commit_num_domains)))
}

#[derive(Debug, Eq, PartialEq)]
pub enum Host<'a> {
  Hostname(&'a Binary, usize),
  Ipv4(Ipv4Addr),
  Ipv6(Ipv6Addr)
}

// host             =  hostname / IPv4address / IPv6reference
#[inline]
pub fn host<'a, 'b>(input: &'a Binary, domains: &'b mut [&'a Binary])
  -> IResult<&'a Binary, Host<'a>> {
  alt!(input,
    call!(hostname, domains) => {
      |(top, num)| Host::Hostname(top, num)
    }
    |
    ipv4address => {
      |v4| Host::Ipv4(v4)
    }
    |
    ipv6reference => {
      |v6| Host::Ipv6(v6)
    }
  )
}

// port             =  1*DIGIT
#[inline]
pub fn port(input: &Binary) -> IResult<&Binary, u16> {
  let (mut rest, first) = complete!(input, single)?;
  if first == 0 {
    return Err(Error((rest, Digit)));
  }

  let mut acc = first as u64;

  while let Ok((r, next)) = single(rest) {

    acc *= 10;
    acc += next as u64;

    if acc > std::u16::MAX as u64 {
      return Err(Error((rest, Digit)));
    }

    rest = r;
  }

  Ok((rest, acc as u16))
}

named!(#[inline],
  pub colon<u8>,
  call!(map_byte, |i| i == b':')
);

// hostport         =  host [ ":" port ]
#[inline]
pub fn hostport<'a, 'b>(input: &'a Binary, domains: &'b mut [&'a Binary])
  -> IResult<&'a Binary, (Host<'a>, Option<u16>)> {
  let (mut rest, h) = host(input, domains)?;

  let p = if let Ok((r, _)) = colon(rest) {
    let (r, p) = port(r)?;
    rest = r;
    Some(p)
  } else {
    None
  };

  Ok((rest, (h, p)))
}

#[cfg(test)]
mod tests {
  use super::{domainlabel, toplabel, hostname, host, Host, port, hostport};
  use nom::Err as Error;
  use nom::error::ErrorKind::{Verify, Digit, Complete};
  use nom::Needed;
  use std::net::{Ipv6Addr, Ipv4Addr};
  use std::str::FromStr;
  macro_rules! parser_ok {
    ( $binary:expr => $parser:ident => $expected:expr, $left:expr ) => {
      assert_eq!( $parser($binary.as_bytes()), Ok(($left.as_bytes(), $expected)))
    };
  }

  macro_rules! parser_fail {
    ( $binary:expr => $parser:ident |= $error:expr) => {
      assert_eq!( $parser($binary.as_bytes()), Err( $error ))
    };
  }

  macro_rules! domainlabel_test {
    ( $input:literal makes $expected:expr, $left:expr) => {
      parser_ok!( $input => domainlabel => $expected.as_bytes(), $left )
    };
    ( $input:literal fails $error:expr, $left:expr ) => {
      parser_fail!($input => domainlabel |= Error::Error(($left.as_bytes(), $error)))
    };
  }

  #[test]
  fn domainlabel_test() {
    domainlabel_test!("a" makes "a", "");
    domainlabel_test!("1" makes "1", "");
    domainlabel_test!("aa" makes "aa", "");
    domainlabel_test!("a1" makes "a1", "");
    domainlabel_test!("1a" makes "1a", "");
    domainlabel_test!("aaa" makes "aaa", "");
    domainlabel_test!("a-9" makes "a-9", "");
    domainlabel_test!("4--a" makes "4--a", "");
    domainlabel_test!("a-B-a" makes "a-B-a", "");
    domainlabel_test!("4-" makes "4", "-");
    domainlabel_test!("s-" makes "s", "-");
    domainlabel_test!("-a" fails Verify, "-a");
    domainlabel_test!("-3" fails Verify, "-3");
  }

  macro_rules! toplabel_test {
    ( $input:literal makes $expected:expr, $left:expr) => {
      parser_ok!( $input => toplabel => $expected.as_bytes(), $left )
    };
    ( $input:literal fails $error:expr, $left:expr ) => {
      parser_fail!($input => toplabel |= Error::Error(($left.as_bytes(), $error)))
    };
  }

  #[test]
  fn toplabel_test() {
    toplabel_test!("a" makes "a", "");
    toplabel_test!("a-" makes "a", "-");
    toplabel_test!("a-3" makes "a-3", "");
    toplabel_test!("3" fails Verify, "3");
  }

  macro_rules! hostname_test {
    ( $input:literal makes $top:literal top, $left:expr) => {
      let mut buf = ["".as_bytes(); 10];
      assert_eq!( hostname($input.as_bytes(), &mut buf), Ok(($left.as_bytes(), ($top.as_bytes(), 0))));
    };
    ( $input:literal makes $top:literal top and domains: $($domain:literal),+  : left $left:literal) => {
      let mut buf = ["".as_bytes(); 100];
      let domains = [$($domain),+];
      assert_eq!(hostname($input.as_bytes(), &mut buf), Ok(($left.as_bytes(), ($top.as_bytes(), domains.len()))));
      Iterator::zip(buf.into_iter(), domains.into_iter()).for_each(|(b, d)|{
        assert_eq!(*b, d.as_bytes());
      });
    };
    ( $input:literal fails $error:expr, $left:expr ) => {
      let mut buf = ["".as_bytes(); 10];
      assert_eq!( hostname($input.as_bytes(), &mut buf), Err(Error::Error(($left.as_bytes(), $error))));
    };
  }

  #[test]
  fn hostname_test() {
    hostname_test!("a" makes "a" top, "");
    hostname_test!("a." makes "a" top, "");
    hostname_test!("a.a." makes "a" top and domains: "a": left "");
    hostname_test!("a.a" makes "a" top and domains: "a": left "");
    hostname_test!("1.a" makes "a" top and domains: "1": left "");
    hostname_test!("1.a." makes "a" top and domains: "1": left "");
    hostname_test!("a.1" makes "a" top, "1");
    hostname_test!("a.1." makes "a" top, "1.");
    hostname_test!("3.a.4.b-d.1." makes "b-d" top and domains: "3", "a", "4" : left "1.");
    assert_eq!(hostname("3.a.4.b-d.1.".as_bytes(), &mut []), Err(Error::Incomplete(Needed::Unknown)));
    hostname_test!("4.4." fails Verify, "4.4.");

    hostname_test!("3450.ns-45.goo.gov a;lkds" makes "gov" top and domains: "3450", "ns-45", "goo" : left " a;lkds");
  }

  macro_rules! host_test {
    ( $input:literal makes $expected:expr, $left:expr) => {
      let mut buf = ["".as_bytes(); 10];
      assert_eq!( host($input.as_bytes(), &mut buf), Ok(($left.as_bytes(), $expected)));
    };
  }

  #[test]
  fn host_test() {
    host_test!("127.0.0.1" makes Host::Ipv4(Ipv4Addr::from_str("127.0.0.1").unwrap()), "");
    host_test!("ringcentral.com" makes Host::Hostname("com".as_bytes(), 1), "");
    host_test!("[fa:2001:db8::9:01]" makes Host::Ipv6(Ipv6Addr::from_str("fa:2001:db8::9:01").unwrap()), "");
  }

  macro_rules! port_test {
    ( $input:literal makes $expected:expr, $left:expr) => {
      parser_ok!( $input => port => $expected, $left );
    };
    ( $input:literal fails $error:expr, $left:expr ) => {
      parser_fail!($input => port |= Error::Error(($left.as_bytes(), $error)))
    };
  }

  #[test]
  fn port_test() {
    port_test!("1" makes 1, "");
    port_test!("1a" makes 1, "a");
    port_test!("5070" makes 5070, "");
    port_test!("20101- " makes 20101, "- ");

    port_test!("" fails Complete, "");
    port_test!("0" fails Digit, "");
    port_test!("a" fails Verify, "a");
    port_test!("99999" fails Digit, "9");
  }

  macro_rules! hostport_test {
    ( $input:literal makes $host:literal,$domains:literal, $left:literal) => {
      let mut buf = ["".as_bytes(); 10];
      assert_eq!(
        hostport($input.as_bytes(), &mut buf),
        Ok(($left.as_bytes(), (Host::Hostname($host.as_bytes(), $domains), None)))
      );
    };
    ( $input:literal makes $host:literal,$domains:literal : $port:literal, $left:expr) => {
      let mut buf = ["".as_bytes(); 10];
      assert_eq!(
        hostport($input.as_bytes(), &mut buf),
        Ok(($left.as_bytes(), (Host::Hostname($host.as_bytes(), $domains), Some($port))))
      );
    };
    ( $input:literal makes v4 $host:literal, $left:literal) => {
      let mut buf = ["".as_bytes(); 10];
      assert_eq!(
        hostport($input.as_bytes(), &mut buf),
        Ok(($left.as_bytes(), (Host::Ipv4(Ipv4Addr::from_str($host).unwrap()), None)))
      );
    };
    ( $input:literal makes v4 $host:literal : $port:literal, $left:expr) => {
      let mut buf = ["".as_bytes(); 10];
      assert_eq!(
        hostport($input.as_bytes(), &mut buf),
        Ok(($left.as_bytes(), (Host::Ipv4(Ipv4Addr::from_str($host).unwrap()), Some($port))))
      );
    };
    ( $input:literal makes v6 $host:literal, $left:literal) => {
      let mut buf = ["".as_bytes(); 10];
      assert_eq!(
        hostport($input.as_bytes(), &mut buf),
        Ok(($left.as_bytes(), (Host::Ipv6(Ipv6Addr::from_str($host).unwrap()), None)))
      );
    };
    ( $input:literal makes v6 $host:literal : $port:literal, $left:expr) => {
      let mut buf = ["".as_bytes(); 10];
      assert_eq!(
        hostport($input.as_bytes(), &mut buf),
        Ok(($left.as_bytes(), (Host::Ipv6(Ipv6Addr::from_str($host).unwrap()), Some($port))))
      );
    };
  }

  #[test]
  fn hostport_test() {
    hostport_test!("127.0.0.1" makes v4"127.0.0.1", "");
    hostport_test!("127.0.0.1:2222" makes v4"127.0.0.1":2222, "");
    hostport_test!("[2001:db8::192.0.2.1]" makes v6"2001:db8::192.0.2.1", "");
    hostport_test!("[2001:db8::10]:5070 " makes v6"2001:db8::10":5070, " ");
    hostport_test!("www.yandex.ru" makes "ru",2, "");
    hostport_test!("yandex.ru:22" makes "ru",1:22, "");
  }


}