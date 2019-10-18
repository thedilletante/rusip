use super::ch::{unreserved, escaped, token};
use super::digit::dec_u8;
use super::super::method::{parse::method, Method};
use super::super::Binary;
use super::host::host;
use nom::{IResult, Needed};
use crate::msg::abnf::host::Host;
use nom::Err::Incomplete;

// param-unreserved =  "[" / "]" / "/" / ":" / "&" / "+" / "$"
named!(#[inline],
  pub param_unreserved<u8>,
  one_of_byte!(b'[' | b']' | b'/' | b':' | b'&' | b'+' | b'$')
);

// paramchar        =  param-unreserved / unreserved / escaped
named!(#[inline],
  pub paramchar<u8>,
  alt!(param_unreserved | unreserved | escaped)
);

// pname            =  1*paramchar
named!(#[inline],
  pub pname,
  at_least_one!(paramchar)
);

// pvalue           =  1*paramchar
named!(#[inline],
  pub pvalue,
  at_least_one!(paramchar)
);

// other-param      =  pname [ "=" pvalue ]
named!(#[inline],
  pub other_param<(&Binary, Option<&Binary>)>,
  tuple!(pname, opt!(preceded!(byte!(b'='), pvalue)))
);

// maddr-param      =  "maddr=" host
#[inline]
pub fn maddr_param<'a, 'b>(input: &'a Binary, domains: &'b mut [&'a Binary])
  -> IResult<&'a Binary, Host<'a, 'b>> {
  let (rest, _) = tag!(input, "maddr=")?;
  host(rest, domains)
}

// ttl-param        =  "ttl=" ttl
// ttl               =  1*3DIGIT ; 0 to 255
named!(#[inline],
  pub ttl_param<u8>,
  preceded!(tag!("ttl="), dec_u8)
);

// method-param     =  "method=" Method
named!(#[inline],
  pub method_param<Method>,
  preceded!(tag!("method="), method)
);

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum User<'a> {
  Phone,
  Ip,
  Other(&'a Binary)
}

// user-param       =  "user=" ( "phone" / "ip" / other-user)
// other-user       =  token
named!(#[inline],
  pub user_param<User>,
  preceded!(tag!("user="), alt!(
    tag!("phone") => { |_| User::Phone } |
    tag!("ip") => { |_| User::Ip } |
    token => { |t| User::Other(t) }
  ))
);

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Transport<'a> {
  UDP,
  TCP,
  SCTP,
  TLS,
  Other(&'a Binary)
}

// transport-param  =  "transport="
//                    ( "udp" / "tcp" / "sctp" / "tls"
//                    / other-transport)
// other-transport  =  token
named!(#[inline],
  pub transport_param<Transport>,
  preceded!(tag!("transport="), alt!(
    tag!("udp") => { |_| Transport::UDP } |
    tag!("tcp") => { |_| Transport::TCP } |
    tag!("sctp") => { |_| Transport::SCTP } |
    tag!("tls") => { |_| Transport::TLS } |
    token => { |t| Transport::Other(t) }
  ))
);

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum UriParam <'a, 'b> {
  Transport(Transport<'a>),
  User(User<'a>),
  Method(Method<'a>),
  Ttl(u8),
  Maddr(Host<'a, 'b>),
  Lr,
  Other(&'a Binary, Option<&'a Binary>)
}

// lr-param         =  "lr"
// uri-parameter    =  transport-param / user-param / method-param
//                    / ttl-param / maddr-param / lr-param / other-param
#[inline]
pub fn uri_parameter<'a, 'b>(input: &'a Binary, domains: &'b mut [&'a Binary])
  -> IResult<&'a Binary, UriParam<'a, 'b>> {
  alt!(input,
    tag!("lr") => { |_| UriParam::Lr } |
    transport_param => { |t| UriParam::Transport(t) } |
    user_param => { |u| UriParam::User(u) } |
    method_param => { |m| UriParam::Method(m) } |
    ttl_param => { |t| UriParam::Ttl(t) } |
    call!(maddr_param, domains) => { |h| UriParam::Maddr(h) } |
    other_param => { |(h, v)| UriParam::Other(h, v) }
  )
}

// uri-parameters   =  *( ";" uri-parameter)
#[inline]
pub fn uri_parameters<'a, 'b, 'c>(
  input: &'a Binary,
  domains: &'b mut [&'a Binary],
  params: &'c mut [UriParam<'a, 'b>]
)
  -> IResult<&'a Binary, &'c [UriParam<'a, 'b>]> {

  let mut rest = input;
  let mut i = 0usize;

  while let Ok((r, _)) = byte!(rest, b';') {
    if let Ok((r, v)) = uri_parameter(r, domains) {
      if i >= params.len() {
        return Err(Incomplete(Needed::Unknown));
      }
      params[i] = v;
      i += 1;
      rest = r;
    } else {
      break;
    }
  }

  Ok((rest, &params[..i]))
}

//#[cfg(test)]
//mod tests {
//  use super::{
//    uri_parameters,
//    UriParam,
//    Transport
//  };
//  use super::super::super::method::Method;
//  use crate::msg::abnf::host::Host;
//  use crate::msg::abnf::uri_params::User;
//
//  #[test]
//  fn uri_parameters_test() {
//    let mut domains = ["".as_bytes(); 100];
//    let mut params = [UriParam::Lr; 100];
//
//    assert_eq!(uri_parameters(
//      ";transport=udp;method=INVITE;ttl=212;maddr=alib.ru;lr;user=phone;ooo=999;q asdf"
//      .as_bytes(),
//      &mut params,
//      &mut domains
//    ), Ok((" asdf".as_bytes(), 8)));
//
//    assert_eq!(params[0], UriParam::Transport(Transport::UDP));
//    assert_eq!(params[1], UriParam::Method(Method::Invite));
//    assert_eq!(params[2], UriParam::Ttl(212));
//    assert_eq!(params[3], UriParam::Maddr(Host::Hostname("ru".as_bytes(), 1)));
//    assert_eq!(domains[0], "alib".as_bytes());
//    assert_eq!(params[4], UriParam::Lr);
//    assert_eq!(params[5], UriParam::User(User::Phone));
//    assert_eq!(params[6], UriParam::Other("ooo".as_bytes(), Some("999".as_bytes())));
//    assert_eq!(params[7], UriParam::Other("q".as_bytes(), None));
//  }
//
//}
