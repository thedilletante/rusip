use super::ch::escaped;
use super::ch::unreserved;
use super::ch::user_unreserved;
use super::digit::single;
use super::host::hostname;
use super::map_byte;
use crate::msg::abnf::ch::utf8;
use crate::msg::Binary;
use nom::error::ErrorKind;
use nom::Err::Error;
use nom::IResult;
use crate::msg::abnf::host::Hostname;

pub enum Identity <'a> {
  User(&'a Binary),
  TelephoneSubscriber
}

pub struct UserInfo <'a> {
  pub identity: Identity<'a>,
  pub password: Option<&'a Binary>
}

// userinfo         =  ( user / telephone-subscriber ) [ ":" password ] "@"
named!(#[inline],
  pub userinfo<UserInfo>,
  map!(
    terminated!(
      tuple!(
        alt!(
          user => { |u| Identity::User(u) }
          |
          telephone_subscriber => { |_| Identity::TelephoneSubscriber }
        ),
        opt!(preceded!(byte!(b':'), password))
      ),
      byte!(b'@')
    ),
    |(identity, password)| UserInfo {
      identity,
      password
    }
  )
);

// password         =  *( unreserved / escaped /
//                    "&" / "=" / "+" / "$" / "," )
named!(#[inline],
  pub password,
  many_times!(alt!(unreserved | escaped | one_of_byte!(b'&' | b'=' | b'+' | b'$' | b',')))
);

// user             =  1*( unreserved / escaped / user-unreserved )
named!(#[inline],
  pub user,
  at_least_one!(alt!(unreserved | escaped | user_unreserved))
);

// The BNF for telephone-subscriber can be found in RFC 2806 [9].  Note,
// however, that any characters allowed there that are not allowed in
// the user part of the SIP URI MUST be escaped.

// telephone-subscriber  = global-phone-number / local-phone-number
named!(#[inline],
  pub telephone_subscriber,
  alt!(global_phone_number | local_phone_number)
);

// global-phone-number   = "+" base-phone-number [isdn-subaddress]
//                          [post-dial] *(area-specifier /
//                          service-provider / future-extension)
named!(#[inline],
  pub global_phone_number,
  recognize!(
    tuple!(
      preceded!(byte!(b'+'), base_phone_number),
      opt!(isdn_subaddress),
      opt!(post_dial),
      many_times!(alt!(
        recognize!(area_specifier) | recognize!(future_extension)
      ))
    )
  )
);

// base-phone-number     = 1*phonedigit
named!(#[inline],
  base_phone_number<u8>,
  call!(phonedigit)
);

// local-phone-number    = 1*(phonedigit / dtmf-digit /
//                          pause-character) [isdn-subaddress]
//                          [post-dial] area-specifier
//                          *(area-specifier / service-provider /
//                          future-extension)
//struct LocalPhoneNumber <'a> {
//  isdn: Option<u8>,
//  post: Option<u8>,
//  area:
//}
named!(#[inline],
  pub local_phone_number,
  recognize!(
    tuple!(
      alt!(phonedigit | dtmf_digit | pause_character),
      opt!(isdn_subaddress),
      opt!(post_dial),
      area_specifier,
      many_times!(alt!(
        recognize!(area_specifier) | recognize!(future_extension)
      ))
    )
  )
);

// isdn-subaddress       = ";isub=" 1*phonedigit
named!(#[inline],
  pub isdn_subaddress<u8>,
  preceded!(tag!(";isub="), phonedigit)
);

// post-dial             = ";postd=" 1*(phonedigit /
//                          dtmf-digit / pause-character)
named!(#[inline],
  pub post_dial<u8>,
  preceded!(tag!(";postd="), alt!(phonedigit | dtmf_digit | pause_character))
);

// area-specifier        = ";" phone-context-tag "=" phone-context-ident
#[inline]
pub fn area_specifier(input: &Binary) -> IResult<&Binary, PhoneContextIdent> {
    let (r, _) = byte!(input, b';')?;
    let (r, _) = phone_context_tag(r)?;
    phone_context_ident(r)
}
// phone-context-tag     = "phone-context"
named!(#[inline],
  pub phone_context_tag,
  tag!("phone-context")
);

pub enum PhoneContextIdent<'a> {
    NetworkPrefix(NetworkPrefix),
    PrivatePrefix(&'a Binary),
}

// phone-context-ident   = network-prefix / private-prefix
named!(#[inline],
  pub phone_context_ident<PhoneContextIdent>,
  alt!(
    network_prefix => { |p| PhoneContextIdent::NetworkPrefix(p) }
    |
    private_prefix => { |p| PhoneContextIdent::PrivatePrefix(p) }
  )
);

pub enum NetworkPrefix {
    Global(u8),
    Local(u8),
}

// network-prefix        = global-network-prefix / local-network-prefix
named!(#[inline],
  pub network_prefix<NetworkPrefix>,
  alt!(
    global_network_prefix => { |b| NetworkPrefix::Global(b) }
    |
    local_network_prefix => { |b| NetworkPrefix::Local(b) }
  )
);

// global-network-prefix = "+" 1*phonedigit
named!(#[inline],
  pub global_network_prefix<u8>,
  preceded!(byte!(b'+'), phonedigit)
);

// local-network-prefix  = 1*(phonedigit / dtmf-digit / pause-character)
named!(#[inline],
  pub local_network_prefix<u8>,
  alt!(phonedigit | dtmf_digit | pause_character)
);

// private-prefix        = (%x21-22 / %x24-27 / %x2C / %x2F / %x3A /
//                          %x3C-40 / %x45-4F / %x51-56 / %x58-60 /
//                          %x65-6F / %x71-76 / %x78-7E)
//                          *(%x21-3A / %x3C-7E)
named!(#[inline],
  pub private_prefix,
  recognize!(
    tuple!(
      one_of_byte!(
        0x21 | 0x22 | 0x24..=0x27 | 0x2C | 0x2F | 0x3A |
        0x3C..=0x40 | 0x45..=0x4F | 0x51..=0x56 | 0x58..=0x60 |
        0x65..=0x6F | 0x71..=0x76 | 0x78..=0x7E),
      many_times!(one_of_byte!(0x21..=0x3A | 0x3C..=0x7E))
    )
  )
);

//
// ; Characters in URLs must follow escaping rules
// ; as explained in [RFC2396]
// ; See sections 1.2 and 2.5.2
//
// service-provider      = ";" provider-tag "=" provider-hostname
#[inline]
pub fn service_provider<'a, 'b>(
    input: &'a Binary,
    domains: &'b mut [&'a Binary],
) -> IResult<
        &'a Binary,
        (&'b mut [&'a Binary], Hostname<'a, 'b>)
    > {
    let (rest, _) = byte!(input, b';')?;
    let (rest, _) = provider_tag(rest)?;
    let (rest, _) = byte!(rest, b'=')?;
    provider_hostname(rest, domains)
}

// provider-tag          = "tsp"
named!(#[inline],
  pub provider_tag,
  tag!("tsp")
);
// provider-hostname     = domain ; <domain> is defined in [RFC1035]
#[inline]
pub fn provider_hostname<'a, 'b>(
    input: &'a Binary,
    domains: &'b mut [&'a Binary],
) -> IResult<
    &'a Binary,
    (&'b mut [&'a Binary], Hostname<'a, 'b>)
    > {
    hostname(input, domains)
}

// ; See section 2.5.10
// future-extension      = ";" 1*(token-char) ["=" ((1*(token-char) ["?" 1*(token-char)]) / quoted-string )]
pub enum FutureExtensionValue<'a> {
    Token(&'a Binary, Option<&'a Binary>),
    Quoted(&'a Binary),
}

#[inline]
pub fn future_extension(
    input: &Binary,
) -> IResult<&Binary, (&Binary, Option<FutureExtensionValue>)> {
    let (rest, _) = byte!(input, b';')?;
    let (rest, token) = at_least_one!(rest, token_char)?;

    if let Ok((rest, _)) = byte!(rest, b'=') {
        let (rest, val) = alt!(rest,
          tuple!(at_least_one!(token_char), opt!(preceded!(byte!(b'?'), at_least_one!(token_char)))) => {
            |(n, v)| FutureExtensionValue::Token(n, v)
          }
          |
          quoted_string => {
            |s| FutureExtensionValue::Quoted(s)
          }
        )?;
        Ok((rest, (token, Some(val))))
    } else {
        Ok((rest, (token, None)))
    }
}

// ; See section 2.5.11 and [RFC2543]
// token-char            = (%x21 / %x23-27 / %x2A-2B / %x2D-2E / %x30-39
//                          / %x41-5A / %x5E-7A / %x7C / %x7E)
named!(#[inline],
  pub token_char<u8>,
  call!(map_byte, |b| match b {
    0x21 | 0x23..=0x27 | 0x2a..=0x2b | 0x2d..=0x2e | 0x30..=0x39 |
    0x41..=0x5a | 0x5e..=0x7a | 0x7c | 0x7e => true,
    _ => false
  })
);

// ; Characters in URLs must follow escaping rules
// ; as explained in [RFC2396]
// ; See sections 1.2 and 2.5.11
// quoted-string         = %x22 *( "\" CHAR / (%x20-21 / %x23-7E
//                         / %x80-FF )) %x22
//                        ; Characters in URLs must follow escaping rules
//                        ; as explained in [RFC2396]
//                        ; See sections 1.2 and 2.5.11
#[inline]
pub fn quoted_string(input: &Binary) -> IResult<&Binary, &Binary> {
    let mut counter = 0usize;
    let (mut rest, _) = byte!(input, 0x22)?;

    loop {
        let (r, ch) = take!(rest, 1)?;
        match ch[0] {
            b'\\' => {
                let (r, ch) = utf8(rest)?;
                rest = r;
                counter += ch.len_utf8();
            }
            0x20..=0x21 | 0x23..=0x7e | 0x80..=0xff => {
                rest = r;
                counter += 1;
            }
            0x22 => {
                rest = r;
                break;
            }
            _ => {
                return Err(Error((input, ErrorKind::Char)));
            }
        }
    }

    Ok((rest, &input[1..counter + 1]))
}

// phonedigit            = DIGIT / visual-separator
named!(#[inline],
  pub phonedigit<u8>,
  alt!(
    single | visual_separator
  )
);

// visual-separator      = "-" / "." / "(" / ")"
named!(#[inline],
  pub visual_separator<u8>,
  one_of_byte!(b'-' | b'.' | b'(' | b')')
);

// pause-character       = one-second-pause / wait-for-dial-tone
named!(#[inline],
  pub pause_character<u8>,
  alt!(
    one_second_pause 
    |
    wait_for_dial_tone
  )
);

// one-second-pause      = "p"
named!(#[inline],
  pub one_second_pause<u8>,
  byte!(b'p')
);

// wait-for-dial-tone    = "w"
named!(#[inline],
  pub wait_for_dial_tone<u8>,
  byte!(b'w')
);

// dtmf-digit            = "*" / "#" / "A" / "B" / "C" / "D"
named!(#[inline],
  pub dtmf_digit<u8>,
  one_of_byte!(b'*' | b'#' | b'A' | b'B' | b'C' | b'D')
);

#[cfg(test)]
mod tests {

    use super::dtmf_digit;

    macro_rules! parse_ok (
      ( $fn:ident( $input:literal ) => $out:expr, $left:literal ) => {
        assert_eq!($fn($input.as_bytes()), Ok(($left.as_bytes(), $out)));
      };
    );

    #[test]
    fn dtmf_digit_test() {
      parse_ok!(dtmf_digit("*") => b'*', "");
    }
}
