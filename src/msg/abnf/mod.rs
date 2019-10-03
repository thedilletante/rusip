
use super::Byte;
use super::Binary;
use nom::IResult;

// utility function
// it was benchmarked that map!(verify!(take!(1))) is faster than equivalent
// written with map!(one_of!())
pub(crate) fn map_byte<F>(input: &Binary, f: F) -> IResult<&Binary, Byte>
  where F: Fn(Byte) -> bool {
  map!(input, verify!(take!(1), |i: &Binary| {
      f(unsafe { *i.get_unchecked(0) })
    }),
    |i| unsafe { *i.get_unchecked(0) }
  )
}

macro_rules! byte (
  ($i:expr, $b:literal) => ( map_byte($i, |i: u8| i == $b) );
);

macro_rules! one_of_byte(
  ($i: expr, $($b:literal)|+) => (
    map_byte($i, |i: u8| {
      match i {
        $($b)|+ => true,
        _ => false
      }
    })
  )
);

pub mod ch;
pub mod digit;
pub mod ip;
pub mod host;
pub mod userinfo;
pub mod uri_headers;
pub mod uri_params;
pub mod absolute_uri;