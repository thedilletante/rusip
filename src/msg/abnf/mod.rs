
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

pub mod ch;
pub mod digit;
pub mod ip;
pub mod host;