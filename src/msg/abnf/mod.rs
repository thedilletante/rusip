
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

named!(#[inline],
  pub(crate) one_byte<Byte>,
  map!(take!(1), |i| unsafe { *i.get_unchecked(0) })
);

macro_rules! byte (
  ($i:expr, $b:expr) => ( $crate::msg::abnf::map_byte($i, |i: u8| i == $b) );
);

macro_rules! one_of_byte(
  ($i: expr, $($e:pat)|+) => (
    $crate::msg::abnf::map_byte($i, |i: u8| {
      match i {
        $($e)|+ => true,
        _ => false
      }
    })
  )
);

// TODO: how to match bytes instead of str
//       is it possible?
//macro_rules! bytes (
//  ($input:expr, $expected:expr) => ({
//    let mut rest = $input;
//    println!("trying to find: {}", std::str::from_utf8($expected).unwrap());
//
//    // TODO: why just iteration does not work???
////    let ret = tag!($input, std::str::from_utf8($expected).unwrap());
////    println!("ret is {:?}", ret);
////    ret
//    for b in $expected {
//      match byte!(rest, *b) {
//        Err(a) => {
//          println!("error is {:?}", a);
//          return Err(a);
//        },
//        Ok((r, _)) => {
//          println!("matched with {}", *b);
//          rest = r;
//        }
//      }
////      let (r, _) = byte!(rest, *b)?;
////      rest = r;
//    }
//    Ok((rest, ()))
//  });
//);

pub(crate) trait Consumed {
  fn consumed(&self) -> usize;
}

impl Consumed for &Binary {
  fn consumed(&self) -> usize {
    self.len()
  }
}

impl Consumed for u8 {
  fn consumed(&self) -> usize {
    1
  }
}

macro_rules! at_least_one (
  ($input:expr, $submac:ident!( $($args:tt)* )) => ({

    let (mut rest, c) = $submac!($input, $($args)*)?;
    let mut len = $crate::msg::abnf::Consumed::consumed(&c);

    while let Ok((r, c)) =  $submac!(rest, $($args)*) {
      rest = r;
      len += $crate::msg::abnf::Consumed::consumed(&c);
    }

    Ok((rest, &$input[..len]))

  });
  ($input:expr, $fn:expr) => ({
    let (mut rest, c) = $fn($input)?;
    let mut len = $crate::msg::abnf::Consumed::consumed(&c);

    while let Ok((r, c)) = $fn(rest) {
      rest = r;
      len += $crate::msg::abnf::Consumed::consumed(&c);
    }

    Ok((rest, &$input[..len]))
  });
);

macro_rules! many_times (
  ($input:expr, $submac:ident!( $($args:tt)* )) => ({

    let mut rest: &Binary = $input;
    let mut len = 0usize;

    while let Ok((r, c)) =  $submac!(rest, $($args)*) {
      rest = r;
      len += $crate::msg::abnf::Consumed::consumed(&c);
    }

    let res: &Binary = &$input[..len];
    Ok((rest, res))
  });
  ($input:expr, $fn:expr) => ({
    let mut rest: &Binary = $input;
    let mut len = 0usize;

    while let Ok((r, c)) = $fn(rest) {
      rest = r;
      len += $crate::msg::abnf::Consumed::consumed(&c);
    }

    let res: &Binary = &$input[..len];
    Ok((rest, res))
  });
);

pub mod ch;
pub mod digit;
pub mod ip;
pub mod host;
pub mod userinfo;
pub mod uri_headers;
pub mod uri_params;
pub mod absolute_uri;
