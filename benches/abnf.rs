#[macro_use] extern crate bencher;
#[macro_use] extern crate nom;
extern crate rusip;

use bencher::Bencher;

fn is_mark(i: u8) -> bool {
  match i {
    b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')' => true,
    _ => false
  }
}

fn to_mark(i: u8) -> Option<u8> {
  match i {
    b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')' => Some(i),
    _ => None
  }
}

named!(#[inline], verify_mark<u8>, map!(verify!(take!(1), |i:&[u8]| is_mark(unsafe{*i.get_unchecked(0)})), |i| unsafe{*i.get_unchecked(0)} as u8));
named!(#[inline], one_of_mark<u8>, map!(one_of!("-_.!~*'()"), |ch| ch as u8));
named!(#[inline], option_mark<u8>, map!(verify!(map!(take!(1), |i| to_mark(unsafe{*i.get_unchecked(0)})), Option::is_some), Option::unwrap));

fn make_suite() -> Vec<(&'static [u8], bool)> {
  vec![
    ("-".as_bytes(), true),
    ("_s".as_bytes(), true),
    ("~sdf".as_bytes(), true),
    ("()".as_bytes(), true),
    ("'".as_bytes(), true),
    ("bjk".as_bytes(), false),
    ("".as_bytes(), false),
    ("`1".as_bytes(), false)
  ]
}

fn bench_verify_mark(b: &mut Bencher) {
  let mut suite = make_suite().into_iter().cycle();
  b.iter(|| {
    let set = suite.next().unwrap();
    assert!(verify_mark(set.0).is_ok() == set.1);
  });
  b.bytes = 1;
}

fn bench_on_of_mark(b: &mut Bencher) {
  let mut suite = make_suite().into_iter().cycle();
  b.iter(|| {
    let set = suite.next().unwrap();
    assert!(one_of_mark(set.0).is_ok() == set.1);
  });
  b.bytes = 1;
}

fn bench_option_mark(b: &mut Bencher) {
  let mut suite = make_suite().into_iter().cycle();
  b.iter(|| {
    let set = suite.next().unwrap();
    assert!(option_mark(set.0).is_ok() == set.1);
  });
  b.bytes = 1;
}


named!(#[inline], single_digit<u8>,
  map!(verify!(take!(1), |ch: &[u8]| { let c = unsafe { ch.get_unchecked(0) }; c > &b'0' && c < &b'9'}), |ch| unsafe { ch.get_unchecked(0) - b'0' })
);

fn is_version_prefix(buf: &[u8]) -> bool {
  let prefix = &[(b's', b'S'), (b'i', b'I'), (b'p', b'P'), (b'/', b'/')];
  Iterator::zip(prefix.into_iter(), buf.into_iter()).all(|((l, u), i)| l == i || u == i)
}

named!(#[inline], pub do_parse_version<(u8, u8)>, do_parse!(
    tag_no_case!("SIP/") >>
    major: single_digit >>
    char!('.') >>
    minor: single_digit >>
    ( major, minor )
  ));

named!(#[inline], pub tuple_version<(u8, u8)>,
  preceded!(verify!(take!(4), |i:&[u8]| is_version_prefix(i)), tuple!(single_digit, preceded!(verify!(take!(1), |i:&[u8]| i[0] == b'.'), single_digit)))
);

fn make_version_suite() -> Vec<(&'static [u8], bool)> {
  vec![
    ("SIP/1.3".as_bytes(), true),
    ("sip/4.5".as_bytes(), true),
    ("SIP,1.3".as_bytes(), false),
    ("()".as_bytes(), false),
    ("SIP/56.0".as_bytes(), false),
    ("siP/4.55".as_bytes(), true)
  ]
}

fn bench_do_parse_version(b: &mut Bencher) {
  let mut suite = make_version_suite().into_iter().cycle();
  b.iter(|| {
    let set = suite.next().unwrap();
    assert!(do_parse_version(set.0).is_ok() == set.1);
  });
  b.bytes = 1;
}

fn bench_tuple_version(b: &mut Bencher) {
  let mut suite = make_version_suite().into_iter().cycle();
  b.iter(|| {
    let set = suite.next().unwrap();
    assert!(tuple_version(set.0).is_ok() == set.1);
  });
  b.bytes = 1;
}

benchmark_group!(benches,
  bench_verify_mark,
  bench_on_of_mark,
  bench_option_mark,
  bench_do_parse_version,
  bench_tuple_version
);
benchmark_main!(benches);