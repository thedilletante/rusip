
#[macro_use]
extern crate bencher;
extern crate rusip;

use bencher::Bencher;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

fn bench_ipv4_parse(b: &mut Bencher) {
  let mut data = vec![
    ("124.0.0.1".as_bytes(), true),
    ("1.1.1.1".as_bytes(), true),
    ("1.1.1.".as_bytes(), false),
  ].into_iter().cycle();

  b.iter(|| {
    let suit = data.next().unwrap();
    assert!(rusip::msg::uri::ipv4address(suit.0).is_ok() == suit.1);
  });
  let stat = data.take(3).fold((0u64, 0u64), |(acc, count), (i, _)| (acc + i.len() as u64, count + 1));
  b.bytes = stat.0 / stat.1;
}

fn bench_std_ipv4_parse(b: &mut Bencher) {
  let mut data = vec![
    ("124.0.0.1", true),
    ("1.1.1.1", true),
    ("1.1.1.", false),
  ].into_iter().cycle();

  b.iter(|| {
    let suit = data.next().unwrap();
    assert!(Ipv4Addr::from_str(suit.0).is_ok() == suit.1);
  });
  let stat = data.take(3).fold((0u64, 0u64), |(acc, count), (i, _)| (acc + i.len() as u64, count + 1));
  b.bytes = stat.0 / stat.1;
}

fn bench_ipv6_parse(b: &mut Bencher) {

  let buf = "[0:0:0:0:0:FFFF:129.144.52.38]".as_bytes();

  b.iter(|| {
    assert!(rusip::msg::uri::ipv6reference(buf).is_ok());
  });
  b.bytes = buf.len() as u64;
}

fn bench_std_ipv6_parse(b: &mut Bencher) {
  let ip = "0:0:0:0:0:FFFF:129.144.52.38";

  b.iter(|| {
    assert!(Ipv6Addr::from_str(ip).is_ok());
  });
  b.bytes = ip.len() as u64;
}

benchmark_group!(benches,
  bench_ipv4_parse,
  bench_std_ipv4_parse,
  bench_ipv6_parse,
  bench_std_ipv6_parse
);
benchmark_main!(benches);
