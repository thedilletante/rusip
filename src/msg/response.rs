use crate::msg::headers::header::{Headers, IgnoredHeaders};
use crate::msg::version::Version;
use crate::msg::reason_code::Code;
use crate::msg::Utf8Str;

pub struct Response<'buf> {
  version: Version,
  code: Code,
  reason: &'buf Utf8Str
}