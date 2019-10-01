
use crate::msg::headers::header::{Headers, IgnoredHeaders};
use crate::msg::method::Method;
use crate::msg::uri::Uri;
use crate::msg::version::{
  Version,
  DEFAULT_VERSION
};
use crate::msg::headers::{
  to::To,
  from::From,
  cseq::CSeq,
  call_id::CallID,
  max_forwards::MaxForwards,
  via::Via
};


pub struct MandatoryHeaders {
  to: To,
  from: From,
  cseq: CSeq,
  call_id: CallID,
  max_forwards: MaxForwards,
  via: Via
}

pub struct Request {
  method: Method,
  uri: Uri,
  version: Version,
  mandatory_headers: MandatoryHeaders
}

impl Request {
  pub fn invite(uri: Uri, mandatory_headers: MandatoryHeaders, version: Option<Version>) -> Request {
    Request {
      method: Method::Invite,
      uri,
      version: version.unwrap_or(DEFAULT_VERSION),
      mandatory_headers
    }
  }
}