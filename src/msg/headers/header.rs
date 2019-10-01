use crate::msg::Binary;

pub struct Header {

}

pub type Headers = [Header];

pub struct IgnoredHeader<'name, 'value> {
  // TODO: need to consult with rfc is it binary or valid UTF-8
  name: &'name Binary,
  value: &'value Binary
}

pub type IgnoredHeaders<'name, 'value> = [IgnoredHeader<'name, 'value>];