
use super::Binary;
use super::parser_aux::parse_token;
use std::convert::TryFrom;
use std::io::Write;
use std::io;

#[derive(Debug, Eq, PartialEq)]
pub enum Method {
  Options,
  Invite,
  Ack,
  Bye,
  Cancel,
  Register,
  Subscribe,
  Notify,
  Refer
}

#[derive(Debug, Eq, PartialEq)]
pub enum ErrorKind {
  NotAMethod
}

impl TryFrom<&Binary> for Method {

  type Error = ErrorKind;

  fn try_from(value: &Binary) -> Result<Self, Self::Error> {
    let token = parse_token(value).map_err(|_| ErrorKind::NotAMethod)?;
    match token {
      "OPTIONS" => Ok(Method::Options),
      "INVITE" => Ok(Method::Invite),
      "ACK" => Ok(Method::Ack),
      "BYE" => Ok(Method::Bye),
      "CANCEL" => Ok(Method::Cancel),
      "REGISTER" => Ok(Method::Register),
      "SUBSCRIBE" => Ok(Method::Subscribe),
      "NOTIFY" => Ok(Method::Notify),
      "REFER" => Ok(Method::Refer),
      _ => Err(ErrorKind::NotAMethod)
    }
  }
}

impl Method {
  pub fn assemble(&self, mut output: &mut Binary) -> io::Result<usize> {
    match self {
      Method::Options => output.write("OPTIONS".as_bytes()),
      Method::Invite => output.write("INVITE".as_bytes()),
      Method::Ack => output.write("ACK".as_bytes()),
      Method::Bye => output.write("BYE".as_bytes()),
      Method::Cancel => output.write("CANCEL".as_bytes()),
      Method::Register => output.write("REGISTER".as_bytes()),
      Method::Subscribe => output.write("SUBSCRIBE".as_bytes()),
      Method::Notify => output.write("NOTIFY".as_bytes()),
      Method::Refer => output.write("REFER".as_bytes())
    }
  }
}

#[cfg(test)]
mod tests {
  use super::{
    Method,
    ErrorKind::NotAMethod
  };
  use std::convert::TryFrom;

  #[test]
  fn parse_works() {
    assert_eq!(Method::try_from("INVITE sfd".as_bytes()).unwrap(), Method::Invite);
    assert_eq!(Method::try_from("asdfs".as_bytes()).err().unwrap(), NotAMethod);
  }

  #[test]
  fn asseble_works() {
    let mut output = [0 as u8; 21];
    assert_eq!(Method::Invite.assemble(&mut output).unwrap(), 6);
    assert_eq!(std::str::from_utf8(&output[0..6]).unwrap(), "INVITE");

    assert_eq!(Method::Refer.assemble(&mut output[6..]).unwrap(), 5);
    assert_eq!(std::str::from_utf8(&output[0..11]).unwrap(), "INVITEREFER");

    assert_eq!(Method::Subscribe.assemble(&mut output[11..]).unwrap(), 9);
    assert_eq!(std::str::from_utf8(&output[0..20]).unwrap(), "INVITEREFERSUBSCRIBE");

    assert_eq!(Method::Options.assemble(&mut output[20..]).unwrap(), 1);
    assert_eq!(std::str::from_utf8(&output).unwrap(), "INVITEREFERSUBSCRIBEO");

    assert_eq!(Method::Bye.assemble(&mut output[21..]).unwrap(), 0);
  }
}