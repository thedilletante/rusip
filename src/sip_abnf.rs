
// mark           =  "-" / "_" / "." / "!" / "~" / "*" / "'"
//                   / "(" / ")"
pub trait Mark {
  fn is_mark(&self) -> bool;
}


// unreserved  =  alphanum / mark
pub trait Unreserved {
  fn is_unreserved(&self) -> bool;
}

// user-unreserved  =  "&" / "=" / "+" / "$" / "," / ";" / "?" / "/"
pub trait UserUnreserved {
  fn is_user_unreserved(&self) -> bool;
}

// hnv-unreserved  =  "[" / "]" / "/" / "?" / ":" / "+" / "$"
pub trait HnvUnreserved {
  fn is_hnv_unreserved(&self) -> bool;
}

// token       =  1*(alphanum / "-" / "." / "!" / "%" / "*"
//                   / "_" / "+" / "`" / "'" / "~" )
pub trait Token {
  fn is_token(&self) -> bool;
}

pub trait LWS {
  fn is_lws(&self) -> bool;
}

// word     =  1*(alphanum / "-" / "." / "!" / "%" / "*" /
//             "_" / "+" / "`" / "'" / "~" /
//             "(" / ")" / "<" / ">" /
//             ":" / "\" / DQUOTE /
//             "/" / "[" / "]" / "?" /
//             "{" / "}" )
pub trait Word {
  fn is_word(&self) -> bool;
}


impl Mark for &[u8] {
  fn is_mark(&self) -> bool {
    self.len() == 1 && match unsafe { self.get_unchecked(0) } {
      b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')' => true,
      _ => false
    }
  }
}

impl Unreserved for &[u8] {
  fn is_unreserved(&self) -> bool {
    self.len() == 1 && (self.is_mark() || {
      let ch = unsafe { self.get_unchecked(0) };
      ch.is_ascii_alphanumeric()
    })
  }
}

impl UserUnreserved for &[u8] {
  fn is_user_unreserved(&self) -> bool {
    self.len() == 1 && match unsafe { self.get_unchecked(0) } {
      b'&' | b'=' | b'+' | b'$' | b',' | b';' | b'?' | b'/' => true,
      _ => false
    }
  }
}

impl HnvUnreserved for &[u8] {
  fn is_hnv_unreserved(&self) -> bool {
    self.len() == 1 && match unsafe { self.get_unchecked(0) } {
      b'[' | b']' | b'/' | b'?' | b':' | b'+' | b'$' => true,
      _ => false
    }
  }
}

impl Token for &[u8] {
  fn is_token(&self) -> bool {
    self.len() == 1 && {
      let ch = unsafe { self.get_unchecked(0) };
      ch.is_ascii_alphanumeric() || match ch {
        b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' | b'`' | b'\'' | b'~' => true,
        _ => false
      }
    }
  }
}

impl LWS for &[u8] {
  fn is_lws(&self) -> bool {
    self.len() == 1 && match unsafe { self.get_unchecked(0) } {
      b'\t' | 32 => true,
      _ => false
    }
  }
}

impl Word for &[u8] {
  fn is_word(&self) -> bool {
    self.len() == 1 && {
      let ch = unsafe { self.get_unchecked(0) };
      ch.is_ascii_alphanumeric() || match ch {
        b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' |
        b'`' | b'\'' | b'~' | b'(' | b')' | b'<' | b'>' |
        b':' | b'\\' | b'"' | b'/' | b'[' | b']' | b'?' |
        b'{' | b'}' => true,
        _ => false
      }
    }
  }
}
