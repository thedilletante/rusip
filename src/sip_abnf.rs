
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


impl Mark for char {
  fn is_mark(&self) -> bool {
    match self {
      '-' | '_' | '.' | '!' | '~' | '*' | '\'' | '(' | ')' => true,
      _ => false
    }
  }
}

impl Unreserved for char {
  fn is_unreserved(&self) -> bool {
    self.is_alphanumeric() || self.is_mark()
  }
}

impl UserUnreserved for char {
  fn is_user_unreserved(&self) -> bool {
    match self {
      '&' | '=' | '+' | '$' | ',' | ';' | '?' | '/' => true,
      _ => false
    }
  }
}

impl HnvUnreserved for char {
  fn is_hnv_unreserved(&self) -> bool {
    match self {
      '[' | ']' | '/' | '?' | ':' | '+' | '$' => true,
      _ => false
    }
  }
}

impl Token for char {
  fn is_token(&self) -> bool {
    self.is_alphanumeric() || match self {
      '-' | '.' | '!' | '%' | '*' | '_' | '+' | '`' | '\'' | '~' => true,
      _ => false
    }
  }
}

impl LWS for char {
  fn is_lws(&self) -> bool {
    *self == '\t' || *self == 32 as char
  }
}

impl Word for char {
  fn is_word(&self) -> bool {
    self.is_alphanumeric() || match self {
      '-' | '.' | '!' | '%' | '*' | '_' | '+' |
      '`' | '\'' | '~' | '(' | ')' | '<' | '>' |
      ':' | '\\' | '"' | '/' | '[' | ']' | '?' |
      '{' | '}' => true,
      _ => false
    }
  }
}
