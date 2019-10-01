pub type Byte = u8;
pub type Binary = [Byte];

pub type Utf8Char = char;
pub type Utf8Str = str;

pub type AssembleResult = std::io::Result<usize>;
pub trait Assemble {
  fn assemble(&self, buf: &mut [u8]) -> AssembleResult;
}

pub mod abnf;
pub mod method;
pub mod uri;
pub mod version;
//pub mod id;
//pub(crate) mod parser_aux;
//pub mod headers;
//pub mod request;
//pub mod reason_code;
//pub mod response;
//pub mod message;