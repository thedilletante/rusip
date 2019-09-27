pub type Byte = u8;
pub type Binary = [Byte];

pub type Utf8Char = char;
pub type Utf8Str = str;

pub(crate) mod parser_aux;
pub mod id;
pub mod method;