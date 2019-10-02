pub type Byte = u8;
pub type Binary = [Byte];

pub type Utf8Char = char;
pub type Utf8Str = str;

pub mod abnf;
pub mod id;
pub mod method;
pub mod uri;
pub mod version;