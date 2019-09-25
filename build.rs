use std::path::Path;
use std::fs::File;
use std::io::Write;

static token_translate_begin: &'static str = "
pub static TOKEN_TRANSLATE: &'static [char] = &[
  '-',
  '.',
  '!',
  '*',
  '_',
  '+',
  '`',
  '\\\'',
  '~',
";

static token_translate_end: &'static str = "];";

fn main() -> std::io::Result<()> {
  let mut id_tables = File::create(
    Path::new(".").join("src").join("msg").join("id_translate_generated.rs")
  )?;

  id_tables.write_all(token_translate_begin.as_bytes())?;
  for ch in (b'0'..=b'9').map(char::from) {
    id_tables.write_all(format!("  '{}',\n", ch).as_bytes())?;
  }
  for ch in (b'a'..=b'z').map(char::from) {
    id_tables.write_all(format!("  '{}',\n", ch).as_bytes())?;
  }
  for ch in (b'A'..=b'Z').map(char::from) {
    id_tables.write_all(format!("  '{}',\n", ch).as_bytes())?;
  }
  id_tables.write_all(token_translate_end.as_bytes())?;

  Ok(())
}
