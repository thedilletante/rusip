use crate::msg::Binary;

pub struct Buffer <'a, T> {
  buf: &'a mut [T],
  num_pushed: usize
}

impl <'a, T> Buffer <'a, T> {

  pub fn new(buf: &'a mut [T]) -> Buffer <'a, T> {
    Buffer {
      buf,
      num_pushed: 0
    }
  }

  pub fn capacity(&self) -> usize {
    self.buf.len() - self.num_pushed
  }

  /// Returns None if everything is ok and value was pushed
  /// Returns Some(value) otherwise (e.g. capacity was exhausted)
  pub fn push(&mut self, value: T) -> Option<T> {
    if self.capacity() == 0 {
      return Some(value)
    }

    self.buf[self.num_pushed] = value;
    self.num_pushed += 1;
    None
  }

  pub fn commit(self) -> (Buffer<'a, T>, &'a [T]) {
    let (filled, left) = self.buf.split_at_mut(self.num_pushed);
    (Buffer::new(left), filled)
  }
}

pub type BinaryBuffer<'a, 'b> = Buffer<'a, &'b Binary>;

pub enum Result <T, Rest, Code, Add> {
  Done(T, Rest, Add),
  Error(Code, Add)
}

#[cfg(test)]
mod tests {

  use crate::msg::parse::BinaryBuffer;

  #[test]
  fn buffer_test() {
    let mut b = ["".as_bytes(); 3];
    let mut buffer = BinaryBuffer::new(&mut b);
    assert_eq!(3, buffer.capacity());
    assert_eq!(None, buffer.push("one".as_bytes()));
    assert_eq!(None, buffer.push("two".as_bytes()));

    let (mut buffer, commit) = buffer.commit();

    assert_eq!(2, commit.len());
    assert_eq!("one".as_bytes(), commit[0]);
    assert_eq!("two".as_bytes(), commit[1]);

    assert_eq!(1, buffer.capacity());
    assert_eq!(None, buffer.push("three".as_bytes()));
    assert_eq!(Some("four".as_bytes()), buffer.push("four".as_bytes()));

    let (mut buffer, commit) = buffer.commit();
    
    assert_eq!(1, commit.len());
    assert_eq!("three".as_bytes(), commit[0]);

    assert_eq!(0, buffer.capacity());
    assert_eq!(Some("five".as_bytes()), buffer.push("five".as_bytes()));
  }

}
