use crate::error::{ParseError, Position};

pub struct Cursor<'a> {
    pos: Position,
    inner: &'a [u8],
}

impl<'a> Cursor<'a> {
    pub fn new(inner: &'a [u8]) -> Self {
        Self {
            pos: Position::new(0),
            inner,
        }
    }

    pub fn pos(&self) -> Position {
        self.pos
    }

    pub fn read_u8(&mut self) -> Result<u8, ParseError> {
        match self.inner.get(self.pos.value) {
            Some(b) => {
                self.pos.next();
                Ok(*b)
            }
            None => Err(ParseError::EndOfStream(self.pos, 1)),
        }
    }

    pub fn read_u16(&mut self) -> Result<u16, ParseError> {
        let b1 = self.read_u8()?;
        let b2 = self.read_u8()?;
        Ok(((b1 as u16) << 8) | (b2 as u16))
    }

    pub fn read_u24(&mut self) -> Result<u32, ParseError> {
        let b = self.read_u8()?;
        let w = self.read_u16()?;
        Ok(((b as u32) << 16) | (w as u32))
    }

    pub fn read_u32(&mut self) -> Result<u32, ParseError> {
        let w1 = self.read_u16()?;
        let w2 = self.read_u16()?;
        Ok(((w1 as u32) << 16) | (w2 as u32))
    }

    pub fn read(&mut self, count : usize) -> Result<&'a [u8], ParseError> {
        match self.inner.get(self.pos.value .. self.pos.value + count) {
            Some(bytes) => {
                self.pos.advance(count);
                Ok(bytes)
            }
            None => Err(ParseError::EndOfStream(self.pos, count))
        }
    }
}
