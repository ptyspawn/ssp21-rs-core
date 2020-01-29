use crate::error::Error;

pub struct Cursor<'a> {
    pos: usize,
    inner: &'a [u8],
}

impl<'a> Cursor<'a> {
    pub fn new(pos: usize, inner: &'a [u8]) -> Self {
        Self { pos, inner }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn read_u8(&mut self) -> Result<u8, Error> {
        match self.inner.get(self.pos) {
            Some(b) => {
                self.pos += 1;
                Ok(*b)
            }
            None => Err(Error::EndOfStream),
        }
    }

    pub fn read_u16(&mut self) -> Result<u16, Error> {
        let b1 = self.read_u8()?;
        let b2 = self.read_u8()?;
        Ok(((b1 as u16) << 8) | (b2 as u16))
    }

    pub fn read_u24(&mut self) -> Result<u32, Error> {
        let b = self.read_u8()?;
        let w = self.read_u16()?;
        Ok(((b as u32) << 16) | (w as u32))
    }

    pub fn read_u32(&mut self) -> Result<u32, Error> {
        let w1 = self.read_u16()?;
        let w2 = self.read_u16()?;
        Ok(((w1 as u32) << 16) | (w2 as u32))
    }
}
