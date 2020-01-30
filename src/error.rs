#[derive(Debug, Copy, Clone, PartialEq)]
pub struct Position {
    pub value: usize,
}

impl Position {
    pub fn new(pos: usize) -> Self {
        Self { value: pos }
    }

    pub fn next(&mut self) {
        self.value += 1;
    }

    pub fn advance(&mut self, count: usize) {
        self.value += count;
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ParseError {
    EndOfStream(Position, usize),
    TrailingBytes(Position),
    BadLengthCount(Position, u8),
    BadLengthEncoding(Position, u8, u32),
    UnknownFunction(Position, u8),
}
