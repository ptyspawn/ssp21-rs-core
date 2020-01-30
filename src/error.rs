#[derive(Debug, Copy, Clone)]
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
}

pub enum ParseError {
    EndOfStream(Position),
    BadLengthCount(Position, u8),
    BadLengthEncoding(Position, u8, u32),
    UnknownFunction(Position, u8),
}
