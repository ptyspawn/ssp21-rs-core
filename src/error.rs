use crate::parse::Position;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ParseError {
    EndOfStream(Position, usize),
    TrailingBytes(Position),
    BadLengthCount(Position, u8),
    BadLengthEncoding(Position, u8, u32),
    UnknownFunction(Position, u8),
}
