pub enum Error {
    EndOfStream,
    BadLengthCount(u8),
    BadLengthEncoding(u8, u32),
}
