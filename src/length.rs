use crate::cursor::Cursor;
use crate::error::ParseError;

const TOP_BIT: u8 = 0b1000_0000;
const BOTTOM_BITS: u8 = !TOP_BIT;

pub fn read(cursor: &mut Cursor) -> Result<u32, ParseError> {
    let pos_before = cursor.pos();
    let first = cursor.read_u8()?;
    if first & TOP_BIT == 0 {
        return Ok((first & BOTTOM_BITS) as u32);
    }

    let count_of_bytes = first & BOTTOM_BITS;

    let pos_after = cursor.pos();

    let value: u32 = match count_of_bytes {
        1 => {
            let value = cursor.read_u8()?;
            if value < 128 {
                return Err(ParseError::BadLengthEncoding(
                    pos_after,
                    count_of_bytes,
                    value as u32,
                ));
            }
            value as u32
        }
        2 => {
            let value = cursor.read_u16()?;
            if value < 256 {
                return Err(ParseError::BadLengthEncoding(
                    pos_after,
                    count_of_bytes,
                    value as u32,
                ));
            }
            value as u32
        }
        3 => {
            let value = cursor.read_u24()?;
            if value < 65536 {
                return Err(ParseError::BadLengthEncoding(
                    pos_after,
                    count_of_bytes,
                    value,
                ));
            }
            value
        }
        4 => {
            let value = cursor.read_u32()?;
            if value < 16777216 {
                return Err(ParseError::BadLengthEncoding(
                    pos_after,
                    count_of_bytes,
                    value,
                ));
            }
            value
        }
        _ => return Err(ParseError::BadLengthCount(pos_before, count_of_bytes)),
    };

    Ok(value)
}
