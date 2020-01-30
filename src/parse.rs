use crate::cursor::Cursor;
use crate::enums::*;
use crate::error::ParseError;
use crate::message::{
    Field, Message, ReplyHandshakeBegin, ReplyHandshakeError, RequestHandshakeBegin, SessionData,
};
use std::fmt::Display;

/// Callbacks that occur during parsing
pub trait ParseCallbacks {
    fn on_start_struct(&mut self, name: &str);
    fn on_field<T>(&mut self, value: &Field<T>)
    where
        T: Display;
    fn on_end_struct(&mut self);
}

pub fn parse_field<T, F, C>(
    name: &'static str,
    cursor: &mut Cursor,
    callbacks: &mut C,
    parser: F,
) -> Result<Field<T>, ParseError>
where
    T: Display,
    F: Fn(&mut Cursor) -> Result<T, ParseError>,
    C: ParseCallbacks,
{
    let start = cursor.pos();
    let value = parser(cursor)?;
    let end = cursor.pos();
    let field = Field::new(value, name, start.value..end.value);
    callbacks.on_field(&field);
    Ok(field)
}

pub fn parse<'a, C>(input: &'a [u8], callbacks: &mut C) -> Result<Message<'a>, ParseError>
where
    C: ParseCallbacks,
{
    let mut cursor = Cursor::new(input);
    let start = cursor.pos();

    let function: Field<Function> = parse_field("function", &mut cursor, callbacks, |c| {
        c.read_u8().map(Function::from)
    })?;

    match function.value {
        Function::RequestHandshakeBegin => Ok(Message::RequestHandshakeBegin(
            parse_request_handshake_begin(function, &mut cursor, callbacks)?,
        )),
        Function::ReplyHandshakeBegin => Ok(Message::ReplyHandshakeBegin(
            parse_reply_handshake_begin(function, &mut cursor, callbacks)?,
        )),
        Function::ReplyHandshakeError => Ok(Message::ReplyHandshakeError(
            parse_reply_handshake_error(function, &mut cursor, callbacks)?,
        )),
        Function::SessionData => Ok(Message::SessionData(parse_session_data(
            function,
            &mut cursor,
            callbacks,
        )?)),
        Function::Unknown(u8) => Err(ParseError::UnknownFunction(start, u8)),
    }
}

pub fn parse_request_handshake_begin<'a, C>(
    function: Field<Function>,
    cursor: &mut Cursor<'a>,
    callbacks: &mut C,
) -> Result<RequestHandshakeBegin<'a>, ParseError>
where
    C: ParseCallbacks,
{
    Err(ParseError::EndOfStream(cursor.pos()))
}

pub fn parse_reply_handshake_begin<'a, C>(
    function: Field<Function>,
    cursor: &mut Cursor<'a>,
    callbacks: &mut C,
) -> Result<ReplyHandshakeBegin<'a>, ParseError>
where
    C: ParseCallbacks,
{
    Err(ParseError::EndOfStream(cursor.pos()))
}

pub fn parse_reply_handshake_error<'a, C>(
    function: Field<Function>,
    cursor: &mut Cursor<'a>,
    callbacks: &mut C,
) -> Result<ReplyHandshakeError, ParseError>
where
    C: ParseCallbacks,
{
    Err(ParseError::EndOfStream(cursor.pos()))
}

pub fn parse_session_data<'a, C>(
    function: Field<Function>,
    cursor: &mut Cursor<'a>,
    callbacks: &mut C,
) -> Result<SessionData<'a>, ParseError>
where
    C: ParseCallbacks,
{
    Err(ParseError::EndOfStream(cursor.pos()))
}
