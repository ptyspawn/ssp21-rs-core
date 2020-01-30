use crate::cursor::Cursor;
use crate::enums::*;
use crate::error::ParseError;
use crate::message::*;
use std::fmt::Display;

/// Callbacks that occur during parsing
pub trait ParseCallbacks {
    fn on_start_struct(&mut self, name: &str);
    fn on_field<T>(&mut self, value: &Field<T>)
    where
        T: Display;
    fn on_end_struct(&mut self);
}

pub fn parse_field<'a, T, F, C>(
    name: &'static str,
    cursor: &mut Cursor<'a>,
    callbacks: &mut C,
    parser: F,
) -> Result<Field<'a, T>, ParseError>
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

pub fn parse_struct<T, F, C>(
    name: &'static str,
    cursor: &mut Cursor,
    callbacks: &mut C,
    parser: F,
) -> Result<Struct<T>, ParseError>
    where
        F: Fn(&mut Cursor, &mut C) -> Result<T, ParseError>,
        C: ParseCallbacks,
{

    let start = cursor.pos();
    callbacks.on_start_struct(name);
    let value = parser(cursor, callbacks)?;
    let end = cursor.pos();
    let s = Struct::new(value, name, start.value..end.value);
    callbacks.on_end_struct();
    Ok(s)
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
        Function::RequestHandshakeBegin => {
            Ok(parse_request_handshake_begin(function, &mut cursor, callbacks)?.into())
        }
        Function::ReplyHandshakeBegin => {
            Ok(parse_reply_handshake_begin(function, &mut cursor, callbacks)?.into())
        }
        Function::ReplyHandshakeError => {
            Ok(parse_reply_handshake_error(function, &mut cursor, callbacks)?.into())
        }
        Function::SessionData => Ok(parse_session_data(function, &mut cursor, callbacks)?.into()),
        Function::Unknown(u8) => Err(ParseError::UnknownFunction(start, u8)),
    }
}

pub fn parse_crypto_spec<'a, C>(
    cursor: &mut Cursor<'a>,
    callbacks: &mut C,
) -> Result<CryptoSpec<'a>, ParseError>
    where
        C: ParseCallbacks,
{
    Ok(
        CryptoSpec {
            handshake_ephemeral : parse_field("handshake ephemeral", cursor, callbacks, |c| c.read_u8().map(HandshakeEphemeral::from))?,
            handshake_hash : parse_field("handshake hash", cursor, callbacks, |c| c.read_u8().map(HandshakeHash::from))?,
            handshake_kdf : parse_field("handshake kdf", cursor, callbacks, |c| c.read_u8().map(HandshakeKDF::from))?,
            session_nonce_mode : parse_field("session nonce mode", cursor, callbacks, |c| c.read_u8().map(SessionNonceMode::from))?,
            session_crypto_mode : parse_field("session crypto mode", cursor, callbacks, |c| c.read_u8().map(SessionCryptoMode::from))?,
        }
    )
}

pub fn parse_constraints<'a, C>(
    cursor: &mut Cursor<'a>,
    callbacks: &mut C,
) -> Result<SessionConstraints<'a>, ParseError>
    where
        C: ParseCallbacks,
{
    Ok(
        SessionConstraints {
            max_nonce : parse_field("max nonce", cursor, callbacks, |c| c.read_u16())?,
            max_session_duration : parse_field("max session duration (ms)", cursor, callbacks, |c| c.read_u32())?,
        }
    )
}

pub fn parse_bytes<'a, C>(
    cursor: &mut Cursor<'a>,
    callbacks: &mut C,
) -> Result<Bytes<'a>, ParseError>
    where
        C: ParseCallbacks,
{
    let length = crate::length::read(cursor)?;

    Ok(Bytes::new(cursor.read(length as usize)?))
}

pub fn parse_request_handshake_begin<'a, C>(
    function: Field<Function>,
    cursor: &mut Cursor<'a>,
    callbacks: &mut C,
) -> Result<RequestHandshakeBegin<'a>, ParseError>
where
    C: ParseCallbacks,
{
    Ok(
        RequestHandshakeBegin {
            function,
            version: parse_field("version", cursor, callbacks, |c| c.read_u16())?,
            crypto_spec: parse_struct("crypto spec", cursor, callbacks, parse_crypto_spec)?,
            constraints: parse_struct("session constraints", cursor, callbacks, parse_constraints)?,
            handshake_mode: parse_field("handshake mode", cursor, callbacks, |c| c.read_u8().map(HandshakeMode::from))?,
            mode_ephemeral: parse_field("mode ephemeral", cursor, callbacks, |c| parse_bytes(c, callbacks))?,
            mode_data: parse_field("mode data", cursor, callbacks, |c| parse_bytes(c, callbacks))?,
        }
    )
}



pub fn parse_reply_handshake_begin<'a, C>(
    function: Field<Function>,
    cursor: &mut Cursor<'a>,
    callbacks: &mut C,
) -> Result<ReplyHandshakeBegin<'a>, ParseError>
where
    C: ParseCallbacks,
{
    Err(ParseError::EndOfStream(cursor.pos(), 1))
}

pub fn parse_reply_handshake_error<'a, C>(
    function: Field<Function>,
    cursor: &mut Cursor<'a>,
    callbacks: &mut C,
) -> Result<ReplyHandshakeError<'a>, ParseError>
where
    C: ParseCallbacks,
{
    Err(ParseError::EndOfStream(cursor.pos(), 1))
}

pub fn parse_session_data<'a, C>(
    function: Field<Function>,
    cursor: &mut Cursor<'a>,
    callbacks: &mut C,
) -> Result<SessionData<'a>, ParseError>
where
    C: ParseCallbacks,
{
    Err(ParseError::EndOfStream(cursor.pos(), 1))
}
