use crate::cursor::{Cursor, Region};
use crate::enums::*;
use crate::error::ParseError;
use crate::message::*;

/// Callbacks that occur during parsing
pub trait ParseCallbacks {
    fn on_start_struct(&mut self, name: &'static str);
    fn on_field(&mut self, name: &'static str, region: Region, value: Field);
    fn on_end_struct(&mut self, region: Region);
    fn on_error(&mut self, error: ParseError);
}

pub trait Struct: Sized {
    fn parse<C: ParseCallbacks>(cursor: &mut Cursor, callbacks: &mut C)
        -> Result<Self, ParseError>;
}

fn parse_region_cb<C, R>(
    cursor: &mut Cursor,
    callbacks: &mut C,
    inner: fn(&mut Cursor, &mut C) -> Result<R, ParseError>,
) -> Result<(R, Region), ParseError>
where
    C: ParseCallbacks,
{
    let begin = cursor.pos();
    let value = inner(cursor, callbacks)?;
    let end = cursor.pos();
    Ok((value, Region::new(begin, end)))
}

fn parse_region<C, R>(
    cursor: &mut Cursor,
    inner: fn(&mut Cursor) -> Result<R, ParseError>,
) -> Result<(R, Region), ParseError> {
    let begin = cursor.pos();
    let value = inner(cursor)?;
    let end = cursor.pos();
    Ok((value, Region::new(begin, end)))
}

fn parse_u16<C>(
    name: &'static str,
    cursor: &mut Cursor,
    callbacks: &mut C,
) -> Result<u16, ParseError>
where
    C: ParseCallbacks,
{
    let (value, region) = parse_region::<C, u16>(cursor, |cursor| cursor.read_u16())?;
    callbacks.on_field(name, region, Field::U16(value));
    Ok(value)
}

fn parse_duration_ms<C>(
    name: &'static str,
    cursor: &mut Cursor,
    callbacks: &mut C,
) -> Result<u32, ParseError>
where
    C: ParseCallbacks,
{
    let (value, region) = parse_region::<C, u32>(cursor, |cursor| cursor.read_u32())?;
    callbacks.on_field(name, region, Field::DurationMilliseconds(value));
    Ok(value)
}

fn parse_enum<'a, C, E>(
    name: &'static str,
    cursor: &mut Cursor<'a>,
    callbacks: &mut C,
) -> Result<E, ParseError>
where
    C: ParseCallbacks,
    E: Enumeration,
{
    let (raw, region) = parse_region::<C, u8>(cursor, |cursor| cursor.read_u8())?;
    callbacks.on_field(name, region, Field::Enum(E::DISPLAY, raw));
    Ok(E::parse(raw))
}

fn parse_bytes<'a, C>(
    name: &'static str,
    cursor: &mut Cursor<'a>,
    callbacks: &mut C,
) -> Result<&'a [u8], ParseError>
where
    C: ParseCallbacks,
{
    let begin = cursor.pos();
    let length = crate::length::read(cursor)?;
    let value = cursor.read(length as usize)?;
    let end = cursor.pos();
    callbacks.on_field(name, Region::new(begin, end), Field::Bytes(value));
    Ok(value)
}

fn parse_struct<C, S>(
    name: &'static str,
    cursor: &mut Cursor,
    callbacks: &mut C,
) -> Result<S, ParseError>
where
    C: ParseCallbacks,
    S: Struct,
{
    callbacks.on_start_struct(name);
    let (value, region) = parse_region_cb(cursor, callbacks, S::parse)?;
    callbacks.on_end_struct(region);
    Ok(value)
}

pub fn parse_message<'a, C>(input: &'a [u8], callbacks: &mut C) -> Result<Message<'a>, ParseError>
where
    C: ParseCallbacks,
{
    let mut cursor = Cursor::new(input);
    let result = parse_message_no_error(&mut cursor, callbacks);

    if let Err(e) = result {
        callbacks.on_error(e);
    }

    result
}

fn parse_message_no_error<'a, C>(
    cursor: &mut Cursor<'a>,
    callbacks: &mut C,
) -> Result<Message<'a>, ParseError>
where
    C: ParseCallbacks,
{
    let start = cursor.pos();

    let function: Function = parse_enum("function", cursor, callbacks)?;

    let message = match function {
        Function::RequestHandshakeBegin => Message::RequestHandshakeBegin(
            parse_request_handshake_begin(function, cursor, callbacks)?,
        ),
        Function::ReplyHandshakeBegin => {
            Message::ReplyHandshakeBegin(parse_reply_handshake_begin(function, cursor, callbacks)?)
        }
        Function::ReplyHandshakeError => {
            Message::ReplyHandshakeError(parse_reply_handshake_error(function, cursor, callbacks)?)
        }
        Function::SessionData => {
            Message::SessionData(parse_session_data(function, cursor, callbacks)?)
        }
        Function::Unknown(u8) => return Err(ParseError::UnknownFunction(start, u8)),
    };

    if !cursor.is_empty() {
        return Err(ParseError::TrailingBytes(cursor.pos()));
    }

    Ok(message)
}

impl Struct for CryptoSpec {
    fn parse<'a, C>(cursor: &mut Cursor<'a>, callbacks: &mut C) -> Result<CryptoSpec, ParseError>
    where
        C: ParseCallbacks,
    {
        Ok(CryptoSpec {
            handshake_ephemeral: parse_enum("handshake ephemeral", cursor, callbacks)?,
            handshake_hash: parse_enum("handshake hash", cursor, callbacks)?,
            handshake_kdf: parse_enum("handshake kdf", cursor, callbacks)?,
            session_nonce_mode: parse_enum("session nonce mode", cursor, callbacks)?,
            session_crypto_mode: parse_enum("session crypto mode", cursor, callbacks)?,
        })
    }
}

impl Struct for SessionConstraints {
    fn parse<C>(cursor: &mut Cursor, callbacks: &mut C) -> Result<SessionConstraints, ParseError>
    where
        C: ParseCallbacks,
    {
        Ok(SessionConstraints {
            max_nonce: parse_u16("max nonce", cursor, callbacks)?,
            max_session_duration: parse_duration_ms("max session duration", cursor, callbacks)?,
        })
    }
}

impl Struct for AuthMetadata {
    fn parse<'a, C>(cursor: &mut Cursor, callbacks: &mut C) -> Result<AuthMetadata, ParseError>
    where
        C: ParseCallbacks,
    {
        Ok(AuthMetadata {
            nonce: parse_u16("nonce", cursor, callbacks)?,
            valid_until_ms: parse_duration_ms("valid until ms", cursor, callbacks)?,
        })
    }
}

fn parse_request_handshake_begin<'a, C>(
    function: Function,
    cursor: &mut Cursor<'a>,
    callbacks: &mut C,
) -> Result<RequestHandshakeBegin<'a>, ParseError>
where
    C: ParseCallbacks,
{
    Ok(RequestHandshakeBegin {
        function,
        version: parse_u16("version", cursor, callbacks)?,
        crypto_spec: parse_struct("crypto spec", cursor, callbacks)?,
        constraints: parse_struct("session constraints", cursor, callbacks)?,
        handshake_mode: parse_enum("handshake mode", cursor, callbacks)?,
        mode_ephemeral: parse_bytes("mode ephemeral", cursor, callbacks)?,
        mode_data: parse_bytes("mode data", cursor, callbacks)?,
    })
}

fn parse_reply_handshake_begin<'a, C>(
    function: Function,
    cursor: &mut Cursor<'a>,
    callbacks: &mut C,
) -> Result<ReplyHandshakeBegin<'a>, ParseError>
where
    C: ParseCallbacks,
{
    Ok(ReplyHandshakeBegin {
        function,
        mode_ephemeral: parse_bytes("mode ephemeral", cursor, callbacks)?,
        mode_data: parse_bytes("mode data", cursor, callbacks)?,
    })
}

fn parse_reply_handshake_error<'a, C>(
    function: Function,
    cursor: &mut Cursor<'a>,
    callbacks: &mut C,
) -> Result<ReplyHandshakeError, ParseError>
where
    C: ParseCallbacks,
{
    Ok(ReplyHandshakeError {
        function,
        error: parse_enum("error", cursor, callbacks)?,
    })
}

fn parse_session_data<'a, C>(
    function: Function,
    cursor: &mut Cursor<'a>,
    callbacks: &mut C,
) -> Result<SessionData<'a>, ParseError>
where
    C: ParseCallbacks,
{
    Ok(SessionData {
        function,
        metadata: parse_struct("auth_metadata", cursor, callbacks)?,
        user_data: parse_bytes("user data", cursor, callbacks)?,
        auth_tag: parse_bytes("auth tag", cursor, callbacks)?,
    })
}
