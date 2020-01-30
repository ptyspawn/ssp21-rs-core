use crate::enums::*;
use std::fmt::{Display, Error, Formatter};

pub struct Field<'a, T>
where
    T: Display,
{
    /// value of the field
    pub value: T,
    /// name of the field
    pub name: &'static str,
    /// Range within the input buffer of this field
    pub range: std::ops::Range<usize>,
}

impl<'a, T> Field<'a, T>
where
    T: Display,
{
    pub fn new(value: T, name: &'static str, range: std::ops::Range<usize>) -> Self {
        Self { value, name, range }
    }
}

pub struct Struct<T> {
    /// value of the struct
    value: T,
    /// name of the struct field
    pub name: &'static str,
    /// Range within the input buffer of this field
    range: std::ops::Range<usize>,
}

impl<T> Struct<T> {
    pub fn new(value: T, name: &'static str, range: std::ops::Range<usize>) -> Self {
        Self { value, name, range }
    }
}

pub struct CryptoSpec<'a> {
    handshake_ephemeral: Field<'a, HandshakeEphemeral>,
    handshake_hash: Field<'a, HandshakeHash>,
    handshake_kdf: Field<'a, HandshakeKDF>,
    session_nonce_mode: Field<'a, SessionNonceMode>,
    session_crypto_mode: Field<'a, SessionCryptoMode>,
}

#[derive(Copy, Clone)]
pub struct Bytes<'a> {
    pub value: &'a [u8],
}

impl<'a> Bytes<'a> {
    pub fn new(value: &'a [u8]) -> Self {
        Self { value }
    }
}

impl<'a> Display for Bytes<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "length: {}", self.value.len())
    }
}

pub struct SessionConstraints<'a> {
    max_nonce: Field<'a, u16>,
    max_session_duration: Field<'a, u32>,
}

pub struct AuthMetadata<'a> {
    nonce: Field<'a, u16>,
    valid_until_ms: Field<'a, u16>,
}

pub struct RequestHandshakeBegin<'a> {
    function: Field<'a, Function>,
    version: Field<'a, u16>,
    crypto_spec: Struct<CryptoSpec<'a>>,
    constraints: Struct<SessionConstraints<'a>>,
    handshake_mode: Field<'a, HandshakeMode>,
    mode_ephemeral: Field<'a, Bytes<'a>>,
    mode_data: Field<'a, Bytes<'a>>,
}

pub struct ReplyHandshakeBegin<'a> {
    function: Field<'a, Function>,
    mode_ephemeral: Field<'a, Bytes<'a>>,
    mode_data: Field<'a, Bytes<'a>>,
}

pub struct ReplyHandshakeError<'a> {
    function: Field<'a, Function>,
    error: Field<'a, HandshakeError>,
}

pub struct SessionData<'a> {
    function: Field<'a, Function>,
    metadata: Struct<AuthMetadata<'a>>,
    user_data: Field<'a, Bytes<'a>>,
    auth_tag: Field<'a, Bytes<'a>>,
}

pub enum Message<'a> {
    RequestHandshakeBegin(RequestHandshakeBegin<'a>),
    ReplyHandshakeBegin(ReplyHandshakeBegin<'a>),
    ReplyHandshakeError(ReplyHandshakeError<'a>),
    SessionData(SessionData<'a>),
}

impl<'a> std::convert::From<RequestHandshakeBegin<'a>> for Message<'a> {
    fn from(msg: RequestHandshakeBegin<'a>) -> Self {
        Message::RequestHandshakeBegin(msg)
    }
}

impl<'a> std::convert::From<ReplyHandshakeBegin<'a>> for Message<'a> {
    fn from(msg: ReplyHandshakeBegin<'a>) -> Self {
        Message::ReplyHandshakeBegin(msg)
    }
}

impl<'a> std::convert::From<ReplyHandshakeError<'a>> for Message<'a> {
    fn from(msg: ReplyHandshakeError) -> Self {
        Message::ReplyHandshakeError(msg)
    }
}

impl<'a> std::convert::From<SessionData<'a>> for Message<'a> {
    fn from(msg: SessionData<'a>) -> Self {
        Message::SessionData(msg)
    }
}
