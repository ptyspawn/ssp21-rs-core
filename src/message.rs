use crate::enums::*;
use std::fmt::{Display, Error, Formatter};

pub struct Field<T>
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

impl<T> Field<T>
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
    /// Range within the input buffer of this field
    range: std::ops::Range<usize>,
}

impl<T> Struct<T> {
    pub fn new(value: T, range: std::ops::Range<usize>) -> Self {
        Self { value, range }
    }
}

pub struct CryptoSpec {
    handshake_ephemeral: Field<HandshakeEphemeral>,
    handshake_hash: Field<HandshakeHash>,
    handshake_kdf: Field<HandshakeKDF>,
    session_nonce_mode: Field<SessionNonceMode>,
    session_crypto_mode: Field<SessionCryptoMode>,
}

pub struct Bytes<'a> {
    pub value: &'a [u8],
}

impl<'a> Bytes<'a> {
    fn new(value: &'a [u8]) -> Self {
        Self { value }
    }
}

impl<'a> Display for Bytes<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "length: {}", self.value.len())
    }
}

pub struct SessionConstraints {
    max_nonce: u16,
    max_session_duration: u32,
}

pub struct AuthMetadata {
    nonce: Field<u16>,
    valid_until_ms: Field<u16>,
}

pub struct RequestHandshakeBegin<'a> {
    function: Field<Function>,
    version: Field<u16>,
    crypto_spec: Struct<CryptoSpec>,
    constraints: Struct<SessionConstraints>,
    handshake_mode: Field<HandshakeMode>,
    mode_ephemeral: Field<Bytes<'a>>,
    mode_data: Field<Bytes<'a>>,
}

pub struct ReplyHandshakeBegin<'a> {
    function: Field<Function>,
    mode_ephemeral: Field<Bytes<'a>>,
    mode_data: Field<Bytes<'a>>,
}

pub struct ReplyHandshakeError {
    function: Field<Function>,
    error: Field<HandshakeError>,
}

pub struct SessionData<'a> {
    function: Field<Function>,
    metadata: Struct<AuthMetadata>,
    user_data: Field<Bytes<'a>>,
    auth_tag: Field<Bytes<'a>>,
}

pub enum Message<'a> {
    RequestHandshakeBegin(RequestHandshakeBegin<'a>),
    ReplyHandshakeBegin(ReplyHandshakeBegin<'a>),
    ReplyHandshakeError(ReplyHandshakeError),
    SessionData(SessionData<'a>),
}
