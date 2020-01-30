use crate::enums::*;

#[derive(Copy, Clone, Debug)]
pub struct EnumDisplay {
    pub render: fn(u8) -> &'static str,
}

#[derive(Copy, Clone, Debug)]
pub enum Field<'a> {
    Enum(EnumDisplay, u8),
    Bytes(&'a [u8]),
    U16(u16),
    DurationMilliseconds(u32),
}

pub struct CryptoSpec {
    pub handshake_ephemeral: HandshakeEphemeral,
    pub handshake_hash: HandshakeHash,
    pub handshake_kdf: HandshakeKDF,
    pub session_nonce_mode: SessionNonceMode,
    pub session_crypto_mode: SessionCryptoMode,
}

pub struct SessionConstraints {
    pub max_nonce: u16,
    pub max_session_duration: u32,
}

pub struct AuthMetadata {
    pub nonce: u16,
    pub valid_until_ms: u32,
}

pub struct RequestHandshakeBegin<'a> {
    pub function: Function,
    pub version: u16,
    pub crypto_spec: CryptoSpec,
    pub constraints: SessionConstraints,
    pub handshake_mode: HandshakeMode,
    pub mode_ephemeral: &'a [u8],
    pub mode_data: &'a [u8],
}

pub struct ReplyHandshakeBegin<'a> {
    pub function: Function,
    pub mode_ephemeral: &'a [u8],
    pub mode_data: &'a [u8],
}

pub struct ReplyHandshakeError {
    pub function: Function,
    pub error: HandshakeError,
}

pub struct SessionData<'a> {
    pub function: Function,
    pub metadata: AuthMetadata,
    pub user_data: &'a [u8],
    pub auth_tag: &'a [u8],
}

pub enum Message<'a> {
    RequestHandshakeBegin(RequestHandshakeBegin<'a>),
    ReplyHandshakeBegin(ReplyHandshakeBegin<'a>),
    ReplyHandshakeError(ReplyHandshakeError),
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

impl<'a> std::convert::From<ReplyHandshakeError> for Message<'a> {
    fn from(msg: ReplyHandshakeError) -> Self {
        Message::ReplyHandshakeError(msg)
    }
}

impl<'a> std::convert::From<SessionData<'a>> for Message<'a> {
    fn from(msg: SessionData<'a>) -> Self {
        Message::SessionData(msg)
    }
}
