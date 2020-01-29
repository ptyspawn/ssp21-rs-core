use crate::error::Error;

pub enum Function {
    RequestHandshakeBegin,
    ReplyHandshakeBegin,
    ReplyHandshakeError,
    SessionData,
    Unknown(u8),
}

impl std::convert::From<u8> for Function {
    fn from(x: u8) -> Self {
        match x {
            0 => Function::RequestHandshakeBegin,
            1 => Function::RequestHandshakeBegin,
            2 => Function::ReplyHandshakeError,
            3 => Function::SessionData,
            _ => Function::Unknown(x)
        }
    }
}

pub struct Field<T> {
    /// value of the field
    value: T,
    /// Range within the input buffer if this field
    range: std::ops::Range<usize>,
}

impl<T> Field<T> {
    pub fn new(value: T, range: std::ops::Range<usize>) -> Self {
        Self { value, range }
    }
}

pub enum HandshakeEphemeral {
    X25519,
    Nonce,
    None,
    Unknown(u8)
}

impl std::convert::From<u8> for HandshakeEphemeral {
    fn from(x: u8) -> Self {
        match x {
            0 => HandshakeEphemeral::X25519,
            1 => HandshakeEphemeral::Nonce,
            2 => HandshakeEphemeral::None,
            _ => HandshakeEphemeral::Unknown(x)
        }
    }
}

pub enum HandshakeHash {}
pub enum HandshakeKDF {}
pub enum SessionNonceMode {}
pub enum SessionCryptoMode {}

pub struct CryptoSpec {
    handshake_ephemeral: Field<HandshakeEphemeral>,
    handshake_hash: Field<HandshakeHash>,
    handshake_kdf: Field<HandshakeKDF>,
    session_nonce_mode: Field<SessionNonceMode>,
    session_crypto_mode: Field<SessionCryptoMode>,
}

pub struct SessionConstraints {
    max_nonce: u16,
    max_session_duration: u32,
}

pub enum HandshakeMode {
    SharedSecret,
    PublicKeys,
    IndustrialCertificates,
    QuantumKeyDistribution,
    Unknown(u8)
}

impl std::convert::From<u8> for HandshakeMode {
    fn from(x: u8) -> Self {
        match x {
            0 => HandshakeMode::SharedSecret,
            1 => HandshakeMode::PublicKeys,
            2 => HandshakeMode::IndustrialCertificates,
            3 => HandshakeMode::QuantumKeyDistribution,
            _ => HandshakeMode::Unknown(x)
        }
    }
}

pub struct RequestHandshakeBegin<'a> {
    function: Field<u8>,
    version: Field<u16>,
    crypto_spec: Field<CryptoSpec>,
    constraints: Field<SessionConstraints>,
    handshake_mode: Field<HandshakeMode>,
    mode_ephemeral: Field<&'a [u8]>,
    mode_data: Field<&'a [u8]>,
}
