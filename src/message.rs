use crate::enums::*;
use crate::error::Error;

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

pub struct RequestHandshakeBegin<'a> {
    function: Field<u8>,
    version: Field<u16>,
    crypto_spec: Field<CryptoSpec>,
    constraints: Field<SessionConstraints>,
    handshake_mode: Field<HandshakeMode>,
    mode_ephemeral: Field<&'a [u8]>,
    mode_data: Field<&'a [u8]>,
}
