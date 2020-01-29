pub mod functions {
    pub const REQUEST_HANDSHAKE_BEGIN: u8 = 0;
    pub const REPLY_HANDSHAKE_BEGIN: u8 = 1;
    pub const REPLY_HANDSHAKE_ERROR: u8 = 2;
    pub const SESSION_DATA: u8 = 3;
}

pub mod modes {
    const SHARED_SECRET: u8 = 0;
    const PUBLIC_KEYS: u8 = 1;
    const INDUSTRIAL_CERTIFICATES: u8 = 2;
    const QUANTUM_KEY_DISTRIBUTION: u8 = 3;
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

pub enum HandshakeEphemeral {}
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
