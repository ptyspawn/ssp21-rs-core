use std::fmt::{Display, Error, Formatter};

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
            _ => Function::Unknown(x),
        }
    }
}

impl Display for Function {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        match self {
            Function::RequestHandshakeBegin => f.write_str("request handshake begin"),
            Function::ReplyHandshakeBegin => f.write_str("reply handshake begin"),
            Function::ReplyHandshakeError => f.write_str("reply handshake error"),
            Function::SessionData => f.write_str("session data"),
            Function::Unknown(x) => write!(f, "unknown: 0x{:2x}", x),
        }
    }
}

pub enum HandshakeEphemeral {
    X25519,
    Nonce,
    None,
    Unknown(u8),
}

impl std::convert::From<u8> for HandshakeEphemeral {
    fn from(x: u8) -> Self {
        match x {
            0 => HandshakeEphemeral::X25519,
            1 => HandshakeEphemeral::Nonce,
            2 => HandshakeEphemeral::None,
            _ => HandshakeEphemeral::Unknown(x),
        }
    }
}

impl Display for HandshakeEphemeral {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        match self {
            HandshakeEphemeral::X25519 => f.write_str("X25519"),
            HandshakeEphemeral::Nonce => f.write_str("Nonce"),
            HandshakeEphemeral::None => f.write_str("None"),
            HandshakeEphemeral::Unknown(x) => write!(f, "unknown: 0x{:2x}", x),
        }
    }
}

pub enum HandshakeHash {
    Sha256,
    Unknown(u8),
}

impl std::convert::From<u8> for HandshakeHash {
    fn from(x: u8) -> Self {
        match x {
            0 => HandshakeHash::Sha256,
            _ => HandshakeHash::Unknown(x),
        }
    }
}

impl Display for HandshakeHash {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        match self {
            HandshakeHash::Sha256 => f.write_str("SHA-256"),
            HandshakeHash::Unknown(x) => write!(f, "unknown: 0x{:2x}", x),
        }
    }
}

pub enum HandshakeKDF {
    HkdfSha256,
    Unknown(u8),
}

impl std::convert::From<u8> for HandshakeKDF {
    fn from(x: u8) -> Self {
        match x {
            0 => HandshakeKDF::HkdfSha256,
            _ => HandshakeKDF::Unknown(x),
        }
    }
}

impl Display for HandshakeKDF {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        match self {
            HandshakeKDF::HkdfSha256 => f.write_str("HKDF-SHA-256"),
            HandshakeKDF::Unknown(x) => write!(f, "unknown: 0x{:2x}", x),
        }
    }
}

pub enum SessionNonceMode {
    IncrementLastRx,
    GreaterThanLastRx,
    Unknown(u8),
}

impl std::convert::From<u8> for SessionNonceMode {
    fn from(x: u8) -> Self {
        match x {
            0 => SessionNonceMode::IncrementLastRx,
            1 => SessionNonceMode::GreaterThanLastRx,
            _ => SessionNonceMode::Unknown(x),
        }
    }
}

impl Display for SessionNonceMode {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        match self {
            SessionNonceMode::IncrementLastRx => f.write_str("increment Last Rx"),
            SessionNonceMode::GreaterThanLastRx => f.write_str("greater than last Rx"),
            SessionNonceMode::Unknown(x) => write!(f, "unknown: 0x{:2x}", x),
        }
    }
}

pub enum SessionCryptoMode {
    HmacSha256Trunc16,
    Aes256Gcm,
    Unknown(u8),
}

impl std::convert::From<u8> for SessionCryptoMode {
    fn from(x: u8) -> Self {
        match x {
            0 => SessionCryptoMode::HmacSha256Trunc16,
            1 => SessionCryptoMode::Aes256Gcm,
            _ => SessionCryptoMode::Unknown(x),
        }
    }
}

impl Display for SessionCryptoMode {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        match self {
            SessionCryptoMode::HmacSha256Trunc16 => f.write_str("HMAC-SHA-256-16"),
            SessionCryptoMode::Aes256Gcm => f.write_str("AES-256-GCM"),
            SessionCryptoMode::Unknown(x) => write!(f, "unknown: 0x{:2x}", x),
        }
    }
}

pub enum HandshakeMode {
    SharedSecret,
    PublicKeys,
    IndustrialCertificates,
    QuantumKeyDistribution,
    Unknown(u8),
}

impl std::convert::From<u8> for HandshakeMode {
    fn from(x: u8) -> Self {
        match x {
            0 => HandshakeMode::SharedSecret,
            1 => HandshakeMode::PublicKeys,
            2 => HandshakeMode::IndustrialCertificates,
            3 => HandshakeMode::QuantumKeyDistribution,
            _ => HandshakeMode::Unknown(x),
        }
    }
}

impl Display for HandshakeMode {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        match self {
            HandshakeMode::SharedSecret => f.write_str("shared secret"),
            HandshakeMode::PublicKeys => f.write_str("pre-shared public keys"),
            HandshakeMode::IndustrialCertificates => f.write_str("industrial certificates"),
            HandshakeMode::QuantumKeyDistribution => f.write_str("quantum Key distribution"),
            HandshakeMode::Unknown(x) => write!(f, "unknown: 0x{:2x}", x),
        }
    }
}

pub enum HandshakeError {
    BadMessageFormat,
    UnsupportedVersion,
    UnsupportedHandshakeEphemeral,
    UnsupportedHandshakeHash,
    UnsupportedHandshakeKdf,
    UnsupportedSessionMode,
    UnsupportedNonceMode,
    UnsupportedHandshakeMode,
    BadCertificateFormat,
    BadCertificateChain,
    UnsupportedCertificateFeature,
    AuthenticationError,
    NoPriorHandshakeBegin,
    KeyNotFound,
    Unknown(u8),
}

impl std::convert::From<u8> for HandshakeError {
    fn from(x: u8) -> Self {
        match x {
            0 => HandshakeError::BadMessageFormat,
            1 => HandshakeError::UnsupportedVersion,
            2 => HandshakeError::UnsupportedHandshakeEphemeral,
            3 => HandshakeError::UnsupportedHandshakeHash,
            4 => HandshakeError::UnsupportedHandshakeKdf,
            5 => HandshakeError::UnsupportedSessionMode,
            6 => HandshakeError::UnsupportedNonceMode,
            7 => HandshakeError::UnsupportedHandshakeMode,
            8 => HandshakeError::BadCertificateFormat,
            9 => HandshakeError::BadCertificateChain,
            10 => HandshakeError::UnsupportedCertificateFeature,
            11 => HandshakeError::AuthenticationError,
            12 => HandshakeError::NoPriorHandshakeBegin,
            13 => HandshakeError::KeyNotFound,
            _ => HandshakeError::Unknown(x),
        }
    }
}

impl Display for HandshakeError {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        match self {
            HandshakeError::BadMessageFormat => f.write_str("bad message format"),
            HandshakeError::UnsupportedVersion => f.write_str("unsupported version"),
            HandshakeError::UnsupportedHandshakeEphemeral => {
                f.write_str("unsupported handshake ephemeral")
            }
            HandshakeError::UnsupportedHandshakeHash => f.write_str("unsupported handshake hash"),
            HandshakeError::UnsupportedHandshakeKdf => f.write_str("unsupported handshake KDF"),
            HandshakeError::UnsupportedSessionMode => f.write_str("unsupported session mode"),
            HandshakeError::UnsupportedNonceMode => f.write_str("unsupported nonce nonce"),
            HandshakeError::UnsupportedHandshakeMode => f.write_str("unsupported handshake mode"),
            HandshakeError::BadCertificateFormat => f.write_str("bad certificate format"),
            HandshakeError::BadCertificateChain => f.write_str("bad certificate chain"),
            HandshakeError::UnsupportedCertificateFeature => {
                f.write_str("unsupported certificate feature")
            }
            HandshakeError::AuthenticationError => f.write_str("authentication error"),
            HandshakeError::NoPriorHandshakeBegin => f.write_str("no prior handshake begin"),
            HandshakeError::KeyNotFound => f.write_str("key not found"),
            HandshakeError::Unknown(x) => write!(f, "unknown: {}", x),
        }
    }
}
