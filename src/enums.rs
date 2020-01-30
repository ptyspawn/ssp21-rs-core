use crate::message::EnumDisplay;

pub trait Enumeration {
    const DISPLAY: EnumDisplay = EnumDisplay {
        render: Self::render,
    };

    fn parse(value: u8) -> Self;
    fn render(value: u8) -> &'static str;
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Function {
    RequestHandshakeBegin,
    ReplyHandshakeBegin,
    ReplyHandshakeError,
    SessionData,
    Unknown(u8),
}

impl Enumeration for Function {
    fn parse(x: u8) -> Self {
        match x {
            0 => Function::RequestHandshakeBegin,
            1 => Function::RequestHandshakeBegin,
            2 => Function::ReplyHandshakeError,
            3 => Function::SessionData,
            _ => Function::Unknown(x),
        }
    }

    fn render(value: u8) -> &'static str {
        match Self::parse(value) {
            Function::RequestHandshakeBegin => "request handshake begin",
            Function::ReplyHandshakeBegin => "reply handshake begin",
            Function::ReplyHandshakeError => "reply handshake error",
            Function::SessionData => "session data",
            Function::Unknown(_) => "unknown",
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum HandshakeEphemeral {
    X25519,
    Nonce,
    None,
    Unknown(u8),
}

impl Enumeration for HandshakeEphemeral {
    fn parse(x: u8) -> Self {
        match x {
            0 => HandshakeEphemeral::X25519,
            1 => HandshakeEphemeral::Nonce,
            2 => HandshakeEphemeral::None,
            _ => HandshakeEphemeral::Unknown(x),
        }
    }

    fn render(value: u8) -> &'static str {
        match Self::parse(value) {
            HandshakeEphemeral::X25519 => "X25519",
            HandshakeEphemeral::Nonce => "Nonce",
            HandshakeEphemeral::None => "None",
            HandshakeEphemeral::Unknown(_) => "unknown",
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum HandshakeHash {
    Sha256,
    Unknown(u8),
}

impl Enumeration for HandshakeHash {
    fn parse(x: u8) -> Self {
        match x {
            0 => HandshakeHash::Sha256,
            _ => HandshakeHash::Unknown(x),
        }
    }

    fn render(value: u8) -> &'static str {
        match Self::parse(value) {
            Self::Sha256 => "SHA-256",
            Self::Unknown(_) => "unknown",
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum HandshakeKDF {
    HkdfSha256,
    Unknown(u8),
}

impl Enumeration for HandshakeKDF {
    fn parse(x: u8) -> Self {
        match x {
            0 => HandshakeKDF::HkdfSha256,
            _ => HandshakeKDF::Unknown(x),
        }
    }

    fn render(value: u8) -> &'static str {
        match Self::parse(value) {
            Self::HkdfSha256 => "HKDF-SHA-256",
            Self::Unknown(_) => "unknown",
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum SessionNonceMode {
    StrictIncrement,
    GreaterThanLastRx,
    Unknown(u8),
}

impl Enumeration for SessionNonceMode {
    fn parse(x: u8) -> Self {
        match x {
            0 => SessionNonceMode::StrictIncrement,
            1 => SessionNonceMode::GreaterThanLastRx,
            _ => SessionNonceMode::Unknown(x),
        }
    }
    fn render(value: u8) -> &'static str {
        match Self::parse(value) {
            SessionNonceMode::StrictIncrement => "strict increment",
            SessionNonceMode::GreaterThanLastRx => "greater than last rx",
            SessionNonceMode::Unknown(_) => "unknown",
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum SessionCryptoMode {
    HmacSha256Trunc16,
    Aes256Gcm,
    Unknown(u8),
}

impl Enumeration for SessionCryptoMode {
    fn parse(x: u8) -> Self {
        match x {
            0 => SessionCryptoMode::HmacSha256Trunc16,
            1 => SessionCryptoMode::Aes256Gcm,
            _ => SessionCryptoMode::Unknown(x),
        }
    }

    fn render(value: u8) -> &'static str {
        match Self::parse(value) {
            SessionCryptoMode::HmacSha256Trunc16 => "HMAC-SHA-256-16",
            SessionCryptoMode::Aes256Gcm => "AES-256-GCM",
            SessionCryptoMode::Unknown(_) => "unknown",
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum HandshakeMode {
    SharedSecret,
    PublicKeys,
    IndustrialCertificates,
    QuantumKeyDistribution,
    Unknown(u8),
}

impl Enumeration for HandshakeMode {
    fn parse(x: u8) -> Self {
        match x {
            0 => HandshakeMode::SharedSecret,
            1 => HandshakeMode::PublicKeys,
            2 => HandshakeMode::IndustrialCertificates,
            3 => HandshakeMode::QuantumKeyDistribution,
            _ => HandshakeMode::Unknown(x),
        }
    }

    fn render(value: u8) -> &'static str {
        match HandshakeMode::parse(value) {
            HandshakeMode::SharedSecret => "shared secret",
            HandshakeMode::PublicKeys => "pre-shared public keys",
            HandshakeMode::IndustrialCertificates => "industrial certificates",
            HandshakeMode::QuantumKeyDistribution => "quantum Key distribution",
            HandshakeMode::Unknown(_) => "unknown",
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
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

impl Enumeration for HandshakeError {
    fn parse(x: u8) -> Self {
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

    fn render(value: u8) -> &'static str {
        match Self::parse(value) {
            HandshakeError::BadMessageFormat => "bad message format",
            HandshakeError::UnsupportedVersion => "unsupported version",
            HandshakeError::UnsupportedHandshakeEphemeral => "unsupported handshake ephemeral",
            HandshakeError::UnsupportedHandshakeHash => "unsupported handshake hash",
            HandshakeError::UnsupportedHandshakeKdf => "unsupported handshake KDF",
            HandshakeError::UnsupportedSessionMode => "unsupported session mode",
            HandshakeError::UnsupportedNonceMode => "unsupported nonce nonce",
            HandshakeError::UnsupportedHandshakeMode => "unsupported handshake mode",
            HandshakeError::BadCertificateFormat => "bad certificate format",
            HandshakeError::BadCertificateChain => "bad certificate chain",
            HandshakeError::UnsupportedCertificateFeature => "unsupported certificate feature",
            HandshakeError::AuthenticationError => "authentication error",
            HandshakeError::NoPriorHandshakeBegin => "no prior handshake begin",
            HandshakeError::KeyNotFound => "key not found",
            HandshakeError::Unknown(_) => "unknown",
        }
    }
}
