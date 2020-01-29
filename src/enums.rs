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
