use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("invalid vault file format: {0}")]
    InvalidFormat(String),

    #[error("unsupported vault version: {0}")]
    UnsupportedVersion(u32),

    #[error("wrong password, keyfile, or corrupted vault")]
    AuthenticationFailed,

    #[error("cryptographic error: {0}")]
    Crypto(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("KDBX import error: {0}")]
    KdbxImport(String),

    #[error("validation error: {0}")]
    Validation(String),
}

pub type Result<T> = std::result::Result<T, VaultError>;
