//! Error types for the Veil cryptographic library.

use thiserror::Error;

/// Errors that can occur during Veil cryptographic operations.
#[derive(Debug, Error)]
pub enum VeilError {
    /// Key generation failed.
    #[error("key generation failed: {0}")]
    KeyGeneration(String),

    /// Key exchange (ECDH) failed.
    #[error("key exchange failed: {0}")]
    KeyExchange(String),

    /// Key derivation (HKDF) failed.
    #[error("key derivation failed: {0}")]
    KeyDerivation(String),

    /// Encryption failed.
    #[error("encryption failed: {0}")]
    Encryption(String),

    /// Decryption failed — ciphertext may have been tampered with.
    #[error("decryption failed (possible tampering): {0}")]
    Decryption(String),

    /// Envelope serialization or deserialization failed.
    #[error("envelope error: {0}")]
    Envelope(String),

    /// Invalid input provided.
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// Session error.
    #[error("session error: {0}")]
    Session(String),
}

pub type VeilResult<T> = Result<T, VeilError>;
