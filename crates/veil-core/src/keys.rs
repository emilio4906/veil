//! X25519 key generation and Diffie-Hellman key exchange.
//!
//! Provides ephemeral and static key pairs for the Veil protocol.
//! All secret keys implement `Zeroize` for secure memory cleanup.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret, StaticSecret};
use zeroize::ZeroizeOnDrop;

use crate::error::{VeilError, VeilResult};

/// A static (long-lived) X25519 key pair for server identity.
/// The secret key is zeroized on drop.
#[derive(ZeroizeOnDrop)]
pub struct StaticKeyPair {
    secret: StaticSecret,
    #[zeroize(skip)]
    public: PublicKey,
}

impl StaticKeyPair {
    /// Generate a new random static key pair.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Reconstruct from raw secret key bytes (32 bytes).
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        let secret = StaticSecret::from(*bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Reconstruct from base64-encoded secret key.
    pub fn from_secret_base64(b64: &str) -> VeilResult<Self> {
        let bytes = BASE64
            .decode(b64)
            .map_err(|e| VeilError::KeyGeneration(format!("invalid base64: {e}")))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| VeilError::KeyGeneration("secret key must be 32 bytes".into()))?;
        Ok(Self::from_secret_bytes(&arr))
    }

    /// Perform ECDH key exchange with a peer's public key.
    pub fn diffie_hellman(&self, peer_public: &PublicKey) -> SharedSecret {
        self.secret.diffie_hellman(peer_public)
    }

    /// Get the public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Export secret key bytes (for secure storage).
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// Export secret key as base64.
    pub fn secret_base64(&self) -> String {
        BASE64.encode(self.secret.to_bytes())
    }

    /// Export public key as base64.
    pub fn public_base64(&self) -> String {
        BASE64.encode(self.public.as_bytes())
    }
}

/// An ephemeral X25519 key pair (single use, forward secrecy).
/// Cannot be cloned or serialized — use once then discard.
pub struct EphemeralKeyPair {
    secret: Option<EphemeralSecret>,
    public: PublicKey,
}

impl EphemeralKeyPair {
    /// Generate a new random ephemeral key pair.
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self {
            secret: Some(secret),
            public,
        }
    }

    /// Consume the ephemeral secret to perform ECDH.
    /// After this call, the secret is gone — forward secrecy.
    pub fn diffie_hellman(mut self, peer_public: &PublicKey) -> VeilResult<SharedSecret> {
        let secret = self
            .secret
            .take()
            .ok_or_else(|| VeilError::KeyExchange("ephemeral key already consumed".into()))?;
        Ok(secret.diffie_hellman(peer_public))
    }

    /// Get the public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Export public key as base64.
    pub fn public_base64(&self) -> String {
        BASE64.encode(self.public.as_bytes())
    }
}

/// Exported public key info for protocol messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyInfo {
    /// Base64-encoded X25519 public key.
    pub public_key: String,
    /// Key identifier for lookup.
    pub key_id: String,
    /// Expiry timestamp (ISO 8601).
    pub expires: Option<String>,
}

/// Parse a base64-encoded public key into an X25519 PublicKey.
pub fn parse_public_key(b64: &str) -> VeilResult<PublicKey> {
    let bytes = BASE64
        .decode(b64)
        .map_err(|e| VeilError::KeyGeneration(format!("invalid base64: {e}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| VeilError::KeyGeneration("public key must be 32 bytes".into()))?;
    Ok(PublicKey::from(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_keypair_generation() {
        let kp = StaticKeyPair::generate();
        assert_eq!(kp.public_key().as_bytes().len(), 32);
    }

    #[test]
    fn test_static_keypair_roundtrip() {
        let kp1 = StaticKeyPair::generate();
        let b64 = kp1.secret_base64();
        let kp2 = StaticKeyPair::from_secret_base64(&b64).unwrap();
        assert_eq!(kp1.public_key().as_bytes(), kp2.public_key().as_bytes());
    }

    #[test]
    fn test_ephemeral_keypair_generation() {
        let kp = EphemeralKeyPair::generate();
        assert_eq!(kp.public_key().as_bytes().len(), 32);
    }

    #[test]
    fn test_ecdh_shared_secret() {
        // Simulate client (ephemeral) and server (static) key exchange
        let server = StaticKeyPair::generate();
        let client = EphemeralKeyPair::generate();

        let client_pub = *client.public_key();

        // Client computes shared secret
        let client_shared = client.diffie_hellman(server.public_key()).unwrap();

        // Server computes shared secret
        let server_shared = server.diffie_hellman(&client_pub);

        // Both should derive the same shared secret
        assert_eq!(client_shared.as_bytes(), server_shared.as_bytes());
    }

    #[test]
    fn test_parse_public_key() {
        let kp = StaticKeyPair::generate();
        let b64 = kp.public_base64();
        let parsed = parse_public_key(&b64).unwrap();
        assert_eq!(parsed.as_bytes(), kp.public_key().as_bytes());
    }
}
