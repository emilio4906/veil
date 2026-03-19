//! Veil session management.
//!
//! A `VeilSession` combines key exchange, key derivation, and
//! symmetric encryption into a single high-level API.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use x25519_dalek::PublicKey;

use crate::{
    cipher,
    envelope::{VeilEnvelope, VeilMetadata, PROTOCOL_VERSION},
    error::{VeilError, VeilResult},
    kdf::SessionKeys,
    keys::{parse_public_key, EphemeralKeyPair, StaticKeyPair},
};

/// Direction of encryption — determines which session key to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Client encrypting a message to the server.
    ClientToServer,
    /// Server encrypting a response to the client.
    ServerToClient,
}

/// A client-side Veil session.
///
/// Created by performing an ECDH key exchange with the server's
/// published public key. Provides encrypt/decrypt for the
/// client→server and server→client directions.
pub struct ClientSession {
    session_keys: SessionKeys,
    ephemeral_public: PublicKey,
    server_key_id: String,
}

impl ClientSession {
    /// Create a new client session by performing ECDH with the server.
    ///
    /// # Arguments
    /// * `server_public_b64` - Server's X25519 public key (base64)
    /// * `server_key_id` - Server's key identifier
    pub fn new(server_public_b64: &str, server_key_id: &str) -> VeilResult<Self> {
        let server_public = parse_public_key(server_public_b64)?;
        let ephemeral = EphemeralKeyPair::generate();
        let ephemeral_public = *ephemeral.public_key();

        let shared_secret = ephemeral.diffie_hellman(&server_public)?;
        let session_keys = SessionKeys::derive(&shared_secret)?;

        Ok(Self {
            session_keys,
            ephemeral_public,
            server_key_id: server_key_id.to_string(),
        })
    }

    /// Encrypt a prompt (client→server).
    ///
    /// Returns an envelope and metadata suitable for HTTP transport.
    pub fn encrypt_request(
        &self,
        plaintext: &[u8],
        model: &str,
        token_estimate: Option<u32>,
    ) -> VeilResult<(VeilEnvelope, VeilMetadata)> {
        let aad = self.build_aad(Direction::ClientToServer);
        let (nonce, ciphertext) =
            cipher::encrypt(&self.session_keys.client_to_server, plaintext, &aad)?;

        let envelope = VeilEnvelope::new(nonce, ciphertext, aad);
        let metadata = VeilMetadata {
            version: PROTOCOL_VERSION,
            key_id: self.server_key_id.clone(),
            ephemeral_key: BASE64.encode(self.ephemeral_public.as_bytes()),
            model: model.to_string(),
            token_estimate,
        };

        Ok((envelope, metadata))
    }

    /// Decrypt a response (server→client).
    pub fn decrypt_response(&self, envelope: &VeilEnvelope) -> VeilResult<Vec<u8>> {
        let expected_aad = self.build_aad(Direction::ServerToClient);

        // Verify AAD matches
        if envelope.aad != expected_aad {
            return Err(VeilError::Decryption(
                "AAD mismatch — possible protocol violation".into(),
            ));
        }

        cipher::decrypt(
            &self.session_keys.server_to_client,
            &envelope.nonce,
            &envelope.ciphertext,
            &envelope.aad,
        )
    }

    /// Get the ephemeral public key (base64) for the handshake.
    pub fn ephemeral_public_base64(&self) -> String {
        BASE64.encode(self.ephemeral_public.as_bytes())
    }

    fn build_aad(&self, direction: Direction) -> Vec<u8> {
        let dir_tag = match direction {
            Direction::ClientToServer => "c2s",
            Direction::ServerToClient => "s2c",
        };
        format!("veil-v{}-{}", PROTOCOL_VERSION, dir_tag).into_bytes()
    }
}

/// A server-side Veil session.
///
/// Created from the server's static key pair and the client's
/// ephemeral public key received in the request.
pub struct ServerSession {
    session_keys: SessionKeys,
}

impl ServerSession {
    /// Create a server session from the client's ephemeral public key.
    ///
    /// # Arguments
    /// * `server_keypair` - Server's static X25519 key pair
    /// * `client_ephemeral_b64` - Client's ephemeral public key (base64)
    pub fn new(server_keypair: &StaticKeyPair, client_ephemeral_b64: &str) -> VeilResult<Self> {
        let client_public = parse_public_key(client_ephemeral_b64)?;
        let shared_secret = server_keypair.diffie_hellman(&client_public);
        let session_keys = SessionKeys::derive(&shared_secret)?;

        Ok(Self { session_keys })
    }

    /// Decrypt a client request (client→server).
    pub fn decrypt_request(&self, envelope: &VeilEnvelope) -> VeilResult<Vec<u8>> {
        let expected_aad = self.build_aad(Direction::ClientToServer);

        if envelope.aad != expected_aad {
            return Err(VeilError::Decryption(
                "AAD mismatch — possible protocol violation".into(),
            ));
        }

        cipher::decrypt(
            &self.session_keys.client_to_server,
            &envelope.nonce,
            &envelope.ciphertext,
            &envelope.aad,
        )
    }

    /// Encrypt a response (server→client).
    pub fn encrypt_response(&self, plaintext: &[u8]) -> VeilResult<VeilEnvelope> {
        let aad = self.build_aad(Direction::ServerToClient);
        let (nonce, ciphertext) =
            cipher::encrypt(&self.session_keys.server_to_client, plaintext, &aad)?;

        Ok(VeilEnvelope::new(nonce, ciphertext, aad))
    }

    fn build_aad(&self, direction: Direction) -> Vec<u8> {
        let dir_tag = match direction {
            Direction::ClientToServer => "c2s",
            Direction::ServerToClient => "s2c",
        };
        format!("veil-v{}-{}", PROTOCOL_VERSION, dir_tag).into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::StaticKeyPair;

    #[test]
    fn test_full_client_server_roundtrip() {
        // Server generates its identity key pair
        let server_kp = StaticKeyPair::generate();
        let server_pub_b64 = server_kp.public_base64();

        // Client creates session
        let client_session = ClientSession::new(&server_pub_b64, "key-001").unwrap();

        // Client encrypts a prompt
        let prompt = b"{\"model\": \"gpt-4\", \"messages\": [{\"role\": \"user\", \"content\": \"Hello!\"}]}";
        let (envelope, metadata) = client_session
            .encrypt_request(prompt, "gpt-4", Some(10))
            .unwrap();

        // Verify metadata
        assert_eq!(metadata.model, "gpt-4");
        assert_eq!(metadata.token_estimate, Some(10));
        assert_eq!(metadata.key_id, "key-001");

        // Server creates session from client's ephemeral key
        let server_session = ServerSession::new(&server_kp, &metadata.ephemeral_key).unwrap();

        // Server decrypts the request
        let decrypted_prompt = server_session.decrypt_request(&envelope).unwrap();
        assert_eq!(decrypted_prompt, prompt);

        // Server encrypts a response
        let response = b"{\"choices\": [{\"message\": {\"content\": \"Hi there!\"}}]}";
        let response_envelope = server_session.encrypt_response(response).unwrap();

        // Client decrypts the response
        let decrypted_response = client_session.decrypt_response(&response_envelope).unwrap();
        assert_eq!(decrypted_response, response);
    }

    #[test]
    fn test_different_sessions_cannot_decrypt() {
        let server_kp = StaticKeyPair::generate();
        let server_pub_b64 = server_kp.public_base64();

        let session1 = ClientSession::new(&server_pub_b64, "key-001").unwrap();
        let session2 = ClientSession::new(&server_pub_b64, "key-001").unwrap();

        let (envelope, _metadata) = session1.encrypt_request(b"secret", "gpt-4", None).unwrap();

        // session2 has different ephemeral key → different shared secret
        let server_session2 =
            ServerSession::new(&server_kp, &session2.ephemeral_public_base64()).unwrap();

        // Should fail to decrypt with wrong session
        assert!(server_session2.decrypt_request(&envelope).is_err());
    }

    #[test]
    fn test_large_prompt_roundtrip() {
        let server_kp = StaticKeyPair::generate();
        let client_session = ClientSession::new(&server_kp.public_base64(), "key-001").unwrap();

        // Simulate a large prompt (~100KB)
        let large_prompt = vec![b'A'; 100_000];
        let (envelope, metadata) = client_session
            .encrypt_request(&large_prompt, "claude-3", Some(25000))
            .unwrap();

        let server_session = ServerSession::new(&server_kp, &metadata.ephemeral_key).unwrap();
        let decrypted = server_session.decrypt_request(&envelope).unwrap();

        assert_eq!(decrypted, large_prompt);
    }

    #[test]
    fn test_metadata_headers() {
        let server_kp = StaticKeyPair::generate();
        let client_session = ClientSession::new(&server_kp.public_base64(), "prod-key-v2").unwrap();

        let (_, metadata) = client_session
            .encrypt_request(b"test", "claude-3-opus", Some(42))
            .unwrap();

        let headers = metadata.to_headers();

        assert!(headers.iter().any(|(k, _)| k == "X-Veil-Version"));
        assert!(headers
            .iter()
            .any(|(k, v)| k == "X-Veil-Model" && v == "claude-3-opus"));
        assert!(headers
            .iter()
            .any(|(k, v)| k == "X-Veil-Token-Estimate" && v == "42"));
    }
}
