//! Veil session management.
//!
//! A `VeilSession` combines key exchange, key derivation, and
//! symmetric encryption into a single high-level API.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::Utc;
use uuid::Uuid;
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
    /// Cached request_id for AAD binding (set on encrypt_request).
    request_id: String,
    /// Cached timestamp for AAD binding (set on encrypt_request).
    timestamp: String,
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
            request_id: String::new(),
            timestamp: String::new(),
        })
    }

    /// Encrypt a prompt (client→server).
    ///
    /// Returns an envelope and metadata suitable for HTTP transport.
    pub fn encrypt_request(
        &mut self,
        plaintext: &[u8],
        model: &str,
        token_estimate: Option<u32>,
    ) -> VeilResult<(VeilEnvelope, VeilMetadata)> {
        // Generate request_id and timestamp FIRST — they are bound into the AAD
        // so the server can verify the ciphertext is tied to this exact request.
        let request_id = Uuid::new_v4().to_string();
        let timestamp = Utc::now().to_rfc3339();
        self.request_id = request_id.clone();
        self.timestamp = timestamp.clone();

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
            timestamp,
            request_id,
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
        let ephemeral_public_b64 = BASE64.encode(self.ephemeral_public.as_bytes());
        // AAD binds ciphertext to: protocol version, direction, key identity,
        // ephemeral key, request ID, and timestamp — preventing cross-request
        // ciphertext substitution even within the replay window.
        format!(
            "veil-v{}-{}-{}-{}-{}-{}",
            PROTOCOL_VERSION, dir_tag, self.server_key_id,
            ephemeral_public_b64, self.request_id, self.timestamp
        )
        .into_bytes()
    }
}

/// A server-side Veil session.
///
/// Created from the server's static key pair and the client's
/// ephemeral public key received in the request.
pub struct ServerSession {
    session_keys: SessionKeys,
    key_id: String,
    ephemeral_public_b64: String,
    /// Request ID from client metadata — bound into AAD for replay binding.
    request_id: String,
    /// Timestamp from client metadata — bound into AAD for temporal binding.
    timestamp: String,
}

impl ServerSession {
    /// Create a server session from the client's ephemeral public key.
    ///
    /// # Arguments
    /// * `server_keypair` - Server's static X25519 key pair
    /// * `client_ephemeral_b64` - Client's ephemeral public key (base64)
    /// * `key_id` - Server's key identifier for AAD binding
    pub fn new(
        server_keypair: &StaticKeyPair,
        client_ephemeral_b64: &str,
        key_id: &str,
        request_id: &str,
        timestamp: &str,
    ) -> VeilResult<Self> {
        let client_public = parse_public_key(client_ephemeral_b64)?;
        let shared_secret = server_keypair.diffie_hellman(&client_public);
        let session_keys = SessionKeys::derive(&shared_secret)?;

        Ok(Self {
            session_keys,
            key_id: key_id.to_string(),
            ephemeral_public_b64: client_ephemeral_b64.to_string(),
            request_id: request_id.to_string(),
            timestamp: timestamp.to_string(),
        })
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
        format!(
            "veil-v{}-{}-{}-{}-{}-{}",
            PROTOCOL_VERSION, dir_tag, self.key_id,
            self.ephemeral_public_b64, self.request_id, self.timestamp
        )
        .into_bytes()
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
        let mut client_session = ClientSession::new(&server_pub_b64, "key-001").unwrap();

        // Client encrypts a prompt
        let prompt = b"{\"model\": \"gpt-4\", \"messages\": [{\"role\": \"user\", \"content\": \"Hello!\"}]}";
        let (envelope, metadata) = client_session
            .encrypt_request(prompt, "gpt-4", Some(10))
            .unwrap();

        // Verify metadata
        assert_eq!(metadata.model, "gpt-4");
        assert_eq!(metadata.token_estimate, Some(10));
        assert_eq!(metadata.key_id, "key-001");
        assert!(!metadata.timestamp.is_empty());
        assert!(!metadata.request_id.is_empty());

        // Server creates session from client's ephemeral key
        let server_session =
            ServerSession::new(&server_kp, &metadata.ephemeral_key, "key-001", &metadata.request_id, &metadata.timestamp).unwrap();

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

        let mut session1 = ClientSession::new(&server_pub_b64, "key-001").unwrap();
        let session2 = ClientSession::new(&server_pub_b64, "key-001").unwrap();

        let (envelope, _metadata) = session1.encrypt_request(b"secret", "gpt-4", None).unwrap();

        // session2 has different ephemeral key → different shared secret
        let server_session2 =
            ServerSession::new(&server_kp, &session2.ephemeral_public_base64(), "key-001", "test-req-id", "2026-01-01T00:00:00Z").unwrap();

        // Should fail to decrypt with wrong session
        assert!(server_session2.decrypt_request(&envelope).is_err());
    }

    #[test]
    fn test_large_prompt_roundtrip() {
        let server_kp = StaticKeyPair::generate();
        let mut client_session = ClientSession::new(&server_kp.public_base64(), "key-001").unwrap();

        // Simulate a large prompt (~100KB)
        let large_prompt = vec![b'A'; 100_000];
        let (envelope, metadata) = client_session
            .encrypt_request(&large_prompt, "claude-3", Some(25000))
            .unwrap();

        let server_session =
            ServerSession::new(&server_kp, &metadata.ephemeral_key, "key-001", &metadata.request_id, &metadata.timestamp).unwrap();
        let decrypted = server_session.decrypt_request(&envelope).unwrap();

        assert_eq!(decrypted, large_prompt);
    }

    #[test]
    fn test_metadata_headers() {
        let server_kp = StaticKeyPair::generate();
        let mut client_session = ClientSession::new(&server_kp.public_base64(), "prod-key-v2").unwrap();

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
        assert!(headers.iter().any(|(k, _)| k == "X-Veil-Timestamp"));
        assert!(headers.iter().any(|(k, _)| k == "X-Veil-Request-Id"));
    }

    #[test]
    fn test_mismatched_key_id_causes_decryption_failure() {
        let server_kp = StaticKeyPair::generate();
        let server_pub_b64 = server_kp.public_base64();

        // Client uses key_id "key-001"
        let mut client_session = ClientSession::new(&server_pub_b64, "key-001").unwrap();

        let (envelope, metadata) = client_session
            .encrypt_request(b"secret data", "gpt-4", None)
            .unwrap();

        // Server uses a DIFFERENT key_id → AAD mismatch
        let server_session =
            ServerSession::new(&server_kp, &metadata.ephemeral_key, "wrong-key-id", &metadata.request_id, &metadata.timestamp).unwrap();

        let result = server_session.decrypt_request(&envelope);
        assert!(
            result.is_err(),
            "Mismatched key_id in AAD should cause decryption failure"
        );
    }

    #[test]
    fn test_timestamp_is_valid_iso8601() {
        let server_kp = StaticKeyPair::generate();
        let mut client_session = ClientSession::new(&server_kp.public_base64(), "key-001").unwrap();

        let (_, metadata) = client_session
            .encrypt_request(b"test", "model", None)
            .unwrap();

        // Verify the timestamp is valid ISO 8601
        let parsed = chrono::DateTime::parse_from_rfc3339(&metadata.timestamp);
        assert!(parsed.is_ok(), "Timestamp should be valid RFC 3339/ISO 8601");
    }

    #[test]
    fn test_request_id_is_valid_uuid() {
        let server_kp = StaticKeyPair::generate();
        let mut client_session = ClientSession::new(&server_kp.public_base64(), "key-001").unwrap();

        let (_, metadata) = client_session
            .encrypt_request(b"test", "model", None)
            .unwrap();

        // Verify the request_id is a valid UUID
        let parsed = uuid::Uuid::parse_str(&metadata.request_id);
        assert!(parsed.is_ok(), "request_id should be a valid UUID v4");
    }
}
