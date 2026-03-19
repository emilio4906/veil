//! Veil encrypted envelope format.
//!
//! Defines the wire format for encrypted payloads sent between
//! client and server. Uses MessagePack for compact serialization.

use serde::{Deserialize, Serialize};

use crate::error::{VeilError, VeilResult};

/// Protocol version.
pub const PROTOCOL_VERSION: u8 = 1;

/// An encrypted Veil envelope containing an opaque payload.
///
/// This is the wire format — everything except the metadata is
/// opaque to any intermediary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VeilEnvelope {
    /// Protocol version.
    pub version: u8,

    /// AES-GCM nonce (12 bytes, base64-encoded in JSON).
    #[serde(with = "base64_bytes")]
    pub nonce: Vec<u8>,

    /// Encrypted ciphertext with GCM tag appended.
    #[serde(with = "base64_bytes")]
    pub ciphertext: Vec<u8>,

    /// Additional Authenticated Data (authenticated, not encrypted).
    /// Contains protocol metadata that must not be tampered with.
    #[serde(with = "base64_bytes")]
    pub aad: Vec<u8>,
}

impl VeilEnvelope {
    /// Create a new envelope from encryption output.
    pub fn new(nonce: Vec<u8>, ciphertext: Vec<u8>, aad: Vec<u8>) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            nonce,
            ciphertext,
            aad,
        }
    }

    /// Serialize to MessagePack binary format (compact).
    pub fn to_msgpack(&self) -> VeilResult<Vec<u8>> {
        rmp_serde::to_vec(self).map_err(|e| VeilError::Envelope(format!("msgpack serialize: {e}")))
    }

    /// Deserialize from MessagePack binary format.
    pub fn from_msgpack(data: &[u8]) -> VeilResult<Self> {
        rmp_serde::from_slice(data)
            .map_err(|e| VeilError::Envelope(format!("msgpack deserialize: {e}")))
    }

    /// Serialize to JSON (for HTTP body transport).
    pub fn to_json(&self) -> VeilResult<String> {
        serde_json::to_string(self).map_err(|e| VeilError::Envelope(format!("json serialize: {e}")))
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> VeilResult<Self> {
        serde_json::from_str(json)
            .map_err(|e| VeilError::Envelope(format!("json deserialize: {e}")))
    }

    /// Get the total size of the encrypted payload.
    pub fn payload_size(&self) -> usize {
        self.ciphertext.len()
    }
}

/// Metadata sent alongside the encrypted envelope in HTTP headers.
/// Visible to middleware for routing, billing, and rate limiting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VeilMetadata {
    /// Protocol version.
    pub version: u8,

    /// Server key ID used for this session.
    pub key_id: String,

    /// Client's ephemeral public key (base64).
    pub ephemeral_key: String,

    /// Target model name (for routing).
    pub model: String,

    /// Estimated token count (for billing).
    pub token_estimate: Option<u32>,
}

impl VeilMetadata {
    /// Convert to HTTP header pairs.
    pub fn to_headers(&self) -> Vec<(String, String)> {
        let mut headers = vec![
            ("X-Veil-Version".to_string(), self.version.to_string()),
            ("X-Veil-Key-Id".to_string(), self.key_id.clone()),
            (
                "X-Veil-Ephemeral-Key".to_string(),
                self.ephemeral_key.clone(),
            ),
            ("X-Veil-Model".to_string(), self.model.clone()),
        ];

        if let Some(tokens) = self.token_estimate {
            headers.push(("X-Veil-Token-Estimate".to_string(), tokens.to_string()));
        }

        headers
    }
}

/// Custom serde module for base64-encoded byte vectors.
mod base64_bytes {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&BASE64.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        BASE64.decode(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_msgpack_roundtrip() {
        let env = VeilEnvelope::new(
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            vec![0xDE, 0xAD, 0xBE, 0xEF],
            vec![0x01, 0x02],
        );

        let bytes = env.to_msgpack().unwrap();
        let restored = VeilEnvelope::from_msgpack(&bytes).unwrap();

        assert_eq!(env.version, restored.version);
        assert_eq!(env.nonce, restored.nonce);
        assert_eq!(env.ciphertext, restored.ciphertext);
        assert_eq!(env.aad, restored.aad);
    }

    #[test]
    fn test_envelope_json_roundtrip() {
        let env = VeilEnvelope::new(
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            vec![0xCA, 0xFE, 0xBA, 0xBE],
            b"veil-v1-test".to_vec(),
        );

        let json = env.to_json().unwrap();
        let restored = VeilEnvelope::from_json(&json).unwrap();

        assert_eq!(env.version, restored.version);
        assert_eq!(env.nonce, restored.nonce);
        assert_eq!(env.ciphertext, restored.ciphertext);
    }

    #[test]
    fn test_metadata_to_headers() {
        let meta = VeilMetadata {
            version: 1,
            key_id: "key-123".to_string(),
            ephemeral_key: "base64pubkey".to_string(),
            model: "gpt-4".to_string(),
            token_estimate: Some(500),
        };

        let headers = meta.to_headers();
        assert_eq!(headers.len(), 5);
        assert!(headers
            .iter()
            .any(|(k, v)| k == "X-Veil-Model" && v == "gpt-4"));
    }

    #[test]
    fn test_payload_size() {
        let env = VeilEnvelope::new(vec![0; 12], vec![0; 1024], vec![]);
        assert_eq!(env.payload_size(), 1024);
    }
}
