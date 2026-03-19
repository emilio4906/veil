//! # Veil Core
//!
//! End-to-end encryption library for LLM inference traffic.
//!
//! Veil provides application-layer encryption that keeps LLM prompts
//! and responses confidential from all intermediaries (API gateways,
//! proxies, load balancers, billing systems). Only the client and
//! the LLM inference engine can see plaintext.
//!
//! ## Protocol Overview
//!
//! 1. Server publishes its X25519 public key
//! 2. Client generates an ephemeral X25519 key pair
//! 3. Both sides compute ECDH shared secret
//! 4. HKDF derives directional AES-256-GCM session keys
//! 5. Client encrypts prompt → sends encrypted envelope + metadata
//! 6. Server decrypts, runs inference, encrypts response
//! 7. Client decrypts response
//!
//! Middleware sees only metadata (model, token estimate, key ID)
//! — never the prompt or response content.
//!
//! ## Quick Start
//!
//! ```rust
//! use veil_core::keys::StaticKeyPair;
//! use veil_core::session::{ClientSession, ServerSession};
//!
//! // Server generates identity key
//! let server_kp = StaticKeyPair::generate();
//!
//! // Client creates session
//! let client = ClientSession::new(
//!     &server_kp.public_base64(),
//!     "key-001",
//! ).unwrap();
//!
//! // Encrypt a prompt
//! let (envelope, metadata) = client.encrypt_request(
//!     b"{\"prompt\": \"Hello!\"}",
//!     "gpt-4",
//!     Some(10),
//! ).unwrap();
//!
//! // Server decrypts
//! let server = ServerSession::new(
//!     &server_kp,
//!     &metadata.ephemeral_key,
//! ).unwrap();
//! let plaintext = server.decrypt_request(&envelope).unwrap();
//! ```

pub mod cipher;
pub mod envelope;
pub mod error;
pub mod kdf;
pub mod keys;
pub mod session;

// Re-export the most commonly used types at crate root.
pub use envelope::{VeilEnvelope, VeilMetadata};
pub use error::{VeilError, VeilResult};
pub use keys::{EphemeralKeyPair, PublicKeyInfo, StaticKeyPair};
pub use session::{ClientSession, Direction, ServerSession};
