//! HKDF-SHA256 key derivation for the Veil protocol.
//!
//! Derives separate encryption keys for each direction (client→server,
//! server→client) from the ECDH shared secret.

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::SharedSecret;
use zeroize::ZeroizeOnDrop;

use crate::error::{VeilError, VeilResult};

/// The length of derived AES-256 keys.
const KEY_LEN: usize = 32;

/// Salt used for HKDF. In production, include protocol version.
const PROTOCOL_SALT: &[u8] = b"veil-e2e-llm-v1";

/// Info strings for deriving directional keys.
const CLIENT_TO_SERVER_INFO: &[u8] = b"veil-c2s";
const SERVER_TO_CLIENT_INFO: &[u8] = b"veil-s2c";

/// A pair of derived session keys — one for each direction.
/// Zeroized on drop for security.
#[derive(ZeroizeOnDrop)]
pub struct SessionKeys {
    /// Key for encrypting client→server traffic.
    #[zeroize(skip)]
    pub client_to_server: [u8; KEY_LEN],
    /// Key for encrypting server→client traffic.
    #[zeroize(skip)]
    pub server_to_client: [u8; KEY_LEN],
}

impl SessionKeys {
    /// Derive session keys from an ECDH shared secret.
    pub fn derive(shared_secret: &SharedSecret) -> VeilResult<Self> {
        let hk = Hkdf::<Sha256>::new(Some(PROTOCOL_SALT), shared_secret.as_bytes());

        let mut c2s = [0u8; KEY_LEN];
        hk.expand(CLIENT_TO_SERVER_INFO, &mut c2s)
            .map_err(|e| VeilError::KeyDerivation(format!("HKDF expand c2s: {e}")))?;

        let mut s2c = [0u8; KEY_LEN];
        hk.expand(SERVER_TO_CLIENT_INFO, &mut s2c)
            .map_err(|e| VeilError::KeyDerivation(format!("HKDF expand s2c: {e}")))?;

        Ok(Self {
            client_to_server: c2s,
            server_to_client: s2c,
        })
    }

    /// Derive from raw shared secret bytes (32 bytes).
    pub fn derive_from_bytes(shared_bytes: &[u8; 32]) -> VeilResult<Self> {
        let hk = Hkdf::<Sha256>::new(Some(PROTOCOL_SALT), shared_bytes);

        let mut c2s = [0u8; KEY_LEN];
        hk.expand(CLIENT_TO_SERVER_INFO, &mut c2s)
            .map_err(|e| VeilError::KeyDerivation(format!("HKDF expand c2s: {e}")))?;

        let mut s2c = [0u8; KEY_LEN];
        hk.expand(SERVER_TO_CLIENT_INFO, &mut s2c)
            .map_err(|e| VeilError::KeyDerivation(format!("HKDF expand s2c: {e}")))?;

        Ok(Self {
            client_to_server: c2s,
            server_to_client: s2c,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{EphemeralKeyPair, StaticKeyPair};

    #[test]
    fn test_derive_session_keys() {
        let server = StaticKeyPair::generate();
        let client = EphemeralKeyPair::generate();
        let client_pub = *client.public_key();

        let client_shared = client.diffie_hellman(server.public_key()).unwrap();
        let server_shared = server.diffie_hellman(&client_pub);

        let client_keys = SessionKeys::derive(&client_shared).unwrap();
        let server_keys = SessionKeys::derive(&server_shared).unwrap();

        // Both sides derive the same keys
        assert_eq!(client_keys.client_to_server, server_keys.client_to_server);
        assert_eq!(client_keys.server_to_client, server_keys.server_to_client);

        // But the two directional keys are different
        assert_ne!(client_keys.client_to_server, client_keys.server_to_client);
    }

    #[test]
    fn test_different_secrets_different_keys() {
        let server1 = StaticKeyPair::generate();
        let server2 = StaticKeyPair::generate();
        let client = EphemeralKeyPair::generate();

        let shared1 = server1.diffie_hellman(client.public_key());
        let shared2 = server2.diffie_hellman(client.public_key());

        let keys1 = SessionKeys::derive(&shared1).unwrap();
        let keys2 = SessionKeys::derive(&shared2).unwrap();

        assert_ne!(keys1.client_to_server, keys2.client_to_server);
    }
}
