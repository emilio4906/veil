//! AES-256-GCM authenticated encryption and decryption.
//!
//! Provides AEAD (Authenticated Encryption with Associated Data)
//! ensuring both confidentiality and integrity of encrypted payloads.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    AeadCore, Aes256Gcm, Nonce,
};

use crate::error::{VeilError, VeilResult};

/// Nonce size for AES-256-GCM (96 bits / 12 bytes).
pub const NONCE_SIZE: usize = 12;

/// Authentication tag size for GCM (128 bits / 16 bytes).
pub const TAG_SIZE: usize = 16;

/// Generate a cryptographically random 256-bit AES key.
pub fn generate_key() -> [u8; 32] {
    use rand::RngCore;
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

/// Encrypt plaintext with AES-256-GCM.
///
/// # Arguments
/// * `key` - 32-byte AES-256 key
/// * `plaintext` - Data to encrypt
/// * `aad` - Additional Authenticated Data (authenticated but not encrypted)
///
/// # Returns
/// Tuple of (nonce, ciphertext_with_tag)
pub fn encrypt(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> VeilResult<(Vec<u8>, Vec<u8>)> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VeilError::Encryption(format!("invalid key: {e}")))?;

    // Generate random nonce
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    // Encrypt with AAD
    let payload = aes_gcm::aead::Payload {
        msg: plaintext,
        aad,
    };

    let ciphertext = cipher
        .encrypt(&nonce, payload)
        .map_err(|e| VeilError::Encryption(format!("AES-GCM encrypt: {e}")))?;

    Ok((nonce.to_vec(), ciphertext))
}

/// Decrypt ciphertext with AES-256-GCM.
///
/// # Arguments
/// * `key` - 32-byte AES-256 key
/// * `nonce` - 12-byte nonce used during encryption
/// * `ciphertext` - Encrypted data (includes GCM tag)
/// * `aad` - Additional Authenticated Data (must match encryption)
///
/// # Returns
/// Decrypted plaintext, or error if authentication fails (tampered data)
pub fn decrypt(key: &[u8; 32], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> VeilResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VeilError::Decryption(format!("invalid key: {e}")))?;

    let nonce = Nonce::from_slice(nonce);

    let payload = aes_gcm::aead::Payload {
        msg: ciphertext,
        aad,
    };

    cipher.decrypt(nonce, payload).map_err(|e| {
        VeilError::Decryption(format!(
            "AES-GCM decrypt failed (data may be tampered): {e}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    fn random_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        key
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = random_key();
        let plaintext = b"Hello, this is a secret LLM prompt!";
        let aad = b"veil-v1";

        let (nonce, ciphertext) = encrypt(&key, plaintext, aad).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_produces_different_ciphertexts() {
        let key = random_key();
        let plaintext = b"Same message";
        let aad = b"";

        let (_, ct1) = encrypt(&key, plaintext, aad).unwrap();
        let (_, ct2) = encrypt(&key, plaintext, aad).unwrap();

        // Different nonces → different ciphertexts
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = random_key();
        let plaintext = b"Secret data";
        let aad = b"metadata";

        let (nonce, mut ciphertext) = encrypt(&key, plaintext, aad).unwrap();

        // Tamper with ciphertext
        if let Some(byte) = ciphertext.first_mut() {
            *byte ^= 0xFF;
        }

        let result = decrypt(&key, &nonce, &ciphertext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let key = random_key();
        let plaintext = b"Secret data";

        let (nonce, ciphertext) = encrypt(&key, plaintext, b"correct-aad").unwrap();
        let result = decrypt(&key, &nonce, &ciphertext, b"wrong-aad");
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = random_key();
        let key2 = random_key();
        let plaintext = b"Secret data";
        let aad = b"";

        let (nonce, ciphertext) = encrypt(&key1, plaintext, aad).unwrap();
        let result = decrypt(&key2, &nonce, &ciphertext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let key = random_key();
        let (nonce, ciphertext) = encrypt(&key, b"", b"").unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext, b"").unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_large_payload() {
        let key = random_key();
        let plaintext = vec![0x42u8; 1_000_000]; // 1MB
        let aad = b"large-payload";

        let (nonce, ciphertext) = encrypt(&key, &plaintext, aad).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
