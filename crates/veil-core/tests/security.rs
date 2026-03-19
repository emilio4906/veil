//! Security property tests for Veil cryptographic operations.

use std::collections::HashSet;
use veil_core::cipher;
use veil_core::keys::StaticKeyPair;
use veil_core::session::ClientSession;

#[test]
fn test_nonces_are_unique() {
    let server_kp = StaticKeyPair::generate();
    let server_pub = server_kp.public_base64();
    let mut nonces = HashSet::new();

    for _ in 0..1000 {
        let session = ClientSession::new(&server_pub, "key").expect("session");
        let (envelope, _) = session
            .encrypt_request(b"test", "model", None)
            .expect("encrypt");

        // Extract nonce from envelope
        let nonce: Vec<u8> = envelope.nonce.clone();
        assert_eq!(nonce.len(), 12, "Nonce must be 96 bits");
        assert!(
            nonces.insert(nonce),
            "Nonce collision detected! Critical security failure."
        );
    }
}

#[test]
fn test_ciphertext_indistinguishability() {
    let server_kp = StaticKeyPair::generate();
    let server_pub = server_kp.public_base64();
    let plaintext = b"identical plaintext";

    let s1 = ClientSession::new(&server_pub, "key").unwrap();
    let s2 = ClientSession::new(&server_pub, "key").unwrap();

    let (e1, _) = s1.encrypt_request(plaintext, "m", None).unwrap();
    let (e2, _) = s2.encrypt_request(plaintext, "m", None).unwrap();

    // Nonces must differ
    assert_ne!(e1.nonce, e2.nonce, "Nonces must be unique per encryption");
    // Ciphertexts must differ (different keys from different ephemeral ECDH)
    assert_ne!(e1.ciphertext, e2.ciphertext, "Ciphertexts must differ");
}

#[test]
fn test_key_material_is_256_bit() {
    let key = cipher::generate_key();
    assert_eq!(key.len(), 32, "Key must be 256 bits (32 bytes)");
}

#[test]
fn test_ephemeral_keys_are_unique() {
    let server_kp = StaticKeyPair::generate();
    let server_pub = server_kp.public_base64();
    let mut keys = HashSet::new();

    for _ in 0..100 {
        let session = ClientSession::new(&server_pub, "key").unwrap();
        let (_, meta) = session.encrypt_request(b"test", "m", None).unwrap();
        assert!(
            keys.insert(meta.ephemeral_key.clone()),
            "Ephemeral key reuse detected! This breaks forward secrecy."
        );
    }
}

#[test]
fn test_generated_keys_are_random() {
    let mut keys = HashSet::new();
    for _ in 0..100 {
        let key = cipher::generate_key();
        assert!(
            keys.insert(key),
            "Key generation produced duplicate! CSPRNG failure."
        );
    }
}

#[test]
fn test_ciphertext_larger_than_plaintext() {
    // GCM adds 16-byte auth tag
    let server_kp = StaticKeyPair::generate();
    let server_pub = server_kp.public_base64();
    let plaintext = b"hello world";

    let session = ClientSession::new(&server_pub, "key").unwrap();
    let (envelope, _) = session.encrypt_request(plaintext, "m", None).unwrap();

    assert!(
        envelope.ciphertext.len() > plaintext.len(),
        "Ciphertext must be larger than plaintext due to GCM auth tag"
    );
    // Specifically: ciphertext = plaintext + 16 byte tag
    assert_eq!(
        envelope.ciphertext.len(),
        plaintext.len() + 16,
        "GCM adds exactly 16 bytes for authentication tag"
    );
}
