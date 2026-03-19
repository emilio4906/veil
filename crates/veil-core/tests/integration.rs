//! End-to-end integration tests for the Veil protocol.

use veil_core::keys::StaticKeyPair;
use veil_core::session::{ClientSession, ServerSession};

#[test]
fn test_full_e2e_roundtrip() {
    let server_kp = StaticKeyPair::generate();
    let server_pub = server_kp.public_base64();

    let client_session =
        ClientSession::new(&server_pub, "test-key").expect("Failed to create client session");

    let prompt = b"{\"model\":\"gpt-4\",\"messages\":[{\"role\":\"user\",\"content\":\"Hello\"}]}";
    let (envelope, metadata) = client_session
        .encrypt_request(prompt, "gpt-4", Some(10))
        .expect("Failed to encrypt request");

    assert_eq!(metadata.model, "gpt-4");
    assert_eq!(metadata.token_estimate, Some(10));
    assert_eq!(metadata.key_id, "test-key");
    assert!(!metadata.ephemeral_key.is_empty());

    let server_session = ServerSession::new(&server_kp, &metadata.ephemeral_key)
        .expect("Failed to create server session");

    let decrypted = server_session
        .decrypt_request(&envelope)
        .expect("Failed to decrypt request");
    assert_eq!(decrypted, prompt);

    let response = b"{\"choices\":[{\"message\":{\"content\":\"Hello back!\"}}]}";
    let response_envelope = server_session
        .encrypt_response(response)
        .expect("Failed to encrypt response");

    let decrypted_response = client_session
        .decrypt_response(&response_envelope)
        .expect("Failed to decrypt response");
    assert_eq!(decrypted_response, response);
}

#[test]
fn test_different_sessions_produce_different_ciphertext() {
    let server_kp = StaticKeyPair::generate();
    let server_pub = server_kp.public_base64();

    let session_a = ClientSession::new(&server_pub, "key-1").expect("Failed to create session A");
    let session_b = ClientSession::new(&server_pub, "key-1").expect("Failed to create session B");

    let prompt = b"secret prompt";

    let (envelope_a, _meta_a) = session_a
        .encrypt_request(prompt, "model", None)
        .expect("Failed to encrypt");

    let (envelope_b, _meta_b) = session_b
        .encrypt_request(prompt, "model", None)
        .expect("Failed to encrypt");

    // Different sessions should produce different ciphertexts
    assert_ne!(
        envelope_a.ciphertext, envelope_b.ciphertext,
        "Different sessions should produce different ciphertexts"
    );
}

#[test]
fn test_cross_session_decryption_works() {
    let server_kp = StaticKeyPair::generate();
    let server_pub = server_kp.public_base64();

    let session = ClientSession::new(&server_pub, "key-1").expect("Failed to create session");

    let prompt = b"secret prompt";
    let (envelope, meta) = session
        .encrypt_request(prompt, "model", None)
        .expect("Failed to encrypt");

    // Server creates session from the ephemeral key
    let server_session = ServerSession::new(&server_kp, &meta.ephemeral_key)
        .expect("Failed to create server session");

    let decrypted = server_session
        .decrypt_request(&envelope)
        .expect("Should decrypt with correct ephemeral key");
    assert_eq!(decrypted, prompt);
}

#[test]
fn test_large_payload_e2e() {
    let server_kp = StaticKeyPair::generate();
    let server_pub = server_kp.public_base64();

    // 1MB payload (large context window)
    let large_prompt: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();

    let session = ClientSession::new(&server_pub, "key-1").expect("Failed to create session");

    let (envelope, metadata) = session
        .encrypt_request(&large_prompt, "gpt-4-turbo", Some(50000))
        .expect("Failed to encrypt large payload");

    let server_session = ServerSession::new(&server_kp, &metadata.ephemeral_key)
        .expect("Failed to create server session");

    let decrypted = server_session
        .decrypt_request(&envelope)
        .expect("Failed to decrypt large payload");

    assert_eq!(decrypted, large_prompt);
}

#[test]
fn test_tampered_ciphertext_rejected() {
    let server_kp = StaticKeyPair::generate();
    let server_pub = server_kp.public_base64();

    let session = ClientSession::new(&server_pub, "key-1").expect("Failed to create session");

    let (mut envelope, metadata) = session
        .encrypt_request(b"secret", "model", None)
        .expect("Failed to encrypt");

    // Tamper with the ciphertext
    if let Some(byte) = envelope.ciphertext.last_mut() {
        *byte ^= 0xFF;
    }

    let server_session = ServerSession::new(&server_kp, &metadata.ephemeral_key)
        .expect("Failed to create server session");

    assert!(
        server_session.decrypt_request(&envelope).is_err(),
        "Tampered ciphertext should be rejected"
    );
}

#[test]
fn test_tampered_nonce_rejected() {
    let server_kp = StaticKeyPair::generate();
    let server_pub = server_kp.public_base64();

    let session = ClientSession::new(&server_pub, "key-1").expect("Failed to create session");

    let (mut envelope, metadata) = session
        .encrypt_request(b"secret", "model", None)
        .expect("Failed to encrypt");

    // Tamper with the nonce
    if let Some(byte) = envelope.nonce.first_mut() {
        *byte ^= 0xFF;
    }

    let server_session = ServerSession::new(&server_kp, &metadata.ephemeral_key)
        .expect("Failed to create server session");

    assert!(
        server_session.decrypt_request(&envelope).is_err(),
        "Tampered nonce should be rejected"
    );
}

#[test]
fn test_wrong_server_key_rejected() {
    let server_kp_real = StaticKeyPair::generate();
    let server_kp_fake = StaticKeyPair::generate();

    let session = ClientSession::new(&server_kp_real.public_base64(), "key-1")
        .expect("Failed to create session");

    let (envelope, metadata) = session
        .encrypt_request(b"secret", "model", None)
        .expect("Failed to encrypt");

    let wrong_session = ServerSession::new(&server_kp_fake, &metadata.ephemeral_key)
        .expect("Failed to create server session");

    assert!(
        wrong_session.decrypt_request(&envelope).is_err(),
        "Wrong server key should fail to decrypt"
    );
}
