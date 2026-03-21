//! HTTP request handlers for the Veil decryption server.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json},
};
use chrono::Utc;
use serde_json::json;
use tracing::{debug, error, info, warn};

use veil_core::{keys::StaticKeyPair, session::ServerSession, VeilEnvelope};

use crate::metrics;

/// Shared application state with multi-key support.
pub struct AppState {
    /// Map of key_id → StaticKeyPair for key rotation support.
    pub keypairs: HashMap<String, StaticKeyPair>,
    /// The currently active key ID served on the public-key endpoint.
    pub active_key_id: String,
    /// URL of the actual LLM inference backend.
    pub backend_url: String,
    /// HTTP client for forwarding requests to the backend.
    pub http_client: reqwest::Client,
    /// Maximum age of a request before it is rejected for replay protection.
    pub max_request_age: Duration,
    /// Replay cache: tracks seen request IDs to prevent replay attacks.
    /// Maps request_id → time received. Entries expire after max_request_age.
    pub replay_cache: Arc<std::sync::Mutex<HashMap<String, Instant>>>,
}

/// Health check endpoint.
pub async fn health() -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "service": "veil-server",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

/// Prometheus metrics endpoint.
pub async fn metrics_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        metrics::encode_metrics(),
    )
}

/// Public key endpoint — clients fetch this to establish sessions.
pub async fn public_key(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let active_keypair = state.keypairs.get(&state.active_key_id);
    match active_keypair {
        Some(kp) => Json(json!({
            "public_key": kp.public_base64(),
            "key_id": state.active_key_id,
            "algorithm": "X25519+HKDF-SHA256+AES-256-GCM",
            "protocol_version": 1
        }))
        .into_response(),
        None => {
            error!("Active key_id '{}'not found in keypairs", state.active_key_id);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Internal server error"})),
            )
                .into_response()
        }
    }
}

/// Main inference endpoint — decrypt, forward, re-encrypt.
pub async fn inference(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    let start = Instant::now();

    // Extract Veil headers
    let ephemeral_key = match headers.get("X-Veil-Ephemeral-Key") {
        Some(v) => v.to_str().unwrap_or_default().to_string(),
        None => {
            metrics::record_request("error");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Missing X-Veil-Ephemeral-Key header"})),
            )
                .into_response();
        }
    };

    let model = headers
        .get("X-Veil-Model")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    // Extract key_id from header (defaults to active key)
    let key_id = headers
        .get("X-Veil-Key-Id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or(&state.active_key_id)
        .to_string();

    // Replay protection: validate timestamp and capture for AAD binding
    let request_timestamp = match headers.get("X-Veil-Timestamp") {
        Some(ts_header) => match ts_header.to_str() {
            Ok(ts_str) => {
                match chrono::DateTime::parse_from_rfc3339(ts_str) {
                    Ok(request_time) => {
                        let now = Utc::now();
                        let age = now
                            .signed_duration_since(request_time.with_timezone(&Utc))
                            .num_seconds();
                        if age < 0 || age > state.max_request_age.as_secs() as i64 {
                            metrics::record_request("error");
                            warn!(
                                "Request timestamp too old or in future: age={}s, max={}s",
                                age,
                                state.max_request_age.as_secs()
                            );
                            return (
                                StatusCode::BAD_REQUEST,
                                Json(json!({"error": "Request expired or invalid timestamp"})),
                            )
                                .into_response();
                        }
                        ts_str.to_string()
                    }
                    Err(e) => {
                        metrics::record_request("error");
                        error!("Invalid timestamp format: {}", e);
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(json!({"error": "Invalid request"})),
                        )
                            .into_response();
                    }
                }
            }
            Err(_) => {
                metrics::record_request("error");
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "Invalid request"})),
                )
                    .into_response();
            }
        },
        None => {
            metrics::record_request("error");
            warn!("Missing X-Veil-Timestamp header");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Missing X-Veil-Timestamp header"})),
            )
                .into_response();
        }
    };

    // Replay protection: validate request_id uniqueness
    let request_id = match headers.get("X-Veil-Request-Id") {
        Some(v) => v.to_str().unwrap_or_default().to_string(),
        None => {
            metrics::record_request("error");
            warn!("Missing X-Veil-Request-Id header — replay protection cannot be enforced");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Missing X-Veil-Request-Id header"})),
            )
                .into_response();
        }
    };

    {
        let mut cache = state.replay_cache.lock().unwrap();
        // Evict expired entries (lazy cleanup)
        let max_age = state.max_request_age;
        cache.retain(|_, received_at| received_at.elapsed() < max_age);
        // Check for replay
        if cache.contains_key(&request_id) {
            metrics::record_request("error");
            warn!(request_id = %request_id, "Replay attack detected — request_id already seen");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Duplicate request — replay detected"})),
            )
                .into_response();
        }
        // Record this request_id
        cache.insert(request_id.clone(), Instant::now());
    }

    debug!(model = %model, key_id = %key_id, request_id = %request_id, "Processing Veil inference request");

    // Look up the keypair for the requested key_id
    let server_keypair = match state.keypairs.get(&key_id) {
        Some(kp) => kp,
        None => {
            metrics::record_request("error");
            warn!("Unknown key_id requested: {}", key_id);
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Invalid request"})),
            )
                .into_response();
        }
    };

    // Parse the encrypted envelope
    let envelope = match VeilEnvelope::from_json(&body) {
        Ok(env) => env,
        Err(e) => {
            metrics::record_request("error");
            error!("Failed to parse envelope: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Invalid request"})),
            )
                .into_response();
        }
    };

    metrics::observe_payload_size(envelope.payload_size());

    // Create server session and decrypt
    let decrypt_start = Instant::now();
    let session = match ServerSession::new(server_keypair, &ephemeral_key, &key_id, &request_id, &request_timestamp) {
        Ok(s) => s,
        Err(e) => {
            metrics::record_request("error");
            error!("Failed to create session: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Invalid request"})),
            )
                .into_response();
        }
    };

    let plaintext = match session.decrypt_request(&envelope) {
        Ok(pt) => pt,
        Err(e) => {
            metrics::record_request("error");
            error!("Decryption failed: {}", e);
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Decryption failed — invalid key or tampered data"})),
            )
                .into_response();
        }
    };
    metrics::observe_decrypt(decrypt_start.elapsed().as_secs_f64());

    info!(
        model = %model,
        payload_size = plaintext.len(),
        decrypt_ms = decrypt_start.elapsed().as_millis() as u64,
        "Request decrypted successfully"
    );

    // Forward plaintext to LLM backend
    let backend_url = format!("{}/v1/chat/completions", state.backend_url);
    let backend_resp = match state
        .http_client
        .post(&backend_url)
        .header("Content-Type", "application/json")
        .body(plaintext)
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            metrics::record_request("error");
            error!("Backend request failed: {}", e);
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": "Backend unavailable"})),
            )
                .into_response();
        }
    };

    let backend_status = backend_resp.status();
    let resp_bytes = match backend_resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            metrics::record_request("error");
            error!("Failed to read backend response: {}", e);
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": "Backend unavailable"})),
            )
                .into_response();
        }
    };

    if !backend_status.is_success() {
        metrics::record_request("backend_error");
        // Encrypt the error response too — don't leak info
        let encrypt_start = Instant::now();
        let resp_envelope = match session.encrypt_response(&resp_bytes) {
            Ok(env) => env,
            Err(e) => {
                error!("Failed to encrypt backend error response: {}", e);
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({"error": "Internal server error"})),
                )
                    .into_response();
            }
        };
        metrics::observe_encrypt(encrypt_start.elapsed().as_secs_f64());

        let resp_json = resp_envelope.to_json().unwrap_or_default();
        return (
            StatusCode::from_u16(backend_status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
            [
                ("content-type", "application/json"),
                ("X-Veil-Encrypted", "true"),
            ],
            resp_json,
        )
            .into_response();
    }

    // Encrypt the successful response
    let encrypt_start = Instant::now();
    let resp_envelope = match session.encrypt_response(&resp_bytes) {
        Ok(env) => env,
        Err(e) => {
            metrics::record_request("error");
            error!("Failed to encrypt response: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Internal server error"})),
            )
                .into_response();
        }
    };
    metrics::observe_encrypt(encrypt_start.elapsed().as_secs_f64());

    let resp_json = match resp_envelope.to_json() {
        Ok(j) => j,
        Err(e) => {
            metrics::record_request("error");
            error!("Envelope serialization failed: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Internal server error"})),
            )
                .into_response();
        }
    };

    metrics::record_request("success");
    info!(
        model = %model,
        total_ms = start.elapsed().as_millis() as u64,
        "Request processed successfully"
    );

    (
        StatusCode::OK,
        [
            ("content-type", "application/json"),
            ("X-Veil-Encrypted", "true"),
        ],
        resp_json,
    )
        .into_response()
}
