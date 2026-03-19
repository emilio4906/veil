//! HTTP request handlers for the Veil decryption server.

use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json},
};
use serde_json::json;
use tracing::{debug, error, info};

use veil_core::{keys::StaticKeyPair, session::ServerSession, VeilEnvelope};

use crate::metrics;

/// Shared application state.
pub struct AppState {
    pub server_keypair: StaticKeyPair,
    pub backend_url: String,
    pub http_client: reqwest::Client,
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
    Json(json!({
        "public_key": state.server_keypair.public_base64(),
        "key_id": "default",
        "algorithm": "X25519+HKDF-SHA256+AES-256-GCM",
        "protocol_version": 1
    }))
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

    debug!(model = %model, "Processing Veil inference request");

    // Parse the encrypted envelope
    let envelope = match VeilEnvelope::from_json(&body) {
        Ok(env) => env,
        Err(e) => {
            metrics::record_request("error");
            error!("Failed to parse envelope: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("Invalid envelope: {}", e)})),
            )
                .into_response();
        }
    };

    metrics::observe_payload_size(envelope.payload_size());

    // Create server session and decrypt
    let decrypt_start = Instant::now();
    let session = match ServerSession::new(&state.server_keypair, &ephemeral_key) {
        Ok(s) => s,
        Err(e) => {
            metrics::record_request("error");
            error!("Failed to create session: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("Session error: {}", e)})),
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
                Json(json!({"error": format!("Backend error: {}", e)})),
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
                Json(json!({"error": format!("Backend read error: {}", e)})),
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
            Err(_) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({"error": "Backend returned error and encryption failed"})),
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
                Json(json!({"error": format!("Response encryption failed: {}", e)})),
            )
                .into_response();
        }
    };
    metrics::observe_encrypt(encrypt_start.elapsed().as_secs_f64());

    let resp_json = match resp_envelope.to_json() {
        Ok(j) => j,
        Err(e) => {
            metrics::record_request("error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Envelope serialization failed: {}", e)})),
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
