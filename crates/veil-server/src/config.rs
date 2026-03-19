//! Server configuration.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use veil_core::keys::StaticKeyPair;

/// Server configuration loaded from TOML file or environment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Address to listen on.
    pub listen_addr: String,

    /// URL of the actual LLM inference backend.
    pub backend_url: String,

    /// Server's static secret key (base64).
    /// In production, load from HSM or secure key store.
    pub server_secret_key: String,

    /// Key ID advertised to clients.
    pub key_id: String,

    /// Maximum request body size in bytes (default: 10MB).
    pub max_body_size: Option<usize>,

    /// Request timeout in seconds (default: 300).
    pub request_timeout_secs: Option<u64>,

    /// Enable Prometheus metrics endpoint.
    pub metrics_enabled: Option<bool>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:8481".to_string(),
            backend_url: "http://127.0.0.1:8000".to_string(),
            server_secret_key: String::new(),
            key_id: "default".to_string(),
            max_body_size: Some(10 * 1024 * 1024),
            request_timeout_secs: Some(300),
            metrics_enabled: Some(true),
        }
    }
}

impl ServerConfig {
    /// Load configuration from a TOML file.
    pub fn from_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path))?;
        toml::from_str(&content).with_context(|| format!("Failed to parse config file: {}", path))
    }

    /// Load the server key pair from the configured secret key.
    pub fn load_keypair(&self) -> Result<StaticKeyPair> {
        StaticKeyPair::from_secret_base64(&self.server_secret_key)
            .map_err(|e| anyhow::anyhow!("Failed to load server key pair: {}", e))
    }

    /// Get the max body size with default.
    pub fn max_body_size(&self) -> usize {
        self.max_body_size.unwrap_or(10 * 1024 * 1024)
    }

    /// Get the request timeout.
    pub fn request_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.request_timeout_secs.unwrap_or(300))
    }
}
