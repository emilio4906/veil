//! Axum server setup and routing.

use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    routing::{get, post},
    Router,
};
use tower_http::{cors::CorsLayer, limit::RequestBodyLimitLayer, trace::TraceLayer};
use tracing::info;

use crate::config::ServerConfig;
use crate::handler::{self, AppState};

/// Build and start the Veil server.
pub async fn run(config: ServerConfig) -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "veil_server=info,tower_http=info".into()),
        )
        .json()
        .init();

    // Load server key pair
    let server_keypair = config
        .load_keypair()
        .context("Failed to load server key pair")?;

    info!(
        key_id = %config.key_id,
        public_key = %server_keypair.public_base64(),
        "Server key pair loaded"
    );

    // Build HTTP client for backend
    let http_client = reqwest::Client::builder()
        .timeout(config.request_timeout())
        .pool_max_idle_per_host(32)
        .build()
        .context("Failed to build HTTP client")?;

    let state = Arc::new(AppState {
        server_keypair,
        backend_url: config.backend_url.clone(),
        http_client,
    });

    // Build router
    let app = Router::new()
        // Veil protocol endpoints
        .route("/v1/veil/inference", post(handler::inference))
        .route("/v1/veil/public-key", get(handler::public_key))
        // Operational endpoints
        .route("/health", get(handler::health))
        .route("/metrics", get(handler::metrics_handler))
        // Middleware
        .layer(RequestBodyLimitLayer::new(config.max_body_size()))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr = config
        .listen_addr
        .parse::<std::net::SocketAddr>()
        .context("Invalid listen address")?;

    info!("🔐 Veil server listening on {}", addr);
    info!("   Backend: {}", config.backend_url);
    info!("   Key ID: {}", config.key_id);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .context("Failed to bind listener")?;

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("Server error")?;

    info!("Server shut down gracefully");
    Ok(())
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C handler");
    info!("Shutdown signal received");
}
