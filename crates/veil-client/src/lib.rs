//! # Veil Client
//!
//! A local HTTP proxy that intercepts OpenAI-compatible API calls,
//! encrypts the payload using the Veil protocol, and forwards the
//! encrypted envelope to the upstream server.
//!
//! ## Architecture
//!
//! ```text
//! Your App → [localhost:8480] → Veil Client Proxy → [encrypted] → Upstream API
//! ```
//!
//! The proxy is transparent — any app that speaks the OpenAI API
//! format works without modification.

pub mod config;
pub mod proxy;
