//! # Veil Server
//!
//! A decryption shim that sits in front of an LLM inference engine.
//!
//! ## Architecture
//!
//! ```text
//! Client → [encrypted] → Middleware → Veil Server → [plaintext] → LLM Engine
//!                                          ↓
//!                                     [decrypt request]
//!                                     [forward to LLM]
//!                                     [encrypt response]
//!                                          ↓
//! Client ← [encrypted] ← Middleware ← Veil Server ← [plaintext] ← LLM Engine
//! ```

pub mod config;
pub mod handler;
pub mod metrics;
pub mod server;
