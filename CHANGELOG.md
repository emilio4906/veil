# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- SSE streaming encryption (per-chunk encryption for streaming LLM responses)
- Python SDK via PyO3 bindings
- Key rotation protocol
- Rate limiting and connection pooling in proxy

## [0.1.0] - 2026-03-19

### Added

#### veil-core (Cryptographic Library)
- X25519 ECDH key exchange with ephemeral client keys (RFC 7748)
- HKDF-SHA256 key derivation with directional info strings (RFC 5869)
- AES-256-GCM authenticated encryption with random nonces (NIST SP 800-38D)
- `VeilEnvelope` wire format with MessagePack and JSON serialization
- `ClientSession` and `ServerSession` for complete key exchange workflows
- `StaticKeyPair` with JSON serialization for server key persistence
- `SessionKeys` with `ZeroizeOnDrop` for automatic key scrubbing
- Comprehensive error types (`VeilError`) with descriptive messages
- Protocol constants: `HKDF_SALT`, `C2S_INFO`, `S2C_INFO`, `C2S_AAD`, `S2C_AAD`

#### veil-client (HTTP Proxy)
- Transparent HTTP proxy that intercepts OpenAI-compatible API calls
- Automatic encryption of outgoing request bodies
- Automatic decryption of incoming response bodies
- Veil metadata headers (`X-Veil-Version`, `X-Veil-Key-Id`, `X-Veil-Ephemeral-Key`)
- Configurable listen address and upstream server URL

#### veil-server (Server Shim)
- Axum-based HTTP server that sits in front of LLM inference engines
- Automatic decryption of incoming encrypted requests
- Automatic encryption of outgoing responses
- Public key endpoint (`GET /v1/veil/public-key`) for key exchange
- Health check endpoint (`GET /health`)
- Configurable upstream LLM backend URL
- Structured logging with `tracing`

#### veil-cli (Command Line Tool)
- `keygen` — Generate server X25519 key pairs with JSON output
- `inspect` — Display public key from a key file
- `encrypt` / `decrypt` — Manual envelope encryption/decryption
- `test-roundtrip` — Verify encryption roundtrip with custom messages
- `proxy` — Launch the client-side encryption proxy
- `server` — Launch the server-side decryption shim

#### Testing
- 22 unit tests covering cipher, envelope, keys, KDF, and session modules
- 7 integration tests for E2E roundtrips, tamper detection, and cross-session isolation
- 6 security property tests for nonce uniqueness, ciphertext indistinguishability,
  key randomness, and key material size validation
- 1 doc test verifying library usage example
- **36 total tests**, all passing

#### Documentation
- `README.md` — Project overview, quick start, architecture, SDK roadmap
- `ARCHITECTURE.md` — Full protocol specification, cryptographic pipeline,
  envelope format, SDK FFI architecture
- `SECURITY.md` — Threat model, security properties, vulnerability reporting
- `CONTRIBUTING.md` — Conventional commits, development setup, PR process
- `CHANGELOG.md` — This file
- `PROJECT_PLAN.md` — Development roadmap with SDK phases

#### Deployment
- Docker multi-stage builds for client and server (`docker/`)
- Docker Compose for local development
- GitHub Actions CI pipeline (fmt, clippy, test, build)
- Python client example with self-test capability

#### Licensing
- Dual licensed under MIT and Apache-2.0

[Unreleased]: https://github.com/oxifederation/veil/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/oxifederation/veil/releases/tag/v0.1.0
