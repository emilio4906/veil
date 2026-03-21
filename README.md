<div align="center">

# 🔐 Veil

**End-to-end encryption for LLM inference — An example, not a working model**

[![CI](https://github.com/oxifederation/veil/actions/workflows/ci.yml/badge.svg)](https://github.com/oxifederation/veil/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)
[![Rust](https://img.shields.io/badge/rust-1.80%2B-orange.svg)](https://www.rust-lang.org)
[![Crates.io](https://img.shields.io/crates/v/veil-core.svg)](https://crates.io/crates/veil-core)

*Your prompts are your thoughts. They deserve the same protection as your messages.*

[Quick Start](#quick-start) · [How It Works](#how-it-works) · [Architecture](ARCHITECTURE.md) · [Security](SECURITY.md) · [Contributing](CONTRIBUTING.md)

</div>

---

## The Problem

When you send a prompt to an LLM API, your request passes through:

```
Your App → App Server → LLM Router (e.g. OpenRouter) → LLM Providers (AWS, Google, Azure, Oracle etc.) → LLM Engine (ChatGPT, Claude, Grok etc.)
```

Every layer in that chain can read your prompts and responses in plaintext.
TLS only protects the connection between hops — not through them.

This means your confidential data — legal documents, medical records, proprietary
code, personal conversations — is visible to every piece of infrastructure
between you and the model.

## The Solution

Veil adds an **application-layer encryption envelope** around your LLM traffic.
When veil-server runs in-process with the LLM engine, only your application and the LLM inference engine can read the content:

```
  Your App ──▶ 🔒 Encrypted Blob ──▶ 🔒 ──▶ 🔒 ──▶ LLM Engine
       ▲            ▲                                    │
       │       Can't read this                           │
       └──── 🔓 Decrypted Response ◀── 🔒 ◀── 🔒 ◀─────┘
```

**Veil is inspired by Signal's approach to messaging** — applying the same principle
of application-layer encryption to LLM inference traffic, so middleware sees only
opaque encrypted blobs regardless of the transport.

---

## Quick Start

### 1. Build from Source

```bash
git clone https://github.com/oxifederation/veil.git
cd veil
cargo build --release
```

### 2. Generate Server Keys

```bash
./target/release/veil keygen --output server-keys.json
```

### 3. Test the Encryption Roundtrip

```bash
./target/release/veil test-roundtrip --message "Hello, encrypted world!"
```

Expected output:
```
=== Veil E2E Encryption Test ===
Original:  Hello, encrypted world!
Encrypted: <base64 envelope>
Decrypted: Hello, encrypted world!
✅ Roundtrip successful — encryption is working correctly
```

### 4. Run as a Proxy (Drop-In Replacement)

```bash
# Terminal 1: Start the Veil server shim (sits in front of your LLM)
./target/release/veil server --key-file server-keys.json --upstream http://localhost:11434

# Terminal 2: Start the Veil client proxy (your app connects here)
./target/release/veil proxy --server-url http://localhost:3100 --listen 127.0.0.1:8080

# Terminal 3: Use any OpenAI-compatible client — it just works
curl http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model": "llama3", "messages": [{"role": "user", "content": "Hello!"}]}'
```

Your traffic is now application-layer encrypted. The proxy and shim handle all crypto transparently.
For full E2EE, deploy veil-server in-process with your LLM inference engine (see [Deployment Modes](#deployment-modes)).

---

## How It Works

```
┌──────────┐          ┌──────────────┐          ┌──────────────┐          ┌──────────┐
│          │ OpenAI   │              │ Encrypted │              │ OpenAI   │          │
│ Your App │────API──▶│ Veil Client  │────blob──▶│ Veil Server  │────API──▶│   LLM    │
│          │◀───────  │ Proxy        │◀────────  │ Shim         │◀───────  │ Engine   │
│          │  (plain) │              │ (opaque)  │              │  (plain) │          │
└──────────┘          └──────────────┘          └──────────────┘          └──────────┘
     🔑                    🔐                       🔐                       🔑
   Sees                 Encrypts/                Gateway only             Decrypts/
  plaintext             decrypts                sees blob               encrypts
```

### Cryptographic Pipeline

| Stage | Algorithm | Purpose |
|-------|-----------|:--------|
| Key Exchange | X25519 ECDH | Establish shared secret; client-side forward secrecy via ephemeral keys |
| Key Derivation | HKDF-SHA256 | Derive directional encryption keys |
| Encryption | AES-256-GCM | Authenticated encryption of prompts/responses |

Every request uses a **fresh client ephemeral key**, providing **client-side forward secrecy** —
compromising the server key does not reveal past conversations.

📖 **Full protocol specification** → [ARCHITECTURE.md](ARCHITECTURE.md)

---

## Features

- 🔒 **End-to-end encryption** — prompts and responses encrypted through all middleware
- 🔑 **Client-side forward secrecy** — fresh ephemeral keys per request (server prekeys roadmapped for v0.2)
- 🛡️ **Authenticated encryption** — AES-256-GCM detects any tampering
- 🔄 **Drop-in proxy mode** — zero changes to existing OpenAI-compatible apps
- ⚡ **Minimal overhead** — ~48 bytes per message, sub-millisecond crypto
- 📦 **Pure Rust** — memory-safe, no unsafe code in core
- 🧹 **Zeroize-on-drop** — key material scrubbed from memory after use
- 🐳 **Docker ready** — multi-stage builds for client and server
- 🧪 **Thoroughly tested** — 36 tests covering crypto, integration, and security properties

---

## Project Structure

```
veil/
├── crates/
│   ├── veil-core/       # Pure cryptographic library (no I/O, no async)
│   │   ├── src/
│   │   │   ├── keys.rs      # X25519 key generation and ECDH
│   │   │   ├── kdf.rs       # HKDF-SHA256 key derivation
│   │   │   ├── cipher.rs    # AES-256-GCM encrypt/decrypt
│   │   │   ├── envelope.rs  # Wire format (MessagePack + JSON)
│   │   │   ├── session.rs   # Client/server session management
│   │   │   └── error.rs     # Error types
│   │   └── tests/
│   │       ├── integration.rs   # E2E roundtrip tests
│   │       └── security.rs      # Security property tests
│   ├── veil-client/     # HTTP proxy (encrypts outgoing requests)
│   ├── veil-server/     # Axum server shim (decrypts, forwards to LLM)
│   └── veil-cli/        # CLI tool for keygen, testing, proxy, server
├── docker/              # Docker deployment configurations
├── examples/            # Integration examples (Python, etc.)
├── benches/             # Cryptographic benchmarks
├── ARCHITECTURE.md      # Full protocol specification
├── SECURITY.md          # Threat model and security policy
├── CONTRIBUTING.md      # Contribution guidelines
└── CHANGELOG.md         # Release history
```

---

## SDK Roadmap

Veil follows a **single-core, many-bindings** architecture. All cryptography lives
in `veil-core` (Rust). Language SDKs are thin FFI wrappers — one implementation,
audited once, available everywhere.

| Phase | SDK | Technology | Status |
|:-----:|-----|-----------|:------:|
| 1 | **Proxy + CLI** | Native Rust | ✅ Current |
| 2 | **Python SDK** | PyO3 bindings | 🔜 Next |
| 3 | **JavaScript/TypeScript SDK** | NAPI-RS (Node) + WASM (Browser) | 📋 Planned |
| 4 | **Go SDK** | CGo FFI | 📋 Planned |
| 5 | **Java/Kotlin SDK** | JNI bindings | 📋 Planned |
| 6 | **Swift/Kotlin Mobile** | Mozilla UniFFI | 📋 Planned |

### Future Python SDK Usage (Preview)

```python
from veil import VeilSession

session = VeilSession(server_public_key="<b64>", key_id="prod-v2")
envelope, headers = session.encrypt_request(prompt, model="gpt-4")
plaintext = session.decrypt_response(response_bytes)
```

📖 **SDK architecture details** → [ARCHITECTURE.md § SDK Architecture](ARCHITECTURE.md#sdk-architecture-ffi-bindings)

---

## Benchmarks

Preliminary benchmarks on Apple M2 (single core):

| Operation | Throughput | Latency |
|-----------|-----------|:-------:|
| X25519 ECDH | ~50,000 ops/sec | ~20 µs |
| HKDF-SHA256 derivation | ~500,000 ops/sec | ~2 µs |
| AES-256-GCM encrypt (1 KB) | ~2 GB/s | ~0.5 µs |
| AES-256-GCM encrypt (1 MB) | ~4 GB/s | ~250 µs |
| Full session roundtrip | ~25,000 ops/sec | ~40 µs |

> **Veil adds < 100 µs** to your LLM API call (which typically takes 200ms–30s).
> The encryption overhead is unmeasurable in practice.

Run benchmarks yourself:

```bash
cargo bench
```

---

## Docker Deployment

```bash
# Build and run both client proxy and server shim
cd docker
docker compose up -d

# Client proxy listens on :8080
# Server shim listens on :3100
```

See [docker/](docker/) for multi-stage Dockerfiles and configuration.

---

## Security

Veil takes security seriously:

- **Cryptographic choices**: X25519, HKDF-SHA256, AES-256-GCM — industry-standard
  algorithms from the RustCrypto project
- **No unsafe code** in `veil-core`
- **Zeroize-on-drop** for all key material
- **36 security and integration tests** including tamper detection, cross-session
  isolation, and ciphertext indistinguishability
- **Constant-time operations** via RustCrypto's timing-safe implementations

### Reporting Vulnerabilities

**Do NOT open a public issue for security vulnerabilities.**

Please email aehthesham.gom@gmail.com with:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment

We will respond within 48 hours.

📖 **Full threat model** → [SECURITY.md](SECURITY.md)

---

## Contributing

We welcome contributions! Please read our [Contributing Guide](CONTRIBUTING.md)
before submitting a PR.

TL;DR:
1. Fork the repo
2. Create a feature branch (`feat/my-feature`)
3. Write tests for your changes
4. Ensure `cargo fmt && cargo clippy -- -D warnings && cargo test` passes
5. Submit a PR with a [Conventional Commit](https://www.conventionalcommits.org/) message

---

## License

Licensed under either of:

- **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE))
- **MIT License** ([LICENSE-MIT](LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

---

<div align="center">

**Veil** is a project by the [Concerned Technologist](https://github.com/oxifederation)

*Protecting the confidentiality of human–AI communication*

</div>
