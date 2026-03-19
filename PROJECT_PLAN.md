# Veil — End-to-End Encrypted LLM Inference

## "Signal Protocol for AI"

> Your prompts. Your data. Nobody in the middle sees a thing.

---

## Vision

Veil is an open-source protocol and toolkit that brings end-to-end encryption
to LLM inference. Like Signal did for messaging, Veil ensures that only the
client and the LLM engine ever see plaintext prompts and responses. Every
intermediary — API gateways, proxies, load balancers, billing systems — handles
only opaque encrypted blobs while continuing to function normally via metadata.

---

## Architecture Overview

```
┌──────────┐     ┌──────────────┐     ┌─────────────┐     ┌──────────────┐
│  Your    │────▶│  Veil Client │────▶│  Provider   │────▶│  Veil Server │
│  App     │     │  Proxy       │     │  Infra      │     │  Shim        │
│          │◀────│  (decrypt)   │◀────│  (opaque)   │◀────│  (decrypt)   │
└──────────┘     └──────────────┘     └─────────────┘     └──────────────┘
   plaintext        encrypts              blind              decrypts
   OpenAI API       ──────────▶       passes blob        ──────────▶ LLM
                    ◀──────────       passes blob        ◀──────────
                    decrypts              blind              encrypts
```

### Components

1. **Veil Client Proxy** — Local HTTP proxy that intercepts OpenAI-compatible
   API calls, encrypts prompts, and decrypts responses. Drop-in transparent.

2. **Veil Server Shim** — Lightweight wrapper around any LLM inference engine.
   Decrypts incoming prompts, runs inference, encrypts responses.

3. **Veil Protocol** — The wire format, key exchange mechanism, and metadata
   envelope specification.

4. **veil-core** — Core cryptographic library shared by client, server, and
   all language SDKs via FFI bindings.

---

## Key Architecture Decision: Single-Core, Many-Bindings

All cryptographic logic lives in `veil-core` (Rust). Every language SDK is a
thin FFI wrapper around the same compiled core. This means:

- **One crypto implementation** → audit once, fix bugs once
- **Consistent behavior** → all SDKs produce identical ciphertext/plaintext
- **Rust performance** → AES-NI, constant-time ops, zero-copy where possible
- **Memory safety** → no buffer overflows in any language's crypto path

```
  Python SDK (PyO3) ─────┐
  JS/TS SDK (NAPI-RS) ───┤
  Go SDK (CGo) ──────────┤──▶ veil-core (Rust) ──▶ X25519 + HKDF + AES-GCM
  Java SDK (JNI) ────────┤
  Mobile (UniFFI) ───────┘
```

See [ARCHITECTURE.md § SDK Architecture](ARCHITECTURE.md#sdk-architecture-ffi-bindings)
for the full FFI specification.

---

## Technical Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Language | **Rust** | Memory safety without GC, excellent async networking (tokio), crypto ecosystem (RustCrypto), zero-cost abstractions for proxy performance |
| Key Exchange | **X25519 ECDH** | Industry standard, used by Signal/TLS 1.3/WireGuard, 128-bit security level |
| Symmetric Encryption | **AES-256-GCM** | AEAD (authenticated encryption), hardware-accelerated (AES-NI), prevents tampering |
| Key Derivation | **HKDF-SHA256** | RFC 5869, deterministic key derivation from ECDH shared secret |
| Session Management | **Ephemeral keys per session** | Forward secrecy — compromise of one session doesn't affect others |
| Wire Format | **MessagePack + custom envelope** | Compact binary format, faster than JSON for encrypted payloads |
| Proxy Protocol | **HTTP reverse proxy** | Compatible with any OpenAI-compatible client, zero client changes |
| Provider Metadata | **Cleartext JSON headers** | Routing, billing, rate limiting work on headers, not payload |
| SDK Strategy | **FFI from Rust core** | One audited crypto implementation, N language wrappers |
| Python Bindings | **PyO3** | Zero-cost Rust→Python, native extension modules, maturin build |
| JS Bindings | **NAPI-RS + WASM** | NAPI for Node.js native, WASM for browser |
| Mobile Bindings | **Mozilla UniFFI** | Single UDL definition → Swift + Kotlin bindings |

---

## Protocol Specification (v0.1)

### Key Exchange (Handshake)

```
Client                                              Server
  │                                                    │
  │──── GET /veil/v1/keys ────────────────────────────▶│
  │◀─── { server_public_key, key_id, expires } ────────│
  │                                                    │
  │  [Client generates ephemeral X25519 keypair]       │
  │  [ECDH: shared_secret = X25519(client_sk, srv_pk)] │
  │  [Derive keys: HKDF(shared_secret, salt, info)]    │
  │    → encrypt_key (client→server)                   │
  │    → decrypt_key (server→client)                   │
  │                                                    │
  │──── POST /v1/chat/completions ────────────────────▶│
  │     Headers:                                       │
  │       X-Veil-Version: 1                            │
  │       X-Veil-Key-Id: <server_key_id>               │
  │       X-Veil-Ephemeral-Key: <client_public_key>    │
  │       X-Veil-Token-Estimate: 1847                  │
  │       Authorization: Bearer <api_key>              │
  │       X-Veil-Model: claude-4                       │
  │     Body: <encrypted_payload>                      │
  │                                                    │
  │  [Server derives same shared_secret via ECDH]      │
  │  [Decrypts payload → runs inference]               │
  │  [Encrypts response with decrypt_key]              │
  │                                                    │
  │◀─── 200 OK ────────────────────────────────────────│
  │     Headers:                                       │
  │       X-Veil-Actual-Tokens: 1823                   │
  │       X-Veil-Safety-Status: pass                   │
  │     Body: <encrypted_response>                     │
  │                                                    │
```

### Encrypted Envelope Format

```
┌─────────────────────────────────────────┐
│ Veil Envelope (MessagePack)             │
├─────────────────────────────────────────┤
│ version: u8           (protocol ver)    │
│ nonce: [u8; 12]       (AES-GCM nonce)   │
│ ciphertext: Vec<u8>   (encrypted body)  │
│ aad: Vec<u8>          (additional data) │
└─────────────────────────────────────────┘

Total overhead: ~48 bytes per message
```

### Metadata Headers (visible to middleware)

| Header | Purpose | Visible To |
|--------|---------|------------|
| `Authorization` | API key / billing | Gateway |
| `X-Veil-Version` | Protocol version | All |
| `X-Veil-Key-Id` | Which server key to use | Server |
| `X-Veil-Ephemeral-Key` | Client's ephemeral public key | Server |
| `X-Veil-Model` | Model routing | Router/Gateway |
| `X-Veil-Token-Estimate` | Estimated tokens (for billing) | Gateway |
| `X-Veil-Content-Safety` | Safety scan result (post-decrypt) | All |
| `X-Veil-Actual-Tokens` | Real token count (response) | Gateway |

---

## Security Properties

1. **Forward Secrecy** — Ephemeral X25519 keys per session. Compromise of
   the server's long-term key doesn't decrypt past sessions.

2. **Authenticated Encryption** — AES-256-GCM provides confidentiality AND
   integrity. Middleware cannot modify encrypted payloads without detection.

3. **No Plaintext Leakage** — Model name and routing info in headers;
   actual prompt content never appears in cleartext outside endpoints.

4. **Key Rotation** — Server keys have expiry. Clients fetch fresh keys.
   Old keys are retired gracefully.

5. **Zero Trust Middleware** — Every intermediary is treated as untrusted.
   They function on metadata only.

6. **Memory Safety** — ZeroizeOnDrop for all key material. No unsafe code
   in veil-core.

---

## Project Structure

```
veil/
├── Cargo.toml                  # Workspace root
├── crates/
│   ├── veil-core/              # Pure cryptographic library (no I/O)
│   │   ├── src/
│   │   │   ├── lib.rs          # Public API and module exports
│   │   │   ├── keys.rs         # X25519 key generation & ECDH
│   │   │   ├── kdf.rs          # HKDF-SHA256 key derivation
│   │   │   ├── cipher.rs       # AES-256-GCM encrypt/decrypt
│   │   │   ├── envelope.rs     # Wire format (MessagePack + JSON)
│   │   │   ├── session.rs      # Client/server session management
│   │   │   └── error.rs        # Error types
│   │   └── tests/
│   │       ├── integration.rs  # E2E roundtrip tests
│   │       └── security.rs     # Security property tests
│   ├── veil-client/            # HTTP proxy (encrypts outgoing)
│   ├── veil-server/            # Axum server shim (decrypts incoming)
│   └── veil-cli/               # CLI: keygen, test, proxy, server
├── docker/                     # Docker deployment
├── examples/                   # Integration examples
├── benches/                    # Criterion benchmarks
├── ARCHITECTURE.md             # Full protocol specification
├── SECURITY.md                 # Threat model & security policy
├── CONTRIBUTING.md             # Contribution guidelines
├── CHANGELOG.md                # Release history
├── LICENSE-MIT                 # MIT license
└── LICENSE-APACHE              # Apache 2.0 license
```

---

## Performance Targets

| Metric | Target | Notes |
|--------|--------|-------|
| Encryption latency | < 1ms for 100KB payload | AES-NI hardware acceleration |
| Key exchange | < 2ms | X25519 is fast |
| Proxy overhead | < 5ms per request | Transparent proxy, minimal processing |
| Memory usage | < 50MB | Rust, no GC |
| Throughput | > 10,000 req/s | Async tokio, connection pooling |
| Binary size | < 10MB | Static binary, no runtime deps |

---

## Implementation Phases

### Phase 1: Foundation ✅ COMPLETE
- [x] Project plan & architecture
- [x] Cargo workspace setup
- [x] veil-core: Key generation (X25519)
- [x] veil-core: ECDH key exchange
- [x] veil-core: HKDF key derivation
- [x] veil-core: AES-256-GCM encrypt/decrypt
- [x] veil-core: Envelope format (MessagePack + JSON)
- [x] veil-core: Comprehensive test suite (36 tests)
- [x] veil-core: Zeroize sensitive memory

### Phase 2: Client Proxy ✅ COMPLETE
- [x] HTTP proxy with hyper
- [x] Request interception (OpenAI format detection)
- [x] Session management (key exchange)
- [x] Transparent encryption of outgoing requests
- [x] Transparent decryption of incoming responses
- [ ] Streaming support (SSE encrypted chunks) — *deferred to v0.2*
- [x] Configuration (CLI args)
- [ ] Health endpoint & Prometheus metrics — *planned*

### Phase 3: Server Shim ✅ COMPLETE
- [x] Axum-based HTTP server
- [x] Decryption middleware
- [x] Forward to upstream LLM API
- [x] Encrypt response
- [x] Public key endpoint
- [x] Health check endpoint
- [ ] Key store with rotation — *planned for v0.2*
- [ ] Content safety filter hook — *planned*
- [ ] Streaming support — *deferred to v0.2*
- [x] Configuration

### Phase 4: CLI & Testing ✅ COMPLETE
- [x] `keygen` command
- [x] `inspect` command
- [x] `encrypt` / `decrypt` commands
- [x] `test-roundtrip` command
- [x] `proxy` command
- [x] `server` command
- [x] Integration tests (7 tests)
- [x] Security property tests (6 tests)
- [x] Doc tests (1 test)
- [ ] Criterion benchmarks — *placeholder created*
- [ ] Fuzz testing (cargo-fuzz) — *planned*
- [x] Clippy clean (zero warnings)

### Phase 5: Distribution ✅ COMPLETE
- [x] Docker images (multi-stage builds)
- [x] GitHub Actions CI/CD pipeline
- [x] Documentation (README, ARCHITECTURE, SECURITY, CONTRIBUTING, CHANGELOG)
- [x] Python client example
- [x] Security policy (SECURITY.md)
- [x] Dual license (MIT + Apache-2.0)
- [x] v0.1.0 release
- [ ] crates.io publish — *after initial testing*
- [ ] brew formula — *planned*

---

## SDK Development Phases

All SDKs wrap `veil-core` via FFI — one crypto implementation, many language bindings.

### Phase 6: Python SDK (PyO3) — *Estimated: 2 weeks*
- [ ] Create `crates/veil-python/` with PyO3 bindings
- [ ] Expose `VeilSession` as native Python class
- [ ] `encrypt_request()` and `decrypt_response()` methods
- [ ] `keygen()` and `inspect()` utility functions
- [ ] maturin build configuration
- [ ] PyPI publishing (`pip install veil-sdk`)
- [ ] Python-specific documentation and examples
- [ ] pytest test suite calling through FFI
- [ ] Type stubs (`.pyi`) for IDE autocompletion
- [ ] Benchmarks vs. pure-Python implementation

### Phase 7: JavaScript/TypeScript SDK — *Estimated: 3 weeks*
- [ ] Create `crates/veil-napi/` with NAPI-RS bindings (Node.js)
- [ ] Create `crates/veil-wasm/` with wasm-bindgen (Browser)
- [ ] npm package `@veil/node` for Node.js
- [ ] npm package `@veil/browser` for browsers
- [ ] TypeScript type definitions
- [ ] Streaming API support (ReadableStream integration)
- [ ] Jest/Vitest test suites
- [ ] Bundle size optimization for WASM target

### Phase 8: Go SDK (CGo) — *Estimated: 2 weeks*
- [ ] Create `crates/veil-ffi/` with C ABI exports (`cdylib`)
- [ ] Go wrapper package `github.com/oxifederation/veil-go`
- [ ] Idiomatic Go types (`VeilSession`, `Envelope`, etc.)
- [ ] CGo build integration and cross-compilation
- [ ] Go module publishing
- [ ] Go test suite

### Phase 9: Mobile SDKs (UniFFI) — *Estimated: 4 weeks*
- [ ] Create `crates/veil-uniffi/` with UDL interface definition
- [ ] Swift bindings for iOS (CocoaPods / SPM)
- [ ] Kotlin bindings for Android (Maven Central)
- [ ] Cross-compilation for ARM targets (iOS, Android NDK)
- [ ] Example iOS app with SwiftUI
- [ ] Example Android app with Jetpack Compose
- [ ] XCTest and JUnit test suites

### Phase 10: Java SDK (JNI) — *Estimated: 2 weeks*
- [ ] JNI bindings from `veil-ffi` C ABI
- [ ] Maven artifact `com.oxifederation:veil-sdk`
- [ ] Idiomatic Java API with try-with-resources
- [ ] JUnit test suite
- [ ] Spring Boot integration example

---

## Protocol Roadmap

### v0.2.0 — Streaming & Key Rotation
- [ ] SSE streaming encryption (per-chunk)
- [ ] Server key rotation protocol
- [ ] Client key caching with TTL
- [ ] Connection pooling in proxy
- [ ] Rate limiting
- [ ] Prometheus metrics endpoints

### v0.3.0 — Production Hardening
- [ ] Fuzz testing with cargo-fuzz
- [ ] Third-party security audit
- [ ] Performance optimization (SIMD, batching)
- [ ] Multi-key support (key IDs)
- [ ] Envelope compression (optional)
- [ ] Protocol version negotiation

### v1.0.0 — Stable Release
- [ ] Stable protocol specification (no breaking changes)
- [ ] All SDKs at 1.0 with SemVer guarantees
- [ ] Production deployment guide
- [ ] Formal security analysis paper
- [ ] Compliance documentation (SOC2, HIPAA considerations)

---

## Threat Model Summary

| Threat | Mitigation |
|--------|------------|
| Middleware reads prompts | Payload encrypted, middleware only sees headers |
| Replay attacks | Nonce per message, optional timestamp in AAD |
| Key compromise (long-term) | Forward secrecy via ephemeral keys |
| Tampered ciphertext | GCM authentication tag detects modifications |
| Side-channel (timing) | Constant-time crypto operations (RustCrypto) |
| Memory exposure | Zeroize trait on all key material |
| Downgrade attacks | Version pinning, reject non-encrypted requests |
| Reflection attacks | Directional keys (c2s ≠ s2c) |

---

## License

Dual-licensed: **Apache 2.0** OR **MIT** (user's choice)
Maximum adoption, compatible with commercial use.
