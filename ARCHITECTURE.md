# Veil Architecture

> Comprehensive technical architecture of the Veil E2E encryption protocol for LLM inference.

## Table of Contents

- [System Overview](#system-overview)
- [Cryptographic Protocol](#cryptographic-protocol)
- [Key Exchange Protocol](#key-exchange-protocol)
- [Envelope Wire Format](#envelope-wire-format)
- [Session Management](#session-management)
- [Crate Architecture](#crate-architecture)
- [SDK Architecture (FFI Bindings)](#sdk-architecture-ffi-bindings)
- [Streaming SSE Handling](#streaming-sse-handling)
- [Threat Model](#threat-model)
- [Security Properties](#security-properties)

---

## System Overview

Veil is an application-layer encryption protocol that provides end-to-end confidentiality
for LLM inference traffic. It operates above TLS, ensuring that prompts and responses
remain encrypted through all intermediary infrastructure.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         NETWORK PATH                                   │
│                                                                         │
│  ┌──────────┐   ┌────────────┐   ┌──────────┐   ┌───────────────────┐  │
│  │          │   │            │   │          │   │                   │  │
│  │   Your   │──▶│   Veil     │──▶│  Cloud   │──▶│    Veil Server    │  │
│  │   App    │   │   Client   │   │  Infra   │   │      Shim        │  │
│  │          │◀──│   Proxy    │◀──│          │◀──│                   │  │
│  │          │   │            │   │          │   │                   │  │
│  └──────────┘   └────────────┘   └──────────┘   └───────┬───────────┘  │
│   plaintext       encrypts/       opaque          decrypts/  │          │
│   OpenAI API      decrypts        blob            encrypts   │          │
│                                                              ▼          │
│                                                     ┌──────────────┐   │
│                                                     │  LLM Engine  │   │
│                                                     │  (plaintext) │   │
│                                                     └──────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘

  🔑 = Has keys         🔒 = Encrypted blob         📋 = Metadata only

  Your App  →  🔑 Client Proxy  →  🔒 Gateway  →  🔒 Load Balancer
            →  🔒 Rate Limiter  →  🔑 Server Shim  →  LLM Engine
```

### Data Visibility Matrix

| Component | Sees Prompt? | Sees Response? | Sees Metadata? |
|-----------|:----------:|:-----------:|:------------:|
| Your Application | ✅ | ✅ | ✅ |
| Veil Client Proxy | ✅ | ✅ | ✅ |
| API Gateway | ❌ | ❌ | ✅ |
| Load Balancer | ❌ | ❌ | ✅ |
| CDN / Proxy | ❌ | ❌ | ✅ |
| Rate Limiter | ❌ | ❌ | ✅ |
| Billing System | ❌ | ❌ | ✅ |
| Veil Server Shim | ✅ | ✅ | ✅ |
| LLM Inference Engine | ✅ | ✅ | N/A |

---

## Cryptographic Protocol

Veil uses a three-stage cryptographic pipeline:

```
┌─────────────────────────────────────────────────────────────┐
│                CRYPTOGRAPHIC PIPELINE                        │
│                                                             │
│  ┌───────────────┐    ┌───────────────┐    ┌─────────────┐  │
│  │   X25519      │    │  HKDF-SHA256  │    │ AES-256-GCM │  │
│  │   ECDH        │───▶│  Key          │───▶│ Authenticated│  │
│  │   Key         │    │  Derivation   │    │ Encryption  │  │
│  │   Exchange    │    │               │    │             │  │
│  └───────────────┘    └───────────────┘    └─────────────┘  │
│                                                             │
│  RFC 7748             RFC 5869             NIST SP 800-38D  │
│  128-bit security     Directional keys     AEAD cipher      │
│  Constant-time        Salt: "veil-e2e-     96-bit nonce     │
│  Forward secrecy       llm-v1"             128-bit tag      │
└─────────────────────────────────────────────────────────────┘
```

### Stage 1: X25519 ECDH Key Exchange (RFC 7748)

The server holds a long-lived **static X25519 key pair** for identity. The client
generates a fresh **ephemeral X25519 key pair** for every request, providing
perfect forward secrecy.

```
  Client (ephemeral)              Server (static)
  ┌──────────────────┐            ┌──────────────────┐
  │ sk_c = random()  │            │ sk_s (long-lived) │
  │ pk_c = X25519(   │            │ pk_s = X25519(    │
  │        sk_c, G)  │            │        sk_s, G)   │
  └────────┬─────────┘            └────────┬──────────┘
           │                               │
           │    shared_secret =             │
           │    X25519(sk_c, pk_s)          │
           │         =                     │
           │    X25519(sk_s, pk_c)          │
           ▼                               ▼
      ┌─────────────────────────────────────────┐
      │  shared_secret (32 bytes, identical)     │
      └─────────────────────────────────────────┘
```

**Properties:**
- **128-bit security level** (equivalent to RSA-3072)
- **Constant-time** execution prevents timing side-channels
- **Forward secrecy**: ephemeral client key is destroyed after use
- **Key compromise**: server key leak does not expose past sessions

### Stage 2: HKDF-SHA256 Key Derivation (RFC 5869)

The shared secret is expanded into two independent 256-bit AES keys using
HKDF with a protocol-specific salt and directional info strings:

```
  shared_secret (32 bytes)
        │
        ▼
  ┌─────────────────────────────────────┐
  │ HKDF-Extract                        │
  │   salt = "veil-e2e-llm-v1"         │
  │   IKM  = shared_secret              │
  │   PRK  = HMAC-SHA256(salt, IKM)     │
  └──────────────┬──────────────────────┘
                 │
        ┌────────┴────────┐
        ▼                 ▼
  ┌───────────┐    ┌───────────┐
  │  Expand   │    │  Expand   │
  │  info =   │    │  info =   │
  │ "veil-c2s"│    │ "veil-s2c"│
  └─────┬─────┘    └─────┬─────┘
        ▼                 ▼
  ┌───────────┐    ┌───────────┐
  │  AES key  │    │  AES key  │
  │  client → │    │  server → │
  │  server   │    │  client   │
  │ (32 bytes)│    │ (32 bytes)│
  └───────────┘    └───────────┘
```

**Directional keys prevent reflection attacks.** A client-encrypted message
cannot be replayed as a server response because they use different keys.

### Stage 3: AES-256-GCM Authenticated Encryption (NIST SP 800-38D)

Each message is encrypted with AES-256-GCM using the appropriate directional key:

```
  Input:                           Output:
  ┌──────────────┐                ┌──────────────────────────────┐
  │ plaintext    │                │ nonce (12 bytes, random)     │
  │ AES-256 key  │───AES-GCM────▶│ ciphertext (= len(plaintext))│
  │ nonce (12B)  │                │ auth tag (16 bytes)          │
  │ AAD          │                └──────────────────────────────┘
  └──────────────┘
```

**AEAD Properties:**
- **Confidentiality**: ciphertext reveals nothing about plaintext
- **Integrity**: any modification is detected (128-bit auth tag)
- **Authenticity**: only the key holder could have produced the ciphertext
- **AAD binding**: metadata (direction tag) is authenticated but not encrypted

**Nonce Generation:**
- 96-bit (12-byte) random nonce from OS CSPRNG
- Generated fresh for every encryption operation
- Collision probability: negligible (~2⁻⁴⁸ after 2²⁴ messages per key)

---

## Key Exchange Protocol

The complete key exchange and encryption flow between client and server:

```
 Client                                                    Server
   │                                                          │
   │ ── GET /v1/veil/public-key ─────────────────────────────▶│
   │                                                          │
   │ ◀─ { public_key: "<b64>", key_id: "prod-v2",           │
   │      algorithm: "X25519+HKDF-SHA256+AES-256-GCM" } ─────│
   │                                                          │
   │  [Generate ephemeral X25519 key pair]                    │
   │  [ECDH: shared = X25519(eph_secret, server_pub)]         │
   │  [HKDF: c2s_key, s2c_key = derive(shared)]               │
   │                                                          │
   │ ── POST /v1/veil/inference ─────────────────────────────▶│
   │    Headers:                                              │
   │      X-Veil-Version: 1                                   │
   │      X-Veil-Key-Id: prod-v2                              │
   │      X-Veil-Ephemeral-Key: <client_eph_pub_b64>         │
   │      X-Veil-Model: gpt-4                                │
   │      X-Veil-Token-Estimate: 500                          │
   │    Body: VeilEnvelope {                                  │
   │      version: 1,                                         │
   │      nonce: <12 bytes>,                                  │
   │      ciphertext: AES-GCM(c2s_key, prompt),              │
   │      aad: "veil-v1-c2s"                                  │
   │    }                                                     │
   │                                                          │
   │                  [ECDH: shared = X25519(server_sk,       │
   │                         client_eph_pub)]                 │
   │                  [HKDF: c2s_key, s2c_key = derive(shared)]│
   │                  [Decrypt: prompt = AES-GCM-Open(        │
   │                            c2s_key, envelope)]           │
   │                  [Forward prompt to LLM backend]          │
   │                  [Receive LLM response]                   │
   │                  [Encrypt: AES-GCM(s2c_key, response)]   │
   │                                                          │
   │ ◀─ 200 OK ──────────────────────────────────────────────│
   │    Headers:                                              │
   │      X-Veil-Encrypted: true                              │
   │    Body: VeilEnvelope {                                  │
   │      version: 1,                                         │
   │      nonce: <12 bytes>,                                  │
   │      ciphertext: AES-GCM(s2c_key, response),            │
   │      aad: "veil-v1-s2c"                                  │
   │    }                                                     │
   │                                                          │
   │  [Decrypt: response = AES-GCM-Open(s2c_key, envelope)]  │
   │  [Destroy ephemeral key — forward secrecy]               │
   │                                                          │
```

---

## Envelope Wire Format

The `VeilEnvelope` is the encrypted payload transported between client and server.
It supports both MessagePack (binary, compact) and JSON serialization.

### Structure

```
  ┌──────────────────────────────────────────────────────┐
  │ VeilEnvelope                                         │
  ├──────────────┬───────────────────────────────────────┤
  │ version      │ u8 — protocol version (currently 1)   │
  ├──────────────┼───────────────────────────────────────┤
  │ nonce        │ [u8; 12] — AES-GCM nonce (base64 in   │
  │              │ JSON, raw bytes in MessagePack)        │
  ├──────────────┼───────────────────────────────────────┤
  │ ciphertext   │ Vec<u8> — encrypted payload with GCM  │
  │              │ auth tag appended (16 bytes)           │
  ├──────────────┼───────────────────────────────────────┤
  │ aad          │ Vec<u8> — Additional Authenticated     │
  │              │ Data (e.g., "veil-v1-c2s")            │
  └──────────────┴───────────────────────────────────────┘

  Total overhead per message:
    Nonce:     12 bytes
    Auth Tag:  16 bytes (appended to ciphertext)
    Envelope:  ~20 bytes (msgpack framing)
    ─────────────────────
    Total:     ~48 bytes + ciphertext length
```

### JSON Representation

```json
{
  "version": 1,
  "nonce": "dGVzdG5vbmNlMTI=",
  "ciphertext": "<base64-encoded ciphertext + 16-byte GCM tag>",
  "aad": "dmVpbC12MS1jMnM="
}
```

### Metadata Headers

Transported alongside the envelope in HTTP headers (visible to middleware):

```
  ┌─────────────────────────────────────────────────────────┐
  │ HTTP Headers (Cleartext Metadata)                        │
  ├───────────────────────────┬─────────────────────────────┤
  │ X-Veil-Version            │ Protocol version ("1")       │
  │ X-Veil-Key-Id             │ Server key ID ("prod-v2")   │
  │ X-Veil-Ephemeral-Key      │ Client ephemeral pub (b64)  │
  │ X-Veil-Model              │ Target model ("gpt-4")      │
  │ X-Veil-Token-Estimate     │ Estimated tokens ("500")    │
  └───────────────────────────┴─────────────────────────────┘
```

---

## Session Management

### Client Session Lifecycle

```
  ┌─────────────────────────────────────────┐
  │            ClientSession                │
  │                                         │
  │  1. Fetch server public key             │
  │  2. Generate ephemeral X25519 keypair   │
  │  3. ECDH → shared secret               │
  │  4. HKDF → c2s_key, s2c_key            │
  │  5. Encrypt request (c2s_key)           │
  │  6. Decrypt response (s2c_key)          │
  │  7. Session complete — keys zeroized    │
  └─────────────────────────────────────────┘
```

### Server Session Lifecycle

```
  ┌─────────────────────────────────────────┐
  │            ServerSession                │
  │                                         │
  │  1. Receive client ephemeral public key │
  │  2. ECDH with server static secret      │
  │  3. HKDF → c2s_key, s2c_key            │
  │  4. Decrypt request (c2s_key)           │
  │  5. Forward to LLM backend              │
  │  6. Encrypt response (s2c_key)          │
  │  7. Session complete — keys zeroized    │
  └─────────────────────────────────────────┘
```

### Memory Safety

- `SessionKeys` implements `ZeroizeOnDrop` — keys are overwritten with zeros when dropped
- `EphemeralSecret` is consumed (moved) on use — cannot be reused accidentally
- `StaticSecret` uses zeroize-on-drop via `StaticKeyPair`
- No `unsafe` code in `veil-core`

---

## Crate Architecture

```
  ┌─────────────────────────────────────────────────────────┐
  │                    Workspace Root                        │
  │                    (Cargo.toml)                          │
  └──────────────────────┬──────────────────────────────────┘
                         │
         ┌───────────────┼───────────────┬───────────────┐
         ▼               ▼               ▼               ▼
  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌──────────┐
  │ veil-core   │ │ veil-client │ │ veil-server │ │ veil-cli │
  │             │ │             │ │             │ │          │
  │ ┌─────────┐ │ │ Depends on  │ │ Depends on  │ │ Depends  │
  │ │ keys.rs │ │ │ veil-core   │ │ veil-core   │ │ on all   │
  │ │ kdf.rs  │ │ │             │ │             │ │          │
  │ │cipher.rs│ │ │ ┌─────────┐ │ │ ┌─────────┐ │ │ Commands:│
  │ │envelope │ │ │ │ proxy   │ │ │ │ server  │ │ │ keygen   │
  │ │ .rs     │ │ │ │ config  │ │ │ │ handler │ │ │ encrypt  │
  │ │session  │ │ │ └─────────┘ │ │ │ config  │ │ │ test     │
  │ │ .rs     │ │ │             │ │ │ metrics │ │ │ proxy    │
  │ │error.rs │ │ │ hyper +     │ │ └─────────┘ │ │ server   │
  │ └─────────┘ │ │ reqwest     │ │             │ │          │
  │             │ │             │ │ axum +      │ │ clap     │
  │ Pure crypto │ │ HTTP proxy  │ │ reqwest     │ │          │
  │ No I/O      │ │ layer       │ │ + prometheus│ │ CLI tool │
  │ No async    │ │             │ │             │ │          │
  └─────────────┘ └─────────────┘ └─────────────┘ └──────────┘
        ▲               │               │               │
        │               │               │               │
        └───────────────┴───────────────┴───────────────┘
                    all depend on veil-core
```

### Dependency Design Principles

1. **`veil-core` is pure cryptography** — no I/O, no async, no networking. This makes
   it ideal for FFI binding to other languages.
2. **`veil-client` handles HTTP proxying** — uses hyper for the proxy server and
   reqwest for upstream calls.
3. **`veil-server` handles HTTP serving** — uses axum with tower middleware for
   production-grade request handling.
4. **`veil-cli` is the user-facing binary** — thin wrapper that orchestrates the
   other crates via clap commands.

---

## SDK Architecture (FFI Bindings)

Veil follows the **single-core, many-bindings** architecture pattern. All cryptographic
logic lives in `veil-core` (Rust), and every language SDK is a thin FFI wrapper around it.

```
  ┌─────────────────────────────────────────────────────────────────┐
  │                     Language SDKs                                │
  │                                                                 │
  │  ┌──────────┐ ┌──────────┐ ┌────────┐ ┌────────┐ ┌───────────┐ │
  │  │  Python  │ │   JS/TS  │ │   Go   │ │  Java  │ │Swift/     │ │
  │  │   SDK    │ │   SDK    │ │  SDK   │ │  SDK   │ │Kotlin SDK │ │
  │  │  (PyO3)  │ │(NAPI-RS/ │ │ (CGo)  │ │ (JNI)  │ │ (UniFFI)  │ │
  │  │         │ │  WASM)   │ │        │ │        │ │           │ │
  │  └────┬─────┘ └────┬─────┘ └───┬────┘ └───┬────┘ └─────┬─────┘ │
  │       │            │           │          │            │       │
  │       └────────────┴─────┬─────┴──────────┴────────────┘       │
  │                          │                                     │
  │                    ┌─────▼──────┐                               │
  │                    │    FFI     │                               │
  │                    │  Boundary  │                               │
  │                    │  (C ABI)   │                               │
  │                    └─────┬──────┘                               │
  │                          │                                     │
  │                    ┌─────▼──────┐                               │
  │                    │ veil-core  │                               │
  │                    │   (Rust)   │                               │
  │                    │            │                               │
  │                    │ X25519     │                               │
  │                    │ HKDF       │                               │
  │                    │ AES-GCM    │                               │
  │                    │ Envelope   │                               │
  │                    │ Session    │                               │
  │                    └────────────┘                               │
  └─────────────────────────────────────────────────────────────────┘
```

### Why Single-Core Architecture?

| Concern | Single-Core (Veil) | Re-implement per Language |
|---------|-------------------|---------------------------|
| Bug surface | 1 implementation | N implementations |
| Crypto audit | Audit once | Audit N times |
| Consistency | Guaranteed identical | Risk of subtle differences |
| Performance | Rust-optimized + AES-NI | Varies by language |
| Maintenance | Fix once, all SDKs get it | Fix N times |
| Security patches | Single point of update | Coordinate N releases |

### SDK Binding Technologies

#### Phase 2: Python SDK (PyO3)

```
  Python app  →  import veil  →  PyO3 bindings  →  veil-core (Rust)
```

[PyO3](https://pyo3.rs/) generates native Python extension modules from Rust code.
The Python SDK exposes `VeilSession`, `encrypt_request()`, and `decrypt_response()`
as native Python classes — no subprocess, no HTTP, no overhead.

```python
# Future Python SDK usage
from veil import VeilSession

session = VeilSession(server_public_key="<b64>", key_id="prod-v2")
envelope, headers = session.encrypt_request(prompt_bytes, model="gpt-4")
plaintext = session.decrypt_response(response_bytes)
```

#### Phase 3: JavaScript/TypeScript SDK (NAPI-RS + WASM)

```
  Node.js app  →  require("@veil/sdk")  →  NAPI-RS  →  veil-core (Rust)
  Browser app  →  import veil from ".." →  WASM     →  veil-core (Rust)
```

- **NAPI-RS** for Node.js: native addon with zero-copy performance
- **wasm-bindgen** for browsers: runs veil-core as WebAssembly

#### Phase 4: Go SDK (CGo)

```
  Go app  →  veil.NewSession()  →  CGo FFI  →  libveil_core.so
```

Rust `veil-core` compiled as a C-compatible shared library (`cdylib`),
wrapped with idiomatic Go types.

#### Phase 5: Mobile SDKs (UniFFI)

```
  Swift app   →  VeilSession()  →  UniFFI  →  veil-core (Rust)
  Kotlin app  →  VeilSession()  →  UniFFI  →  veil-core (Rust)
```

[UniFFI](https://mozilla.github.io/uniffi-rs/) (Mozilla) generates Swift and Kotlin
bindings from a single Rust crate with a UDL interface definition. One build produces
both iOS and Android native libraries.

### FFI Surface

The FFI boundary exposes a minimal, stable C ABI:

```c
// Opaque handles
typedef struct VeilClientSession VeilClientSession;
typedef struct VeilServerSession VeilServerSession;

// Client operations
VeilClientSession* veil_client_session_new(
    const char* server_public_key_b64,
    const char* key_id
);

int veil_client_encrypt_request(
    VeilClientSession* session,
    const uint8_t* plaintext, size_t plaintext_len,
    const char* model,
    uint32_t token_estimate,
    uint8_t** envelope_out, size_t* envelope_len,
    char** headers_json_out
);

int veil_client_decrypt_response(
    VeilClientSession* session,
    const uint8_t* envelope, size_t envelope_len,
    uint8_t** plaintext_out, size_t* plaintext_len
);

void veil_client_session_free(VeilClientSession* session);

// Memory management
void veil_free_bytes(uint8_t* ptr, size_t len);
void veil_free_string(char* ptr);
```

---

## Streaming SSE Handling

LLM APIs often return Server-Sent Events (SSE) for streaming responses. Veil handles
this by encrypting each SSE chunk independently:

```
  LLM Backend                    Veil Server              Client
      │                              │                       │
      │ ── SSE: data: {chunk1} ────▶ │                       │
      │                              │ encrypt(chunk1)       │
      │                              │ ── SSE: data:         │
      │                              │    {encrypted1} ────▶ │
      │                              │                       │ decrypt
      │ ── SSE: data: {chunk2} ────▶ │                       │
      │                              │ encrypt(chunk2)       │
      │                              │ ── SSE: data:         │
      │                              │    {encrypted2} ────▶ │
      │                              │                       │ decrypt
      │ ── SSE: data: [DONE] ──────▶ │                       │
      │                              │ encrypt([DONE])       │
      │                              │ ── SSE: data:         │
      │                              │    {encrypted3} ────▶ │
      │                              │                       │ decrypt
```

**Streaming Design Decisions:**

- Each SSE chunk is independently encrypted with a fresh nonce
- The same session keys (c2s/s2c) are reused within a single request
- Chunk ordering is preserved by the SSE transport (TCP ordering)
- Each chunk is independently authenticated (GCM tag per chunk)
- **Status:** Planned for v0.2.0

---

## Threat Model

### Adversary Capabilities

| Adversary | Capabilities | Veil Mitigation |
|-----------|-------------|------------------|
| Passive network observer | Read all traffic | AES-256-GCM encryption |
| Compromised API gateway | Read/modify traffic | AEAD prevents tampering; encryption prevents reading |
| Compromised load balancer | Duplicate/reorder | Nonce uniqueness; AAD binding |
| Stolen server key (future) | Decrypt future traffic | Rotate keys; past sessions safe (forward secrecy) |
| Stolen server key (past) | Decrypt past sessions | ❌ Cannot — ephemeral keys destroyed |
| Rogue middleware | Inject fake responses | GCM auth tag rejects modifications |
| Metadata analyst | Infer content from size/timing | Partial: can see model, token estimate, timing |

### What Veil Does NOT Protect Against

1. **Compromised endpoints**: If the LLM engine or client device is compromised,
   the attacker has access to plaintext.
2. **Traffic analysis**: Request/response sizes and timing patterns may leak
   information about prompt content.
3. **Side-channel attacks**: CPU cache timing or power analysis on the crypto
   implementation (mitigated by constant-time operations in RustCrypto).
4. **Metadata leakage**: Model name, token estimates, and key IDs are visible
   by design (required for middleware functionality).

---

## Security Properties

### Formal Security Goals

| Property | Definition | How Veil Achieves It |
|----------|-----------|---------------------|
| **Confidentiality** | Prompts/responses unreadable by non-endpoints | AES-256-GCM encryption with ECDH-derived keys |
| **Integrity** | Tampering is detected and rejected | GCM 128-bit authentication tag |
| **Authenticity** | Messages provably from key holder | ECDH binds message to specific key pair |
| **Forward Secrecy** | Past sessions safe if key leaks | Fresh ephemeral X25519 key per request |
| **Key Separation** | c2s and s2c use different keys | HKDF with directional info strings |
| **Replay Resistance** | Old messages cannot be replayed | Random nonce per message; session binding |
| **Memory Safety** | No secret key remnants in RAM | Zeroize-on-drop for all key material |

### Cryptographic Constants

```
  HKDF Salt:     "veil-e2e-llm-v1"   (15 bytes)
  C2S Info:      "veil-c2s"           (8 bytes)
  S2C Info:      "veil-s2c"           (8 bytes)
  C2S AAD:       "veil-v1-c2s"        (11 bytes)
  S2C AAD:       "veil-v1-s2c"        (11 bytes)
  AES Key Size:  256 bits             (32 bytes)
  GCM Nonce:     96 bits              (12 bytes)
  GCM Tag:       128 bits             (16 bytes)
  X25519 Key:    256 bits             (32 bytes)
```

### Test Coverage Summary

| Category | Tests | What They Verify |
|----------|:-----:|------------------|
| Unit (cipher) | 7 | Encrypt/decrypt, tampering, wrong keys, AAD, empty, large |
| Unit (envelope) | 4 | MessagePack roundtrip, JSON roundtrip, headers, size |
| Unit (keys) | 5 | Generation, roundtrip, ECDH, parsing |
| Unit (kdf) | 2 | Key derivation, different secrets |
| Unit (session) | 4 | Full roundtrip, cross-session, large prompt, headers |
| Integration | 7 | E2E roundtrip, tampering, wrong keys, large payloads |
| Security | 6 | Nonce uniqueness, ciphertext indistinguishability, key randomness |
| Doc tests | 1 | Library usage example compiles and runs |
| **Total** | **36** | |
