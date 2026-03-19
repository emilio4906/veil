# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Veil, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, email: **security@oxifederation.org**

You should receive a response within 48 hours. We will work with you to understand
and address the issue before any public disclosure.

## Supported Versions

| Version | Supported          |
|---------|--------------------|  
| 0.1.x   | ✅ Current release  |

## Security Model

### Cryptographic Primitives

| Component        | Algorithm              | Standard           |
|------------------|------------------------|--------------------|  
| Key Exchange     | X25519 ECDH            | RFC 7748           |
| Key Derivation   | HKDF-SHA256            | RFC 5869           |
| Encryption       | AES-256-GCM            | NIST SP 800-38D    |
| Nonce Generation | OS CSPRNG (12 bytes)   | Per-message random |

### Threat Model

Veil protects against:
- ✅ Passive eavesdropping on prompt/response content
- ✅ Man-in-the-middle tampering (GCM authentication)
- ✅ Replay attacks (unique nonce per message)
- ✅ Intermediary data harvesting (API gateways, proxies, CDNs)
- ✅ Forward secrecy compromise (ephemeral keys per session)

Veil does NOT protect against:
- ❌ Compromised LLM inference engine (has the decryption key)
- ❌ Compromised client device
- ❌ Metadata analysis (model name, request size, timing)
- ❌ Side-channel attacks on the crypto implementation

### Memory Safety

- All secret keys use `zeroize` for secure memory cleanup on drop
- Ephemeral keys are consumed (moved) after use — cannot be reused
- No unsafe code in veil-core

### Dependencies

All cryptographic dependencies are well-audited Rust crates:
- `x25519-dalek` — dalek-cryptography project
- `aes-gcm` — RustCrypto project  
- `hkdf` — RustCrypto project
- `sha2` — RustCrypto project
- `rand` — Rust standard CSPRNG
- `zeroize` — Secure memory zeroing
