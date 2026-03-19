#!/usr/bin/env python3
"""Veil Python Client — E2E encrypted LLM API calls.

Demonstrates how to integrate Veil encryption from Python.
Uses the same cryptographic primitives as the Rust client.
"""
import json
import os
import hashlib
import hmac
from base64 import b64encode, b64decode
from typing import Tuple

import requests
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


class VeilSession:
    """Client session for Veil E2E encryption."""

    HKDF_INFO_C2S = b"veil-c2s-v1"
    HKDF_INFO_S2C = b"veil-s2c-v1"

    def __init__(self, server_public_key_b64: str, key_id: str = "default"):
        """Create a new Veil session.

        Args:
            server_public_key_b64: Base64-encoded X25519 public key of the server.
            key_id: Server key identifier for routing.
        """
        self.key_id = key_id

        # Generate ephemeral keypair
        self._ephemeral_private = X25519PrivateKey.generate()
        self._ephemeral_public = self._ephemeral_private.public_key()

        # Decode server public key
        server_pub_bytes = b64decode(server_public_key_b64)
        server_public_key = X25519PublicKey.from_public_bytes(server_pub_bytes)

        # ECDH shared secret
        shared_secret = self._ephemeral_private.exchange(server_public_key)

        # Derive directional keys via HKDF
        self._c2s_key = self._derive_key(shared_secret, self.HKDF_INFO_C2S)
        self._s2c_key = self._derive_key(shared_secret, self.HKDF_INFO_S2C)

        # Ephemeral public key for the server
        self.ephemeral_public_b64 = b64encode(
            self._ephemeral_public.public_bytes_raw()
        ).decode()

    @staticmethod
    def _derive_key(shared_secret: bytes, info: bytes) -> bytes:
        """Derive a 256-bit AES key using HKDF-SHA256."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info,
        )
        return hkdf.derive(shared_secret)

    def encrypt_request(self, plaintext: bytes, model: str = "unknown",
                        token_estimate: int = 0) -> Tuple[bytes, dict]:
        """Encrypt a request payload.

        Returns:
            Tuple of (ciphertext, metadata_headers)
        """
        aesgcm = AESGCM(self._c2s_key)
        nonce = os.urandom(12)
        aad = b"veil-request"
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

        # Envelope: nonce || ciphertext
        envelope = nonce + ciphertext

        headers = {
            "X-Veil-Version": "1",
            "X-Veil-Key-Id": self.key_id,
            "X-Veil-Ephemeral-Key": self.ephemeral_public_b64,
            "X-Veil-Model": model,
            "X-Veil-Token-Estimate": str(token_estimate),
            "Content-Type": "application/octet-stream",
        }

        return envelope, headers

    def decrypt_response(self, envelope: bytes) -> bytes:
        """Decrypt a response from the server."""
        nonce = envelope[:12]
        ciphertext = envelope[12:]
        aesgcm = AESGCM(self._s2c_key)
        return aesgcm.decrypt(nonce, ciphertext, b"veil-response")


def main():
    """Example: send an encrypted prompt to a Veil server."""
    # In production, get this from the server's published key endpoint
    SERVER_URL = os.environ.get("VEIL_SERVER_URL", "http://localhost:8481")
    SERVER_KEY = os.environ.get("VEIL_SERVER_KEY", "")

    if not SERVER_KEY:
        print("Set VEIL_SERVER_KEY environment variable to the server's public key.")
        print("Example: export VEIL_SERVER_KEY='<base64-encoded-key>'")

        # Demo mode: self-test
        print("\nRunning self-test instead...\n")

        # Generate a test server keypair
        server_private = X25519PrivateKey.generate()
        server_public = server_private.public_key()
        server_pub_b64 = b64encode(server_public.public_bytes_raw()).decode()

        # Create client session
        session = VeilSession(server_pub_b64, "test-key")

        # Encrypt a prompt
        prompt = json.dumps({
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "What is the meaning of life?"}]
        }).encode()

        envelope, headers = session.encrypt_request(prompt, "gpt-4", 50)
        print(f"✅ Encrypted {len(prompt)} bytes → {len(envelope)} bytes")
        print(f"   Headers: {json.dumps(headers, indent=2)}")

        # Server side: decrypt
        client_ephemeral_pub = X25519PublicKey.from_public_bytes(
            b64decode(headers["X-Veil-Ephemeral-Key"])
        )
        shared_secret = server_private.exchange(client_ephemeral_pub)

        c2s_key = VeilSession._derive_key(shared_secret, VeilSession.HKDF_INFO_C2S)
        s2c_key = VeilSession._derive_key(shared_secret, VeilSession.HKDF_INFO_S2C)

        # Decrypt request
        nonce = envelope[:12]
        ct = envelope[12:]
        aesgcm = AESGCM(c2s_key)
        decrypted = aesgcm.decrypt(nonce, ct, b"veil-request")
        print(f"✅ Decrypted: {decrypted.decode()}")

        # Encrypt response
        response = json.dumps({"choices": [{"message": {"content": "42"}}]}).encode()
        resp_nonce = os.urandom(12)
        resp_aesgcm = AESGCM(s2c_key)
        resp_ct = resp_aesgcm.encrypt(resp_nonce, response, b"veil-response")
        resp_envelope = resp_nonce + resp_ct

        # Client decrypts response
        final = session.decrypt_response(resp_envelope)
        print(f"✅ Response decrypted: {final.decode()}")
        print("\n🎉 Self-test PASSED!")
        return

    # Production mode: send to actual server
    session = VeilSession(SERVER_KEY)
    prompt = json.dumps({
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "Hello from Veil!"}]
    }).encode()

    envelope, headers = session.encrypt_request(prompt, "gpt-4", 20)
    print(f"Sending encrypted request ({len(envelope)} bytes)...")

    resp = requests.post(
        f"{SERVER_URL}/v1/chat/completions",
        data=envelope,
        headers=headers,
        timeout=120,
    )

    if resp.status_code == 200:
        decrypted = session.decrypt_response(resp.content)
        print(f"Response: {decrypted.decode()}")
    else:
        print(f"Error: {resp.status_code} — {resp.text}")


if __name__ == "__main__":
    main()
