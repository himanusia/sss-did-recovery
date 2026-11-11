"""Sealed share envelopes (X25519 + HKDF-SHA256 + ChaCha20-Poly1305).

Wire format, versioned so a future scheme can be added without ambiguity:

    b"SD1" | ephemeral_public_key (32) | nonce (12) | ciphertext+tag

The same construction is implemented in the browser (apps/web/src/sealing.ts),
so a share sealed by the device can only be opened by the guardian it was
addressed to, and a rewrapped share can only be opened by the recovering device.
The server moves ciphertext; it never holds a key that opens these boxes.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PREFIX = b"SD1"
AAD_TAG = b"sss-did/sealed/v1"
INFO = b"sss-did sealed share v1"


def _derive(shared: bytes, ephemeral_public: bytes, recipient_public: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=ephemeral_public + recipient_public,
        info=INFO,
    ).derive(shared)


def generate_keypair() -> tuple[bytes, bytes]:
    private = X25519PrivateKey.generate()
    return (
        private.private_bytes_raw(),
        private.public_key().public_bytes_raw(),
    )


def public_key_of(private_bytes: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(private_bytes).public_key().public_bytes_raw()


def seal(plaintext: bytes, recipient_public: bytes) -> bytes:
    if len(recipient_public) != 32:
        raise ValueError("recipient public key must be 32 bytes")
    ephemeral = X25519PrivateKey.generate()
    ephemeral_public = ephemeral.public_key().public_bytes_raw()
    shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(recipient_public))
    key = _derive(shared, ephemeral_public, recipient_public)
    nonce = os.urandom(12)
    aad = AAD_TAG + ephemeral_public + recipient_public
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
    return PREFIX + ephemeral_public + nonce + ciphertext


def open_sealed(blob: bytes, private_bytes: bytes) -> bytes:
    if not blob.startswith(PREFIX):
        raise ValueError("not a sealed envelope")
    body = blob[len(PREFIX) :]
    if len(body) < 32 + 12 + 16:
        raise ValueError("sealed envelope is truncated")
    ephemeral_public = body[:32]
    nonce = body[32:44]
    ciphertext = body[44:]
    private = X25519PrivateKey.from_private_bytes(private_bytes)
    recipient_public = private.public_key().public_bytes_raw()
    shared = private.exchange(X25519PublicKey.from_public_bytes(ephemeral_public))
    key = _derive(shared, ephemeral_public, recipient_public)
    aad = AAD_TAG + ephemeral_public + recipient_public
    return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)
