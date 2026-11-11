/**
 * Sealed share envelopes — the browser half of services/api/app/sealing.py.
 *
 * Format (must stay byte-identical to the Python side):
 *   "SD1" | ephemeral X25519 public key (32) | nonce (12) | ChaCha20-Poly1305 ciphertext
 *
 * Key derivation: HKDF-SHA256(shared, salt = ephemeral || recipient, info = "sss-did sealed share v1").
 * AAD binds both public keys, so a ciphertext cannot be replayed to another device
 * or attributed to a different sender key.
 */
import { x25519 } from '@noble/curves/ed25519';
import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';

const PREFIX = new TextEncoder().encode('SD1');
const AAD_TAG = new TextEncoder().encode('sss-did/sealed/v1');
const INFO = new TextEncoder().encode('sss-did sealed share v1');

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function fromHex(value: string): Uint8Array {
  const clean = value.startsWith('0x') ? value.slice(2) : value;
  if (clean.length % 2 !== 0) throw new Error('odd-length hex');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function derive(shared: Uint8Array, ephemeral: Uint8Array, recipient: Uint8Array): Uint8Array {
  return hkdf(sha256, shared, concat(ephemeral, recipient), INFO, 32);
}

export interface TransportKeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

/** Ephemeral key the recovering device uses to receive rewrapped shares. */
export function transportKeyPair(): TransportKeyPair {
  const privateKey = x25519.utils.randomPrivateKey();
  return { privateKey, publicKey: x25519.getPublicKey(privateKey) };
}

/** Seal `plaintext` to a guardian's X25519 public key (0x-prefixed hex accepted). */
export function sealTo(plaintext: Uint8Array, recipientHex: string): string {
  const recipient = fromHex(recipientHex);
  const ephemeralPrivate = x25519.utils.randomPrivateKey();
  const ephemeralPublic = x25519.getPublicKey(ephemeralPrivate);
  const shared = x25519.getSharedSecret(ephemeralPrivate, recipient);
  const key = derive(shared, ephemeralPublic, recipient);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = chacha20poly1305(key, nonce, concat(AAD_TAG, ephemeralPublic, recipient)).encrypt(
    plaintext,
  );
  return `0x${toHex(concat(PREFIX, ephemeralPublic, nonce, ciphertext))}`;
}

/** Open an envelope addressed to `privateKey`. Throws when the box is not ours. */
export function openSealed(sealedHex: string, privateKey: Uint8Array): Uint8Array {
  const blob = fromHex(sealedHex);
  if (blob.length < 3 + 32 + 12 + 16) throw new Error('sealed envelope is truncated');
  if (blob[0] !== PREFIX[0] || blob[1] !== PREFIX[1] || blob[2] !== PREFIX[2]) {
    throw new Error('not a sealed envelope');
  }
  const ephemeralPublic = blob.slice(3, 35);
  const nonce = blob.slice(35, 47);
  const ciphertext = blob.slice(47);
  const recipient = x25519.getPublicKey(privateKey);
  const shared = x25519.getSharedSecret(privateKey, ephemeralPublic);
  const key = derive(shared, ephemeralPublic, recipient);
  return chacha20poly1305(key, nonce, concat(AAD_TAG, ephemeralPublic, recipient)).decrypt(ciphertext);
}

export function hexOf(bytes: Uint8Array): string {
  return `0x${toHex(bytes)}`;
}
