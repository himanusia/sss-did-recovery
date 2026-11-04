/**
 * Shamir's Secret Sharing over the secp256k1 scalar field.
 *
 * The secret is a valid secp256k1 private key (the "recovery key"), so the
 * reconstructed value can sign a recovery transaction directly. Shares are
 * evaluations of a random polynomial of degree k-1 at x = 1..n.
 *
 * Everything in this module runs on the client. No share ever needs to leave
 * the device that received it except when the owner explicitly gathers them.
 */
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';

/** Order of the secp256k1 group: every scalar is reduced modulo this value. */
export const FIELD = secp256k1.CURVE.n;

export interface Share {
  /** Non-zero x coordinate, 1..255 (kept small so shares are short). */
  index: number;
  /** Polynomial evaluation f(index), 1 <= value < FIELD. */
  value: bigint;
}

export function mod(a: bigint, m: bigint = FIELD): bigint {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

function modPow(base: bigint, exponent: bigint, m: bigint): bigint {
  let result = 1n;
  let b = mod(base, m);
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return result;
}

export function modInverse(a: bigint, m: bigint = FIELD): bigint {
  if (a === 0n) throw new Error('inverse of zero');
  return modPow(a, m - 2n, m);
}

export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  globalThis.crypto.getRandomValues(out);
  return out;
}

export function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

export function bigIntToBytes(value: bigint, length = 32): Uint8Array {
  if (value < 0n) throw new Error('negative value');
  const out = new Uint8Array(length);
  let v = value;
  for (let i = length - 1; i >= 0; i -= 1) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) throw new Error('value does not fit');
  return out;
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function fromHex(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) throw new Error('odd-length hex');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    const byte = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error('invalid hex');
    out[i] = byte;
  }
  return out;
}

/** Uniform non-zero scalar below the group order. */
export function randomScalar(): bigint {
  for (;;) {
    const candidate = bytesToBigInt(randomBytes(32));
    if (candidate > 0n && candidate < FIELD) return candidate;
  }
}

/**
 * Splits `secret` into `shareCount` shares where any `threshold` of them
 * reconstruct it. Threshold 1 is allowed by the math but must be rejected by
 * the product: a 1-of-n share set is a plaintext copy of the secret.
 */
export function splitSecret(secret: bigint, threshold: number, shareCount: number): Share[] {
  if (!Number.isInteger(threshold) || !Number.isInteger(shareCount)) {
    throw new Error('threshold and shareCount must be integers');
  }
  if (threshold < 2) throw new Error('threshold must be at least 2');
  if (shareCount < threshold) throw new Error('shareCount must be >= threshold');
  if (shareCount > 255) throw new Error('shareCount must be <= 255');
  if (secret <= 0n || secret >= FIELD) throw new Error('secret out of field range');

  const coefficients: bigint[] = [secret];
  for (let i = 1; i < threshold; i += 1) coefficients.push(randomScalar());

  const shares: Share[] = [];
  for (let index = 1; index <= shareCount; index += 1) {
    let value = 0n;
    let power = 1n;
    for (const coefficient of coefficients) {
      value = mod(value + coefficient * power);
      power = mod(power * BigInt(index));
    }
    shares.push({ index, value });
  }
  return shares;
}

/** Lagrange interpolation at x = 0 over the scalar field. */
export function combineShares(shares: Share[]): bigint {
  if (shares.length === 0) throw new Error('no shares provided');

  const seen = new Set<number>();
  for (const share of shares) {
    if (!Number.isInteger(share.index) || share.index < 1 || share.index > 255) {
      throw new Error(`invalid share index: ${share.index}`);
    }
    if (share.value <= 0n || share.value >= FIELD) throw new Error('share value out of range');
    if (seen.has(share.index)) throw new Error(`duplicate share index: ${share.index}`);
    seen.add(share.index);
  }

  let secret = 0n;
  for (const share of shares) {
    let numerator = 1n;
    let denominator = 1n;
    for (const other of shares) {
      if (other.index === share.index) continue;
      numerator = mod(numerator * BigInt(other.index));
      denominator = mod(denominator * BigInt(other.index - share.index));
    }
    secret = mod(secret + share.value * numerator * modInverse(denominator));
  }
  return secret;
}

export function recoverySecretToPrivateKey(secret: bigint): Uint8Array {
  if (secret <= 0n || secret >= FIELD) throw new Error('secret out of field range');
  return bigIntToBytes(secret, 32);
}

/** Ethereum-style address of the recovery key derived from the secret. */
export function recoveryAddress(secret: bigint): string {
  const publicKey = secp256k1.getPublicKey(recoverySecretToPrivateKey(secret), false);
  return `0x${toHex(keccak_256(publicKey.slice(1)).slice(12))}`;
}

/** Keccak commitment to a single share, used as a Merkle leaf. */
export function commitmentOf(share: Share): Uint8Array {
  const payload = new Uint8Array(33);
  payload[0] = share.index;
  payload.set(bigIntToBytes(share.value, 32), 1);
  return keccak_256(payload);
}
