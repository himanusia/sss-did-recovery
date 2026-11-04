/**
 * DID and key helpers.
 *
 * Method name: `did:sss` (prototype-specific). The identifier is a 20-byte
 * random namespace value generated once at registration. It is deliberately
 * NOT derived from the authentication key: the whole point of recovery is that
 * the key rotates while the identity stays the same. The DID document lives in
 * the registry contract; this module only derives and validates identifiers.
 */
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import { randomBytes, toHex } from './sss.js';

export const DID_PREFIX = 'did:sss:';

export function addressFromPublicKey(publicKey: Uint8Array): string {
  const uncompressed =
    publicKey.length === 65 ? publicKey : secp256k1.getPublicKey(publicKey, false);
  return `0x${toHex(keccak_256(uncompressed.slice(1)).slice(12))}`;
}

export interface AuthKeyPair {
  privateKey: string;
  publicKey: string;
  address: string;
}

export function createAuthKeyPair(): AuthKeyPair {
  const privateKey = secp256k1.utils.randomPrivateKey();
  const publicKey = secp256k1.getPublicKey(privateKey, false);
  return {
    privateKey: `0x${toHex(privateKey)}`,
    publicKey: `0x${toHex(publicKey)}`,
    address: addressFromPublicKey(publicKey),
  };
}

export function publicKeyFromPrivateKey(privateKey: string): Uint8Array {
  return secp256k1.getPublicKey(privateKey.replace(/^0x/, ''), false);
}

export function addressFromPrivateKey(privateKey: string): string {
  return addressFromPublicKey(publicKeyFromPrivateKey(privateKey));
}

/** Fresh 20-byte identifier for a new identity. */
export function newDidId(): string {
  return `0x${toHex(randomBytes(20))}`;
}

export function didFromId(id: string): string {
  const clean = id.toLowerCase().replace(/^0x/, '');
  if (!/^[0-9a-f]{40}$/.test(clean)) throw new Error('invalid DID id');
  return `${DID_PREFIX}0x${clean}`;
}

/** Convenience for a brand-new identity. */
export function newDid(): string {
  return didFromId(newDidId());
}

export function isValidDid(did: string): boolean {
  return /^did:sss:0x[0-9a-fA-F]{40}$/.test(did);
}

/** bytes32 key used by the registry for a DID string. */
export function didHash(did: string): string {
  if (!isValidDid(did)) throw new Error('invalid did:sss identifier');
  return `0x${toHex(keccak_256(new TextEncoder().encode(did.toLowerCase())))}`;
}

export function idFromDid(did: string): string {
  if (!isValidDid(did)) throw new Error('invalid did:sss identifier');
  return did.slice(DID_PREFIX.length);
}
